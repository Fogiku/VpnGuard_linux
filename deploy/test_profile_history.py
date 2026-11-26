import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from contextlib import closing
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest

from compare_client_profiles import compare, profile_digest
from profile_history import DAY, record
from test_compare_client_profiles import report


class ShadowHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name, "history.db")
        self.now = 1780000000

    def reports(self, session, at, reflector=True):
        left, right = report("base", 1), report("candidate", 2)
        for r in [left, right]:
            r["lab"]["session"] = session
            for i, sample in enumerate(r["samples"]):
                sample["utc"] = datetime.fromtimestamp(at + 30*i, timezone.utc).isoformat()
                if reflector:
                    sample["egress"] = {"v4": dict(target_sha256="test", expected="192.0.2.0/24",
                                                   address="192.0.2.1", status="matched")}
        for sample in left["samples"]:
            sample["playback"] = "media_error"
        return left, right

    def test_history_isolation_freshness_and_inconclusive(self):
        first = compare(*self.reports("a", self.now-600))
        second = compare(*self.reports("b", self.now-300))
        self.assertIsNone(record(self.path, "isp", first, self.now)["youtube"]["suggested_profile"])
        result = record(self.path, "isp", second, self.now)
        self.assertEqual(result["youtube"]["suggested_profile"], "candidate")
        self.assertIsNone(result["discord_gateway"]["suggested_profile"])
        self.assertIsNone(record(self.path, "other", second, self.now)["youtube"]["suggested_profile"])
        self.assertEqual(record(self.path, "isp", second, self.now+DAY)["youtube"]["reason"], "expired")
        late = compare(*self.reports("c", self.now-100, False))
        self.assertEqual(record(self.path, "isp", late, self.now)["youtube"]["reason"], "no_egress_control")
        a,b = self.reports("d", self.now-100)
        b["samples"][0]["control_http"] = 503
        self.assertIsNone(record(self.path, "isp", compare(a,b), self.now)["youtube"]["suggested_profile"])

    def test_file_revisions_and_target_sets(self):
        profile = self.path.with_suffix(".conf")
        def tagged(session, at):
            pair = self.reports(session, at)
            for item, value in zip(pair, [b"base", b"candidate"]):
                profile.write_bytes(value)
                item["schema"] = 4
                item["lab"]["probe_version"] = 1
                item["lab"]["profile_revision"] = profile_digest(profile)
            return pair
        first = tagged("a", self.now-900)
        second = tagged("b", self.now-600)
        baseline = compare(*first)
        record(self.path, "isp", baseline, self.now)
        result = record(self.path, "isp", compare(*second), self.now)["youtube"]
        self.assertEqual(result["suggested_profile"], second[1]["lab"]["profile_revision"])
        third = tagged("c", self.now-300)
        for sample in third[0]["samples"] + third[1]["samples"]:
            del sample["discord_gateway"]
        different = compare(*third)
        self.assertNotEqual(different["target_set_sha256"], baseline["target_set_sha256"])
        self.assertEqual(record(self.path, "isp", different, self.now)["youtube"]["reason"], "need_second_session")
        profile.write_bytes(b"edited candidate")
        second[1]["lab"]["profile_revision"] = profile_digest(profile)
        self.assertEqual(record(self.path, "isp", compare(*second), self.now)["youtube"]["reason"], "need_second_session")
        second[1]["schema"] = 3
        with self.assertRaises(ValueError):
            compare(*second)
        second[0]["schema"] = 3
        self.assertEqual(record(self.path, "isp", compare(*second), self.now)["youtube"]["reason"], "need_second_session")

    def test_concurrent_replay_and_rollback(self):
        result = compare(*self.reports("a", self.now-500))
        with ThreadPoolExecutor(2) as pool:
            for value in pool.map(lambda _: record(self.path, "isp", result, self.now), range(2)):
                self.assertEqual(len(value["youtube"]["recent_trials"]), 1)
        modified = copy.deepcopy(result)
        modified["comparison"]["discord_gateway"]["outcome"] = "both_failed"
        with self.assertRaisesRegex(ValueError, "different evidence"):
            record(self.path, "isp", modified, self.now)
        self.assertEqual(record(self.path, "isp", result, self.now)["discord_gateway"]["recent_trials"][0]["outcome"], "both_observed")
        replay = compare(*self.reports("new-label", self.now-500))
        self.assertEqual(record(self.path, "isp", replay, self.now)["youtube"]["reason"], "overlapping_trials")
        with self.assertRaisesRegex(ValueError, "30 days"):
            record(self.path, "isp", result, self.now+31*DAY)

    def test_retention_and_changed_advantage(self):
        record(self.path, "isp", compare(*self.reports("a", self.now-600)), self.now)
        a, b = self.reports("b", self.now-300)
        for sample in a["samples"]:
            sample["playback"] = "playing"
        for sample in b["samples"]:
            sample["playback"] = "media_error"
        result = record(self.path, "isp", compare(a, b), self.now)
        self.assertEqual(result["youtube"]["reason"], "results_disagree")
        with patch("profile_history.MAX_ROWS", 4):
            record(self.path, "isp", compare(*self.reports("c", self.now-90)), self.now)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM profile_trials").fetchone()[0], 4)
        future = self.now + 31*DAY
        record(self.path, "isp", compare(*self.reports("d", future-60)), future)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM profile_trials").fetchone()[0], 2)

    def test_cli_legacy_and_opt_in(self):
        import time
        pair = self.reports("a", time.time()-300)
        command = [sys.executable, str(Path(__file__).with_name("compare_client_profiles.py"))]
        for i,r in enumerate(pair):
            f = self.path.with_suffix(f".{i}.json")
            f.write_text(json.dumps(r))
            command.append(str(f))
        self.assertNotIn("shadow", json.loads(subprocess.check_output(command)))
        result = json.loads(subprocess.check_output(command+["--history",str(self.path),"--network","demo"]))
        self.assertEqual(result["shadow"]["youtube"]["reason"], "need_second_session")
        with closing(sqlite3.connect(self.path)) as db:
            dump = " ".join(db.iterdump())
        self.assertNotIn("192.0.2.", dump)
        self.assertNotIn("candidate", dump)
