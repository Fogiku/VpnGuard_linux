import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from compare_client_profiles import compare, lab_context


def report(revision, inode):
    return dict(schema=3, source="client_browser", video_id="jNQXAC9IVRw",
                lab=dict(session="run1", boot_sha256="boot", netns_inode=inode,
                         browser_version="123", channel="chromium", control_sha256="control",
                         profile_revision=revision),
                samples=[dict(utc=f"2026-11-22T12:0{i}:00Z", control_http=200, page_http=200,
                              continuous_seconds=5, playback="playing", discord_gateway="hello")
                         for i in range(2)])


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = report("base", 1), report("candidate", 2)

    def test_comparison_by_service(self):
        for sample in self.a["samples"]:
            sample["playback"] = "media_error"
        result = compare(self.a, self.b)["comparison"]
        self.assertEqual(result["youtube"]["outcome"], "only_second_observed")
        self.assertEqual(result["discord_gateway"]["outcome"], "both_observed")
        self.b["samples"][1]["control_http"] = 503
        result = compare(self.a, self.b)["comparison"]
        self.assertEqual(result["youtube"]["outcome"], "inconclusive")
        self.assertEqual(result["discord_gateway"]["pairs"][1]["states"][1], "control_inconclusive")

    def test_unconfirmed_mixed_and_interruptions(self):
        for status in ("unconfirmed", "observation_interrupted", "media_error"):
            self.b["samples"][0]["playback"] = status
            self.assertEqual(compare(self.a, self.b)["comparison"]["youtube"]["outcome"], "inconclusive")
        self.b["samples"][0].update(playback="playing", continuous_seconds=1)
        self.assertEqual(compare(self.a, self.b)["comparison"]["youtube"]["outcome"], "inconclusive")

    def test_mismatched_context(self):
        for key in ("session", "control_sha256", "boot_sha256", "browser_version", "channel",
                    "netns_inode", "profile_revision"):
            other = copy.deepcopy(self.b)
            other["lab"][key] = self.a["lab"][key] if key in ("netns_inode", "profile_revision") else "other"
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare(self.a, other)
        for update in ({"schema": 1}, {"video_id": "different"}, {"samples": self.b["samples"][:1]}):
            with self.assertRaises(ValueError):
                compare(self.a, dict(self.b, **update))
        for utc in ("2026-11-22T12:10:00Z", self.b["samples"][0]["utc"], "2026-11-22T12:01:00"):
            self.b["samples"][1]["utc"] = utc
            with self.assertRaises(ValueError):
                compare(self.a, self.b)

    @unittest.skipUnless(os.getenv("VPNGUARD_TEST_PROFILE_NETNS") == "1", "requires Linux netns privileges")
    def test_namespace_identity(self):
        with self.assertRaises(ValueError):
            lab_context("test", "base", "https://example.org", "123", "chromium")
        script = ("import json,sys; from compare_client_profiles import lab_context; "
                  "print(json.dumps(lab_context('test',sys.argv[1],'https://example.org','123','chromium')),flush=True); "
                  "sys.stdin.readline()")
        children = []
        try:
            for revision in ("base", "candidate"):
                children.append(subprocess.Popen(["unshare", "--net", sys.executable, "-c", script, revision],
                                                 cwd=Path(__file__).parent, text=True,
                                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE))
            for sample, child in zip((self.a, self.b), children):
                sample["lab"] = json.loads(child.stdout.readline())
            self.assertEqual(compare(self.a, self.b)["comparison"]["youtube"]["outcome"], "both_observed")
        finally:
            for child in children:
                child.communicate(timeout=8)
