"""Replay anonymized synthetic browser evidence with the production classifier."""
import json
from pathlib import Path
import unittest

from compare_client_profiles import sample_state
from profile_history import capture_timestamp

FIXTURE = Path(__file__).resolve().parents[1] / "testdata" / "stage0.json"


class StageZeroClientTests(unittest.TestCase):
    def test_three_client_outcomes(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["source"], "synthetic_fixture")
        self.assertRegex(fixture["agent_version"], r"^\d+\.\d+\.\d+$")
        expected = {"healthy": "observed", "application_failure": "failure",
                    "wan_failure": "control_inconclusive"}
        self.assertCountEqual([c["id"] for c in fixture["cases"]], expected)
        for case in fixture["cases"]:
            with self.subTest(scenario=case["id"]):
                self.assertEqual(case["client_type"], "WG")
                self.assertEqual(case["probe"], "youtube_playback")
                self.assertEqual(case["report"]["source"], "client_browser")
                self.assertEqual(case["expected_client"], expected[case["id"]])
                samples = case["report"]["samples"]
                self.assertGreaterEqual(len(samples), 2)
                times = [capture_timestamp(s["utc"]) for s in samples]
                self.assertEqual(times, sorted(set(times)))
                for sample in samples:
                    self.assertEqual(sample_state(sample, "youtube"), case["expected_client"])
