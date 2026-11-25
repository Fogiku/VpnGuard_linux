"""Run stage 0 against the checkout. Print a JSON summary only after all checks pass."""
from contextlib import redirect_stdout
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
GO_CASES = (
    "TestServerAndClientWithoutPresharedKey",
    "TestImportPreservesDisabledClients",
    "TestRestartLoadsWgWithoutSync",
    "TestRouteAssignmentMigrationAndBadState",
    "TestStartupRecoveryRestoresNetworkKeysOnly",
    "TestRouteRollbackRestoresModelAndDisk",
    "TestStageZeroGatewayReplay",
)


def replay():
    pattern = "^(" + "|".join(GO_CASES) + ")$"
    run = subprocess.run(["go", "test", "-json", "-count=1", "-run", pattern, "."],
                         cwd=ROOT, stdout=subprocess.PIPE, text=True)
    events = [json.loads(line) for line in run.stdout.splitlines()]
    passed = {e.get("Test") for e in events if e.get("Action") == "pass"}
    missing = set(GO_CASES) - passed
    if run.returncode or missing:
        for event in events:
            if "Output" in event:
                sys.stderr.write(event["Output"])
        raise RuntimeError("Go regression failure or missing tests: " + ", ".join(sorted(missing)))

    # GuardTests exercises the actual updater functions in temporary directories.
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        ["test_guarded_update.GuardTests", "test_stage0.StageZeroClientTests"])
    with redirect_stdout(sys.stderr):
        checks = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    if not checks.wasSuccessful() or not checks.testsRun:
        raise RuntimeError("updater or browser regression failed")
    fixture = json.loads((ROOT / "testdata/stage0.json").read_text())
    version = re.search(r'^const Version = "([^"]+)"', (ROOT / "core.go").read_text(), re.M)[1]
    cases = []
    for case in fixture["cases"]:
        if "TestStageZeroGatewayReplay/" + case["id"] not in passed:
            raise RuntimeError("gateway scenario did not run: " + case["id"])
        cases.append(dict(scenario=case["id"], client_type=case["client_type"], probe=case["probe"],
                          sample_utc=[s["utc"] for s in case["report"]["samples"]],
                          client_result=case["expected_client"], gateway_result=case["expected_gateway"]))
    return dict(status="passed", environment="simulator", agent_version=version,
                fixture_version=fixture["agent_version"], utc=datetime.now(timezone.utc).isoformat(),
                cases=cases, go_tests=list(GO_CASES),
                python_tests=checks.testsRun, skipped=[dict(test=t.id(), reason=why) for t, why in checks.skipped])


if __name__ == "__main__":
    print(json.dumps(replay(), ensure_ascii=False, indent=2))
