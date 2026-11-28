"""Submit a paired report to the gateway without forwarding client addresses."""
import json
import re
import subprocess
import sys
from pathlib import Path


def admission_report(report):
    evidence = {k: report[k] for k in ("schema", "source", "profile_source", "profiles")}
    comparison = {}
    for service, series in report["comparison"].items():
        pairs = []
        for p in series["pairs"]:
            pair = {"states": p["states"], "utc": p["utc"]}
            if "egress" in p:
                pair["egress"] = [{f: {"status": c["status"]} for f, c in checks.items()} for checks in p["egress"]]
            pairs.append(pair)
        comparison[service] = {"outcome": series["outcome"], "pairs": pairs}
    return dict(**evidence, comparison=comparison)


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", sys.argv[1]):
        sys.exit("Usage: submit_profile_reserve.py SSH_ALIAS comparison.json")
    try:
        report = admission_report(json.loads(Path(sys.argv[2]).read_text()))
        reply = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                "-o", "ConnectTimeout=5", sys.argv[1], "curl", "-fsS", "--max-time", "90",
                                "-H", "X-VG:1", "--data-binary", "@-", "http://127.0.0.1:8765/api/zapret-admit-reserve"],
                               input=json.dumps({"report": report}), text=True, capture_output=True, timeout=100, check=True)
        data = json.loads(reply.stdout)
        if not data.get("ok"):
            sys.exit(data.get("error", "Report rejected"))
        print(data["result"])
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as err:
        sys.exit(str(err))
