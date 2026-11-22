"""Compare two client browser reports from an isolated Linux lab session."""
import argparse
import hashlib
import ipaddress
import json
import math
import os
from datetime import datetime
from pathlib import Path


def lab_context(session, revision, control, browser_version, channel):
    current = os.stat("/proc/self/ns/net")
    if os.path.samestat(current, os.stat("/proc/1/ns/net")):
        raise ValueError("run the browser probe in a separate Linux network namespace")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return dict(session=session, profile_revision=revision,
                boot_sha256=hashlib.sha256(boot.encode()).hexdigest(),
                netns_inode=current.st_ino, browser_version=browser_version,
                channel=channel or "chromium",
                control_sha256=hashlib.sha256(control.encode()).hexdigest())


def sample_state(sample, service):
    control = sample.get("control_http")
    if type(control) is not int or not 200 <= control < 300:
        return "control_inconclusive"
    if service == "youtube":
        state = sample.get("playback")
        duration = sample.get("continuous_seconds")
        page = sample.get("page_http")
        if (state == "playing" and type(duration) in (float, int) and math.isfinite(duration)
                and duration >= 5 and type(page) is int and 200 <= page < 300):
            return "observed"
        if state in ("media_error", "page_failed"):
            return "failure"
    else:
        state = sample.get("discord_gateway")
        if state == "hello":
            return "observed"
        if state in ("connection_error", "closed_before_hello", "timeout"):
            return "failure"
    return "inconclusive"


def capture_time(sample):
    stamp = datetime.fromisoformat(sample["utc"].replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("missing UTC offset")
    return stamp.timestamp()


def compare(a, b):
    for report in (a, b):
        if report.get("schema") != 3 or report.get("source") != "client_browser":
            raise ValueError("expected two browser reports captured with --lab-session")
    labs = [r["lab"] for r in (a, b)]
    for key in ("session", "boot_sha256", "control_sha256", "channel", "browser_version"):
        if not labs[0].get(key) or labs[0][key] != labs[1].get(key):
            raise ValueError("different or missing " + key)
    for key in ("netns_inode", "profile_revision"):
        if any(not lab.get(key) for lab in labs) or labs[0][key] == labs[1][key]:
            raise ValueError("expected two distinct " + key + " values")
    if a.get("video_id") != b.get("video_id"):
        raise ValueError("different video targets")
    left, right = a["samples"], b["samples"]
    if len(left) != len(right) or not 2 <= len(left) <= 5:
        raise ValueError("expected two to five samples per profile with equal counts")
    discord = ["discord_gateway" in s for s in left + right]
    if any(discord) != all(discord):
        raise ValueError("different Discord targets")
    services = (["youtube"] if a.get("video_id") else []) + (["discord_gateway"] if all(discord) else [])
    if not services:
        raise ValueError("no common application probe")
    # Legacy reports have no requested reflector. When enabled, require the same
    # reflector per family in every trial and a stable expectation per profile.
    families = set(left[0].get("egress", {}))
    all_egress_matched = True
    for samples in (left, right):
        for sample in samples:
            checks = sample.get("egress", {})
            if set(checks) != families or not families <= {"v4", "v6"}:
                raise ValueError("different egress probe families")
            for family in families:
                check = checks[family]
                if (not check.get("target_sha256") or
                        check["target_sha256"] != left[0]["egress"][family]["target_sha256"] or
                        not check.get("expected") or
                        check["expected"] != samples[0]["egress"][family]["expected"]):
                    raise ValueError("inconsistent egress probe configuration")
                if check.get("status") == "matched":
                    address = ipaddress.ip_address(check.get("address"))
                    network = ipaddress.ip_network(check["expected"])
                    if family != f"v{address.version}" or address not in network:
                        raise ValueError("reported egress match contradicts address or family")
                else:
                    all_egress_matched = False
    times = [[capture_time(s) for s in samples] for samples in (left, right)]
    if any(any(y <= x for x, y in zip(t, t[1:])) for t in times):
        raise ValueError("unordered or duplicate samples")
    result = dict(schema=1, source="paired_client_browser", session=labs[0]["session"],
                  browser_version=labs[0]["browser_version"], channel=labs[0]["channel"],
                  control_sha256=labs[0]["control_sha256"],
                  video_id=a.get("video_id"), profiles=[lab["profile_revision"] for lab in labs],
                  comparison={})
    for service in services:
        pairs = []
        for i, (first, second) in enumerate(zip(left, right)):
            skew = abs(times[0][i] - times[1][i])
            if skew > 120:
                raise ValueError("paired samples started more than 120 seconds apart")
            pairs.append(dict(utc=[first["utc"], second["utc"]], skew_seconds=round(skew, 2),
                              states=[sample_state(s, service) for s in (first, second)]))
        states = {tuple(pair["states"]) for pair in pairs}
        outcome = "inconclusive"
        if len(states) == 1:
            outcome = {("observed", "failure"): "only_first_observed",
                       ("failure", "observed"): "only_second_observed",
                       ("observed", "observed"): "both_observed",
                       ("failure", "failure"): "both_failed"}.get(states.pop(), outcome)
        if families:
            for pair, first, second in zip(pairs, left, right):
                pair["egress"] = [s["egress"] for s in (first, second)]
            if not all_egress_matched:
                outcome = "inconclusive"
        counts = []
        for index in range(2):
            summary = dict(observed=0, failure=0, control_inconclusive=0, inconclusive=0)
            for pair in pairs:
                summary[pair["states"][index]] += 1
            counts.append(summary)
        result["comparison"][service] = dict(outcome=outcome, pairs=pairs, sample_counts=counts)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    try:
        reports = [json.loads(p.read_text(encoding="utf-8")) for p in (args.first, args.second)]
        print(json.dumps(compare(*reports), ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        parser.exit(2, f"Cannot compare reports: {exc}\n")


if __name__ == "__main__":
    main()
