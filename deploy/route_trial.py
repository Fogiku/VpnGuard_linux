"""Apply the agent-generated trial in a fresh anonymous network namespace."""
import json
import os
import signal
import subprocess
import sys


def run(*args, stdin=None):
    return subprocess.run(args, input=stdin, stdout=subprocess.PIPE, text=True,
                          check=True, timeout=5).stdout


def apply(trial, parent):
    if os.readlink("/proc/self/ns/net") == parent:
        raise ValueError("network namespace was not isolated")
    links = json.loads(run("ip", "-j", "link", "show"))
    if [link["ifname"] for link in links] != ["lo"]:
        raise ValueError("expected a fresh network namespace")
    before, after = trial["before"] or [], trial["after"] or []
    devices = {trial["wan"]}
    for command in before + after:
        if command[:3] == ["route", "replace", "default"]:
            devices.add(command[command.index("dev") + 1])
    for index, name in enumerate(sorted(devices), 1):
        run("ip", "link", "add", "dev", name, "type", "dummy")
        run("ip", "addr", "add", f"192.0.2.{index}/32", "dev", name)
        run("ip", "link", "set", "dev", name, "up")
    run("ip", "route", "add", "default", "dev", trial["wan"])

    def commands(batch):
        for command in batch:
            # Live application clears previous selectors. This namespace starts empty.
            if command[:2] != ["rule", "del"]:
                run("ip", *command)

    commands(before)
    run("nft", "-f", "-", stdin=trial["nft"])
    commands(after)
    run("nft", "list", "chain", "inet", "vpnguard", "vg_policy_" + trial["revision"])
    route = json.loads(run("ip", "-j", "-4", "route", "get", "198.51.100.1",
                           "mark", str(trial["mark"])))
    if len(route) != 1 or route[0].get("dev") != trial["device"]:
        raise ValueError("marked lookup selected an unexpected device")


if __name__ == "__main__":
    signal.alarm(25)
    try:
        apply(json.load(sys.stdin), sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
    print("verified")
