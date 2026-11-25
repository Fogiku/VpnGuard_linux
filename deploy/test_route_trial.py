import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import unittest

WORKER = Path(__file__).with_name("route_trial.py")


def run(*args, data=None):
    return subprocess.check_output(args, text=True, input=data, timeout=10)


def bind_queue(number):
    # NFQNL_MSG_CONFIG with NFQA_CFG_CMD=BIND. Keep the socket open to own the queue.
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER
    try:
        sock.settimeout(3)
        sock.bind((0, 0))
        nfgen = struct.pack("!BBH", socket.AF_INET, 0, number)
        command = struct.pack("=HH", 8, 1) + struct.pack("!BBH", 1, 0, 0)
        header = struct.pack("=IHHII", 16 + len(nfgen + command), 0x302, 5, 1, 0)
        sock.sendto(header + nfgen + command, (0, 0))
        ack = sock.recv(4096)
        if len(ack) < 20 or struct.unpack_from("=H", ack, 4)[0] != 2:
            raise RuntimeError("unexpected netfilter acknowledgement")
        error, = struct.unpack_from("=i", ack, 16)
        if error:
            raise OSError(-error, os.strerror(-error))
        return sock
    except BaseException:
        sock.close()
        raise


@unittest.skipUnless(os.environ.get("VPNGUARD_TEST_ROUTE_TRIAL") == "1",
                     "requires a disposable network namespace")
class RouteTrialTest(unittest.TestCase):
    def test_collision_failure_and_crash(self):
        parent = os.readlink("/proc/self/ns/net")
        self.assertNotEqual(parent, os.readlink("/proc/1/ns/net"))
        self.assertEqual([i["ifname"] for i in json.loads(run("ip", "-j", "link"))], ["lo"])
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "fixture0", "type", "dummy")
        run("ip", "addr", "add", "192.0.2.1/32", "dev", "fixture0")
        run("ip", "link", "set", "fixture0", "up")
        run("ip", "route", "add", "203.0.113.8/32", "dev", "fixture0")
        route = ["route", "replace", "default", "dev", "fixture0", "table", "101"]
        rule = ["rule", "add", "fwmark", "0x11", "lookup", "101", "priority", "1101"]
        run("ip", *route)
        run("ip", *rule)
        revision = "f" * 64
        nft = ("table inet vpnguard {\n chain vg_policy_" + revision +
               " { }\n chain check { udp dport 54321 queue num 200 bypass; }\n}\n")
        run("nft", "-f", "-", data=nft + "table inet foreign { chain managed_elsewhere { }\n}\n")
        trial = dict(nft=nft, before=[route, rule], after=[], device="fixture0",
                     revision=revision, wan="fixture0", mark=17)

        def snapshot():
            return (run("nft", "-s", "list", "ruleset"), run("ip", "-4", "rule"),
                    run("ip", "-4", "route", "show", "table", "101"),
                    run("ip", "-4", "route", "show", "203.0.113.8/32"),
                    json.loads(run("ip", "-j", "-4", "route", "get", "203.0.113.8"))[0]["dev"])

        expected = snapshot()
        self.assertEqual(expected[-1], "fixture0")
        with bind_queue(200), socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with socket.create_connection(listener.getsockname(), timeout=3) as client:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(3)

                    def check_parent():
                        self.assertEqual(snapshot(), expected)
                        client.sendall(b"A")
                        self.assertEqual(conn.recv(1), b"A")
                        conn.sendall(b"B")
                        self.assertEqual(client.recv(1), b"B")

                    check_parent()
                    cmd = ["unshare", "--net", "--", sys.executable, str(WORKER), parent]
                    self.assertEqual(run(*cmd, data=json.dumps(trial)).strip(), "verified")
                    check_parent()
                    failed = subprocess.run(cmd, input=json.dumps(dict(trial, after=[
                        ["route", "add", "default", "dev", "missing0"]])),
                        capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn("missing0", failed.stderr)
                    check_parent()
                    code = ("import route_trial,json,time,sys; from test_route_trial import bind_queue; "
                            "queue_owner=bind_queue(200); "
                            "route_trial.apply(json.load(sys.stdin),sys.argv[1]); "
                            "print('ready',flush=True); time.sleep(60)")
                    with subprocess.Popen(["unshare", "--net", sys.executable, "-c", code, parent],
                                          cwd=WORKER.parent, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, text=True) as child:
                        try:
                            child.stdin.write(json.dumps(trial))
                            child.stdin.close()
                            self.assertTrue(select.select([child.stdout], [], [], 30)[0])
                            self.assertEqual(child.stdout.readline().strip(), "ready")
                            check_parent()
                        finally:
                            child.kill()
                            child.wait(timeout=5)
                        self.assertEqual(child.returncode, -9)
                    check_parent()
