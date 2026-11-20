import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_bundle as builder
import guard_install as guard
import verify_payload as verifier

class DeploymentTests(unittest.TestCase):
    def test_live_installer_access_preserves_keys_and_checks_target(self):
        import types
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "payload"
            root.mkdir()
            home = base / "home"
            (home / ".ssh").mkdir(parents=True)
            authorized = home / ".ssh/authorized_keys"
            authorized.write_text("existing-key\n")
            mac = base / "mac"
            mac.write_text("00:11:22:33:44:55")
            builder.write_json(root / "install.json", {"captureReady": True, "wanMac": mac.read_text()})
            (root / "admin.pub").write_text("ssh-ed25519 AAAA admin")
            builder.write_json(root / "manifest.json", builder.manifest(root))
            account = types.SimpleNamespace(pw_dir=str(home), pw_uid=1000, pw_gid=1000)
            spec = importlib.util.spec_from_file_location("installer_access_test", HERE / "installer_access.py")
            access = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, {"pwd": types.SimpleNamespace(getpwnam=lambda name: account)}):
                spec.loader.exec_module(access)
            with patch.object(access.Path, "glob", return_value=[mac]), patch.object(access.os, "chown", create=True):
                access.enable(root)
                access.enable(root)
                self.assertTrue(authorized.read_text().startswith("existing-key\n"))
                self.assertEqual(authorized.read_text().count("ssh-ed25519 AAAA admin"), 1)
                mac.write_text("00:00:00:00:00:00")
                with self.assertRaisesRegex(ValueError, "adapter"):
                    access.enable(root)

    def test_live_seed_has_independent_key_access_and_identical_install_config(self):
        from deployment_config import live_seed, INSTALLER_USER
        ai = builder.autoinstall("SSD-1", "00:11:22:33:44:55", "vpnadmin", "ssh-ed25519 AAAA")
        config = json.loads(live_seed(ai, "ssh-ed25519 AAAA", "host-private-test", "ssh-ed25519 BBBB").split("\n", 1)[1])
        self.assertEqual(config["autoinstall"], ai["autoinstall"])
        recovery = next(u for u in config["users"] if isinstance(u, dict))
        self.assertEqual(recovery["name"], INSTALLER_USER)
        self.assertNotEqual(recovery["name"], ai["autoinstall"]["identity"]["username"])
        self.assertTrue(recovery["lock_passwd"])
        self.assertEqual(recovery["ssh_authorized_keys"], ["ssh-ed25519 AAAA"])
        self.assertFalse(config["ssh_pwauth"])
        self.assertEqual(config["ssh_keys"]["ed25519_public"], "ssh-ed25519 BBBB")
        self.assertIn("live_start.sh", config["runcmd"][0][1])

    def test_installer_shell_assets_have_linux_line_endings(self):
        for pattern in ("*.sh", "*.service"):
            for path in HERE.glob(pattern):
                with self.subTest(path=path.name):
                    self.assertNotIn(b"\r", path.read_bytes())

    def test_ssh_verification_rejects_wrong_target_or_payload(self):
        from verify_installer_ssh import validate
        expected = {"diskSerial": "SSD-1", "manifestSha256": "a"*64, "wanMac": "00:11:22:33:44:55"}
        actual = dict(expected, macs=[expected["wanMac"]], disks=[{"serial":"SSD-1","tran":"sata","size":64*1024**3}], guardRunning=True)
        validate(expected, actual)
        for bad in (dict(actual,manifestSha256="b"*64),dict(actual,macs=[]),dict(actual,guardRunning=False),
                    dict(actual,disks=[{"serial":"SSD-1","tran":"usb","size":64*1024**3}])):
            with self.assertRaises(ValueError):validate(expected,bad)

    def test_controller_approval_is_one_shot_even_if_result_is_uncertain(self):
        import types
        import watch_retry_installer as watcher
        for approval_code, stage in [(0, "approved-once"), (1, "approval-result-unknown-no-retry")]:
            with self.subTest(code=approval_code), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "expected-install.json").write_text(json.dumps({"lanIp":"192.168.1.66","wanMac":"00:11:22:33:44:55","diskSerial":"SSD-1","manifestSha256":"a"*64}))
                with patch.object(sys, "argv", ["watch", "--access", tmp, "--seconds", "1"]), patch.object(watcher.time, "monotonic", return_value=0), patch.object(watcher.Path, "exists", return_value=False), patch.object(watcher.subprocess, "run", side_effect=[types.SimpleNamespace(returncode=0), types.SimpleNamespace(returncode=approval_code)]) as calls:
                    watcher.main()
                self.assertEqual(calls.call_count, 2)
                self.assertNotIn("--approve", calls.call_args_list[0].args[0])
                self.assertIn("--approve", calls.call_args_list[1].args[0])
                self.assertEqual(json.loads((root / "auto-install-status.json").read_text())["stage"], stage)

    def test_normal_console_login_and_mac_matched_dhcp_are_configured(self):
        from access_config import network_config
        from deployment_config import live_seed
        settings={"wanMac":"00:11:22:33:44:55","lanIp":"192.168.1.66","lanPrefix":24,"lanGateway":"192.168.1.1"}
        lan=network_config(settings)["network"]["ethernets"]["vpnguard-lan"]
        self.assertTrue(lan["dhcp4"])
        self.assertNotIn("set-name",lan)
        self.assertEqual(lan["addresses"],["192.168.1.66/24"])
        self.assertLess(lan["dhcp4-overrides"]["route-metric"],lan["routes"][0]["metric"])
        ai=builder.autoinstall("SSD-1",settings["wanMac"],"vpnadmin","ssh-ed25519 AAAA", "$6$salt$testhash")
        self.assertTrue(ai["autoinstall"]["ssh"]["allow-pw"])
        live=json.loads(live_seed(ai,"ssh-ed25519 AAAA","private","ssh-ed25519 BBBB").split("\n",1)[1])
        user=next(u for u in live["users"] if isinstance(u,dict) and u["name"]=="vpnadmin")
        self.assertFalse(user["lock_passwd"])
        self.assertEqual(user["hashed_passwd"],"$6$salt$testhash")
        self.assertTrue(live["ssh_pwauth"])

    def test_console_password_hashing_uses_binary_lf_input_on_windows(self):
        import types
        import console_credentials as credentials
        with patch.object(credentials.shutil,"which",return_value="openssl"), patch.object(credentials.Path,"is_file",return_value=True), patch.object(credentials.subprocess,"run",return_value=types.SimpleNamespace(stdout=b"$6$salt$hash\n")) as call:
            password,hashed=credentials.create()
        self.assertEqual(call.call_args.kwargs["input"],(password+"\n").encode())
        self.assertNotIn("text",call.call_args.kwargs)
        self.assertNotIn(b"\r",call.call_args.kwargs["input"])
        self.assertTrue(hashed.startswith("$6$"))

    def test_disk_selection_is_exact_and_refuses_ambiguity(self):
        disk = {"type": "disk", "serial": "SSD-1", "path": "/dev/nvme0n1", "tran": "nvme", "size": 64 * 1024**3}
        self.assertEqual(guard.select_disk([disk], "SSD-1"), disk["path"])
        for disks, serial in [([disk], "SSD-*"), ([disk, disk], "SSD-1"),
                              ([dict(disk, tran="usb")], "SSD-1"), ([dict(disk, size=100)], "SSD-1")]:
            with self.assertRaises(ValueError):
                guard.select_disk(disks, serial)

    def test_config_is_unattended_and_bound_to_machine(self):
        ai = builder.autoinstall("SSD-1", "00:11:22:33:44:55", "vpnadmin", "ssh-ed25519 AAAA")["autoinstall"]
        self.assertEqual(ai["storage"]["layout"]["match"], {"serial": "SSD-1"})
        self.assertEqual(ai["network"]["ethernets"]["wan"]["match"]["macaddress"], "00:11:22:33:44:55")
        self.assertEqual(ai["identity"]["password"], "!")
        self.assertFalse(ai["ssh"]["allow-pw"])
        self.assertTrue(ai["early-commands"])
        self.assertTrue(any("setup.sh" in cmd for cmd in ai["late-commands"]))
        self.assertNotIn("interactive-sections", ai)

    def test_rejects_disk_patterns_and_invalid_mac(self):
        for serial, mac in [("*", "00:11:22:33:44:55"), ("", "00:11:22:33:44:55"), ("SSD", "invalid")]:
            with self.assertRaises(ValueError):
                builder.validate(serial, mac, "vpnadmin", "ssh-ed25519 AAAA")

    def test_payload_hashes_and_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").write_text("original")
            builder.write_json(root / "manifest.json", builder.manifest(root))
            verifier.verify(root)
            (root / "a").write_text("changed")
            with self.assertRaises(ValueError):
                verifier.verify(root)
            builder.write_json(root / "manifest.json", {"../escape": "0" * 64})
            with self.assertRaises(ValueError):
                verifier.verify(root)

    def test_vendor_packages_require_release_digest(self):
        mdz = {"files": [{"key": "meduzavpn_amd64.deb", "url": "https://example.test/mdz", "sha256": "a" * 64}]}
        z = {"tag_name": "v1.0.7", "assets": [{"name": "zapret2-v1.0.7.tar.gz", "browser_download_url": "https://example.test/z", "digest": "sha256:" + "b" * 64}]}
        z["assets"].insert(0, {"name": "zapret2-v1.0.7-openwrt-embedded.tar.gz", "browser_download_url": "https://example.test/wrong", "digest": "sha256:" + "c" * 64})
        self.assertEqual(builder.package_metadata(mdz, z)[1][2], "b" * 64)
        del z["assets"][1]["digest"]
        with self.assertRaises(ValueError):
            builder.package_metadata(mdz, z)

    def test_modified_source_does_not_escape_incomplete_bundle(self):
        # Build stops on invalid identity before creating any output.
        with tempfile.TemporaryDirectory() as tmp:
            from argparse import Namespace
            root = Path(tmp)
            key = root / "id.pub"
            key.write_text("ssh-ed25519 AAAA")
            out = root / "bundle"
            args = Namespace(username="INVALID USER", ssh_key=key, output=out, go=None)
            with self.assertRaises(ValueError):
                builder.build(args)
            self.assertFalse(out.exists())


    def test_unprepared_or_interrupted_usb_never_probes_disks(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "vpnguard"
            payload.mkdir()
            builder.write_json(payload / "install.json", {"captureReady": False})
            builder.write_json(payload / "manifest.json", builder.manifest(payload))
            with patch.object(guard.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "START-INSTALL"):
                    guard.check(payload)
                run.assert_not_called()
            builder.write_json(payload / "install.json", {"captureReady": True})
            builder.write_json(payload / "manifest.json", builder.manifest(payload))
            (Path(tmp) / "CAPTURE-INCOMPLETE").write_text("incomplete")
            with patch.object(guard.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "START-INSTALL"):
                    guard.check(payload)
                run.assert_not_called()

    def test_download_retries_but_never_accepts_wrong_hash(self):
        import io, hashlib
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "package.deb"
            expected = hashlib.sha256(b"correct").hexdigest()
            with patch.object(builder.urllib.request, "urlopen", side_effect=[io.BytesIO(b"truncated"), io.BytesIO(b"correct")]):
                builder.download("https://example.test/p", expected, dest)
            self.assertEqual(dest.read_bytes(), b"correct")
            with patch.object(builder.urllib.request, "urlopen", side_effect=[io.BytesIO(b"wrong") for _ in range(3)]):
                with self.assertRaisesRegex(ValueError, "verification"):
                    builder.download("https://example.test/p", expected, Path(tmp) / "bad.deb")
            self.assertFalse((Path(tmp) / "bad.deb").exists())
            self.assertFalse((Path(tmp) / "bad.deb.part").exists())

if __name__ == "__main__":
    unittest.main()
