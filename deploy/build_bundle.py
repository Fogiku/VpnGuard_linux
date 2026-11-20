#!/usr/bin/env python3
"""Prepare a generic USB payload. Target Windows captures migration data later."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request
from deployment_config import live_seed, INSTALLER_USER
from console_credentials import create as create_console_credentials

HERE = Path(__file__).resolve().parent
LINUX = HERE.parent
MEDUZA_RELEASE = "https://meduzavpn-builds.fra1.digitaloceanspaces.com/latest/release.json"
ZAPRET_RELEASE = "https://api.github.com/repos/bol-van/zapret2/releases/latest"

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)

def validate(serial, mac, username, ssh_key):
    serial = serial.strip()
    if not serial or len(serial) > 128 or any(c in serial for c in "*?[]\r\n\x00"):
        raise ValueError("РќСѓР¶РµРЅ С‚РѕС‡РЅС‹Р№ СЃРµСЂРёР№РЅС‹Р№ РЅРѕРјРµСЂ РІС‹Р±СЂР°РЅРЅРѕРіРѕ РґРёСЃРєР°")
    mac = mac.lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("РќРµРІРµСЂРЅС‹Р№ MAC Ethernet")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", username):
        raise ValueError("РќРµРґРѕРїСѓСЃС‚РёРјРѕРµ РёРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ Ubuntu")
    if not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", ssh_key.strip()):
        raise ValueError("РќСѓР¶РµРЅ РѕС‚РєСЂС‹С‚С‹Р№ SSH-РєР»СЋС‡")
    return serial, mac

def build_runtime(go, payload):
    payload = Path(payload)
    (payload / "bin").mkdir(exist_ok=True)
    env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0", GOTOOLCHAIN="local", GOROOT=str(Path(go).resolve().parent.parent))
    subprocess.run([str(go), "build", "-trimpath", "-o", str(payload / "bin/vpnguard"), "."], cwd=LINUX, env=env, check=True)
    source = {str(p.relative_to(payload / "source")).replace("\\", "/"): digest(p)
              for p in sorted((payload / "source").rglob("*")) if p.is_file()}
    write_json(payload / "runtime-build.json", {"goos":"linux", "goarch":"amd64", "cgo":False,
        "binarySha256":digest(payload / "bin/vpnguard"), "source":source})

def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "VpnGuard-Installer"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)

def download(url, sha256, destination):
    if not isinstance(url, str) or not url.startswith("https://") or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise ValueError("Р”Р»СЏ РїР°РєРµС‚Р° С‚СЂРµР±СѓСЋС‚СЃСЏ HTTPS URL Рё РїРѕР»РЅС‹Р№ SHA256")
    part = destination.with_suffix(destination.suffix + ".part")
    error = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VpnGuard-Installer"})
            with urllib.request.urlopen(req, timeout=120) as response, open(part, "wb") as output:
                shutil.copyfileobj(response, output)
            if digest(part) != sha256.lower():
                raise ValueError("SHA256 mismatch: " + destination.name)
            part.replace(destination)
            return
        except (OSError, ValueError) as e:
            error = e
            part.unlink(missing_ok=True)
    raise ValueError("Package failed verification after 3 attempts: " + str(error))

def package_metadata(meduza, zapret):
    files = meduza.get("files", [])
    if not isinstance(files, list):
        raise ValueError("РќРµРёР·РІРµСЃС‚РЅС‹Р№ С„РѕСЂРјР°С‚ release.json MeduzaVPN")
    mdz = next((x for x in files if x.get("key") == "meduzavpn_amd64.deb"), None)
    if not mdz:
        raise ValueError("Р’ release.json РЅРµС‚ meduzavpn_amd64.deb")
    asset = next((x for x in zapret.get("assets", [])
                  if x.get("name") == "zapret2-" + zapret.get("tag_name", "") + ".tar.gz"), None)
    if not asset or not asset.get("digest", "").startswith("sha256:"):
        raise ValueError("Р’ СЂРµР»РёР·Рµ zapret2 РЅРµС‚ Р°СЂС…РёРІР° СЃ РѕРїСѓР±Р»РёРєРѕРІР°РЅРЅС‹Рј SHA256")
    return [
        ("meduzavpn.deb", mdz.get("versioned_url") or mdz.get("url"), mdz.get("sha256", "")),
        ("zapret2.tar.gz", asset["browser_download_url"], asset["digest"][7:]),
    ]

def autoinstall(serial, mac, username, ssh_key, password_hash="!"):
    return {"autoinstall": {
        "version": 1,
        "locale": "en_US.UTF-8",
        "keyboard": {"layout": "us"},
        "timezone": "Europe/Moscow",
        "refresh-installer": {"update": False},
        "identity": {"hostname": "vpnguard", "username": username, "password": password_hash},
        "ssh": {"install-server": True, "allow-pw": password_hash != "!", "authorized-keys": [ssh_key.strip()]},
        "network": {"version": 2, "ethernets": {
            "wan": {"match": {"macaddress": mac}, "set-name": "vgwan", "dhcp4": True, "dhcp6": False}}},
        "apt": {"geoip": False, "fallback": "abort"},
        "storage": {"layout": {"name": "direct", "match": {"serial": serial}}},
        "early-commands": [
            "bash /cdrom/vpnguard/live_start.sh",
            "python3 /cdrom/vpnguard/installer_access.py /cdrom/vpnguard",
            "python3 /cdrom/vpnguard/guard_install.py /cdrom/vpnguard"
        ],
        "late-commands": [
            "mkdir -p /target/opt/vpnguard-install",
            "cp -a /cdrom/vpnguard/. /target/opt/vpnguard-install/",
            "curtin in-target --target=/target -- /bin/bash /opt/vpnguard-install/setup.sh",
            "bash /cdrom/vpnguard/save_install_logs.sh completed || true"
        ],
        "error-commands": [
            "bash /cdrom/vpnguard/save_install_logs.sh error || true"
        ],
        "shutdown": "reboot",
    }}

def manifest(root):
    return {str(p.relative_to(root)).replace("\\", "/"): digest(p)
            for p in sorted(root.rglob("*")) if p.is_file() and p.name != "manifest.json" and "__pycache__" not in p.relative_to(root).parts and p.suffix not in (".pyc", ".pyo")}

def build(args):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", args.username):
        raise ValueError("РќРµРґРѕРїСѓСЃС‚РёРјРѕРµ РёРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ Ubuntu")
    out = args.output.resolve()
    if out.exists() and not getattr(args, "resume", False):
        raise ValueError("Р’С‹С…РѕРґРЅР°СЏ РїР°РїРєР° СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚; СѓРєР°Р¶РёС‚Рµ РЅРѕРІСѓСЋ")
    go = args.go or shutil.which("go")
    if not go:
        raise ValueError("Р”Р»СЏ СЃР±РѕСЂРєРё РІР°Р»РёРґР°С‚РѕСЂР° РЅСѓР¶РµРЅ Go: СѓРєР°Р¶РёС‚Рµ --go РїСѓС‚СЊ-Рє-go.exe")
    public_key = args.ssh_key.read_text(encoding="utf-8").strip() if args.ssh_key else None
    if public_key:
        validate("UNARMED", "00:00:00:00:00:00", args.username, public_key)
    elif not shutil.which("ssh-keygen"):
        raise ValueError("РќРµС‚ ssh-keygen; РїРµСЂРµРґР°Р№С‚Рµ СЃРІРѕР№ РѕС‚РєСЂС‹С‚С‹Р№ РєР»СЋС‡ С‡РµСЂРµР· --ssh-key")
    if out.exists() and (out / "vpnguard/install.json").exists():
        if json.loads((out / "vpnguard/install.json").read_text(encoding="utf-8")).get("captureReady"):
            raise ValueError("Cannot resume a captured installation payload")
    out.mkdir(parents=True, exist_ok=True)
    if public_key is None:
        private = out / "SSH-PRIVATE-KEY"
        if not private.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vpnguard-admin", "-f", str(private)], check=True)
        public_key = Path(str(private) + ".pub").read_text().strip()
    payload = out / "vpnguard"
    (payload / "migration").mkdir(parents=True, exist_ok=True)
    (payload / "tools").mkdir(exist_ok=True)
    shutil.copytree(LINUX / "web", payload / "source/web", dirs_exist_ok=True)
    for p in LINUX.glob("*.go"):
        shutil.copyfile(p, payload / "source" / p.name)
    shutil.copyfile(LINUX / "go.mod", payload / "source/go.mod")
    env = dict(os.environ, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0", GOTOOLCHAIN="local")
    subprocess.run([str(go), "build", "-trimpath", "-o", str(payload / "tools/validator.exe"), "."], cwd=LINUX, env=env, check=True)
    (payload / "admin.pub").write_text(public_key + "\n", encoding="utf-8")
    build_runtime(go, payload)
    for name in ["setup.sh", "access_config.py", "repair_installed.py", "installer_access.py", "live_start.sh", "save_install_logs.sh", "guard_install.py", "verify_payload.py", "vpnguard.service", "vpnguard-nfqws2.service"]:
        (payload / name).write_bytes((HERE / name).read_bytes().replace(b"\r\n", b"\n"))
    for name in ["Start-UsbInstall.ps1", "Capture-Windows.ps1", "START-INSTALL.cmd", "UefiBoot.cs", "Prepare-Usb.ps1", "README.md"]:
        shutil.copyfile(HERE / name, out / name)
    console_password, console_hash = create_console_credentials()
    settings = {
        "schema": 3, "consolePassword": console_password, "consolePasswordHash": console_hash, "installerUsername": INSTALLER_USER, "requireSshApproval": False, "captureReady": False, "diskSerial": "UNARMED",
        "wanMac": "00:00:00:00:00:00", "username": args.username,
        "installAwg": False, "awgEnabled": False, "migrationDir": "migration",
    }
    write_json(payload / "install.json", settings)
    write_json(out / "autoinstall.yaml", autoinstall("UNARMED", settings["wanMac"], args.username, public_key, console_hash))
    hostkey = out / "INSTALLER-HOST-KEY"
    if not hostkey.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vpnguard-installer", "-f", str(hostkey)], check=True)
    seed = out / "nocloud"
    seed.mkdir(exist_ok=True)
    (seed / "user-data").write_text(live_seed(json.loads((out / "autoinstall.yaml").read_text()), public_key,
        hostkey.read_text(), Path(str(hostkey) + ".pub").read_text()), encoding="utf-8")
    write_json(seed / "meta-data", {"instance-id": "vpnguard-" + os.urandom(12).hex(), "local-hostname": "vpnguard-installer"})
    packages = payload / "packages"
    packages.mkdir(exist_ok=True)
    metadata = package_metadata(fetch_json(MEDUZA_RELEASE), fetch_json(ZAPRET_RELEASE))
    for name, url, sha in metadata:
        download(url, sha, packages / name)
    write_json(payload / "packages.json", [{"file": name, "url": url, "sha256": sha} for name, url, sha in metadata])
    write_json(payload / "manifest.json", manifest(payload))
    write_json(out / "bundle.json", {
        "schema": 3, "captureReady": False,
        "seedSha256": digest(out / "nocloud/user-data"),
        "seedMetaSha256": digest(out / "nocloud/meta-data"),
        "autoinstallSha256": digest(out / "autoinstall.yaml"),
        "manifestSha256": digest(payload / "manifest.json")})
    print("РљРѕРјРїР»РµРєС‚ РґР»СЏ С„Р»РµС€РєРё РіРѕС‚РѕРІ: " + str(out))
    print("Р”Р°РЅРЅС‹Рµ СЂР°Р±РѕС‡РµРіРѕ РџРљ Р±СѓРґСѓС‚ СЃРѕР±СЂР°РЅС‹ РїСЂРё Р·Р°РїСѓСЃРєРµ START-INSTALL.cmd РЅР° РЅС‘Рј.")
    print("Р•СЃР»Рё СЃРѕР·РґР°РЅ SSH-PRIVATE-KEY, СЃРѕС…СЂР°РЅРёС‚Рµ РµРіРѕ РЅР° РєРѕРјРїСЊСЋС‚РµСЂРµ Р°РґРјРёРЅРёСЃС‚СЂРёСЂРѕРІР°РЅРёСЏ.")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--username", default="vpnadmin")
    p.add_argument("--ssh-key", type=Path)
    p.add_argument("--go", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--resume", action="store_true")
    args = p.parse_args()
    try:
        build(args)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as e:
        p.exit(1, "РљРѕРјРїР»РµРєС‚ РЅРµ РіРѕС‚РѕРІ: " + str(e) + "\n")

if __name__ == "__main__":
    main()
