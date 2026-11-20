#!/bin/bash
# Runs in /target via curtin, after Ubuntu has been installed. No disk partitioning here.
set -Eeuo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
ROOT=/opt/vpnguard-install
LOG=/var/log/vpnguard-install
mkdir -p "$LOG"
exec > >(tee -a "$LOG/setup.log") 2>&1
trap 'rc=$?; printf "FAILED line=%s code=%s\n" "$LINENO" "$rc" > "$LOG/result"; exit "$rc"' ERR
chmod 700 "$ROOT"
cd "$ROOT"
python3 verify_payload.py "$ROOT"
# Install recovery login before downloads/builds, so a failed late-command stays repairable.
if ! id vgrecovery >/dev/null 2>&1; then useradd -m -s /bin/bash vgrecovery; fi
install -d -o vgrecovery -g vgrecovery -m 700 /home/vgrecovery/.ssh
install -o vgrecovery -g vgrecovery -m 600 "$ROOT/admin.pub" /home/vgrecovery/.ssh/authorized_keys
printf 'vgrecovery ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/91-vpnguard-recovery
chmod 440 /etc/sudoers.d/91-vpnguard-recovery
MIGRATION=$(python3 -c 'import json; print(json.load(open("install.json"))["migrationDir"])')
test -f "$ROOT/$MIGRATION/wg_server.conf"
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ "$(dpkg --print-architecture)" == amd64 ]]
apt-get update
apt-get install -y wireguard-tools nftables curl ca-certificates python3 openssh-server
# Optional AmneziaWG; plain MeduzaVPN deployment does not require DKMS or Secure Boot changes.
if python3 -c 'import json; exit(not json.load(open("install.json")).get("installAwg", False))'; then
    apt-get install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-generic dkms
    add-apt-repository -y ppa:amnezia/ppa
    apt-get update
    apt-get install -y amneziawg
    command -v awg
    command -v awg-quick
fi
# Do not let vendor postinst start a tunnel before routing/configuration has been installed.
mkdir -p /run/systemd/system/meduzavpnd.service.d
printf '[Service]\nExecStartPre=/bin/false\n' > /run/systemd/system/meduzavpnd.service.d/vpnguard-install.conf
apt-get install -y "$ROOT/packages/meduzavpn.deb"
command -v meduzavpn
# Release archive is pinned by SHA256 at bundle creation. Do not run install_easy.sh.
mkdir -p /opt/zapret2
python3 - <<'PY'
import pathlib, tarfile
src = pathlib.Path("/opt/vpnguard-install/packages/zapret2.tar.gz")
dest = pathlib.Path("/opt/zapret2")
with tarfile.open(src) as archive:
    members = archive.getmembers()
    roots = {m.name.split("/")[0] for m in members if m.name not in ("", ".")}
    if len(roots) != 1:
        raise ValueError("Unexpected zapret2 archive layout")
    prefix = next(iter(roots)) + "/"
    for m in members:
        if m.name.rstrip("/") == prefix.rstrip("/"):
            continue
        if not m.name.startswith(prefix):
            raise ValueError("Unexpected archive member")
        m.name = m.name[len(prefix):]
        if not m.name or m.issym() or m.islnk() or not (m.isdir() or m.isfile()):
            continue
        if not (dest / m.name).resolve().is_relative_to(dest):
            raise ValueError("Unsafe archive member")
        archive.extract(m, dest)
PY
install -m 755 /opt/zapret2/binaries/linux-x86_64/nfqws2 /opt/zapret2/nfq2/nfqws2
# nfqws2 drops root before loading Lua; archive directory modes may be 0700.
chmod 755 /opt/zapret2 /opt/zapret2/lua
chmod 644 /opt/zapret2/lua/*.lua
test -x /opt/zapret2/nfq2/nfqws2
test -f /opt/zapret2/lua/zapret-lib.lua
test -f /opt/zapret2/lua/zapret-antidpi.lua
# The pinned runtime is cross-built and checked on the preparation computer.
python3 - <<'PYRUNTIME'
import hashlib, json, pathlib, struct
root = pathlib.Path("/opt/vpnguard-install")
build = json.loads((root / "runtime-build.json").read_text())
binary = (root / "bin/vpnguard").read_bytes()
assert binary[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", binary, 18)[0] == 62
assert hashlib.sha256(binary).hexdigest() == build["binarySha256"]
for name, expected in build["source"].items():
    assert hashlib.sha256((root / "source" / name).read_bytes()).hexdigest() == expected
PYRUNTIME
install -m 755 "$ROOT/bin/vpnguard" /usr/local/bin/vpnguard
install -d -m 700 /var/lib/vpnguard /etc/wireguard /etc/vpnguard /etc/amnezia/amneziawg
/usr/local/bin/vpnguard --data /var/lib/vpnguard --import "$ROOT/$MIGRATION" --write-wg-config
python3 - <<'PY'
import json, pathlib, datetime
root = pathlib.Path("/opt/vpnguard-install")
s = json.loads((root / "install.json").read_text())
p = pathlib.Path("/var/lib/vpnguard/config.json")
c = json.loads(p.read_text())
win = json.loads((root / s["migrationDir"] / "config.json").read_text(encoding="utf-8-sig"))
wg_settings = win.get("wg", win.get("ws4w", {}))
if "enabled" in win.get("zapret", {}):
    c["zapret.enabled"] = str(bool(win["zapret"]["enabled"])).lower()
routes = {
    "profiles": [{"id": "p1", "name": "Windows migration", "rules": []}],
    "clients": {}, "overrides": {},
    "policy": {"meduza": {"reserve": "awg", "ifDown": "block"},
               "awg": {"reserve": "meduza", "ifDown": "block"},
               "zapret": {"reserve": "meduza", "ifDown": "block"}}
}
base_rules = routes["profiles"][0]["rules"]
if wg_settings.get("clientZapret", False):
    base_rules.append({"id": "r1", "title": "YouTube and Discord", "preset": "yt", "exit": "zapret"})
base_rules.append({"id": "r2", "title": "Other traffic", "exit": "meduza", "last": True})
for ip in wg_settings.get("clientNoZapret", []):
    routes["overrides"][str(ip).split("/")[0]] = [{"id": "nozapret", "title": "VPN without zapret", "exit": "meduza", "last": True}]
rp = pathlib.Path("/var/lib/vpnguard/routes.json")
rp.write_text(json.dumps(routes, indent=2) + "\n")
rp.chmod(0o600)
for key in ("protocol", "serviceId"):
    value = win.get("meduza", {}).get(key)
    if value:
        c["meduza." + key] = str(value)
c.update({"net.wan": "vgwan", "web.token": s["webToken"],
          "remote.token": s["remoteToken"], "remote.enabled": "true",
          "remote.allowActions": "false", "remote.allowFrom": "local",
          "remote.until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).isoformat(),
          "awg.enabled": str(s["awgEnabled"]).lower(), "meduza.enabled": "true"})
if s["awgEnabled"]:
    c["awg.active"] = s["awgActive"]
p.write_text(json.dumps(c, indent=2) + "\n")
p.chmod(0o600)
sudo = pathlib.Path("/etc/sudoers.d/90-vpnguard-admin")
sudo.write_text(s["username"] + " ALL=(ALL) NOPASSWD: ALL\n")
sudo.chmod(0o440)
PY
install -m 644 vpnguard.service vpnguard-nfqws2.service /etc/systemd/system/
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=2\nnet.ipv4.conf.default.rp_filter=2\n' > /etc/sysctl.d/90-vpnguard.conf
# Config commands only write the CLI settings file; no daemon or tunnel is started in chroot.
# Do not run them in vendor ExecStartPost: its sandbox makes /root read-only.
rm -f /etc/systemd/system/meduzavpnd.service.d/vpnguard.conf /usr/local/sbin/vpnguard-meduza-config
XDG_CONFIG_HOME=/root/.config meduzavpn config set kill_switch false
XDG_CONFIG_HOME=/root/.config meduzavpn config set exclude_routes 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
python3 "$ROOT/access_config.py" / "$ROOT/install.json"
systemctl enable ssh meduzavpnd wg-quick@wg_server vpnguard
# Enable selected AWG on first boot only if a configuration was supplied.
if python3 -c 'import json; exit(not json.load(open("/opt/vpnguard-install/install.json"))["awgEnabled"])'; then
    active=$(python3 -c 'import json; print(json.load(open("/opt/vpnguard-install/install.json"))["awgActive"])')
    systemctl enable "awg-quick@$active"
fi
# No login credentials are embedded. MeduzaVPN login is completed through the web UI.
printf 'INSTALLED: reboot required; MeduzaVPN login required via web\n' > "$LOG/result"
echo "VpnGuard installed. Web: http://LAN_IP:8765/ . MeduzaVPN login is required."
