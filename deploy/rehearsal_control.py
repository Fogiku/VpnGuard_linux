"""Control only the file-backed local installer rehearsal."""
import argparse,json,logging,socket,sys
from pathlib import Path
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
BASE=Path(__file__).resolve().parent / "output"
VM=BASE / "rehearsal"

def qmp(command, arguments=None):
    with socket.create_connection(("127.0.0.1",4444),3) as s:
        f=s.makefile("rwb",buffering=0)
        f.readline();f.write(b'{"execute":"qmp_capabilities"}\n');f.readline()
        request={"execute":command}
        if arguments:request["arguments"]=arguments
        f.write((json.dumps(request)+"\n").encode())
        while True:
            answer=json.loads(f.readline())
            if "return" in answer or "error" in answer:return answer

COMMANDS={
 "installed-poweroff":'sudo shutdown -h now',
 "installed-reboot":'sudo shutdown -r +0',
 "installed-fix-meduza":'sudo env XDG_CONFIG_HOME=/tmp/vpnguard-config-probe MEDUZAVPN_SOCKET=/tmp/vpnguard-nonexistent.sock meduzavpn config set kill_switch false && echo FILE_ONLY_CONFIG_VERIFIED; sudo meduzavpn config set kill_switch false; sudo meduzavpn config set exclude_routes 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12; sudo rm -f /etc/systemd/system/meduzavpnd.service.d/vpnguard.conf /usr/local/sbin/vpnguard-meduza-config; sudo systemctl daemon-reload; sudo systemctl restart meduzavpnd; sudo systemctl is-active meduzavpnd; sudo meduzavpn config get kill_switch',
 "installed-logs":'sudo systemctl --no-pager -l status meduzavpnd; sudo journalctl --no-pager -n 30 -u meduzavpnd; sudo meduzavpn config --help; sudo meduzavpn config set --help',
 "update-options":"grep -n -i -E 'cancel|update|shutdown' /snap/subiquity/current/lib/python3.10/site-packages/subiquity/common/apidef.py | tail -n 25; grep -n -i -E 'cancel|unattended' /snap/subiquity/current/lib/python3.10/site-packages/subiquity/server/controllers/install.py | tail -n 25; sudo sh -c 'tail -n 5 /target/var/log/unattended-upgrades/unattended-upgrades-dpkg.log 2>/dev/null'",
 "update-api":"ps -eo pid,comm,pcpu,etime --sort=-pcpu | head -n 7; sudo sh -c 'tail -n 10 /target/var/log/unattended-upgrades/unattended-upgrades.log'; grep -n -A 8 -B 5 -E 'cancel.*update|cancel.*uu|stop_uu|cancel_shutdown' /snap/subiquity/current/lib/python3.10/site-packages/subiquity/common/apidef.py /snap/subiquity/current/lib/python3.10/site-packages/subiquity/server/controllers/shutdown.py /snap/subiquity/current/lib/python3.10/site-packages/subiquity/server/controllers/install.py",
 "nfq-version":'tar -xOzf /cdrom/vpnguard/packages/zapret2.tar.gz zapret2-v1.0.7/binaries/linux-x86_64/nfqws2 > /tmp/vpnguard-nfqws2-probe; chmod 700 /tmp/vpnguard-nfqws2-probe; /tmp/vpnguard-nfqws2-probe --version',
 "upgrades":"ps -eo pid,comm,pcpu,etime --sort=-pcpu | head -n 10; sudo sh -c 'tail -n 18 /target/var/log/unattended-upgrades/unattended-upgrades.log; tail -n 5 /target/var/log/unattended-upgrades/unattended-upgrades-dpkg.log 2>/dev/null'; sudo curl --silent --unix-socket /run/subiquity/socket http://localhost/meta/status",
 "login-flags":"find /tmp/vpnguard-cli-probe -type f -name meduzavpn -exec {} login --json --help ';'; sudo curl --silent --unix-socket /run/subiquity/socket http://localhost/meta/status; echo; sudo sh -c 'tail -n 4 /target/var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null'",
 "binary-help":"/cdrom/vpnguard/bin/vpnguard --help; mkdir -p /tmp/vpnguard-cli-probe; dpkg-deb -x /cdrom/vpnguard/packages/meduzavpn.deb /tmp/vpnguard-cli-probe; find /tmp/vpnguard-cli-probe -type f -name meduzavpn -exec {} login --help ';'",
 "media":'sudo systemctl --no-pager -l status casper-md5check.service; sudo cat /run/casper-md5check.json; sudo sh -c \'grep -E "Err:|Failed|failed|404|Hash Sum|not found" /var/log/installer/curtin-install.log | tail -n 14\'',
 "progress":"sudo du -sx /target; ps -eo pid,comm,pcpu,etime --sort=-pcpu | head -n 9; sudo sh -c 'tail -n 4 /var/log/installer/curtin-install.log; tail -n 8 /target/var/log/vpnguard-install/setup.log 2>/dev/null'",
 "apt-dns":"sudo sh -c 'for f in /tmp/tmp*/mount/etc/resolv.conf; do echo $f; cat $f; done; tail -n 12 /var/log/installer/curtin-install/subiquity-curtin-apt.conf'",
 "summary":"cat /proc/cmdline; sudo curl --silent --unix-socket /run/subiquity/socket http://localhost/meta/status; echo; sudo lsblk -o NAME,SIZE,TYPE,SERIAL,MOUNTPOINTS; sudo sh -c 'tail -n 8 /var/log/installer/curtin-install.log 2>/dev/null'",
 "fix-vm-dns":'sudo resolvectl dns vgwan 192.168.1.3; sudo resolvectl flush-caches; timeout 15 getent ahostsv4 archive.ubuntu.com; curl -I --max-time 15 http://archive.ubuntu.com/ubuntu/dists/noble/InRelease',
 "network":'resolvectl status; timeout 12 getent ahostsv4 archive.ubuntu.com; ip route',
 "status":"hostname; sudo cloud-init status; sudo systemctl --no-pager -l status snap.subiquity.subiquity-service.service; sudo pgrep -af guard_install.py; sudo lsblk -o NAME,SIZE,TYPE,SERIAL,MOUNTPOINTS; sudo find /var/log/installer -maxdepth 1 -type f -printf '%f\n'; sudo tail -n 12 /var/log/vpnguard-install/setup.log /target/var/log/vpnguard-install/setup.log 2>/dev/null",
 "logs":"sudo sh -c 'tail -n 40 /var/log/installer/subiquity-server-debug.log.*; tail -n 30 /target/var/log/vpnguard-install/setup.log; cat /cdrom/INSTALL-STATUS.txt'",
 "health":"hostname; sudo systemctl --no-pager -l status vpnguard meduzavpnd ssh wg-quick@wg_server; sudo cat /var/log/vpnguard-install/result; sudo ss -ltnp; sudo journalctl --no-pager -n 30 -u vpnguard",
 "approve":'sudo pgrep -f \'^python3 /cdrom/vpnguard/guard_install.py \' >/dev/null && sudo python3 -c \'import json,hashlib,pathlib; r=pathlib.Path("/cdrom/vpnguard"); s=json.loads((r/"install.json").read_text()); pathlib.Path("/run/vpnguard-install-approved.json").write_text(json.dumps({"diskSerial":s["diskSerial"],"manifestSha256":hashlib.sha256((r/"manifest.json").read_bytes()).hexdigest()})); print("Verified SSH approval written for virtual disk")\'',
}

def main():
 p=argparse.ArgumentParser();p.add_argument("action",choices=[*COMMANDS,"screen","stop"]);a=p.parse_args()
 if a.action=="screen":print(qmp("screendump",{"filename":(VM/"screen.png").as_posix(),"format":"png"}));return
 if a.action=="stop":print(qmp("quit"));return
 client=paramiko.SSHClient();client.load_host_keys(str(VM/"installed-known-hosts" if a.action.startswith("installed-") else BASE/"retry-access/INSTALLER-KNOWN-HOSTS"))
 try:
  client.connect("127.0.0.1",port=2222,username="vgrecovery",key_filename=str(BASE/"retry-access/SSH-PRIVATE-KEY"),allow_agent=False,look_for_keys=False,timeout=4,banner_timeout=5,auth_timeout=5)
  _,out,err=client.exec_command(COMMANDS[a.action],timeout=60)
  print(out.read().decode(errors="replace"));print(err.read().decode(errors="replace"))
  print("Exit:",out.channel.recv_exit_status())
 finally:client.close()

if __name__=="__main__":main()
