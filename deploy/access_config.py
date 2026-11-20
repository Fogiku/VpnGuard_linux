"""Console/SSH access and Ethernet configuration shared by install and offline repair."""
import datetime,json,re,shutil,subprocess
from pathlib import Path


def network_config(settings):
    return {"network":{"version":2,"renderer":"networkd","ethernets":{"vpnguard-lan":{
        "match":{"macaddress":settings["wanMac"]},"dhcp4":True,"dhcp6":False,
        "dhcp4-overrides":{"route-metric":100},"optional":True,
        "addresses":[str(settings["lanIp"])+"/"+str(settings["lanPrefix"])],
        "routes":[{"to":"default","via":settings["lanGateway"],"metric":600}],
        "nameservers":{"addresses":[settings["lanGateway"],"1.1.1.1"]}}}}}


def configure(root,settings):
    root=Path(root)
    username=settings["username"]
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}",username):raise ValueError("Invalid login")
    password_hash=settings["consolePasswordHash"]
    if not password_hash.startswith("$6$"):raise ValueError("Expected SHA512 console password hash")
    def run(args,input=None,check=True):
        return subprocess.run(["chroot",str(root),*args],input=input,text=True,check=check,capture_output=True)
    def write(name,text,mode=0o644):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding="utf-8");p.chmod(mode)
    if run(["id",username],check=False).returncode:run(["useradd","-m","-s","/bin/bash",username])
    run(["chpasswd","-e"],username+":"+password_hash+"\n")
    run(["chage","-M","99999","-E","-1",username])
    write("etc/sudoers.d/90-vpnguard-admin",username+" ALL=(ALL) NOPASSWD: ALL\n",0o440)
    write("etc/ssh/sshd_config.d/00-vpnguard-access.conf","PasswordAuthentication yes\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\n")
    write("etc/cloud/cloud.cfg.d/99-vpnguard-access.cfg","ssh_pwauth: true\nssh_deletekeys: false\n")
    write("etc/cloud/cloud.cfg.d/99-vpnguard-network.cfg","network: {config: disabled}\n")
    write("etc/hostname","vpnguard\n")
    net=root/"etc/netplan";net.mkdir(parents=True,exist_ok=True)
    backup=root/"var/backups/vpnguard-network"/datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup.mkdir(parents=True,exist_ok=True)
    for p in net.glob("*.yaml"):
        if p.is_symlink():raise ValueError("Refusing linked netplan file")
        shutil.move(str(p),str(backup/p.name))
    write("etc/netplan/90-vpnguard-lan.yaml",json.dumps(network_config(settings),indent=2)+"\n",0o600)
    script=r'''import json,pathlib,subprocess,time
mac=MAC_VALUE
iface=None
for attempt in range(30):
 for p in pathlib.Path('/sys/class/net').glob('*/address'):
  if p.read_text().strip().lower()==mac:iface=p.parent.name;break
 if iface:break
 time.sleep(1)
if not iface:raise SystemExit('Captured Ethernet interface not found')
p=pathlib.Path('/var/lib/vpnguard/config.json')
c=json.loads(p.read_text());c['net.wan']=iface
p.write_text(json.dumps(c,indent=2)+'\n');p.chmod(0o600)
addresses=subprocess.check_output(['ip','-4','-o','addr','show','dev',iface],text=True)
pathlib.Path('/etc/issue').write_text('Ubuntu VpnGuard - login: vpnadmin\n'+addresses+'\n')
print('VpnGuard Ethernet:',iface)
'''.replace('MAC_VALUE',repr(settings['wanMac']))
    write("usr/local/sbin/vpnguard-detect-lan.py",script)
    write("etc/systemd/system/vpnguard-lan.service","[Unit]\nDescription=Detect captured Ethernet for VpnGuard\nAfter=systemd-udev-settle.service network-online.target\nWants=systemd-udev-settle.service network-online.target\nBefore=vpnguard.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/sbin/vpnguard-detect-lan.py\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n")
    write("etc/systemd/system/vpnguard.service.d/lan.conf","[Unit]\nAfter=vpnguard-lan.service\nWants=vpnguard-lan.service\n")
    p=root/"var/lib/vpnguard/config.json"
    c=json.loads(p.read_text()) if p.exists() else {}
    c["web.token"]=settings["consolePassword"]
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(c,indent=2)+"\n");p.chmod(0o600)
    write("etc/issue","Ubuntu VpnGuard - login: "+username+"\nWeb: http://"+settings["lanIp"]+":8765/\nPassword: see LOGIN.txt on the USB.\n\n")
    for service in ["systemd-networkd","systemd-resolved","ssh","vpnguard-lan","vpnguard","meduzavpnd","wg-quick@wg_server"]:run(["systemctl","enable",service])
    run(["netplan","generate"])

if __name__=="__main__":
    import sys
    configure(Path(sys.argv[1]),json.loads(Path(sys.argv[2]).read_text()))
