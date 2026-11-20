"""Verify the prepared installer over pinned SSH before allowing partitioning."""
import argparse,json,logging,shlex,sys
from pathlib import Path
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def validate(expected, actual):
    for key in ("diskSerial", "manifestSha256"):
        if actual.get(key) != expected[key]:
            raise ValueError("Installer mismatch: " + key)
    if expected["wanMac"] not in actual.get("macs", []):
        raise ValueError("Target Ethernet MAC mismatch")
    disks = [d for d in actual.get("disks", []) if (d.get("serial") or "").strip() == expected["diskSerial"]]
    if len(disks) != 1 or disks[0].get("tran") == "usb" or int(disks[0].get("size") or 0) < 32*1024**3:
        raise ValueError("Target disk identity or size mismatch")
    if not actual.get("guardRunning"):
        raise ValueError("Installer is not waiting in the protected disk guard")

READ = """import json,pathlib,hashlib,subprocess
r=pathlib.Path('/cdrom/vpnguard');s=json.loads((r/'install.json').read_text())
p=subprocess.run(['pgrep','-f','^python3 /cdrom/vpnguard/guard_install.py '],capture_output=True)
print(json.dumps({'diskSerial':s['diskSerial'],'manifestSha256':hashlib.sha256((r/'manifest.json').read_bytes()).hexdigest(),
'macs':[p.read_text().strip().lower() for p in pathlib.Path('/sys/class/net').glob('*/address')],
'disks':json.loads(subprocess.check_output(['lsblk','-bdJ','-o','PATH,SERIAL,TRAN,SIZE,TYPE']))['blockdevices'],
'guardRunning':p.returncode==0}))
"""

def run(client, command):
    _,out,err=client.exec_command(command,timeout=30)
    result=out.read().decode()
    error=err.read().decode()
    if out.channel.recv_exit_status()!=0:raise RuntimeError(error.strip() or 'Remote verification failed')
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--access',type=Path,required=True);p.add_argument('--approve',action='store_true');a=p.parse_args()
    expected=json.loads((a.access/'expected-install.json').read_text())
    c=paramiko.SSHClient();c.load_host_keys(str(a.access/'INSTALLER-KNOWN-HOSTS'))
    try:
        c.connect(expected['lanIp'],username='vgrecovery',key_filename=str(a.access/'SSH-PRIVATE-KEY'),look_for_keys=False,allow_agent=False,timeout=8,banner_timeout=8,auth_timeout=8)
        actual=json.loads(run(c,'sudo python3 -c '+shlex.quote(READ)))
        validate(expected,actual)
        print('Pinned SSH key, sudo, target MAC, disk serial and payload hash verified.')
        if a.approve:
            receipt={k:expected[k] for k in ('diskSerial','manifestSha256')}
            code="import pathlib; pathlib.Path('/run/vpnguard-install-approved.json').write_text("+repr(json.dumps(receipt))+")"
            run(c,'sudo python3 -c '+shlex.quote(code))
            print('Installation approved for verified captured target.')
    finally:c.close()

if __name__=='__main__':main()
