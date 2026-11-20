#!/usr/bin/env python3
"""Offline repair of the captured installed Ubuntu. Never partitions or formats disks."""
import datetime,json,os,re,shutil,subprocess,sys,tarfile,time
from pathlib import Path
from access_config import configure
from verify_payload import verify


def run(args,check=True):
    return subprocess.run(args,text=True,capture_output=True,check=check,timeout=300)


def repair(payload):
    payload=Path(payload);medium=payload.parent
    if "vpnguard.repair=1" not in Path('/proc/cmdline').read_text():raise ValueError('Repair boot mode is required')
    run(['systemctl','mask','--runtime','--now','snap.subiquity.subiquity-service.service'])
    print('REPAIR: checking the existing Ubuntu; disk will NOT be formatted',flush=True)
    verify(payload)
    s=json.loads((payload/'install.json').read_text())
    macs=[p.read_text().strip().lower() for p in Path('/sys/class/net').glob('*/address')]
    if s['wanMac'] not in macs:raise ValueError('Wrong target Ethernet MAC')
    data=json.loads(run(['lsblk','-bJpo','NAME,TYPE,SERIAL,TRAN,FSTYPE,PARTUUID']).stdout)['blockdevices']
    matches=[d for d in data if d['type']=='disk' and str(d.get('serial') or '').strip()==s['diskSerial'] and d.get('tran')!='usb']
    if len(matches)!=1:raise ValueError('Expected exactly one authorised non-USB disk')
    if run(['findmnt','-n','-o','FSTYPE','--target',str(medium)]).stdout.strip()!='vfat':raise ValueError('Repair requires the prepared FAT32 USB')
    run(['mount','-o','remount,rw',str(medium)])
    disk=matches[0];parts=disk.get('children',[])
    roots=[p for p in parts if p.get('fstype')=='ext4'];esps=[p for p in parts if p.get('fstype')=='vfat']
    if len(roots)!=1 or len(esps)!=1:raise ValueError('Expected existing Ubuntu root and EFI partition; no formatting performed')
    root=Path('/mnt/vpnguard-repair');root.mkdir(exist_ok=True)
    run(['mount','-o','rw',roots[0]['name'],str(root)])
    mounted=[root];reboot=False
    dest=medium/'repair-logs'/datetime.datetime.now().strftime('%Y%m%d-%H%M%S');dest.mkdir(parents=True,exist_ok=True)
    try:
        if not (root/'etc/os-release').is_file() or 'ubuntu' not in (root/'etc/os-release').read_text().lower():raise ValueError('Existing root is not Ubuntu')
        with tarfile.open(dest/'before-repair.tar.gz','w:gz') as archive:
            for name in ['etc/netplan','etc/ssh','etc/cloud/cloud.cfg.d','etc/passwd','etc/shadow','var/lib/vpnguard','var/log/vpnguard-install']:
                if (root/name).exists():archive.add(root/name,arcname=name)
        (dest/'live-network.txt').write_text(run(['ip','-4','addr']).stdout+run(['ip','route']).stdout)
        for name in ['etc/netplan','var/log/installer']:
            if (root/name).exists():shutil.copytree(root/name,dest/Path(name).name,dirs_exist_ok=True)
        journal=root/'var/log/journal'
        if journal.exists():
            (dest/'installed-journal.txt').write_text(run(['journalctl','--directory='+str(journal),'--no-pager','-b','0','-n','350'],check=False).stdout)
        esp=root/'boot/efi';esp.mkdir(parents=True,exist_ok=True)
        run(['mount',esps[0]['name'],str(esp)]);mounted.append(esp)
        for name in ['dev','proc','sys','run']:
            target=root/name;target.mkdir(exist_ok=True)
            run(['mount','--rbind','/'+name,str(target)]);run(['mount','--make-rslave',str(target)]);mounted.append(target)
        if not (root/'usr/local/bin/vpnguard').exists():
            install=root/'opt/vpnguard-install';shutil.copytree(payload,install,dirs_exist_ok=True)
            run(['chroot',str(root),'/bin/bash','/opt/vpnguard-install/setup.sh'])
        print('REPAIR: applying console password, SSH and Ethernet settings',flush=True)
        configure(root,s)
        cfg=root/'var/lib/vpnguard';(cfg/'usb-repair-complete').write_text(datetime.datetime.now().isoformat())
        host=root/'etc/ssh/ssh_host_ed25519_key.pub'
        if host.exists():(medium/'TARGET-HOST-KEY.pub').write_text(host.read_text())
        loader=esp/'EFI/ubuntu/shimx64.efi'
        if not loader.exists():loader=esp/'EFI/ubuntu/grubx64.efi'
        if not loader.exists():raise ValueError('Ubuntu EFI loader missing; access repaired, automatic reboot cancelled')
        fallback=esp/'EFI/BOOT';fallback.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(loader,fallback/'BOOTX64.EFI')
        for name in ['grubx64.efi','mmx64.efi','grub.cfg']:
            if (esp/'EFI/ubuntu'/name).exists():shutil.copyfile(esp/'EFI/ubuntu'/name,fallback/name)
        manager=run(['chroot',str(root),'/bin/sh','-c','command -v efibootmgr'],check=False).stdout.strip()
        if not manager:raise ValueError('efibootmgr missing; access repaired, choose Ubuntu in UEFI')
        command=['chroot',str(root),manager]
        listing=run(command+['-v']).stdout
        partuuid=esps[0]['partuuid'].lower()
        boot=None
        for line in listing.splitlines():
            m=re.match(r'Boot([0-9A-Fa-f]{4})\*?\s+ubuntu\b',line,re.I)
            if m and partuuid in line.lower():boot=m.group(1);break
        if not boot:
            number=(Path('/sys/class/block')/Path(esps[0]['name']).name/'partition').read_text().strip()
            run(command+['-c','-d',disk['name'],'-p',number,'-L','ubuntu','-l','\\EFI\\ubuntu\\'+loader.name])
            listing=run(command+['-v']).stdout
            for line in listing.splitlines():
                m=re.match(r'Boot([0-9A-Fa-f]{4})\*?\s+ubuntu\b',line,re.I)
                if m and partuuid in line.lower():boot=m.group(1);break
        if not boot:raise ValueError('Could not identify target Ubuntu boot entry')
        order=re.search(r'BootOrder:\s*([0-9A-Fa-f,]+)',listing)
        if order:
            entries=[boot]+[x for x in order.group(1).split(',') if x.lower()!=boot.lower()]
            run(command+['-o',','.join(entries)])
        run(command+['-n',boot])
        text='SUCCESS: existing Ubuntu repaired without formatting.\nLogin: '+s['username']+'\nPassword: LOGIN.txt\nWeb: http://'+s['lanIp']+':8765/\nRebooting into the installed disk.\n'
        (medium/'REPAIR-RESULT.txt').write_text(text);print(text,flush=True);reboot=True
    finally:
        run(['sync'])
        for path in reversed(mounted):run(['umount','-R',str(path)],check=False)
    if reboot:run(['systemctl','reboot'])

if __name__=='__main__':
    try:repair(Path(sys.argv[1]))
    except Exception as e:
        message='REPAIR STOPPED: '+str(e)+'\nNo disk formatting was performed.\n'
        print(message,flush=True)
        Path(sys.argv[1]).parent.joinpath('REPAIR-RESULT.txt').write_text(message)
        raise
