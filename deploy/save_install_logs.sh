#!/bin/bash
set -u
medium=/cdrom
fs=$(findmnt -n -o FSTYPE --target "$medium")
# Never attempt to write to a stock CD-ROM or an unrelated mounted filesystem.
[[ "$fs" == vfat ]] || exit 0
mount -o remount,rw "$medium" || exit 0
[[ -f "$medium/vpnguard/install.json" ]] || exit 0
boot=$(cat /proc/sys/kernel/random/boot_id)
dest="$medium/install-logs/$boot"
mkdir -p "$dest"
for f in /var/log/cloud-init.log /var/log/cloud-init-output.log /var/log/vpnguard-install/* /target/var/log/vpnguard-install/*; do
    [[ -f "$f" ]] && cp -f "$f" "$dest/" || true
done
[[ -d /var/log/installer ]] && cp -r /var/log/installer "$dest/" || true
journalctl --no-pager -n 350 -u ssh -u subiquity-server -u subiquity-server.service > "$dest/journal.txt" 2>&1 || true
cp /etc/ssh/ssh_host_ed25519_key.pub "$dest/installer-host-key.pub" 2>/dev/null || true
printf 'UTC=%s\nStage=%s\nBoot=%s\n' "$(date -u +%FT%TZ)" "${1:-unknown}" "$boot" > "$medium/INSTALL-STATUS.txt"
sync
