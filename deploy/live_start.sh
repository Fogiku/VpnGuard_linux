#!/bin/bash
set -Eeuo pipefail
# Runs only inside the live installation environment; no target partition changes.
cat > /etc/systemd/system/vpnguard-install-logs.service <<'EOF'
[Unit]
Description=Copy VpnGuard installer diagnostics to USB
[Service]
Type=oneshot
ExecStart=/bin/bash /cdrom/vpnguard/save_install_logs.sh periodic
EOF
cat > /etc/systemd/system/vpnguard-install-logs.timer <<'EOF'
[Unit]
Description=Keep installer diagnostics on USB
[Timer]
OnActiveSec=5s
OnUnitActiveSec=20s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl start ssh
systemctl start vpnguard-install-logs.timer
bash /cdrom/vpnguard/save_install_logs.sh started || true
