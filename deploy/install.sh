#!/bin/sh
# Установка VpnGuard на Ubuntu Server LTS. На настоящей системе этот сценарий ещё НЕ проверялся —
# сначала запускайте его в виртуальной машине (см. README, раздел «Как перейти без риска»).
set -eu
[ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo sh install.sh"; exit 1; }
cd "$(dirname "$0")/.."
apt-get update
apt-get install -y wireguard-tools nftables curl
install -m 755 bin/vpnguard /usr/local/bin/vpnguard
install -d -m 700 /var/lib/vpnguard /etc/vpnguard
install -m 644 deploy/vpnguard.service deploy/vpnguard-nfqws2.service /etc/systemd/system/
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-vpnguard.conf
sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now vpnguard
echo "Готово. Веб-интерфейс: http://АДРЕС_ШЛЮЗА:8765/  Пароль для входа из сети: значение web.token в /var/lib/vpnguard/config.json"
echo "Отдельно установите: meduzavpn (пакет с сайта MeduzaVPN), amneziawg-tools и модуль amneziawg, zapret2."
