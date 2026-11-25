#!/bin/sh
set -eu
exec 3>&1 1>&2
phase() { printf '%s\n' "$1" >&3; }
case "$(uname -m)" in
    x86_64) arch=amd64; digest=7db6390ef09c29789d9fe89c0066ac17b7227c5c59e26fcd13e5b9736d5cbfe8 ;;
    aarch64) arch=arm64; digest=dd32685c9e9251eafe80133659d0b3b0c008b2decb64cf47109e760f9591d28d ;;
    *) echo "Неподдерживаемая архитектура: $(uname -m)" >&2; exit 1 ;;
esac
install -d /usr/local/bin
stage=$(mktemp /usr/local/bin/.olcrtc-XXXXXX)
trap 'rm -f "$stage"' EXIT
phase "Скачивание сборки olcRTC ($arch)"
curl --fail --silent --show-error --location --proto '=https' --max-time 180 --max-filesize 67108864 \
    "https://raw.githubusercontent.com/Fogiku/VpnGuard_linux/olcrtc-f3ad8fb/olcrtc-linux-$arch" -o "$stage"
phase "Проверка SHA-256"
printf '%s  %s\n' "$digest" "$stage" | sha256sum -c -
phase "Установка бинарника"
chmod 0755 "$stage"
ln -T "$stage" /usr/local/bin/olcrtc
