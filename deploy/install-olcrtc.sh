#!/bin/sh
set -eu
exec 3>&1 1>&2
phase() { printf '%s\n' "$1" >&3; }
phase "Скачивание исходников olcRTC"
revision=f3ad8fb7c0d0fa981423f83269526fa94077c23d
work=$(mktemp -d)
stage=
trap 'rm -rf "$work"; if [ -n "$stage" ]; then rm -f "$stage"; fi' EXIT
cd "$work"
git init -q source
git -C source fetch -q --depth=1 https://github.com/openlibrecommunity/olcRTC.git "$revision"
git -C source checkout -q --detach "$revision"

# Use a private Go toolchain so installing the tunnel works on runtime-only gateways.
case "$(uname -m)" in
    x86_64) arch=amd64; digest=2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556 ;;
    aarch64) arch=arm64; digest=9d89a3ea57d141c2b22d70083f2c8459ba3890f2d9e818e7e933b75614936565 ;;
    *) echo "Неподдерживаемая архитектура: $(uname -m)" >&2; exit 1 ;;
esac
archive="go1.26.3.linux-$arch.tar.gz"
phase "Скачивание Go"
curl -fsSL "https://go.dev/dl/$archive" -o "$archive"
phase "Проверка и распаковка Go"
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
tar -xzf "$archive"
cd source
# A systemd service may have no home directory or writable user cache.
export GOMODCACHE="$work/modcache" GOCACHE="$work/buildcache"
export GOPROXY="${GOPROXY:-https://proxy.golang.org|direct}"
phase "Загрузка зависимостей и сборка olcRTC"
CGO_ENABLED=0 GOTOOLCHAIN=local "$work/go/bin/go" build -mod=readonly -modcacherw -trimpath -buildvcs=false -o "$work/olcrtc" ./cmd/olcrtc
phase "Установка бинарника"
install -d /usr/local/bin
stage=$(mktemp /usr/local/bin/.olcrtc-XXXXXX)
install -m 0755 "$work/olcrtc" "$stage"
mv -fT "$stage" /usr/local/bin/olcrtc
