#!/bin/sh
set -eu
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
curl -fsSL "https://go.dev/dl/$archive" -o "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
tar -xzf "$archive"
cd source
export GOPROXY="${GOPROXY:-https://proxy.golang.org|direct}"
CGO_ENABLED=0 GOTOOLCHAIN=local "$work/go/bin/go" build -mod=readonly -trimpath -o "$work/olcrtc" ./cmd/olcrtc
install -d /usr/local/bin
stage=$(mktemp /usr/local/bin/.olcrtc-XXXXXX)
install -m 0755 "$work/olcrtc" "$stage"
mv -fT "$stage" /usr/local/bin/olcrtc
