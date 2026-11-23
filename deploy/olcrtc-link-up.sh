#!/bin/sh
set -eu
ip address add 198.18.0.1/32 dev olc0
ip link set dev olc0 up
