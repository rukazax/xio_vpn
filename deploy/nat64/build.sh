#!/bin/sh
# build.sh - cross-build the static vpn4 binary for the server.
#
# vpn4 uses only the standard library and package syscall, so CGO is off and the
# result runs on a bare LXC container with no toolchain installed.
set -eu
cd "$(dirname "$0")"
cd src/vpn4
CGO_ENABLED=0 GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} \
    go build -trimpath -ldflags '-s -w' -o ../../vpn4 .
cd ../..
ls -l vpn4
file vpn4 2>/dev/null || true
