#!/bin/sh
set -eu
XIO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
XIO_GTK="$XIO_ROOT/.build-support/gtk-root"
if test -d "$XIO_GTK"; then
    export PKG_CONFIG_PATH="$XIO_GTK/usr/lib/x86_64-linux-gnu/pkgconfig:$XIO_GTK/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export PKG_CONFIG_SYSROOT_DIR="$XIO_GTK"
fi
cd "$XIO_ROOT/app"
XIO_VERSION=$(sed -n 's/^version: \([0-9.]*\).*/\1/p' pubspec.yaml)
flutter pub get
flutter analyze
flutter test
flutter build linux --release
mkdir -p build/linux/x64/release/bundle/libexec
cd "$XIO_ROOT/protocol/rivet"
go build -trimpath -ldflags='-s -w' -o "$XIO_ROOT/app/build/linux/x64/release/bundle/libexec/xio-tunnel" ./cmd/xio-desktop
cd "$XIO_ROOT"
python3 tooling/cross-platform/package-ubuntu.py
