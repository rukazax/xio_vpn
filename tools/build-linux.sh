#!/bin/sh
set -eu
X1O_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
X1O_GTK="$X1O_ROOT/.build-support/gtk-root"
if test -d "$X1O_GTK"; then
    export PKG_CONFIG_PATH="$X1O_GTK/usr/lib/x86_64-linux-gnu/pkgconfig:$X1O_GTK/usr/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export PKG_CONFIG_SYSROOT_DIR="$X1O_GTK"
fi
cd "$X1O_ROOT/app"
X1O_VERSION=$(sed -n 's/^version: \([0-9.]*\).*/\1/p' pubspec.yaml)
flutter pub get
flutter analyze
flutter test
flutter build linux --release
mkdir -p build/linux/x64/release/bundle/libexec
cd "$X1O_ROOT/protocol/rivet"
go build -trimpath -ldflags='-s -w' -o "$X1O_ROOT/app/build/linux/x64/release/bundle/libexec/xio-tunnel" ./cmd/xio-desktop
cd "$X1O_ROOT"
python3 tooling/cross-platform/package-ubuntu.py
