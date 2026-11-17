#!/usr/bin/env bash
set -eu
base=/srv/archives/agent-fallback-integration-finalize-20261105
mkdir -p "$base/format-check"
tar -xf "$base/format-input.tar" -C "$base/format-check"
files='setup_lease.go setup_lease_test.go setup_network_linux_test.go setup_network_windows_test.go runtime.go network_common.go network_linux.go network_windows.go sharing.go sharing_linux.go sharing_windows.go'
for file in $files;do
 /opt/go1.27.3/bin/gofmt -w "$base/format-check/protocol/rivet/internal/desktop/$file"
 cmp "$base/format-check/protocol/rivet/internal/desktop/$file" "$base/candidate/protocol/rivet/internal/desktop/$file"
done
printf 'Canonical gofmt comparison: all 11 modified/new Go files byte-identical to tested candidate, exit0\n'
