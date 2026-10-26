#!/bin/sh
# Run explicitly as root on the test VPS. Removes only this xio deployment.
set -eu
test "$(id -u)" = 0
test -f /etc/xio/deployment.json || { echo 'xio ownership marker absent' >&2; exit 1; }
python3 - <<'PY'
import json
from pathlib import Path
assert json.loads(Path('/etc/xio/deployment.json').read_text())['owner']=='xio-vps-test-20261017'
PY
systemctl stop xio-vps-http-test.service 2>/dev/null || true
systemctl disable --now xio-awg-test.service
systemctl disable --now wg-quick@xio0.service
rm -f /etc/systemd/system/xio-awg-test.service /etc/wireguard/xio0.conf /etc/sysctl.d/91-xio.conf
rm -f /etc/xio/awg.uapi /etc/xio/outbound-interface /etc/xio/deployment.json
rm -f /opt/xio/amneziawg-go
rm -f /usr/local/lib/xio-test/configure-awg.py /usr/local/lib/xio-test/http-check.py /usr/local/lib/xio-test/rollback-test.sh
rmdir /etc/xio /opt/xio /usr/local/lib/xio-test 2>/dev/null || true
systemctl daemon-reload
# Do not restore a whole firewall snapshot: other services may have updated it.
# Original forwarding value is in /root/xio-before-test-20261017/ip_forward.
# Review current router/container use before restoring that global setting.
printf 'xio stopped and own files/rules removed. Packages, baseline snapshots and forwarding state retained for review.\n'
