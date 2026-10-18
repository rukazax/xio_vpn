#!/bin/sh
# Run explicitly as root on the test VPS. Removes only this x1o deployment.
set -eu
test "$(id -u)" = 0
test -f /etc/x1o/deployment.json || { echo 'x1o ownership marker absent' >&2; exit 1; }
python3 - <<'PY'
import json
from pathlib import Path
assert json.loads(Path('/etc/x1o/deployment.json').read_text())['owner']=='x1o-vps-test-20261017'
PY
systemctl stop x1o-vps-http-test.service 2>/dev/null || true
systemctl disable --now x1o-awg-test.service
systemctl disable --now wg-quick@x1o0.service
rm -f /etc/systemd/system/x1o-awg-test.service /etc/wireguard/x1o0.conf /etc/sysctl.d/91-x1o.conf
rm -f /etc/x1o/awg.uapi /etc/x1o/outbound-interface /etc/x1o/deployment.json
rm -f /opt/x1o/amneziawg-go
rm -f /usr/local/lib/x1o-test/configure-awg.py /usr/local/lib/x1o-test/http-check.py /usr/local/lib/x1o-test/rollback-test.sh
rmdir /etc/x1o /opt/x1o /usr/local/lib/x1o-test 2>/dev/null || true
systemctl daemon-reload
# Do not restore a whole firewall snapshot: other services may have updated it.
# Original forwarding value is in /root/x1o-before-test-20261017/ip_forward.
# Review current router/container use before restoring that global setting.
printf 'x1o stopped and own files/rules removed. Packages, baseline snapshots and forwarding state retained for review.\n'
