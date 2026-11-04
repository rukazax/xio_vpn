#!/bin/bash
# probe.sh - NAT64 applicability probe (fixed version of nat64-probe.sh from
# https://github.com/rukazax/nat64-bridge).
#
# Difference from the upstream script: it formats the discovered /96 prefix as
# six hextets without trailing zero groups.  Upstream uses
# ipaddress.IPv6Network(...).network_address, which prints all eight groups for
# prefixes whose sixth hextet is non-zero (the provider here answers
# 2a00:1098:2b::1:c000:aa, i.e. prefix 2a00:1098:2b::1).  Appending two more
# groups to that string produces a nine-group literal and every TCP test fails
# with "Name or service not known".
#
#   ./probe.sh [PREFIX] [IPV4]
#     PREFIX  optional /96 prefix; when omitted it is discovered via DNS64
#     IPV4    optional test address (default 1.1.1.1)
set -uo pipefail

TEST_V4="${2:-1.1.1.1}"
PREFIX="${1:-}"

echo "=== 1. IPv4 route on the host ==="
if ip -4 route show default | grep -q .; then
    echo "WARNING: an IPv4 default route exists - the recipe is not needed here."
    ip -4 route show default
else
    echo "no IPv4 default route (this is what the recipe expects)."
fi

echo
echo "=== 2. IPv6 addresses ==="
ip -6 addr show scope global | awk '/inet6/{print "  " $2}'

echo
echo "=== 3. NAT64 prefix ==="
if [ -z "$PREFIX" ]; then
    AAAA=$(getent ahostsv6 ipv4only.arpa 2>/dev/null | awk '{print $1}' | head -1)
    if [ -z "$AAAA" ]; then
        echo "  no AAAA for ipv4only.arpa - DNS64 is unavailable; pass the prefix explicitly."
        exit 1
    fi
    echo "  AAAA: $AAAA"
    PREFIX=$(python3 - "$AAAA" <<'PY'
import ipaddress, sys
groups = ipaddress.IPv6Address(sys.argv[1]).exploded.split(':')
print(':'.join(groups[:6]))
PY
)
fi
# normalise "a:b:c:d:e:f", "a:...:f::" and "a:...:f::/96" to six hextets
PREFIX=$(python3 - "$PREFIX" <<'PY'
import ipaddress, sys
raw = sys.argv[1].strip()
if '/' in raw:
    raw = raw.split('/', 1)[0]
if not raw.endswith('::'):
    raw += '::' if raw.count(':') < 7 else ''
groups = ipaddress.IPv6Address(raw).exploded.split(':')
print(':'.join(groups[:6]))
PY
)
echo "  NAT64 prefix: ${PREFIX}::/96"

echo
echo "=== 4. ICMP through NAT64 ==="
python3 - "$PREFIX" "$TEST_V4" <<'PY'
import socket, sys
prefix, v4 = sys.argv[1], sys.argv[2]
p = [int(x) for x in v4.split('.')]
print('  target: [%s:%x:%x]' % (prefix, p[0] * 256 + p[1], p[2] * 256 + p[3]))
PY
target=$(python3 - "$PREFIX" "$TEST_V4" <<'PY'
import sys
prefix, v4 = sys.argv[1], sys.argv[2]
p = [int(x) for x in v4.split('.')]
print('%s:%x:%x' % (prefix, p[0] * 256 + p[1], p[2] * 256 + p[3]))
PY
)
ping -6 -c 2 -W 3 "$target" 2>&1 | tail -2 | sed 's/^/  /'

echo
echo "=== 5. TCP through NAT64 (the gate) ==="
python3 - "$PREFIX" <<'PY'
import socket, sys, time
prefix = sys.argv[1]
rc = 0
for v4 in ('1.1.1.1', '149.154.167.51'):
    p = [int(x) for x in v4.split('.')]
    dst = '%s:%x:%x' % (prefix, p[0] * 256 + p[1], p[2] * 256 + p[3])
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        t0 = time.time()
        s.connect((dst, 443))
        print('  %s:443 -> TCP OK  %.0f ms' % (dst, (time.time() - t0) * 1000))
    except Exception as e:
        print('  %s:443 -> FAIL %r' % (dst, e))
        rc = 1
    finally:
        s.close()
sys.exit(rc)
PY
rc=$?
echo
if [ "$rc" -eq 0 ]; then
    echo "OK: TCP through NAT64 works; install-dc6.sh / install-vpn4.sh are applicable."
else
    echo "FAIL: TCP through NAT64 does not work; the recipe is not applicable."
fi
exit "$rc"
