#!/bin/sh
# verify.sh - read-only proof that the vpn4 bridge is alive.
#
# Prints for every check what was run and what came back, so the output can be
# pasted into a report as-is.  Exits non-zero when a check that must pass fails;
# checks that legitimately depend on the provider (DNS64 discovery) are marked
# informational and never fail the run.
set -u

[ -r /etc/xio-vpn4.conf ] && . /etc/xio-vpn4.conf
PREFIX=${PREFIX:-2a01:4f8:c2c:123f:64:5}
AWG_IF=${AWG_IF:-awg0}
TCP_PORT=${TCP_PORT:-19192}
DNS_PORT=${DNS_PORT:-5353}
FAIL=0
ok()   { echo "  [OK]   $*"; }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
info() { echo "  [info] $*"; }
head_() { printf '\n=== %s ===\n' "$*"; }

head_ "1. the host itself has no IPv4"
if ip -4 route show default | grep -q .; then
    info "IPv4 default route: $(ip -4 route show default)"
else
    ok "no IPv4 default route (as expected for this recipe)"
fi
ip -6 addr show scope global | awk '/inet6/{print "  IPv6: " $2}'

head_ "2. NAT64 prefix in use"
echo "  prefix: $PREFIX/96 (from /etc/xio-vpn4.conf)"

head_ "3. DNS64 discovery (informational)"
AAAA=$(getent ahostsv6 ipv4only.arpa 2>/dev/null | awk '{print $1}' | head -1)
if [ -n "$AAAA" ]; then
    ok "ipv4only.arpa -> $AAAA"
else
    info "no DNS64 answer via /etc/resolv.conf (server resolver is plain DNS);"
    info "the prefix is confirmed by the literal tests in step 4 instead"
fi

head_ "4. TCP through NAT64, opened by a local process"
python3 - "$PREFIX" <<'PY'
import socket, sys, time
prefix = sys.argv[1]
def target(ip):
    p = [int(x) for x in ip.split('.')]
    return '%s:%x:%x' % (prefix, p[0] * 256 + p[1], p[2] * 256 + p[3])
rc = 0
for ip, port in (('1.1.1.1', 443), ('149.154.167.51', 443)):
    dst = target(ip)
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        t0 = time.time()
        s.connect((dst, port))
        print('  [OK]   tcp %s:%d -> [%s]:%d  %.0f ms' % (ip, port, dst, port, (time.time() - t0) * 1000))
    except Exception as e:
        print('  [FAIL] tcp %s:%d -> [%s]:%d  %r' % (ip, port, dst, port, e))
        rc = 1
    finally:
        s.close()
sys.exit(rc)
PY
[ $? -eq 0 ] || FAIL=$((FAIL + 1))

head_ "5. units"
for u in vpn4-rules vpn4; do
    en=$(systemctl is-enabled "$u" 2>&1)
    ac=$(systemctl is-active "$u" 2>&1)
    if [ "$en" = enabled ] && [ "$ac" = active ]; then
        ok "$u: enabled / active"
    else
        bad "$u: enabled=$en active=$ac"
    fi
done

head_ "6. listening sockets"
ss -tlnp 2>/dev/null | grep ":$TCP_PORT " | sed 's/^/  /' && ok "tcp/$TCP_PORT" || bad "tcp/$TCP_PORT is not listening"
ss -ulnp 2>/dev/null | grep ":$DNS_PORT " | sed 's/^/  /' && ok "udp/$DNS_PORT" || bad "udp/$DNS_PORT is not listening"

head_ "7. netfilter rules owned by xio-vpn4"
iptables -t nat -S PREROUTING | grep -- "-i $AWG_IF" | sed 's/^/  /'
tagged_tcp=$(iptables -t nat -S PREROUTING | grep -- "-i $AWG_IF -p tcp" | grep -c 'xio-vpn4' || true)
bare_tcp=$(iptables -t nat -S PREROUTING | grep -- "-i $AWG_IF -p tcp" | grep -vc 'xio-vpn4' || true)
tagged_udp=$(iptables -t nat -S PREROUTING | grep -- "-i $AWG_IF -p udp" | grep -c 'xio-vpn4' || true)
bare_udp=$(iptables -t nat -S PREROUTING | grep -- "-i $AWG_IF -p udp" | grep -vc 'xio-vpn4' || true)
if [ "$tagged_tcp" = 1 ] && [ "$bare_tcp" = 0 ] && [ "$tagged_udp" = 1 ] && [ "$bare_udp" = 0 ]; then
    ok "$AWG_IF: one tagged tcp rule and one tagged udp/53 rule, no untagged duplicates"
else
    bad "$AWG_IF PREROUTING: tcp tagged=$tagged_tcp bare=$bare_tcp, udp tagged=$tagged_udp bare=$bare_udp"
fi

head_ "8. IPv4 address on the AmneziaWG interface"
if ip -4 addr show dev "$AWG_IF" 2>/dev/null | grep -q 'inet '; then
    ip -4 addr show dev "$AWG_IF" | grep 'inet ' | sed 's/^/  /'
    ok "$AWG_IF carries IPv4"
else
    bad "$AWG_IF has no IPv4 address"
fi
ip -4 route show | sed 's/^/  route: /'

head_ "9. real relayed flows in the journal"
LINES=$(journalctl -u vpn4 --no-pager 2>/dev/null | grep -c -- '-> \[' || true)
if [ "$LINES" -gt 0 ]; then
    ok "$LINES relayed flow(s); last 5:"
    journalctl -u vpn4 --no-pager 2>/dev/null | grep -- '-> \[' | tail -5 | sed 's/^/  /'
    journalctl -u vpn4 --no-pager 2>/dev/null | grep -- 'dns client=' | tail -3 | sed 's/^/  /'
else
    info "no relayed flow yet - generate one: wget -4 -qO- http://1.1.1.1/cdn-cgi/trace from a client"
fi

printf '\n=== result: '
if [ "$FAIL" -eq 0 ]; then echo "all checks passed ==="; else echo "$FAIL check(s) FAILED ==="; fi
exit "$FAIL"
