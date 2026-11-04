#!/bin/sh
# vpn4-rules.sh - persistent addresses and netfilter rules for the vpn4 bridge.
#
# The host has no IPv4 route and never will: every IPv4 packet that appears here
# was produced by an AmneziaWG client and arrives through awg0.  Such a packet
# is DNATed to 127.0.0.1:<port> by the REDIRECT rules below, where vpn4 picks it
# up, asks netfilter for the pre-redirect destination (SO_ORIGINAL_DST) and
# opens an IPv6 connection to <NAT64 prefix>:<those four bytes>.
#
# Every rule this script owns carries the comment tag "xio-vpn4"; the script is
# idempotent and deletes the untagged duplicates left behind by earlier
# hand-made runs.  Safe to run repeatedly.
set -eu

[ -r /etc/xio-vpn4.conf ] && . /etc/xio-vpn4.conf

PREFIX=${PREFIX:-2a01:4f8:c2c:123f:64:5}
AWG_IF=${AWG_IF:-awg0}
TUN_V4=${TUN_V4:-10.90.0.1}
TUN_CIDR=${TUN_CIDR:-24}
TCP_PORT=${TCP_PORT:-19192}
DNS_PORT=${DNS_PORT:-5353}
TAG=xio-vpn4

# ---- 1. the interface keeps its IPv6 role, we only add an IPv4 /24 -----------
# awg-owner's apply.py does the same on every start, so this survives restarts
# even when this oneshot is not re-run; doing it here as well makes the unit
# self-sufficient and keeps "ip addr show" truthful right after enabling it.
i=0
while ! ip link show "$AWG_IF" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 150 ]; then
        echo "vpn4-rules: interface $AWG_IF never appeared" >&2
        exit 1
    fi
    sleep 0.1
done
ip link set "$AWG_IF" up
ip -4 addr replace "$TUN_V4/$TUN_CIDR" dev "$AWG_IF"

# The connected route 10.90.0.0/24 dev awg0 is created by the kernel together
# with the address.  A "ip -4 route replace <client net> dev lo" entry is NOT
# needed for this path: client packets arrive through awg0, so they are already
# routed to us.  (A lo route is only required for locally generated IPv4
# traffic, which the dc6 Telegram bridge uses for its own OUTPUT REDIRECTs.)
ip -4 route replace "$TUN_V4/$TUN_CIDR" dev "$AWG_IF" scope link 2>/dev/null || true

# ---- 2. TCP from the clients goes to the userspace bridge --------------------
# Drop untagged leftovers first (they would otherwise shadow the tagged rule).
while iptables -t nat -D PREROUTING -i "$AWG_IF" -p tcp -j REDIRECT --to-ports "$TCP_PORT" 2>/dev/null; do :; done
iptables -t nat -C PREROUTING -i "$AWG_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$AWG_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT"

# ---- 3. UDP/53 from the clients goes to the DNS relay ------------------------
while iptables -t nat -D PREROUTING -i "$AWG_IF" -p udp -m udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null; do :; done
iptables -t nat -C PREROUTING -i "$AWG_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$AWG_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT"

# ---- 4. forwarding (harmless today, needed the day a route appears) ----------
while iptables -D FORWARD -i "$AWG_IF" -j ACCEPT 2>/dev/null; do :; done
while iptables -D FORWARD -o "$AWG_IF" -j ACCEPT 2>/dev/null; do :; done
iptables -C FORWARD -i "$AWG_IF" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$AWG_IF" -m comment --comment "$TAG" -j ACCEPT
iptables -C FORWARD -o "$AWG_IF" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "$AWG_IF" -m comment --comment "$TAG" -j ACCEPT

sysctl -q -w net.ipv4.ip_forward=1

# ---- 5. assertions: fail the unit instead of pretending success ---------------
iptables -t nat -C PREROUTING -i "$AWG_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT"
iptables -t nat -C PREROUTING -i "$AWG_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT"
ip -4 addr show dev "$AWG_IF" | grep -q "inet $TUN_V4/"

echo "vpn4-rules: $AWG_IF $TUN_V4/$TUN_CIDR; tcp -> $TCP_PORT, dns -> $DNS_PORT; prefix $PREFIX"
