#!/bin/sh
# xio-nat64-exit.sh - IPv4 for the cascade on the IPv6-only exit host.
#
# The bridge (81.177.142.37) sends its AmneziaWG clients' IPv4 into the
# ssh -w tun0 tunnel, already SNATed to 10.200.0.1 (the bridge end of the
# point-to-point /30).  On this host the packets arrive on tun0 and are
# REDIRECTed to the recipe's vpn4 process, which re-opens each TCP connection
# over IPv6 towards the provider NAT64 prefix and relays UDP/53 the same way.
#
# The host still has no IPv4 default route: everything is consumed locally by
# the REDIRECT, exactly like the awg0 path from deploy/nat64/xio-vpn4-setup.sh.
#
# Idempotent.  Exits 0 when tun0 is not there yet (cascade down or still
# connecting); xio-nat64-exit.timer re-runs it every minute, so the address and
# the rules come back after every ssh -w reconnect without touching
# xio-cascade.service.
set -eu

[ -r /etc/xio-nat64.conf ] && . /etc/xio-nat64.conf

TUN_IF=${TUN_IF:-tun0}
EXIT_V4=${EXIT_V4:-10.200.0.2}
TUN_CIDR=${TUN_CIDR:-30}
TCP_PORT=${TCP_PORT:-19192}
DNS_PORT=${DNS_PORT:-5353}
TAG=xio-nat64-tun0

i=0
while ! ip link show "$TUN_IF" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
        echo "xio-nat64-exit: $TUN_IF is absent (cascade down), nothing to do"
        exit 0
    fi
    sleep 0.5
done

ip link set "$TUN_IF" up
ip -4 addr replace "$EXIT_V4/$TUN_CIDR" dev "$TUN_IF"
ip -4 route replace "10.200.0.0/$TUN_CIDR" dev "$TUN_IF" scope link 2>/dev/null || true

# TCP from the tunnel -> vpn4
iptables -t nat -C PREROUTING -i "$TUN_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$TUN_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT"

# UDP/53 -> vpn4 DNS relay (same relay that serves awg0)
iptables -t nat -C PREROUTING -i "$TUN_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$TUN_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT"

# The REDIRECT turns the packets into local input, so no FORWARD rule is
# needed; keep forwarding on anyway for the vpn4 reply path and future use.
sysctl -q -w net.ipv4.ip_forward=1

# assertions
iptables -t nat -C PREROUTING -i "$TUN_IF" -p tcp -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$TCP_PORT"
iptables -t nat -C PREROUTING -i "$TUN_IF" -p udp -m udp --dport 53 -m comment --comment "$TAG" \
        -j REDIRECT --to-ports "$DNS_PORT"
ip -4 addr show dev "$TUN_IF" | grep -q "inet $EXIT_V4/"

echo "xio-nat64-exit: $TUN_IF $EXIT_V4/$TUN_CIDR; tcp -> $TCP_PORT, dns -> $DNS_PORT"
