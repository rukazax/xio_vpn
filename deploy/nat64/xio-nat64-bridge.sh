#!/bin/sh
# xio-nat64-bridge.sh - send the AmneziaWG clients' IPv4 into the cascade.
#
# Before: clients (10.78.0.0/24 on xioawg0) were MASQUERADEd out of enp3s0 and
# left through the bridge's own public IPv4.
# After:  their packets are policy-routed into the ssh -w tun0 tunnel
# (10.200.0.0/30), SNATed there to the bridge tunnel address 10.200.0.1, and
# the exit REDIRECTs every TCP flow to vpn4, which dials the provider NAT64.
#
# NAT44 is narrowed, not deleted: the rule that xio-managed-awg owns
#   -s 10.78.0.0/24 -o enp3s0 -j MASQUERADE
# is left untouched (it belongs to another service) but is shadowed twice:
# a tagged RETURN in nat POSTROUTING stops it, and the source rule sends the
# packets to tun0, never to enp3s0.  The only NAT that remains for this subnet
# is the tagged MASQUERADE on tun0.
#
# Idempotent.  Exits 0 when tun0 is not there yet; xio-nat64-bridge.timer
# re-runs it every minute so a cascade reconnect gets the IPv4 path back
# without editing xio-cascade.service.
set -eu

[ -r /etc/xio-nat64.conf ] && . /etc/xio-nat64.conf

TUN_IF=${TUN_IF:-tun0}
BRIDGE_V4=${BRIDGE_V4:-10.200.0.1}
TUN_CIDR=${TUN_CIDR:-30}
CLIENT_NET=${CLIENT_NET:-10.78.0.0/24}
AWG_IF=${AWG_IF:-xioawg0}
PUB_IF=${PUB_IF:-enp3s0}
TABLE=${TABLE:-78}
TAG=xio-nat64
PRIO=${PRIO:-100}

i=0
while ! ip link show "$TUN_IF" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 20 ]; then
        echo "xio-nat64-bridge: $TUN_IF is absent (cascade down), nothing to do"
        exit 0
    fi
    sleep 0.5
done

ip link set "$TUN_IF" up
ip -4 addr replace "$BRIDGE_V4/$TUN_CIDR" dev "$TUN_IF"
ip -4 route replace "10.200.0.0/$TUN_CIDR" dev "$TUN_IF" table "$TABLE" 2>/dev/null || true
ip -4 route replace default dev "$TUN_IF" table "$TABLE"

# Source policy: clients leave through the tunnel, the host keeps its own
# default route on enp3s0.  Re-create the rule so a changed priority or prefix
# does not leave duplicates behind.
while ip -4 rule del from "$CLIENT_NET" lookup "$TABLE" 2>/dev/null; do :; done
ip -4 rule add from "$CLIENT_NET" lookup "$TABLE" priority "$PRIO"

# The only NAT44 left for this subnet: into the tunnel, to a single address.
iptables -t nat -C POSTROUTING -s "$CLIENT_NET" -o "$TUN_IF" -m comment --comment "$TAG" \
        -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$CLIENT_NET" -o "$TUN_IF" -m comment --comment "$TAG" \
        -j MASQUERADE

# Fail closed on the old path: no MASQUERADE towards the public interface.
iptables -t nat -C POSTROUTING -s "$CLIENT_NET" -o "$PUB_IF" -m comment --comment "$TAG" \
        -j RETURN 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s "$CLIENT_NET" -o "$PUB_IF" -m comment --comment "$TAG" \
        -j RETURN

# Forwarding: xioawg0 -> tun0 must be accepted before the generic DROP that
# xio-managed-awg keeps at the end of FORWARD.  The return direction already
# has a conntrack ESTABLISHED/RELATED accept owned by xio-managed-awg.
iptables -C FORWARD -i "$AWG_IF" -o "$TUN_IF" -m comment --comment "$TAG" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -i "$AWG_IF" -o "$TUN_IF" -m comment --comment "$TAG" -j ACCEPT

sysctl -q -w net.ipv4.ip_forward=1

# assertions
ip -4 rule show | grep -q "from $CLIENT_NET lookup $TABLE"
ip -4 route show table "$TABLE" | grep -q "^default dev $TUN_IF"
iptables -t nat -C POSTROUTING -s "$CLIENT_NET" -o "$TUN_IF" -m comment --comment "$TAG" -j MASQUERADE
iptables -C FORWARD -i "$AWG_IF" -o "$TUN_IF" -m comment --comment "$TAG" -j ACCEPT
ip -4 addr show dev "$TUN_IF" | grep -q "inet $BRIDGE_V4/"

echo "xio-nat64-bridge: $CLIENT_NET -> table $TABLE dev $TUN_IF, SNAT $BRIDGE_V4"
