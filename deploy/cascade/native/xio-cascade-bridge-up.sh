#!/bin/bash
# XIO cascade bridge (RU VPS): client traffic from every xio* tunnel -> SSH TUN -> exit VPS.
# Idempotent. No secrets in this file; the SSH key lives in /root/.ssh/xio_cascade.
set -euo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
EXIT_HOST=${XIO_CASCADE_EXIT_HOST:-103.102.135.124}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "no IPv4 default route" >&2; exit 1; }
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip tuntap add dev "$TUN" mode tun 2>/dev/null || true
ip link set "$TUN" mtu 1400 up
ip addr replace 10.250.0.1/30 dev "$TUN"
ip -6 addr replace fd78:2::1/64 dev "$TUN"
# Every client-facing transport forwards into the cascade, and the interface name
# differs per transport (xioawg0 for AWG, xiorivet for the RIVET gateway, a
# separate TUN when Xray runs one). Discover them instead of hardcoding a single
# name: a transport installed later must not silently keep exiting from the RU
# address just because this file only knew about AWG.
client_ifs() {
  ip -br link show | awk -v skip="$TUN" '
    { name = $1; sub(/@.*/, "", name) }
    name ~ /^xio/ && name != skip { print name }
  '
}
CLIENT_IFS=$(client_ifs)
[ -n "$CLIENT_IFS" ] || echo "warning: no client tunnel interface found yet" >&2
for IF in $CLIENT_IFS; do
  ip rule add iif "$IF" lookup 51888 priority 1000 2>/dev/null || true
  ip -6 rule add iif "$IF" lookup 51888 priority 1000 2>/dev/null || true
  iptables -C FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -i "$IF" -o "$TUN" -j ACCEPT
  iptables -C FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -C FORWARD -i "$IF" -o "$TUN" -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD 1 -i "$IF" -o "$TUN" -j ACCEPT
  ip6tables -C FORWARD -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD 1 -o "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
done
# FORWARD accepts for every client interface are installed by the loop above.
ip rule add fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
# Traffic a local transport generates itself (Xray, the RIVET gateway dialling
# upstream) has no input interface, so the iif rules above cannot match it: such
# a socket must set XIO_CASCADE_MARK (default 0x518) to leave through this table.
ip route replace default dev "$TUN" table 51888
ip -6 route replace default dev "$TUN" table 51888
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE
# Locally generated, marked traffic (Xray/RIVET egress) keeps the bridge address
# as its source, so it needs its own SNAT rule on the cascade tunnel.
iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -o "$TUN" -j MASQUERADE
iptables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t nat -C POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:1::/64 -o "$TUN" -j MASQUERADE
ip6tables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo "bridge cascade up: $TUN -> $EXIT_HOST via $WAN"
