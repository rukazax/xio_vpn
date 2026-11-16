#!/bin/bash
# XIO cascade exit (foreign VPS): terminate SSH TUN and NAT client traffic to the Internet.
set -euo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "no IPv4 default route" >&2; exit 1; }
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip tuntap add dev "$TUN" mode tun 2>/dev/null || true
ip link set "$TUN" mtu 1400 up
ip addr replace 10.250.0.2/30 dev "$TUN"
ip -6 addr replace fd78:2::2/64 dev "$TUN"
ip route replace 10.78.0.0/24 dev "$TUN"
iptables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$TUN" -j ACCEPT
iptables -C FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.250.0.0/30 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.250.0.0/30 -o "$WAN" -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$WAN" -j MASQUERADE
ip6tables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -i "$TUN" -j ACCEPT
ip6tables -C FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t nat -C POSTROUTING -s fd78:2::/64 -o "$WAN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:2::/64 -o "$WAN" -j MASQUERADE
echo "exit cascade up: $TUN -> $WAN"
