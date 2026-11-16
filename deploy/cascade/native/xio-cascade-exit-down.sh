#!/bin/bash
set -uo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
WAN=$(ip -4 route show default | awk '{print $5; exit}')
ip route del 10.78.0.0/24 dev "$TUN" 2>/dev/null || true
for i in $(seq 1 4); do iptables -D FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
[ -n "${WAN:-}" ] && { for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s 10.250.0.0/30 -o "$WAN" -j MASQUERADE 2>/dev/null || break; done; }
[ -n "${WAN:-}" ] && { for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o "$WAN" -j MASQUERADE 2>/dev/null || break; done; }
for i in $(seq 1 4); do ip6tables -D FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
[ -n "${WAN:-}" ] && { for i in $(seq 1 4); do ip6tables -t nat -D POSTROUTING -s fd78:2::/64 -o "$WAN" -j MASQUERADE 2>/dev/null || break; done; }
ip link del "$TUN" 2>/dev/null || true
echo "exit cascade down"
