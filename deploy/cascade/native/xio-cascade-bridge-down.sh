#!/bin/bash
set -uo pipefail
TUN=${XIO_CASCADE_TUN:-tun0}
ip rule del iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip -6 rule del iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip rule del fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
ip route flush table 51888 2>/dev/null || true
ip -6 route flush table 51888 2>/dev/null || true
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t nat -D POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -D FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do iptables -t mangle -D FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -t nat -D POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -D FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || break; done
for i in $(seq 1 4); do ip6tables -t mangle -D FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break; done
ip link del "$TUN" 2>/dev/null || true
echo "bridge cascade down"
