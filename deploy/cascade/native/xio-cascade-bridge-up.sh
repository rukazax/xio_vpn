#!/bin/bash
# XIO cascade bridge (RU VPS): client traffic from xioawg0 -> SSH TUN -> exit VPS.
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
ip rule add iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
ip -6 rule add iif xioawg0 lookup 51888 priority 1000 2>/dev/null || true
# Client traffic forwarded from xioawg0 is covered by the iif rule above. Traffic
# that a local transport (Xray, RIVET gateway) generates itself has no input
# interface, so it is matched by SO_MARK instead: such a socket must set
# XIO_CASCADE_MARK (default 0x518) and then leaves through the same table.
ip rule add fwmark ${XIO_CASCADE_MARK:-0x518} lookup 51888 priority 1000 2>/dev/null || true
ip route replace default dev "$TUN" table 51888
ip -6 route replace default dev "$TUN" table 51888
iptables -t nat -C POSTROUTING -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 10.78.0.0/24 -o "$TUN" -j MASQUERADE
# Locally generated, marked traffic (Xray/RIVET egress) keeps the bridge address
# as its source, so it needs its own SNAT rule on the cascade tunnel.
iptables -t nat -C POSTROUTING -o "$TUN" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -o "$TUN" -j MASQUERADE
iptables -C FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i xioawg0 -o "$TUN" -j ACCEPT
iptables -C FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t nat -C POSTROUTING -s fd78:1::/64 -o "$TUN" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -I POSTROUTING 1 -s fd78:1::/64 -o "$TUN" -j MASQUERADE
ip6tables -C FORWARD -i xioawg0 -o "$TUN" -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -i xioawg0 -o "$TUN" -j ACCEPT
ip6tables -C FORWARD -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  ip6tables -I FORWARD 1 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t mangle -C FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  ip6tables -t mangle -I FORWARD 1 -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo "bridge cascade up: $TUN -> $EXIT_HOST via $WAN"
