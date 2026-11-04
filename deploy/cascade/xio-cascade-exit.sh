#!/bin/sh
# XIO Cascade exit side: make IPv6 forwarding and NAT66 for the tunnel persistent.
#
# The bridge reaches this host over the provider IPv4 SSH proxy and runs a plain
# address on tun0 (fd00:201::/126). Without an explicit rule for that subnet the
# cascade silently depends on an ad-hoc catch-all masquerade that no unit restores
# after a reboot, so the tunnel stays "active" while nothing leaves the host.
set -eu
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv6.conf.default.forwarding=1
sysctl -q -w net.ipv4.ip_forward=1

ip6tables -C FORWARD -i tun0 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD -i tun0 -j ACCEPT
ip6tables -C FORWARD -o tun0 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD -o tun0 -j ACCEPT
ip6tables -t nat -C POSTROUTING -s fd00:201::/126 -o eth0 -m comment --comment xio-cascade-v1 -j MASQUERADE 2>/dev/null \
  || ip6tables -t nat -A POSTROUTING -s fd00:201::/126 -o eth0 -m comment --comment xio-cascade-v1 -j MASQUERADE

echo "xio-cascade-exit: forwarding and NAT66 for fd00:201::/126 are in place"
