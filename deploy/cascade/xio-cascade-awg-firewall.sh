#!/bin/bash
# XIO cascade: явные правила для AWG-клиентов на bridge (вариант 2).
# IPv6 подключившихся устройств уходит в tun0 (каскад на IPv6-exit),
# IPv4 идёт напрямую через публичный интерфейс bridge.
# Правила идемпотентны и переживают перезагрузку через xio-cascade-fw.service.
set -euo pipefail
PUB="${XIO_PUBLIC_IFACE:-$(ip -4 route show default | awk '{print $5; exit}')}"
TUN="${XIO_CASCADE_IFACE:-tun0}"
TAG="xio-cascade-awg-v1"
NAT6="fd78:1::/64"
NAT4="10.78.0.0/24"

del() { "$@" 2>/dev/null || true; }
while ip6tables -S FORWARD | grep -q "$TAG"; do
  line=$(ip6tables -S FORWARD | grep "$TAG" | head -1)
  del ip6tables ${line/-A /-D }
done

ip6tables -I FORWARD 1 -i xioawg0 -o "$TUN" -m comment --comment "$TAG" -j ACCEPT
ip6tables -I FORWARD 2 -i "$TUN" -o xioawg0 -m comment --comment "$TAG" -j ACCEPT
ip6tables -I FORWARD 3 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$TAG" -j ACCEPT
ip6tables -I FORWARD 4 -i xioawg0 ! -o "$TUN" -m comment --comment "$TAG-no-leak" -j DROP
ip6tables -t nat -C POSTROUTING -s "$NAT6" -o "$TUN" -m comment --comment "xio-dualstack-v1-xioawg0" -j MASQUERADE 2>/dev/null || \
  ip6tables -t nat -A POSTROUTING -s "$NAT6" -o "$TUN" -m comment --comment "xio-dualstack-v1-xioawg0" -j MASQUERADE

iptables -I FORWARD 1 -i xioawg0 -o "$PUB" -m comment --comment "xio-awg-v1-egress" -j ACCEPT
iptables -I FORWARD 2 -o xioawg0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "xio-awg-v1-egress" -j ACCEPT
iptables -t nat -C POSTROUTING -s "$NAT4" -o "$PUB" -m comment --comment "xio-managed-v1-awg" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$NAT4" -o "$PUB" -m comment --comment "xio-managed-v1-awg" -j MASQUERADE

install -d -m 0755 /etc/xio-managed
ip6tables-save > /etc/xio-managed/ip6tables-cascade-v1.rules
iptables-save  > /etc/xio-managed/iptables-cascade-v1.rules

cat > /etc/systemd/system/xio-cascade-fw.service <<'UNIT'
[Unit]
Description=XIO cascade firewall rules (AWG clients -> IPv6 exit)
After=xio-managed-awg.service xio-cascade.service
Wants=xio-managed-awg.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c '/sbin/iptables-restore < /etc/xio-managed/iptables-cascade-v1.rules && /sbin/ip6tables-restore < /etc/xio-managed/ip6tables-cascade-v1.rules'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now xio-cascade-fw.service >/dev/null
echo "cascade firewall applied: pub=$PUB tun=$TUN"
ip6tables -S FORWARD | grep "$TAG" | head -4