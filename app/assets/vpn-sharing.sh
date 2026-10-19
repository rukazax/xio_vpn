#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# IPv4 tether forwarding; invoked only after an explicit root-authorised toggle.
set -eu
[ "$(id -u)" = 0 ] || { echo ROOT_REQUIRED; exit 77; }
mode=${1:--}; down=${2:--}; vpn=${3:--}
valid_iface() { case "$1" in ''|*[!a-zA-Z0-9_-]*|lo) return 1;; esac; [ "${#1}" -le 15 ]; }
state=${XIO_SHARING_STATE:-/data/local/xio-sharing}
for cmd in ip iptables ip6tables; do command -v "$cmd" >/dev/null || { echo FIREWALL_UNAVAILABLE; exit 78; }; done
if [ -e "$state" ]; then
 [ -d "$state" ] && [ ! -L "$state" ] && [ "$(stat -c %u "$state")" = 0 ] && [ "$(cat "$state/owner")" = xio-sharing-v1 ] || { echo FOREIGN_STATE; exit 79; }
fi
ipt() { iptables -w 5 "$@"; }
ip6() { ip6tables -w 5 "$@"; }
if [ "$mode" = disable ]; then
 [ -d "$state" ] || exit 0
 down=$(cat "$state/downstream")
 valid_iface "$down" || exit 79
 # Remove only our exact hooks, table, mark rule and named chains.
 for pair in 'filter FORWARD XIOH_FWD' 'mangle PREROUTING XIOH_MARK' 'nat PREROUTING XIOH_DNS' 'nat POSTROUTING XIOH_NAT'; do
  set -- $pair
  while ipt -t "$1" -C "$2" -j "$3" 2>/dev/null; do ipt -t "$1" -D "$2" -j "$3"; done
  ipt -t "$1" -F "$3" 2>/dev/null || true; ipt -t "$1" -X "$3" 2>/dev/null || true
 done
 for pair in 'FORWARD XIOH_V6' 'INPUT XIOH_V6DNS'; do
  set -- $pair
  while ip6 -C "$1" -j "$2" 2>/dev/null; do ip6 -D "$1" -j "$2"; done
  ip6 -F "$2" 2>/dev/null || true; ip6 -X "$2" 2>/dev/null || true
 done
 ip -4 rule del pref 10900 fwmark 0x1000000/0x1000000 lookup 24680 2>/dev/null || true
 ip -4 route flush table 24680 2>/dev/null || true
 if command -v settings >/dev/null && [ -f "$state/offload-before" ]; then
  old=$(cat "$state/offload-before"); if [ "$old" = null ]; then settings delete global tether_offload_disabled >/dev/null; else settings put global tether_offload_disabled "$old"; fi
 fi
 rm -f "$state/downstream" "$state/owner" "$state/offload-before"; rmdir "$state"
 exit 0
fi
[ "$mode" = enable ] || exit 78
valid_iface "$down" || exit 78
[ "$vpn" = - ] || valid_iface "$vpn" || exit 78
[ "$down" != "$vpn" ] || exit 78
ip link show dev "$down" >/dev/null
if [ ! -d "$state" ]; then
 # Refuse collisions before touching routing or foreign firewall state.
 [ -z "$(ip -4 rule show | sed -n '/^10900:/p')" ] || { echo RULE_CONFLICT; exit 79; }
 [ -z "$(ip -4 route show table 24680 2>/dev/null)" ] || { echo TABLE_CONFLICT; exit 79; }
 for pair in 'filter XIOH_FWD' 'mangle XIOH_MARK' 'nat XIOH_DNS' 'nat XIOH_NAT'; do
  set -- $pair; if ipt -t "$1" -S "$2" >/dev/null 2>&1; then echo CHAIN_CONFLICT; exit 79; fi
 done
 for chain in XIOH_V6 XIOH_V6DNS; do if ip6 -S "$chain" >/dev/null 2>&1; then echo CHAIN_CONFLICT; exit 79; fi; done
 mkdir -m 700 "$state"; echo xio-sharing-v1 > "$state/owner"; printf '%s\n' "$down" > "$state/downstream"
 if command -v settings >/dev/null; then
  settings get global tether_offload_disabled > "$state/offload-before"
  settings put global tether_offload_disabled 1
 fi
 # Install drop guards before permitting or marking any forwarded client traffic.
 ipt -N XIOH_FWD; ipt -A XIOH_FWD -i "$down" -j DROP; ipt -I FORWARD 1 -j XIOH_FWD
 ip6 -N XIOH_V6; ip6 -A XIOH_V6 -i "$down" -j DROP; ip6 -I FORWARD 1 -j XIOH_V6
 ip6 -N XIOH_V6DNS
 for proto in udp tcp; do ip6 -A XIOH_V6DNS -i "$down" -p "$proto" --dport 53 -j DROP; done
 ip6 -I INPUT 1 -j XIOH_V6DNS
 ip -4 route add unreachable default table 24680 metric 32760
 ip -4 rule add pref 10900 fwmark 0x1000000/0x1000000 lookup 24680
 ipt -t mangle -N XIOH_MARK; ipt -t mangle -A XIOH_MARK -i "$down" -j MARK --set-xmark 0x1000000/0x1000000
 ipt -t mangle -I PREROUTING 1 -j XIOH_MARK
 ipt -t nat -N XIOH_DNS
 for proto in udp tcp; do ipt -t nat -A XIOH_DNS -i "$down" -p "$proto" --dport 53 -j DNAT --to-destination 9.9.9.9:53; done
 ipt -t nat -I PREROUTING 1 -j XIOH_DNS
 ipt -t nat -N XIOH_NAT; ipt -t nat -I POSTROUTING 1 -j XIOH_NAT
else
 [ "$(cat "$state/downstream")" = "$down" ] || { echo INTERFACE_CHANGED; exit 79; }
 # Restore missing hooks after ordinary netd rule refreshes. Never flush a live guard.
 for pair in 'filter FORWARD XIOH_FWD' 'mangle PREROUTING XIOH_MARK' 'nat PREROUTING XIOH_DNS' 'nat POSTROUTING XIOH_NAT'; do
  set -- $pair; ipt -t "$1" -C "$2" -j "$3" 2>/dev/null || ipt -t "$1" -I "$2" 1 -j "$3"
 done
 ip6 -C FORWARD -j XIOH_V6 2>/dev/null || ip6 -I FORWARD 1 -j XIOH_V6
 ip6 -C INPUT -j XIOH_V6DNS 2>/dev/null || ip6 -I INPUT 1 -j XIOH_V6DNS
fi
# Recover the marked rule if netd removed it, but refuse a foreign replacement.
rule=$(ip -4 rule show | sed -n '/^10900:/p')
if [ -z "$rule" ]; then ip -4 rule add pref 10900 fwmark 0x1000000/0x1000000 lookup 24680
else case "$rule" in *'fwmark 0x1000000/0x1000000 lookup 24680'*) :;; *) echo RULE_CONFLICT; exit 79;; esac; fi
# A permanent unreachable route prevents fall-through to the cellular uplink.
ip -4 route replace unreachable default table 24680 metric 32760
ip -4 route del default table 24680 metric 10 2>/dev/null || true
if [ "$vpn" != - ]; then
 ip link show dev "$vpn" >/dev/null
 ipt -C XIOH_FWD -i "$down" -o "$vpn" -j ACCEPT 2>/dev/null || ipt -I XIOH_FWD 1 -i "$down" -o "$vpn" -j ACCEPT
 ipt -C XIOH_FWD -i "$vpn" -o "$down" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ipt -I XIOH_FWD 1 -i "$vpn" -o "$down" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 ipt -t nat -C XIOH_NAT -o "$vpn" -m mark --mark 0x1000000/0x1000000 -j MASQUERADE 2>/dev/null || ipt -t nat -A XIOH_NAT -o "$vpn" -m mark --mark 0x1000000/0x1000000 -j MASQUERADE
 ip -4 route add default dev "$vpn" table 24680 metric 10
fi
printf 'XIO_SHARING_OK\n'
