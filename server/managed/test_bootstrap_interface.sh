#!/bin/sh
# Checks the device bootstrap.sh records for the catalog probe, and the unit's guard.
#
# The resolver lives inside bootstrap.sh, which refuses to run outside a supported host,
# so the block between the catalog-iface markers is extracted verbatim and exercised in
# a network namespace. Anything else would test a copy instead of the shipped lines.
#
# Requires root and unshare(1); without them the namespace cases are skipped and only
# the unit-line cases run.
set -u

here=$(cd "$(dirname "$0")" && pwd)
src="$here/bootstrap.sh"
unit="$here/../catalog/xio-catalog.service"
block=$(sed -n '/^# >>> catalog-iface >>>$/,/^# <<< catalog-iface <<<$/p' "$src")

if [ -z "$block" ]; then
  echo "FAIL: catalog-iface markers not found in $src" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' "$block" > "$work/block.sh"

checks=0
bad=0

say() { printf '%s\n' "$*"; }
ok() { checks=$((checks + 1)); say "ok   $1"; }
no() { checks=$((checks + 1)); bad=$((bad + 1)); say "FAIL $1"; }

# Cases that need a network namespace: setup snippet, then the resolver must print $2.
check_resolver() {
  label=$1
  want=$2
  setup=$3
  cat > "$work/case.sh" <<EOF
set -u
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
$setup
. "$work/block.sh"
xio_catalog_iface || true
EOF
  got=$(unshare -n -m sh "$work/case.sh" 2>/dev/null || true)
  if [ "$got" = "$want" ]; then
    ok "$label -> [$got]"
  else
    no "$label: want [$want], got [$got]"
  fi
}

if [ "$(id -u)" = 0 ] && command -v unshare >/dev/null 2>&1 && unshare -n -m true 2>/dev/null; then
  # The regression this block was rewritten for: an IPv6-only host with docker present
  # has no IPv4 route, and the old scan returned the bridge that sorts before ens3.
  check_resolver 'no route, docker bridges and ens3' ens3 '
    ip link add docker0 type bridge; ip link add br-1a2b3c4d5e6f type bridge
    ip link add virbr0 type bridge; ip link add ens3 type dummy
    ip link set ens3 up'

  check_resolver 'IPv6-only host, default route via ens3' ens3 '
    ip link add ens3 type dummy; ip link set ens3 up
    ip -6 addr add fd00::1/64 dev ens3
    ip -6 route add default via fd00::2 dev ens3'

  check_resolver 'IPv4 default route via enp1s0, bridge present' enp1s0 '
    ip link add enp1s0 type dummy; ip link set enp1s0 up
    ip -4 addr add 192.0.2.2/24 dev enp1s0
    ip route add default via 192.0.2.1 dev enp1s0
    ip link add br-1a2b3c4d5e6f type bridge'

  check_resolver 'default route through the tunnel, physical device exists' ens3 '
    ip link add xio0 type dummy; ip link set xio0 up
    ip -4 addr add 10.9.9.1/24 dev xio0
    ip route add default via 10.9.9.2 dev xio0
    ip link add ens3 type dummy; ip link set ens3 up'

  check_resolver 'bond device is a usable uplink' bond0 '
    ip link add bond0 type bond; ip link add br-1a2b3c4d5e6f type bridge'

  check_resolver 'nothing usable: loopback and a bridge only' '' '
    ip link add br-1a2b3c4d5e6f type bridge'
else
  say 'skip resolver cases: root and unshare(1) are required'
fi

# The guard and the argument assembly come from the unit file, not from a paraphrase.
guard=$(sed -n 's/^ExecStartPre=\/bin\/sh -c .//p' "$unit" | sed "s/'$//")
start=$(sed -n 's/^ExecStart=\/bin\/sh -c .//p' "$unit" | sed "s/'$//")

if [ -z "$guard" ] || [ -z "$start" ]; then
  no 'cannot read ExecStartPre/ExecStart from the unit'
else
  XIO_CATALOG_INTERFACE=eth99 sh -c "$guard" >/dev/null 2>&1
  [ $? -eq 78 ] && ok 'guard: missing device exits 78' || no "guard: missing device exit $?"

  XIO_CATALOG_INTERFACE=eth0 sh -c "$guard" >/dev/null 2>&1
  [ $? -eq 0 ] && ok 'guard: present device passes' || no "guard: present device exit $?"

  XIO_CATALOG_INTERFACE= sh -c "$guard" >/dev/null 2>&1
  [ $? -eq 0 ] && ok 'guard: empty means do not bind, not a failure' || no "guard: empty exit $?"

  stub=$(printf '%s' "$start" | sed 's|/usr/bin/python3|/bin/echo|')
  args=$(XIO_CATALOG_INTERFACE=ens3 sh -c "$stub")
  case $args in
    *'--interface ens3'*) ok 'start: binds to the configured device' ;;
    *) no "start: expected --interface ens3, got [$args]" ;;
  esac
  args=$(XIO_CATALOG_INTERFACE= sh -c "$stub")
  case $args in
    *--interface*) no "start: empty must not bind, got [$args]" ;;
    *) ok 'start: empty leaves the probe unbound' ;;
  esac
fi

sh -n "$src" || no 'bootstrap.sh does not parse under sh -n'

say "checks=$checks failures=$bad"
[ "$bad" -eq 0 ]
