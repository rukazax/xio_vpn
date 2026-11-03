#!/bin/sh
# XIO Cascade: L3 tunnel bridge(IPv4) -> exit(IPv6-only) over the provider IPv4 SSH proxy.
#
# The script owns tun0: it removes a stale device first, waits for the new one while
# watching the ssh child (a refused connection must fail fast, not after a minute),
# and keeps a watchdog that re-asserts the device and the default route. A link-down
# wipes the route while ssh stays alive, so systemd alone cannot notice it.
#
# XIO builds its per-tunnel IPv6 firewall rules from the IPv6 default route at the
# moment the tunnel starts. At boot the tunnel is usually up after the VPN units, so
# they see no route and skip those rules; the same reason makes a re-apply necessary
# after every reconnect. The hook below re-runs the idempotent dualstack apply.
set -eu
PROXY=${XIO_CASCADE_PROXY:-vps-721137.ssh.vps1euro.fr}
PORT=${XIO_CASCADE_PORT:-9046}
KEY=${XIO_CASCADE_KEY:-/root/.ssh/id_ed25519_cascade}
BRIDGE_ADDR=fd00:201::1/126
EXIT_ADDR=fd00:201::2/126
EXIT_GW=fd00:201::2
DUALSTACK=/usr/local/lib/xio-managed/dualstack.py

reapply_v6() {
  [ -f "$DUALSTACK" ] && python3 "$DUALSTACK" apply >/dev/null 2>&1 || true
}

ip link del tun0 2>/dev/null || true
ssh -i "$KEY" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -w 0:0 \
  root@"$PROXY" "pkill -f '^sleep infinity$' 2>/dev/null || true; ip addr replace $EXIT_ADDR dev tun0; ip link set tun0 mtu 1400 up; exec sleep infinity" &
child=$!

i=0
while [ "$i" -lt 60 ]; do
  if ! kill -0 "$child" 2>/dev/null; then
    echo "xio-cascade: ssh exited before tun0 appeared" >&2
    exit 1
  fi
  ip link show tun0 >/dev/null 2>&1 && break
  sleep 1
  i=$((i + 1))
done
# 1400 matches the provider uplink; 1500 caused oversized packets on the exit.
ip addr replace "$BRIDGE_ADDR" dev tun0
ip link set tun0 mtu 1400 up
ip -6 route replace default via "$EXIT_GW" dev tun0
reapply_v6

# Watchdog: re-assert the route when the link flapped, leave when ssh is gone so
# Restart=always rebuilds the tunnel from scratch.
while kill -0 "$child" 2>/dev/null; do
  sleep 10
  if ! ip -6 route show default dev tun0 2>/dev/null | grep -q "via $EXIT_GW"; then
    ip link set tun0 mtu 1400 up 2>/dev/null || true
    ip addr replace "$BRIDGE_ADDR" dev tun0 2>/dev/null || true
    ip -6 route replace default via "$EXIT_GW" dev tun0 2>/dev/null || true
    reapply_v6
  fi
done
wait "$child" 2>/dev/null || true
exit 1
