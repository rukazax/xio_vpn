#!/bin/sh
# XIO Cascade: L3 tunnel bridge(IPv4) -> exit(IPv6-only) over the provider IPv4 SSH proxy.
# The device is owned by this script: it is removed first so a restart can never
# configure an old tun0 that the previous ssh session still holds.
set -eu
PROXY=${XIO_CASCADE_PROXY:-vps-721137.ssh.vps1euro.fr}
PORT=${XIO_CASCADE_PORT:-9046}
KEY=/root/.ssh/id_ed25519_cascade
BRIDGE_ADDR=fd00:201::1/126
EXIT_ADDR=fd00:201::2/126
ip link del tun0 2>/dev/null || true
ssh -i "$KEY" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -w 0:0 \
  root@"$PROXY" "ip addr replace $EXIT_ADDR dev tun0; ip link set tun0 up; exec sleep infinity" &
child=$!
for _ in $(seq 1 60); do
  ip link show tun0 >/dev/null 2>&1 && break
  sleep 1
done
ip addr replace "$BRIDGE_ADDR" dev tun0
ip link set tun0 up
ip -6 route replace default via fd00:201::2 dev tun0
wait "$child"
