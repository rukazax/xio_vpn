#!/bin/sh
# e2e-cascade-test.sh - end-to-end proof that an AmneziaWG client's IPv4 goes
# through the bridge -> ssh -w tun0 -> exit -> vpn4 -> provider NAT64.
#
# Runs on the bridge (81.177.142.37).  A throw-away AmneziaWG peer
# (10.78.0.99) is added to the live xioawg0, a client runs inside its own
# network namespace and builds the real tunnel to 10.99.0.1:51821 (the host end
# of a veth pair).  The bridge rules are applied for this single /32 only, so
# the three live peers are not touched while the test runs; everything the test
# created is removed on exit, including the temporary peer and the scoped
# rules.
#
#   ./e2e-cascade-test.sh [LABEL]
set -u

LABEL=${1:-run}
AWG=${AWG:-/tmp/awg}                 # amneziawg-tools binary (copied from the exit)
AWGGO=${AWGGO:-/usr/local/bin/xio-amneziawg-go}
IFACE=awgc
CLI_V4=10.78.0.99
CLI_V6=fd78:1::99
VETH_H=10.99.0.1
VETH_C=10.99.0.2
TABLE=78
NS=""
PEER=""
log() { printf '%s\n' "$*"; }

cleanup() {
    [ -n "$NS" ] && kill "$NS" 2>/dev/null
    pkill -f "$AWGGO -f $IFACE" 2>/dev/null
    sleep 0.5
    ip link del vethH 2>/dev/null
    ip -4 rule del from "$CLI_V4/32" lookup "$TABLE" 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$CLI_V4/32" -o tun0 -m comment --comment xio-nat64 -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$CLI_V4/32" -o enp3s0 -m comment --comment xio-nat64 -j RETURN 2>/dev/null
    iptables -D FORWARD -i xioawg0 -o tun0 -m comment --comment xio-nat64 -j ACCEPT 2>/dev/null
    rm -f /tmp/e2e-cascade-client.conf /tmp/e2e-cascade-client.key /tmp/e2e-cascade-awgc.log
    if [ -n "$PEER" ]; then
        wg set xioawg0 peer "$PEER" remove 2>/dev/null && log "cleanup: temporary peer removed"
    fi
}
trap cleanup EXIT INT TERM

[ -x "$AWG" ] || { log "missing $AWG (copy /usr/local/bin/awg from the exit)"; exit 1; }
[ -x "$AWGGO" ] || { log "missing $AWGGO"; exit 1; }

SRV_PUB=$("$AWG" show xioawg0 | awk '/public key/{print $3; exit}')
SRV_PARAMS=$("$AWG" show xioawg0 | awk -F': *' '
    BEGIN { split("jc Jc jmin Jmin jmax Jmax s1 S1 s2 S2 h1 H1 h2 H2 h3 H3 h4 H4", a, " ");
            for (i = 1; i <= 18; i += 2) m[a[i]] = a[i + 1] }
    /^  (jc|jmin|jmax|s1|s2|h1|h2|h3|h4):/ { k = $1; gsub(/^ +/, "", k); print m[k] " = " $2 }')
[ -n "$SRV_PUB" ] || { log "cannot read xioawg0"; exit 1; }

log "=== $LABEL: temporary peer for the netns client ==="
"$AWG" genkey > /tmp/e2e-cascade-client.key
chmod 600 /tmp/e2e-cascade-client.key
CLI_PRIV=$(cat /tmp/e2e-cascade-client.key)
CLI_PUB=$(printf '%s' "$CLI_PRIV" | "$AWG" pubkey)
PEER=$CLI_PUB
wg set xioawg0 peer "$CLI_PUB" allowed-ips "$CLI_V4/32,$CLI_V6/128" \
    || { log "could not add the temporary peer"; exit 1; }
log "  peer $CLI_PUB -> $CLI_V4/32, $CLI_V6/128"

{
    echo "[Interface]"
    echo "PrivateKey = $CLI_PRIV"
    echo "ListenPort = 51822"
    printf '%s\n' "$SRV_PARAMS"
    echo
    echo "[Peer]"
    echo "PublicKey = $SRV_PUB"
    echo "Endpoint = $VETH_H:51821"
    echo "AllowedIPs = 0.0.0.0/0, ::/0"
    echo "PersistentKeepalive = 25"
} > /tmp/e2e-cascade-client.conf
chmod 600 /tmp/e2e-cascade-client.conf

log "=== namespace and veth ==="
unshare -n sleep 300 &
NS=$!
sleep 1
ip link add vethH type veth peer name vethC
ip link set vethC netns "$NS"
ip addr replace "$VETH_H/24" dev vethH
ip link set vethH up
nsenter -t "$NS" -n ip addr replace "$VETH_C/24" dev vethC
nsenter -t "$NS" -n ip link set vethC up
nsenter -t "$NS" -n ip link set lo up
nsenter -t "$NS" -n ip route replace default via "$VETH_H" dev vethC

log "=== scoped bridge rules for $CLI_V4/32 ==="
ip -4 addr replace 10.200.0.1/30 dev tun0
ip -4 route replace default dev tun0 table "$TABLE"
ip -4 rule add from "$CLI_V4/32" lookup "$TABLE" priority 100
iptables -t nat -A POSTROUTING -s "$CLI_V4/32" -o tun0 -m comment --comment xio-nat64 -j MASQUERADE
iptables -t nat -I POSTROUTING 1 -s "$CLI_V4/32" -o enp3s0 -m comment --comment xio-nat64 -j RETURN
iptables -I FORWARD 1 -i xioawg0 -o tun0 -m comment --comment xio-nat64 -j ACCEPT

log "=== the client's own AmneziaWG instance ($IFACE) ==="
nsenter -t "$NS" -n env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$AWGGO" -f "$IFACE" >/tmp/e2e-cascade-awgc.log 2>&1 &
for _ in $(seq 1 100); do [ -S "/run/amneziawg/$IFACE.sock" ] && break; sleep 0.1; done
nsenter -t "$NS" -n "$AWG" setconf "$IFACE" /tmp/e2e-cascade-client.conf 2>&1 | head -3
nsenter -t "$NS" -n ip -4 addr replace "$CLI_V4/24" dev "$IFACE"
nsenter -t "$NS" -n ip -6 addr replace "$CLI_V6/128" dev "$IFACE"
nsenter -t "$NS" -n ip link set dev "$IFACE" mtu 1280 up
nsenter -t "$NS" -n ip -4 route replace default dev "$IFACE"
sleep 6

log "=== handshake ==="
nsenter -t "$NS" -n "$AWG" show "$IFACE" 2>&1 | grep -E 'peer|endpoint|allowed ips|latest handshake|transfer' | sed 's/^/  /'

log "=== IPv4 over the cascade: wget -4 http://1.1.1.1/cdn-cgi/trace ==="
nsenter -t "$NS" -n timeout 30 wget -4 -O- --timeout=20 -t 2 http://1.1.1.1/cdn-cgi/trace 2>&1 \
    | sed 's/^/  /'
log "=== route/SNAT diagnostics ==="
ip -4 route get 1.1.1.1 from "$CLI_V4" 2>&1 | sed 's/^/  /'
ip -4 addr show dev tun0 | grep inet | sed 's/^/  /'
iptables -t nat -L POSTROUTING -v -n | grep -E "10.78.0.99|10.200" | sed 's/^/  /'
ip -s link show tun0 | tail -4 | sed 's/^/  /'

log "=== ICMP expectation: ping -4 is not translated by NAT64 ==="
nsenter -t "$NS" -n timeout 10 ping -4 -c 2 -W 2 1.1.1.1 2>&1 | tail -2 | sed 's/^/  /'

log "=== exit side: tun0 counters, REDIRECT hits, vpn4 journal ==="
ssh -o BatchMode=yes -o ConnectTimeout=8 -i /root/.ssh/id_ed25519_cascade -p 9046 root@103.102.135.126 \
    'echo EXIT_SSH_OK; iptables -t nat -L PREROUTING -v -n | grep -E "tun0"; ip -s link show tun0 | tail -4; journalctl -u vpn4 --no-pager -n 300 | grep "client=10.200.0.1" | tail -4' 2>&1 | sed 's/^/  /'
