#!/bin/sh
# e2e-netns-test.sh - end-to-end proof of the vpn4 path with a real AWG client.
#
# A throw-away AmneziaWG peer is added to the live interface (10.90.0.3), a client
# runs inside its own network namespace, builds the tunnel to the real server
# endpoint and then asks for IPv4: HTTP through the vpn4 bridge and a DNS query
# to the tunnel's resolver address.  Everything the test created is removed on
# exit, including the temporary peer; the live peers are never touched.
#
#   ./e2e-netns-test.sh [LABEL]
#
# NOTE: this script must not write /etc/resolv.conf - a network namespace shares
# the mount namespace, so such a write would reconfigure the *server's* resolver.
set -u

LABEL=${1:-run}
AWG=/usr/local/bin/awg
AWGGO=/usr/local/bin/awg-go-3.1
HOST_V6=$(ip -6 addr show dev eth0 scope global | awk '/inet6/{print $2}' | cut -d/ -f1 | head -1)
SRV_PUB=$(cat /etc/awg-owner/server.pub)
DIR=/etc/awg-owner
IFACE=awgc
CLI_V4=10.90.0.3
CLI_V6=fd90:1::3
NS=""
PEER=""

log() { printf '%s\n' "$*"; }

cleanup() {
    [ -n "$NS" ] && kill "$NS" 2>/dev/null
    pkill -f "$AWGGO -f $IFACE" 2>/dev/null
    sleep 0.5
    ip link del vethH 2>/dev/null
    ip6tables -D FORWARD -i vethH -o eth0 -j ACCEPT 2>/dev/null
    ip6tables -D FORWARD -i eth0 -o vethH -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    ip6tables -t nat -D POSTROUTING -s fd91::/64 -o eth0 -j MASQUERADE 2>/dev/null
    rm -f "/run/amneziawg/$IFACE.sock" /tmp/e2e-client.conf /tmp/e2e-client.key /tmp/e2e-awgc.log
    if [ -n "$PEER" ]; then
        if $AWG set awg0 peer "$PEER" remove 2>/dev/null; then
            log "cleanup: temporary peer removed"
        else
            # fall back to the authoritative config, which lists only live peers
            $AWG setconf awg0 /etc/awg-owner/awg0.setconf.conf 2>/dev/null \
                && log "cleanup: awg0 restored from awg0.setconf.conf"
        fi
    fi
}
trap cleanup EXIT INT TERM

log "=== $LABEL: temporary peer for the netns client ==="
$AWG genkey > /tmp/e2e-client.key 2>/dev/null || { log "awg genkey failed"; exit 1; }
chmod 600 /tmp/e2e-client.key
CLI_PRIV=$(cat /tmp/e2e-client.key)
CLI_PUB=$(printf '%s' "$CLI_PRIV" | $AWG pubkey)
PEER=$CLI_PUB
$AWG set awg0 peer "$CLI_PUB" allowed-ips "$CLI_V4/32,$CLI_V6/128" \
    || { log "could not add the temporary peer"; exit 1; }
log "  peer $CLI_PUB -> $CLI_V4/32, $CLI_V6/128"

cat > /tmp/e2e-client.conf <<EOF
[Interface]
PrivateKey = $CLI_PRIV
ListenPort = 51831
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 30
S2 = 40
H1 = 1122334455
H2 = 1277335533
H3 = 1443302144
H4 = 1777000123
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20

[Peer]
PublicKey = $SRV_PUB
Endpoint = [$HOST_V6]:51830
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
chmod 600 /tmp/e2e-client.conf

log "=== namespace and veth ==="
# a previous aborted run may have left the pair behind, and the names would clash
ip link del vethH 2>/dev/null
ip link del vethC 2>/dev/null
unshare -n sleep 240 &
NS=$!
sleep 1
ip link add vethH type veth peer name vethC
ip link set vethC netns "$NS"
ip -6 addr replace fd91::1/64 dev vethH
ip link set vethH up
nsenter -t "$NS" -n ip -6 addr replace fd91::2/64 dev vethC
nsenter -t "$NS" -n ip link set vethC up
nsenter -t "$NS" -n ip link set lo up
nsenter -t "$NS" -n ip -6 route replace default via fd91::1 dev vethC
ip6tables -I FORWARD -i vethH -o eth0 -j ACCEPT
ip6tables -I FORWARD -i eth0 -o vethH -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -t nat -I POSTROUTING -s fd91::/64 -o eth0 -j MASQUERADE
sysctl -q -w net.ipv6.conf.all.forwarding=1

log "=== the client's own AmneziaWG instance ($IFACE) ==="
nsenter -t "$NS" -n env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$AWGGO" -f "$IFACE" >/tmp/e2e-awgc.log 2>&1 &
for _ in $(seq 1 100); do [ -S "/run/amneziawg/$IFACE.sock" ] && break; sleep 0.1; done
nsenter -t "$NS" -n "$AWG" setconf "$IFACE" /tmp/e2e-client.conf 2>&1 | head -3
nsenter -t "$NS" -n ip -4 addr replace "$CLI_V4/24" dev "$IFACE"
nsenter -t "$NS" -n ip -6 addr replace "$CLI_V6/128" dev "$IFACE"
nsenter -t "$NS" -n ip link set dev "$IFACE" mtu 1280 up
nsenter -t "$NS" -n ip -6 route replace "$HOST_V6/128" via fd91::1 dev vethC
nsenter -t "$NS" -n ip -6 route replace default dev "$IFACE"
nsenter -t "$NS" -n ip -4 route replace default dev "$IFACE"
sleep 6

log "=== handshake ==="
nsenter -t "$NS" -n "$AWG" show "$IFACE" 2>&1 | grep -E 'peer|endpoint|allowed ips|latest handshake|transfer' | sed 's/^/  /'

log "=== IPv4 over the tunnel: wget -4 http://1.1.1.1/cdn-cgi/trace ==="
nsenter -t "$NS" -n timeout 30 wget -4 -O- --timeout=20 -t 2 http://1.1.1.1/cdn-cgi/trace 2>&1 \
    | grep -E '^(ip|loc|colo|warp)=' | sed 's/^/  /'

log "=== IPv4 DNS relay: dig @10.90.0.1 example.com ==="
nsenter -t "$NS" -n timeout 15 dig @10.90.0.1 +time=5 +tries=1 example.com A 2>&1 \
    | grep -E 'status:|ANSWER SECTION|IN\s+A' | head -4 | sed 's/^/  /'

log "=== ICMP is deliberately not provided: ping -4 must fail ==="
nsenter -t "$NS" -n timeout 12 ping -4 -c 2 -W 2 1.1.1.1 2>&1 | tail -3 | sed 's/^/  /'

log "=== vpn4 journal for this client ($CLI_V4) ==="
journalctl -u vpn4 --no-pager -n 400 2>/dev/null | grep -- "client=$CLI_V4" | tail -6 | sed 's/^/  /'
journalctl -u vpn4 --no-pager -n 400 2>/dev/null | grep -- "dns client=$CLI_V4" | tail -3 | sed 's/^/  /'
