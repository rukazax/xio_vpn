#!/usr/bin/env bash
# Standalone WireGuard cascade in isolated containers. NOT native XIO profile integration.
set -euo pipefail
umask 077
export LC_ALL=C
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
ROLE= EXIT_HOST= EXIT_PUBKEY= PEER_PUBKEY= TOKEN_FILE= EXIT_FINGERPRINT=
EXIT_FAMILY=ipv6 ROUTING=split PORT=9443 CLIENT_PORT=51820 WEB_PORT=8443
DATA_DIR=/var/lib/xio-cascade DRY_RUN=0 RECREATE=0 RUNTIME=
IMAGE=xio-cascade:local NETWORK=xio-cascade
fail() { printf 'cascade-install: %s\n' "$*" >&2; exit 2; }
need() { [ "$#" -ge 2 ] || fail "$1 needs a value"; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --role) need "$@"; ROLE=$2; shift 2;;
        --exit-host) need "$@"; EXIT_HOST=$2; shift 2;;
        --exit-pubkey) need "$@"; EXIT_PUBKEY=$2; shift 2;;
        --exit-fingerprint) need "$@"; EXIT_FINGERPRINT=$2; shift 2;;
        --peer-pubkey) need "$@"; PEER_PUBKEY=$2; shift 2;;
        --exit-family) need "$@"; EXIT_FAMILY=$2; shift 2;;
        --routing) need "$@"; ROUTING=$2; shift 2;;
        --port) need "$@"; PORT=$2; shift 2;;
        --client-port) need "$@"; CLIENT_PORT=$2; shift 2;;
        --web-port) need "$@"; WEB_PORT=$2; shift 2;;
        --token-file) need "$@"; TOKEN_FILE=$2; shift 2;;
        --data-dir) need "$@"; DATA_DIR=$2; shift 2;;
        --dry-run) DRY_RUN=1; shift;;
        --recreate) RECREATE=1; shift;;
        --enable-whitelists) fail 'automatic host timers are not supported by this bounded installer; run whitelist-update.sh manually for split mode';;
        --help|-h) cat <<'EOF'
cascade-install.sh --role exit|bridge|both [options]
  --exit-family ipv4|ipv6  exit source/transport family (default ipv6)
  --exit-host IP           bridge: bare literal; family inferred strictly
  --exit-pubkey BASE64     bridge: real exit public key, required
  --peer-pubkey BASE64     exit: register bridge public key (else manual step)
  --routing all|split     bridge IPv4 routing (default split); IPv6 always tunnel
  --exit-fingerprint SHA  optional pin, sha256:<hex>
  --data-dir PATH         persistent state (default /var/lib/xio-cascade)
  --token-file PATH       same PSK secret on both sides
  --port N                exit UDP (9443)
  --client-port N         bridge WireGuard UDP (51820)
  --web-port N            accepted legacy metadata; NO web service is installed
  --dry-run               validate/render plan, do not create files/runtime objects
  --recreate              replace existing cascade containers after config update
No host packages installed. Requires existing Docker/Podman and kernel WireGuard.
Native RIVET/AWG profiles are NOT automatically connected to this standalone wg1.
EOF
            exit 0;;
        *) fail "unknown argument: $1 (use separated --option value syntax)";;
    esac
done
case "$ROLE" in exit|bridge|both) ;; *) fail '--role exit|bridge|both required';; esac
case "$EXIT_FAMILY" in ipv4|ipv6) ;; *) fail 'invalid --exit-family';; esac
case "$ROUTING" in all|split) ;; *) fail 'invalid --routing';; esac
command -v python3 >/dev/null || fail 'python3 required'
# No docker/runtime/filesystem mutation before this entire preflight succeeds.
python3 - "$PORT" "$CLIENT_PORT" "$WEB_PORT" "$EXIT_PUBKEY" "$PEER_PUBKEY" "$DATA_DIR" <<'PY'
import base64, os, re, sys
for p in sys.argv[1:4]:
    if not re.fullmatch('[0-9]{1,5}', p) or not 1 <= int(p) <= 65535: raise SystemExit('invalid port')
for k in sys.argv[4:6]:
    if k and (len(k) != 44 or len(base64.b64decode(k, validate=True)) != 32): raise SystemExit('invalid public key')
p = sys.argv[6]
if not p.startswith('/') or os.path.realpath(p) == '/' or any(c in p for c in '\r\n:,'):
    raise SystemExit('data-dir must be absolute, non-root, without newline, colon or comma')
PY
if [ -n "$EXIT_HOST" ]; then
    HOST_FAMILY=$(python3 "$SCRIPT_DIR/cascade-config.py" --validate-host "$EXIT_HOST")
else HOST_FAMILY=; fi
if [ "$ROLE" != exit ]; then
    [ -n "$EXIT_HOST" ] || fail '--exit-host required'
    [ "$ROLE" != both ] || [ "$HOST_FAMILY" = "$EXIT_FAMILY" ] || fail 'both: exit host/family mismatch'
    [ "$ROLE" != bridge ] || [ -n "$EXIT_PUBKEY" ] || fail '--exit-pubkey required'
fi
COMMON=(--port "$PORT")
[ -z "$TOKEN_FILE" ] || COMMON+=(--token-file "$TOKEN_FILE")
EXIT_ARGS=(--data-dir "$DATA_DIR/exit" --exit-family "$EXIT_FAMILY" --routing "$ROUTING" "${COMMON[@]}")
[ -z "$PEER_PUBKEY" ] || EXIT_ARGS+=(--add-peer "$PEER_PUBKEY")
BRIDGE_ARGS=(--data-dir "$DATA_DIR/bridge" --exit-host "$EXIT_HOST" --client-port "$CLIENT_PORT" --web-port "$WEB_PORT" --routing "$ROUTING" "${COMMON[@]}")
[ -z "$EXIT_FINGERPRINT" ] || BRIDGE_ARGS+=(--exit-fingerprint "$EXIT_FINGERPRINT")
# Validate roles using renderer dry-run, including source-family and PSK checks.
if [ "$ROLE" != bridge ]; then bash "$SCRIPT_DIR/cascade-exit-setup.sh" "${EXIT_ARGS[@]}" --dry-run; fi
if [ "$ROLE" != exit ]; then
    PREFLIGHT_KEY=${EXIT_PUBKEY:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
    bash "$SCRIPT_DIR/cascade-bridge-setup.sh" "${BRIDGE_ARGS[@]}" --exit-pubkey "$PREFLIGHT_KEY" --dry-run
fi
if [ "$DRY_RUN" -eq 1 ]; then
    printf 'Plan: isolated dual-stack network %s, kernel WG, persistent data %s; no web server\n' "$NETWORK" "$DATA_DIR" >&2
    exit 0
fi
[ "$(id -u)" -eq 0 ] || fail 'root required'
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null && "$candidate" info >/dev/null 2>&1; then RUNTIME=$candidate; break; fi
done
[ -n "$RUNTIME" ] || fail 'existing working Docker/Podman required (not installed automatically)'
# Persist the verified helpers before bootstrap's private temporary directory is removed.
mkdir -p -- "$DATA_DIR/payload"
chmod 700 "$DATA_DIR" "$DATA_DIR/payload"
for source in "$SCRIPT_DIR"/*; do
    [ -f "$source" ] || continue
    [ "$source" != "$DATA_DIR/payload/${source##*/}" ] || continue
    install -m 600 -- "$source" "$DATA_DIR/payload/${source##*/}"
done
SCRIPT_DIR="$DATA_DIR/payload"
"$RUNTIME" build --pull=false -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
if "$RUNTIME" network inspect "$NETWORK" >/dev/null 2>&1; then
    [ "$("$RUNTIME" network inspect -f '{{.EnableIPv6}}' "$NETWORK")" = true ] || fail 'existing cascade network has IPv6 disabled; migrate explicitly, not silently reused'
else
    "$RUNTIME" network create --driver bridge --ipv6 --subnet fd42:ca5c:ade::/64 "$NETWORK"
fi
if [ "$ROLE" != bridge ]; then bash "$SCRIPT_DIR/cascade-exit-setup.sh" "${EXIT_ARGS[@]}"; fi
if [ "$ROLE" = both ]; then
    EXIT_PUBKEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pubkey"])' "$DATA_DIR/exit/state.json")
fi
if [ "$ROLE" != exit ]; then
    bash "$SCRIPT_DIR/cascade-bridge-setup.sh" "${BRIDGE_ARGS[@]}" --exit-pubkey "$EXIT_PUBKEY"
    if [ ! -f "$DATA_DIR/whitelists.conf" ]; then install -m 600 "$SCRIPT_DIR/whitelists.conf" "$DATA_DIR/whitelists.conf"; fi
fi
if [ "$ROLE" = both ]; then
    PEER_PUBKEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pubkey"])' "$DATA_DIR/bridge/state.json")
    bash "$SCRIPT_DIR/cascade-exit-setup.sh" "${EXIT_ARGS[@]}" --add-peer "$PEER_PUBKEY"
fi
start() {
    local role=$1 name=xio-cascade-$1
    if "$RUNTIME" container inspect "$name" >/dev/null 2>&1; then
        [ "$RECREATE" -eq 1 ] || fail "$name exists; use --recreate to apply regenerated config"
        "$RUNTIME" rm -f "$name"
    fi
    local args=(run -d --name "$name" --restart unless-stopped --network "$NETWORK" --cap-add NET_ADMIN
        --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1
        -v "$DATA_DIR/$role:/data" -e "CASCADE_ROLE=$role")
    if [ "$role" = exit ]; then args+=(-p "$PORT:$PORT/udp"); else args+=(-p "$CLIENT_PORT:$CLIENT_PORT/udp"); fi
    "$RUNTIME" "${args[@]}" "$IMAGE"
}
[ "$ROLE" = bridge ] || start exit
[ "$ROLE" = exit ] || start bridge
printf '%s\n' 'Configuration installed, NOT an egress acceptance test. Register BOTH public keys; native XIO profiles are NOT attached.' >&2
if [ "$ROLE" = bridge ]; then
    printf 'On exit: bash <persistent-payload>/cascade-exit-setup.sh --exit-family <family> --data-dir <persistent-exit-data> --add-peer <bridge-public-key>; then recreate/restart exit container.\n' >&2
fi
