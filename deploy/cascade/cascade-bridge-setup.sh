#!/usr/bin/env bash
# XIO Cascade — настройка bridge-сервера (IPv4).
#
# Что делает:
#   * проверяет IPv4 и санити (loopback, приватизацию, отсутствие конфликта портов);
#   * генерирует ключи WireGuard идемпотентно;
#   * поднимает два интерфейса:
#       wg0 — защищённый туннель до exit (UDP поверх IPv6, endpoint [exit]:port);
#       wg1 — приём устройств (UDP client-port, 10.202.0.0/24 + fd42:201::/64);
#   * включает NAT44 для «прямого» IPv4-трафика;
#   * включает split-tunneling: только адреса из nft-сета xio_whitelist4
#     уходят в туннель (fwmark + таблица 200), остальное идёт напрямую;
#   * весь IPv6 от устройств уходит в туннель всегда (у bridge нет IPv6-аплинка);
#   * печатает JSON-сводку: pubkey для регистрации на exit и путь к web-интерфейсу.
#
# Пример:
#   ./cascade-bridge-setup.sh --exit-host 2a01:4f8::10 --exit-pubkey <b64> \
#       --add-client <pubkey устройства> --client-ip 10.202.0.10
#
# Запускается и вручную, и из cascade-install.sh.

set -eu
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1

DATA_DIR="$SCRIPT_DIR/data/bridge"
EXIT_HOST=""
EXIT_PUBKEY=""
EXIT_FINGERPRINT=""
PORT=9443
CLIENT_PORT=51820
TUN_ADDR="10.201.0.2/24"
EXIT_TUN_ADDR="10.201.0.1"
CLIENT_NET4="10.202.0.0/24"
CLIENT_NET6="fd42:201::/64"
CONTAINER_DATA="/data"
CLIENT_IP=""
PSK_FILE=""
ADD_CLIENT=""
REMOVE_CLIENT=""
IMAGE="xio-cascade:local"
RUNTIME=""
DRY_RUN=0
BRIDGE_IP4=""
WEB_PORT=8443

log() { printf '[bridge] %s\n' "$*" >&2; }
warn() { printf '[bridge] warning: %s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }

cleanup() {
    if [ -n "${DATA_DIR:-}" ] && [ -d "$DATA_DIR" ]; then
        rm -f -- "$DATA_DIR/private.key.tmp" "$DATA_DIR/public.key.tmp" \
            "$DATA_DIR/wg0.conf.tmp" "$DATA_DIR/wg1.conf.tmp" "$DATA_DIR/state.json.tmp" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
bridge-setup — настройка bridge-сервера XIO Cascade (IPv4 -> IPv6)

  --exit-host <ipv6>         публичный IPv6 exit-сервера (обязательно)
  --exit-pubkey <b64>        публичный ключ exit (обязательно)
  --exit-fingerprint <sha256:…>  запинить отпечаток exit и проверить его
  --data-dir <path>          каталог состояния (по умолчанию ./data/bridge)
  --port <p>                 UDP-порт туннеля до exit (по умолчанию 9443)
  --client-port <p>          UDP-порт приёма устройств (по умолчанию 51820)
  --tunnel-addr <cidr>       адрес bridge в туннеле (10.201.0.2/24)
  --exit-tunnel-addr <ip>    адрес exit в туннеле (10.201.0.1)
  --client-net4 <cidr>       IPv4-сеть устройств (10.202.0.0/24)
  --client-net6 <cidr>       ULA-сеть устройств (fd42:201::/64)
  --psk-file <path>          общий секрет (PresharedKey)
  --add-client <pubkey>      зарегистрировать устройство
  --client-ip <ip>           IPv4 устройства для --add-client (10.202.0.x)
  --remove-client <pubkey>   удалить устройство
  --image <tag>              образ для генерации ключей через контейнер
  --web-port <p>             TCP-порт web-интерфейса entry (по умолчанию 8443)
  --dry-run                  показать план, ничего не записывать
  -h, --help                 справка
EOF
}

need_arg() { [ "$#" -ge 2 ] || die "опция $1 требует значение"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --exit-host)         need_arg "$@"; EXIT_HOST=$2; shift 2 ;;
        --exit-host=*)       EXIT_HOST=${1#*=}; shift ;;
        --exit-pubkey)       need_arg "$@"; EXIT_PUBKEY=$2; shift 2 ;;
        --exit-pubkey=*)     EXIT_PUBKEY=${1#*=}; shift ;;
        --exit-fingerprint)  need_arg "$@"; EXIT_FINGERPRINT=$2; shift 2 ;;
        --exit-fingerprint=*) EXIT_FINGERPRINT=${1#*=}; shift ;;
        --data-dir)          need_arg "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*)        DATA_DIR=${1#*=}; shift ;;
        --port)              need_arg "$@"; PORT=$2; shift 2 ;;
        --port=*)            PORT=${1#*=}; shift ;;
        --client-port)       need_arg "$@"; CLIENT_PORT=$2; shift 2 ;;
        --client-port=*)     CLIENT_PORT=${1#*=}; shift ;;
        --tunnel-addr)       need_arg "$@"; TUN_ADDR=$2; shift 2 ;;
        --tunnel-addr=*)     TUN_ADDR=${1#*=}; shift ;;
        --exit-tunnel-addr)  need_arg "$@"; EXIT_TUN_ADDR=$2; shift 2 ;;
        --exit-tunnel-addr=*) EXIT_TUN_ADDR=${1#*=}; shift ;;
        --client-net4)       need_arg "$@"; CLIENT_NET4=$2; shift 2 ;;
        --client-net4=*)     CLIENT_NET4=${1#*=}; shift ;;
        --client-net6)       need_arg "$@"; CLIENT_NET6=$2; shift 2 ;;
        --client-net6=*)     CLIENT_NET6=${1#*=}; shift ;;
        --container-data-dir) need_arg "$@"; CONTAINER_DATA=$2; shift 2 ;;
        --psk-file)          need_arg "$@"; PSK_FILE=$2; shift 2 ;;
        --psk-file=*)        PSK_FILE=${1#*=}; shift ;;
        --add-client)        need_arg "$@"; ADD_CLIENT=$2; shift 2 ;;
        --add-client=*)      ADD_CLIENT=${1#*=}; shift ;;
        --client-ip)         need_arg "$@"; CLIENT_IP=$2; shift 2 ;;
        --client-ip=*)       CLIENT_IP=${1#*=}; shift ;;
        --remove-client)     need_arg "$@"; REMOVE_CLIENT=$2; shift 2 ;;
        --image)             need_arg "$@"; IMAGE=$2; shift 2 ;;
        --web-port)          need_arg "$@"; WEB_PORT=$2; shift 2 ;;
        --web-port=*)        WEB_PORT=${1#*=}; shift ;;
        --dry-run)           DRY_RUN=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        *) die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "нужны права root"
[ -n "$EXIT_HOST" ] || die "обязателен --exit-host <ipv6>"
case "$EXIT_HOST" in *:*) ;; *) die "--exit-host должен быть IPv6-адресом" ;; esac
[ -n "$EXIT_PUBKEY" ] || die "обязателен --exit-pubkey (его печатает установка на exit)"
[[ $EXIT_PUBKEY =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "--exit-pubkey не похож на ключ WireGuard (base64, 44 символа)"
case "$PORT" in ''|*[!0-9]*) die "--port должен быть числом" ;; esac
case "$CLIENT_PORT" in ''|*[!0-9]*) die "--client-port должен быть числом" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port вне диапазона"
[ "$CLIENT_PORT" -ge 1 ] && [ "$CLIENT_PORT" -le 65535 ] || die "--client-port вне диапазона"
[ "$PORT" != "$CLIENT_PORT" ] || die "--port и --client-port должны различаться"
case "$WEB_PORT" in ''|*[!0-9]*) die "--web-port должен быть числом" ;; esac
[ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || die "--web-port вне диапазона"

command -v sed >/dev/null 2>&1 || die "не найдена команда sed"

if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p -- "$DATA_DIR/clients"
    chmod 700 "$DATA_DIR" "$DATA_DIR/clients"
fi

# --- санити: IPv4 -----------------------------------------------------------
detect_ipv4() {
    local cand=""
    if command -v ip >/dev/null 2>&1; then
        cand=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1) || cand=""
        if [ -z "$cand" ]; then
            cand=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1) || cand=""
        fi
    fi
    printf '%s' "$cand"
}

BRIDGE_IP4=$(detect_ipv4)
if command -v ip >/dev/null 2>&1; then
    [ -n "$BRIDGE_IP4" ] || die "у хоста нет IPv4-адреса: bridge принимает устройства по IPv4"
    case "$BRIDGE_IP4" in
        127.*) die "IPv4 $BRIDGE_IP4 — loopback, устройства до bridge не дойдут" ;;
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            warn "IPv4 $BRIDGE_IP4 приватизированный: устройства должны быть в этой же сети либо нужен проброс UDP $CLIENT_PORT" ;;
        *) : ;;
    esac
    case "$EXIT_HOST" in
        fe80:*|fd*|fc*) warn "EXIT_HOST $EXIT_HOST — ULA/link-local: из интернета такой exit не достижим" ;;
        *) : ;;
    esac
    log "IPv4 bridge: $BRIDGE_IP4"
fi

# --- контейнерный fallback для wg ------------------------------------------
detect_runtime_quiet() {
    local c
    for c in docker podman; do
        if command -v "$c" >/dev/null 2>&1 && "$c" info >/dev/null 2>&1; then
            RUNTIME=$c
            return 0
        fi
    done
    return 1
}

wg_tool() {
    if command -v wg >/dev/null 2>&1; then
        wg "$@"
        return 0
    fi
    if [ -z "$RUNTIME" ] && detect_runtime_quiet; then :; fi
    [ -n "$RUNTIME" ] || die "нет ни wg, ни рабочего docker/podman: ключи сгенерировать нечем"
    "$RUNTIME" run --rm -i --network none --entrypoint wg "$IMAGE" "$@"
}

# --- ключи ------------------------------------------------------------------
PRIV="$DATA_DIR/private.key"
PUB="$DATA_DIR/public.key"
if [ -s "$PRIV" ] && [ -s "$PUB" ]; then
    log "ключи уже есть — использую существующие (идемпотентность)"
elif [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run: были бы сгенерированы $PRIV и $PUB"
else
    log "генерирую ключевую пару WireGuard"
    wg_tool genkey > "$PRIV.tmp"
    chmod 600 "$PRIV.tmp"
    wg_tool pubkey < "$PRIV.tmp" > "$PUB.tmp"
    chmod 644 "$PUB.tmp"
    mv -f -- "$PRIV.tmp" "$PRIV"
    mv -f -- "$PUB.tmp" "$PUB"
fi
PUBKEY=""
if [ -s "$PUB" ]; then PUBKEY=$(tr -d '\r\n' < "$PUB"); fi

# --- PresharedKey -----------------------------------------------------------
PSK_STATE="$DATA_DIR/preshared.key"
derive_psk() {
    local src=$1 norm=$2
    tr -d '\r\n' < "$src" > "$norm"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode())' < "$norm"
    elif command -v xxd >/dev/null 2>&1; then
        sha256sum "$norm" | awk '{print $1}' | xxd -r -p | base64 -w0
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -binary "$norm" | base64 -w0
    else
        return 1
    fi
}

if [ -n "$PSK_FILE" ]; then
    [ -f "$PSK_FILE" ] && [ -r "$PSK_FILE" ] || die "не читается --psk-file: $PSK_FILE"
    if [ "$DRY_RUN" -eq 0 ]; then
        token=$(tr -d '\r\n' < "$PSK_FILE")
        if [[ $token =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
            printf '%s\n' "$token" > "$PSK_STATE"
        else
            derive_psk "$PSK_FILE" "$PSK_STATE.norm" > "$PSK_STATE.tmp" \
                || die "нечем вывести PSK из файла секрета: нужен python3, xxd или openssl"
            rm -f -- "$PSK_STATE.norm"
            mv -f -- "$PSK_STATE.tmp" "$PSK_STATE"
        fi
        chmod 600 "$PSK_STATE"
    fi
    log "PresharedKey: используется файл секрета (значение не печатается)"
elif [ -s "$PSK_STATE" ]; then
    log "PresharedKey: взят ранее сохранённый $PSK_STATE"
fi
PSK=""
if [ -s "$PSK_STATE" ]; then PSK=$(tr -d '\r\n' < "$PSK_STATE"); fi

# --- устройства -------------------------------------------------------------
if [ -n "$ADD_CLIENT" ]; then
    [[ $ADD_CLIENT =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "--add-client: некорректный публичный ключ"
    [ -n "$CLIENT_IP" ] || die "--add-client требует --client-ip (например 10.202.0.10)"
    [[ $CLIENT_IP =~ ^10\.202\.0\.[0-9]{1,3}$ ]] || die "--client-ip вне $CLIENT_NET4: $CLIENT_IP"
    if [ "$DRY_RUN" -eq 0 ]; then
        printf '%s %s/32\n' "$ADD_CLIENT" "$CLIENT_IP" > "$DATA_DIR/clients/$ADD_CLIENT.conf"
        chmod 600 "$DATA_DIR/clients/$ADD_CLIENT.conf"
    fi
    log "устройство добавлено: ${ADD_CLIENT:0:8}… -> $CLIENT_IP"
fi
if [ -n "$REMOVE_CLIENT" ]; then
    if [ -f "$DATA_DIR/clients/$REMOVE_CLIENT.conf" ]; then
        rm -f -- "$DATA_DIR/clients/$REMOVE_CLIENT.conf"
        log "устройство удалено: ${REMOVE_CLIENT:0:8}…"
    fi
fi

# --- nft-скрипт bridge ------------------------------------------------------
NFT_SCRIPT="$DATA_DIR/nft-bridge.sh"
if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$NFT_SCRIPT" <<NFTEOF
#!/bin/sh
# Сгенерировано cascade-bridge-setup.sh. Не редактировать вручную.
# bridge: NAT44 для прямого трафика + split-tunneling по nft-сету xio_whitelist4.
set -u
ACTION=\${1:-up}
UPLINK=\${CASCADE_UPLINK_IF:-wg0}
CLIENTS=\${CASCADE_CLIENT_IF:-wg1}
CLIENT_NET4="$CLIENT_NET4"
CLIENT_NET6="$CLIENT_NET6"
MARK=1
TABLE4=200
TABLE6=201

sysctl_try() { command -v sysctl >/dev/null 2>&1 && sysctl -qw "\$1" 2>/dev/null || true; }

case "\$ACTION" in
up)
    sysctl_try net.ipv4.ip_forward=1
    sysctl_try net.ipv6.conf.all.forwarding=1
    nft list table inet xio_cascade >/dev/null 2>&1 || nft add table inet xio_cascade
    # набор белых списков (заполняется whitelist-update.sh)
    nft 'add set inet xio_cascade xio_whitelist4 { type ipv4_addr; flags interval; auto-merge; }' 2>/dev/null || true
    nft 'add chain inet xio_cascade prerouting { type filter hook prerouting priority mangle; }' 2>/dev/null || true
    nft 'add chain inet xio_cascade forward { type filter hook forward priority filter; }' 2>/dev/null || true
    nft 'add chain inet xio_cascade postrouting { type nat hook postrouting priority srcnat; }' 2>/dev/null || true
    nft flush chain inet xio_cascade prerouting
    nft flush chain inet xio_cascade forward
    nft flush chain inet xio_cascade postrouting

    # 1) только адреса из белого списка помечаются и уходят в туннель
    nft add rule inet xio_cascade prerouting iifname "\$CLIENTS" ip daddr @xio_whitelist4 meta mark set \$MARK
    # 2) NAT44 для «прямого» IPv4 (не в туннель)
    nft add rule inet xio_cascade postrouting ip saddr "\$CLIENT_NET4" oifname != "\$UPLINK" masquerade
    # 3) forward: устройства -> туннель, туннель -> устройства, остальное напрямую
    nft add rule inet xio_cascade forward iifname "\$CLIENTS" oifname "\$UPLINK" accept
    nft add rule inet xio_cascade forward iifname "\$UPLINK" oifname "\$CLIENTS" ct state established,related accept
    nft add rule inet xio_cascade forward iifname "\$CLIENTS" oifname != "\$UPLINK" accept
    nft add rule inet xio_cascade forward oifname "\$CLIENTS" ct state established,related accept

    # 4) policy routing: помеченное — в таблицу 200 (default dev wg0), IPv6 — всегда в туннель
    ip rule del fwmark \$MARK table \$TABLE4 2>/dev/null || true
    ip rule add fwmark \$MARK lookup \$TABLE4 2>/dev/null || true
    ip route replace default dev "\$UPLINK" table \$TABLE4
    ip -6 rule del from "\$CLIENT_NET6" table \$TABLE6 2>/dev/null || true
    ip -6 rule add from "\$CLIENT_NET6" lookup \$TABLE6 2>/dev/null || true
    ip -6 route replace default dev "\$UPLINK" table \$TABLE6 2>/dev/null || true
    echo "bridge: split-tunneling активен (mark=\$MARK, таблицы \$TABLE4/\$TABLE6)"
    ;;
down)
    ip rule del fwmark \$MARK table \$TABLE4 2>/dev/null || true
    ip -6 rule del from "\$CLIENT_NET6" table \$TABLE6 2>/dev/null || true
    nft delete table inet xio_cascade 2>/dev/null || true
    ;;
*)
    echo "usage: \$0 up|down" >&2
    exit 2
    ;;
esac
NFTEOF
    chmod 700 "$NFT_SCRIPT"
fi

# --- wg0: туннель до exit ---------------------------------------------------
WG0="$DATA_DIR/wg0.conf"
PRIV_VALUE=""
if [ -s "$PRIV" ]; then PRIV_VALUE=$(tr -d '\r\n' < "$PRIV"); fi
if [ "$DRY_RUN" -eq 0 ]; then
    {
        printf '# Сгенерировано cascade-bridge-setup.sh. Права 600, секреты не логируются.\n'
        printf '[Interface]\n'
        printf 'Address = %s\n' "$TUN_ADDR"
        printf 'PrivateKey = %s\n' "$PRIV_VALUE"
        printf 'MTU = 1420\n'
        printf 'Table = off\n'
        printf 'PostUp = /bin/sh %s/nft-bridge.sh up\n' "$CONTAINER_DATA"
        printf 'PostDown = /bin/sh %s/nft-bridge.sh down\n' "$CONTAINER_DATA"
        printf '\n[Peer]\n# exit %s\n' "$EXIT_HOST"
        printf 'PublicKey = %s\n' "$EXIT_PUBKEY"
        printf 'Endpoint = [%s]:%s\n' "$EXIT_HOST" "$PORT"
        printf 'AllowedIPs = 0.0.0.0/0, ::/0\n'
        printf 'PersistentKeepalive = 25\n'
        if [ -n "$PSK" ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
    } > "$WG0.tmp"
    chmod 600 "$WG0.tmp"
    mv -f -- "$WG0.tmp" "$WG0"
    log "конфиг туннеля: $WG0"
fi

# --- wg1: приём устройств ---------------------------------------------------
WG1="$DATA_DIR/wg1.conf"
CLIENT4_ADDR="${CLIENT_NET4%.*}.1"
CLIENT6_ADDR="${CLIENT_NET6%/*}1"
if [ "$DRY_RUN" -eq 0 ]; then
    {
        printf '# Сгенерировано cascade-bridge-setup.sh. Интерфейс приёма устройств.\n'
        printf '[Interface]\n'
        printf 'Address = %s/24, %s/64\n' "$CLIENT4_ADDR" "$CLIENT6_ADDR"
        printf 'ListenPort = %s\n' "$CLIENT_PORT"
        printf 'PrivateKey = %s\n' "$PRIV_VALUE"
        printf 'MTU = 1420\n'
        printf 'Table = off\n'
        for client_file in "$DATA_DIR"/clients/*.conf; do
            [ -s "$client_file" ] || continue
            client_line=$(tr -d '\r' < "$client_file" | head -n 1)
            client_key=${client_line%% *}
            client_ips=${client_line#* }
            [ -n "$client_key" ] && [ "$client_key" != "$client_line" ] || continue
            printf '\n[Peer]\n# устройство %s…\n' "${client_key:0:8}"
            printf 'PublicKey = %s\n' "$client_key"
            printf 'AllowedIPs = %s\n' "$client_ips"
            if [ -n "$PSK" ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
        done
    } > "$WG1.tmp"
    chmod 600 "$WG1.tmp"
    mv -f -- "$WG1.tmp" "$WG1"
    log "конфиг приёма устройств: $WG1"
fi

# --- проверка отпечатка exit ------------------------------------------------
FP=""
if command -v sha256sum >/dev/null 2>&1; then
    FP="sha256:$(printf 'xio-cascade-exit-v1|%s|%s|%s' "$EXIT_HOST" "$PORT" "$EXIT_PUBKEY" | sha256sum | awk '{print $1}')"
fi
PIN_STATUS="not-requested"
if [ -n "$EXIT_FINGERPRINT" ]; then
    if [ "$EXIT_FINGERPRINT" = "$FP" ]; then
        PIN_STATUS="match"
        log "отпечаток exit совпал с запиненным"
    else
        PIN_STATUS="mismatch"
        die "отпечаток exit не совпал: ожидался $EXIT_FINGERPRINT, получен $FP (возможна подмена или другой --port)"
    fi
fi

STATE="$DATA_DIR/state.json"
if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$STATE.tmp" <<EOF
{
  "role": "bridge",
  "ipv4": "$BRIDGE_IP4",
  "web": "http://$BRIDGE_IP4:$WEB_PORT/",
  "exit_host": "$EXIT_HOST",
  "exit_port": $PORT,
  "client_port": $CLIENT_PORT,
  "tunnel_addr": "$TUN_ADDR",
  "exit_tunnel_addr": "$EXIT_TUN_ADDR",
  "client_net4": "$CLIENT_NET4",
  "client_net6": "$CLIENT_NET6",
  "pubkey": "$PUBKEY",
  "exit_fingerprint": "$FP",
  "pin": "$PIN_STATUS",
  "wg_conf": "$WG0",
  "clients_conf": "$WG1"
}
EOF
    chmod 600 "$STATE.tmp"
    mv -f -- "$STATE.tmp" "$STATE"
fi

cat <<EOF
{
  "role": "bridge",
  "dry_run": $([ "$DRY_RUN" -eq 1 ] && printf 'true' || printf 'false'),
  "ipv4": "$BRIDGE_IP4",
  "web": "http://$BRIDGE_IP4:$WEB_PORT/",
  "exit_host": "$EXIT_HOST",
  "exit_port": $PORT,
  "client_port": $CLIENT_PORT,
  "tunnel_addr": "$TUN_ADDR",
  "client_net4": "$CLIENT_NET4",
  "pubkey": "$PUBKEY",
  "exit_fingerprint": "$FP",
  "pin": "$PIN_STATUS",
  "clients": $(ls -1 "$DATA_DIR/clients" 2>/dev/null | wc -l | tr -d ' '),
  "configs": ["$WG0", "$WG1"]
}
EOF

log "дальше: зарегистрируйте ключ bridge на exit: cascade-exit-setup.sh --add-peer $PUBKEY"
log "готово"
