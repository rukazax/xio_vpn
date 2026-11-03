#!/usr/bin/env bash
# XIO Cascade — настройка exit-сервера (только IPv6).
#
# Что делает:
#   * проверяет, что у хоста есть глобальный IPv6 (это единственный транспорт exit);
#   * генерирует ключи WireGuard (или переиспользует существующие — идемпотентно);
#   * собирает wg0.conf: слушает туннель на <port>/udp, peers — только bridge;
#   * кладёт рядом nft-exit.sh: NAT66 (клиентский IPv6 -> мировой IPv6),
#     NAT46 (IPv4-клиенты bridge -> IPv6, best effort) и forward;
#   * считает «exit fingerprint» — sha256 от адреса, порта и публичного ключа,
#     чтобы bridge мог запинить именно этот exit;
#   * печатает JSON-сводку и кладёт её в <data-dir>/state.json.
#
# Запускается и вручную, и из cascade-install.sh. Ключи никогда не печатаются.
#
# Примеры:
#   ./cascade-exit-setup.sh
#   ./cascade-exit-setup.sh --port 9443 --add-peer <b64> --allowed-ips 10.201.0.2/32,10.202.0.0/24
#   ./cascade-exit-setup.sh --dry-run --allow-ula        # тест без глобального IPv6

set -eu
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1

DATA_DIR="$SCRIPT_DIR/data/exit"
PORT=9443
TUN_IF=wg0
TUN_ADDR="10.201.0.1/24"
BRIDGE_IP="10.201.0.2"
CLIENT_NET4="10.202.0.0/24"
CLIENT_NET6="fd42:201::/64"
CONTAINER_DATA="/data"
PSK_FILE=""
ADD_PEER=""
REMOVE_PEER=""
ALLOWED_IPS="10.201.0.2/32,10.202.0.0/24,fd42:201::/64"
ALLOW_ULA=0
DRY_RUN=0
IMAGE="xio-cascade:local"
RUNTIME=""
EXIT_V6=""

log() { printf '[exit] %s\n' "$*" >&2; }
warn() { printf '[exit] warning: %s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }

cleanup() {
    if [ -n "${DATA_DIR:-}" ] && [ -d "$DATA_DIR" ]; then
        rm -f -- "$DATA_DIR/private.key.tmp" "$DATA_DIR/public.key.tmp" \
            "$DATA_DIR/$TUN_IF.conf.tmp" "$DATA_DIR/state.json.tmp" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
exit-setup — настройка exit-сервера XIO Cascade (только IPv6)

  --data-dir <path>        каталог состояния (по умолчанию ./data/exit)
  --port <p>               UDP-порт туннеля (по умолчанию 9443)
  --tunnel-addr <cidr>     адрес exit в туннеле (по умолчанию 10.201.0.1/24)
  --bridge-ip <ip>         адрес bridge в туннеле (по умолчанию 10.201.0.2)
  --client-net4 <cidr>     IPv4-сеть устройств за bridge (10.202.0.0/24)
  --client-net6 <cidr>     ULA-сеть устройств за bridge (fd42:201::/64)
  --psk-file <path>        общий секрет (PresharedKey) для всех peers
  --add-peer <pubkey>      добавить/обновить peer bridge
  --allowed-ips <list>     AllowedIPs для --add-peer
  --remove-peer <pubkey>   удалить peer
  --allow-ula              разрешить ULA-адрес вместо глобального (только для тестов)
  --image <tag>            образ для генерации ключей через контейнер
  --dry-run                показать план, ничего не записывать
  -h, --help               справка
EOF
}

need_arg() { [ "$#" -ge 2 ] || die "опция $1 требует значение"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --data-dir)      need_arg "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*)    DATA_DIR=${1#*=}; shift ;;
        --port)          need_arg "$@"; PORT=$2; shift 2 ;;
        --port=*)        PORT=${1#*=}; shift ;;
        --tunnel-addr)   need_arg "$@"; TUN_ADDR=$2; shift 2 ;;
        --tunnel-addr=*) TUN_ADDR=${1#*=}; shift ;;
        --bridge-ip)     need_arg "$@"; BRIDGE_IP=$2; shift 2 ;;
        --bridge-ip=*)   BRIDGE_IP=${1#*=}; shift ;;
        --client-net4)   need_arg "$@"; CLIENT_NET4=$2; shift 2 ;;
        --client-net6)   need_arg "$@"; CLIENT_NET6=$2; shift 2 ;;
        --container-data-dir) need_arg "$@"; CONTAINER_DATA=$2; shift 2 ;;
        --psk-file)      need_arg "$@"; PSK_FILE=$2; shift 2 ;;
        --psk-file=*)    PSK_FILE=${1#*=}; shift ;;
        --add-peer)      need_arg "$@"; ADD_PEER=$2; shift 2 ;;
        --add-peer=*)    ADD_PEER=${1#*=}; shift ;;
        --allowed-ips)   need_arg "$@"; ALLOWED_IPS=$2; shift 2 ;;
        --allowed-ips=*) ALLOWED_IPS=${1#*=}; shift ;;
        --remove-peer)   need_arg "$@"; REMOVE_PEER=$2; shift 2 ;;
        --image)         need_arg "$@"; IMAGE=$2; shift 2 ;;
        --allow-ula)     ALLOW_ULA=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

case "$PORT" in ''|*[!0-9]*) die "--port должен быть числом" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port вне диапазона"
[ "$(id -u)" -eq 0 ] || die "нужны права root"
command -v sed >/dev/null 2>&1 || die "не найдена команда sed"

if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p -- "$DATA_DIR/peers"
    chmod 700 "$DATA_DIR" "$DATA_DIR/peers"
fi

# --- контейнерный движок нужен только если на хосте нет wg -------------------
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

# --- 1. проверка глобального IPv6 ------------------------------------------
ipv6_is_global() {
    local addr=$1
    case "$addr" in
        ''|::1|fe80:*|fc*|fd*|2001:db8:*) return 1 ;;
        *:*) return 0 ;;
        *) return 1 ;;
    esac
}

detect_exit_ipv6() {
    local cand=""
    if command -v ip >/dev/null 2>&1; then
        cand=$(ip -6 route get 2606:4700:4700:1111 2>/dev/null | sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' | head -n 1) || cand=""
        if [ -z "$cand" ]; then
            cand=$(ip -6 -o addr show scope global 2>/dev/null | awk 'NR==1 {print $4}' | cut -d/ -f1) || cand=""
        fi
    fi
    printf '%s' "$cand"
}

EXIT_V6=$(detect_exit_ipv6)
if [ -z "$EXIT_V6" ]; then
    if [ "$ALLOW_ULA" -eq 1 ]; then
        warn "глобального IPv6 не найдено, --allow-ula задан: продолжаю с ULA-заглушкой"
        EXIT_V6="fd00::1"
    else
        die "на хосте нет глобального IPv6-адреса: exit без IPv6 работать не может (для теста: --allow-ula)"
    fi
elif ! ipv6_is_global "$EXIT_V6"; then
    if [ "$ALLOW_ULA" -eq 1 ]; then
        warn "адрес $EXIT_V6 не выглядит глобальным, но --allow-ula задан"
    else
        die "адрес $EXIT_V6 не глобальный (ULA/link-local/loopback): нужен публичный IPv6 или --allow-ula"
    fi
fi
log "публичный IPv6 exit: $EXIT_V6"

# --- 2. ключи ---------------------------------------------------------------
PRIV="$DATA_DIR/private.key"
PUB="$DATA_DIR/public.key"
if [ -s "$PRIV" ] && [ -s "$PUB" ]; then
    log "ключи уже есть — использую существующие (идемпотентность)"
else
    if [ "$DRY_RUN" -eq 1 ]; then
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
fi
PUBKEY=""
if [ -s "$PUB" ]; then PUBKEY=$(tr -d '\r\n' < "$PUB"); fi

# --- 3. PresharedKey --------------------------------------------------------
PSK_STATE="$DATA_DIR/preshared.key"

# Произвольный секрет из --token-file приводим к валидному 32-байтному ключу.
# Хешируем нормализованный файл (без CR/LF), чтобы все ветки дали один результат.
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
            # уже валидный ключ WireGuard (base64 от 32 байт)
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

# --- 4. peers ---------------------------------------------------------------
PEERS_DIR="$DATA_DIR/peers"
if [ -n "$ADD_PEER" ]; then
    case "$ADD_PEER" in
        *[!A-Za-z0-9+/=]*) die "--add-peer: ключ содержит недопустимые символы" ;;
    esac
    LOG_IPS=${ALLOWED_IPS//,/ }
    printf '%s %s\n' "$ADD_PEER" "$LOG_IPS" > "$DATA_DIR/peers/$ADD_PEER.conf"
    chmod 600 "$DATA_DIR/peers/$ADD_PEER.conf"
    log "peer добавлен/обновлён: ${ADD_PEER:0:8}… allowed=$ALLOWED_IPS"
fi
if [ -n "$REMOVE_PEER" ]; then
    if [ -f "$DATA_DIR/peers/$REMOVE_PEER.conf" ]; then
        rm -f -- "$DATA_DIR/peers/$REMOVE_PEER.conf"
        log "peer удалён: ${REMOVE_PEER:0:8}…"
    fi
fi

# --- 5. nft-скрипт exit -----------------------------------------------------
NFT_SCRIPT="$DATA_DIR/nft-exit.sh"
if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$NFT_SCRIPT" <<NFTEOF
#!/bin/sh
# Сгенерировано cascade-exit-setup.sh. Не редактировать вручную.
# exit: NAT66 для IPv6-клиентов bridge, NAT46 (best effort) для IPv4-клиентов.
set -u
ACTION=\${1:-up}
TUN_IF=\${CASCADE_TUN_IF:-$TUN_IF}
EXIT_V6="$EXIT_V6"
CLIENT_NET4="$CLIENT_NET4"
CLIENT_NET6="$CLIENT_NET6"

sysctl_try() { command -v sysctl >/dev/null 2>&1 && sysctl -qw "\$1" 2>/dev/null || true; }

case "\$ACTION" in
up)
    sysctl_try net.ipv4.ip_forward=1
    sysctl_try net.ipv6.conf.all.forwarding=1
    nft list table inet xio_cascade >/dev/null 2>&1 || nft add table inet xio_cascade
    nft 'add chain inet xio_cascade forward { type filter hook forward priority filter; }' 2>/dev/null || true
    nft 'add chain inet xio_cascade postrouting { type nat hook postrouting priority srcnat; }' 2>/dev/null || true
    nft flush chain inet xio_cascade forward
    nft flush chain inet xio_cascade postrouting
    nft add rule inet xio_cascade forward iifname "\$TUN_IF" accept
    nft add rule inet xio_cascade forward oifname "\$TUN_IF" ct state established,related accept
    # NAT66: IPv6-клиенты bridge (ULA) получают мировой IPv6 exit-сервера
    nft add rule inet xio_cascade postrouting meta nfproto ipv6 ip6 saddr "\$CLIENT_NET6" oifname != "\$TUN_IF" masquerade
    # NAT46: IPv4-клиенты bridge. Поддержка зависит от ядра и версии nftables.
    if nft add rule inet xio_cascade postrouting meta nfproto ipv4 ip saddr "\$CLIENT_NET4" oifname != "\$TUN_IF" snat ip6 to "\$EXIT_V6" 2>/dev/null; then
        echo "exit: NAT46 активен (\$CLIENT_NET4 -> \$EXIT_V6)"
    else
        echo "exit: ВНИМАНИЕ, NAT46 не поддержан этим ядром/nftables — IPv4-клиенты останутся без выхода" >&2
    fi
    ;;
down)
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

# --- 6. wg0.conf ------------------------------------------------------------
WG_CONF="$DATA_DIR/$TUN_IF.conf"
PRIV_VALUE=""
if [ -s "$PRIV" ]; then PRIV_VALUE=$(tr -d '\r\n' < "$PRIV"); fi

if [ "$DRY_RUN" -eq 0 ]; then
    {
        printf '# Сгенерировано cascade-exit-setup.sh. Права 600, секреты не логируются.\n'
        printf '[Interface]\n'
        printf 'Address = %s\n' "$TUN_ADDR"
        printf 'ListenPort = %s\n' "$PORT"
        printf 'PrivateKey = %s\n' "$PRIV_VALUE"
        printf 'PostUp = /bin/sh %s/nft-exit.sh up\n' "$CONTAINER_DATA"
        printf 'PostDown = /bin/sh %s/nft-exit.sh down\n' "$CONTAINER_DATA"
        if [ -n "$PSK" ]; then
            printf '\n# PresharedKey общий для всех peers (файл %s)\n' "$PSK_STATE"
        fi
        for peer_file in "$PEERS_DIR"/*.conf; do
            [ -s "$peer_file" ] || continue
            peer_line=$(tr -d '\r' < "$peer_file" | head -n 1)
            peer_key=${peer_line%% *}
            peer_ips=${peer_line#* }
            if [ -z "$peer_key" ] || [ "$peer_key" = "$peer_line" ]; then
                warn "пропускаю некорректный $peer_file"
                continue
            fi
            printf '\n[Peer]\n# bridge %s…\n' "${peer_key:0:8}"
            printf 'PublicKey = %s\n' "$peer_key"
            printf 'AllowedIPs = %s\n' "$peer_ips"
            if [ -n "$PSK" ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
            printf 'PersistentKeepalive = 25\n'
        done
    } > "$WG_CONF.tmp"
    chmod 600 "$WG_CONF.tmp"
    mv -f -- "$WG_CONF.tmp" "$WG_CONF"
    log "конфиг туннеля: $WG_CONF"
fi

# --- 7. отпечаток и состояние ----------------------------------------------
FP=""
if [ -n "$PUBKEY" ]; then
    FP="sha256:$(printf 'xio-cascade-exit-v1|%s|%s|%s' "$EXIT_V6" "$PORT" "$PUBKEY" | sha256sum | awk '{print $1}')"
fi

STATE="$DATA_DIR/state.json"
if [ "$DRY_RUN" -eq 0 ]; then
    cat > "$STATE.tmp" <<EOF
{
  "role": "exit",
  "ipv6": "$EXIT_V6",
  "port": $PORT,
  "tunnel_addr": "$TUN_ADDR",
  "bridge_addr": "$BRIDGE_IP",
  "client_net4": "$CLIENT_NET4",
  "client_net6": "$CLIENT_NET6",
  "interface": "$TUN_IF",
  "pubkey": "$PUBKEY",
  "fingerprint": "$FP",
  "wg_conf": "$WG_CONF",
  "nft_script": "$NFT_SCRIPT"
}
EOF
    chmod 600 "$STATE.tmp"
    mv -f -- "$STATE.tmp" "$STATE"
    printf '%s\n' "$FP" > "$DATA_DIR/fingerprint.txt"
    chmod 600 "$DATA_DIR/fingerprint.txt"
fi

cat <<EOF
{
  "role": "exit",
  "dry_run": $([ "$DRY_RUN" -eq 1 ] && printf 'true' || printf 'false'),
  "ipv6": "$EXIT_V6",
  "port": $PORT,
  "interface": "$TUN_IF",
  "tunnel_addr": "$TUN_ADDR",
  "pubkey": "$PUBKEY",
  "fingerprint": "$FP",
  "peers": $(ls -1 "$PEERS_DIR" 2>/dev/null | wc -l | tr -d ' '),
  "config": "$WG_CONF"
}
EOF

log "дальше: на bridge выполните cascade-bridge-setup.sh --exit-host $EXIT_V6 --exit-pubkey <pubkey выше>"
log "готово"
