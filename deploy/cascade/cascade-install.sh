#!/usr/bin/env bash
# XIO Cascade — установка последовательной двухсерверной схемы (bridge -> exit).
#
#   bridge (IPv4)  принимает устройство, держит защищённый туннель до exit
#   exit   (IPv6)  выпускает трафик в мир, IPv4-адреса у него нет вообще
#
# Всё живёт в контейнере (docker/podman), чтобы не задевать остальной софт сервера.
# Данные и конфиги — в ./data/, монтируются в контейнер томами.
#
# Примеры:
#   ./cascade-install.sh --role exit
#   ./cascade-install.sh --role bridge --exit-host 2a01:4f8:1:2::10 --exit-pubkey <b64>
#   ./cascade-install.sh --role both --exit-host 2a01:4f8:1:2::10      # лабораторный стенд
#   ./cascade-install.sh --role bridge --exit-host 2a01:... --enable-whitelists --dry-run
#
# Коды выхода: 0 — успех, 1 — ошибка установки, 2 — неверные аргументы.

set -eu
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1

ROLE=""
EXIT_HOST=""
EXIT_PUBKEY=""
PEER_PUBKEY=""
PORT=9443
TOKEN_FILE=""
ENABLE_WHITELISTS=0
DRY_RUN=0
RECREATE=0
DATA_DIR="$SCRIPT_DIR/data"
CLIENT_PORT=51820
WEB_PORT=8443
IMAGE="xio-cascade:local"
RUNTIME=""
NETWORK="xio-cascade"
EXIT_CONTAINER="xio-cascade-exit"
BRIDGE_CONTAINER="xio-cascade-bridge"
TMP_DIR=""

log() { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s] warning: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }
usage_error() { printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2; printf 'Подсказка: %s --help\n' "$SCRIPT_NAME" >&2; exit 2; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "не найдена команда «$1» — установите её и повторите"
}

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf -- "$TMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
XIO Cascade installer

Использование:
  cascade-install.sh --role bridge|exit|both [опции]

Обязательные:
  --role <bridge|exit|both>   какую роль ставим на этой машине
  --exit-host <ipv6>          публичный IPv6 exit-сервера (для bridge и both)

Опции:
  --exit-pubkey <b64>         публичный ключ exit (для --role bridge; можно взять
                              из вывода установки на exit-сервере)
  --peer-pubkey <b64>         публичный ключ bridge (для --role exit — разрешить мост)
  --port <p>                  UDP-порт туннеля на exit (по умолчанию 9443)
  --client-port <p>           UDP-порт приёма устройств на bridge (по умолчанию 51820)
  --web-port <p>              TCP-порт web/admin интерфейса entry (по умолчанию 8443)
  --token-file <path>         файл с общим секретом (используется как PresharedKey)
  --enable-whitelists         поставить еженедельное обновление белых списков
  --data-dir <path>           каталог состояния (по умолчанию ./data рядом со скриптом)
  --recreate                  пересоздать контейнеры (данные в ./data сохраняются)
  --dry-run                   только показать план, ничего не менять
  -h, --help                  эта справка

Порты в мир:
  exit:   <port>/udp  (туннель)
  bridge: <client-port>/udp (устройства), <web-port>/tcp (entry)
EOF
}

need_arg() {
    [ "$#" -ge 2 ] || usage_error "опция $1 требует значение"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --role)          need_arg "$@"; ROLE=$2; shift 2 ;;
        --role=*)        ROLE=${1#*=}; shift ;;
        --exit-host)     need_arg "$@"; EXIT_HOST=$2; shift 2 ;;
        --exit-host=*)   EXIT_HOST=${1#*=}; shift ;;
        --exit-pubkey)   need_arg "$@"; EXIT_PUBKEY=$2; shift 2 ;;
        --exit-pubkey=*) EXIT_PUBKEY=${1#*=}; shift ;;
        --peer-pubkey)   need_arg "$@"; PEER_PUBKEY=$2; shift 2 ;;
        --peer-pubkey=*) PEER_PUBKEY=${1#*=}; shift ;;
        --port)          need_arg "$@"; PORT=$2; shift 2 ;;
        --port=*)        PORT=${1#*=}; shift ;;
        --client-port)   need_arg "$@"; CLIENT_PORT=$2; shift 2 ;;
        --client-port=*) CLIENT_PORT=${1#*=}; shift ;;
        --web-port)      need_arg "$@"; WEB_PORT=$2; shift 2 ;;
        --web-port=*)    WEB_PORT=${1#*=}; shift ;;
        --token-file)    need_arg "$@"; TOKEN_FILE=$2; shift 2 ;;
        --token-file=*)  TOKEN_FILE=${1#*=}; shift ;;
        --data-dir)      need_arg "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*)    DATA_DIR=${1#*=}; shift ;;
        --enable-whitelists) ENABLE_WHITELISTS=1; shift ;;
        --recreate)      RECREATE=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift; break ;;
        -*)              usage_error "неизвестная опция: $1" ;;
        *)               usage_error "лишний аргумент: $1" ;;
    esac
done

case "$ROLE" in
    bridge|exit|both) ;;
    '') usage_error "не задана роль: --role bridge|exit|both" ;;
    *)  usage_error "недопустимая роль «$ROLE» (ожидается bridge, exit или both)" ;;
esac

case "$PORT" in ''|*[!0-9]*) usage_error "--port должен быть числом" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || usage_error "--port вне диапазона 1..65535"
case "$CLIENT_PORT" in ''|*[!0-9]*) usage_error "--client-port должен быть числом" ;; esac
[ "$CLIENT_PORT" -ge 1 ] && [ "$CLIENT_PORT" -le 65535 ] || usage_error "--client-port вне диапазона"
case "$WEB_PORT" in ''|*[!0-9]*) usage_error "--web-port должен быть числом" ;; esac
[ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || usage_error "--web-port вне диапазона"

[ "$(id -u)" -eq 0 ] || die "нужны права root (контейнеры, тома, порты)"

if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    [ -n "$EXIT_HOST" ] || usage_error "для роли $ROLE обязателен --exit-host <ipv6>"
    case "$EXIT_HOST" in
        *:*) ;;
        *) usage_error "--exit-host должен быть IPv6-адресом (в нём есть «:»), получено: $EXIT_HOST" ;;
    esac
fi
if [ "$ROLE" = "bridge" ] && [ -z "$EXIT_PUBKEY" ]; then
    usage_error "для --role bridge нужен --exit-pubkey (его печатает установка на exit-сервере)"
fi

if [ -n "$TOKEN_FILE" ]; then
    [ -f "$TOKEN_FILE" ] && [ -r "$TOKEN_FILE" ] || die "файл секрета недоступен для чтения: $TOKEN_FILE"
    [ -s "$TOKEN_FILE" ] || die "файл секрета пуст: $TOKEN_FILE"
    MODE=$(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || printf '600')
    if [ "$MODE" != "600" ] && [ "$MODE" != "400" ]; then
        warn "у $TOKEN_FILE права $MODE — рекомендуется 600"
    fi
fi

detect_runtime() {
    local seen="" candidate
    for candidate in docker podman; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        seen="$seen $candidate"
        if "$candidate" info >/dev/null 2>&1; then
            RUNTIME=$candidate
            return 0
        fi
    done
    if [ -n "$seen" ]; then
        die "найден контейнерный движок (${seen# }), но демон не отвечает: запустите службу (systemctl start docker) или дайте доступ текущему root"
    fi
    die "нет ни docker, ни podman: поставьте один из них (apt-get install -y docker.io) и повторите"
}

if [ "$DRY_RUN" -eq 1 ]; then
    # для наглядности плана: показываем docker, если он есть, иначе podman
    if command -v docker >/dev/null 2>&1; then RUNTIME=docker
    elif command -v podman >/dev/null 2>&1; then RUNTIME=podman
    else RUNTIME=docker; fi
else
    detect_runtime
fi

need_cmd sha256sum
need_cmd sed
[ "$DRY_RUN" -eq 1 ] || need_cmd ip

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'dry-run:' >&2
        printf ' %q' "$@" >&2
        printf '\n' >&2
        return 0
    fi
    "$@"
}

json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/ }
    s=${s//$'\t'/ }
    printf '%s' "$s"
}

state_get() {
    local file=$1 key=$2
    [ -r "$file" ] || return 0
    sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n 1
}

# ---------------------------------------------------------------------------
# 1. Подготовка каталогов и образа
# ---------------------------------------------------------------------------

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xio-cascade.XXXXXX")
chmod 700 "$TMP_DIR"

DATA_DIR=${DATA_DIR%/}
case "$DATA_DIR" in
    /*) ;;
    *) DATA_DIR="$PWD/$DATA_DIR" ;;
esac
log "роль: $ROLE | данные: $DATA_DIR | движок: $RUNTIME | dry-run: $DRY_RUN"

if [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run: каталоги, образ, сеть и контейнеры НЕ создаются"
else
    mkdir -p -- "$DATA_DIR"
    chmod 700 "$DATA_DIR"
fi

[ -f "$SCRIPT_DIR/Dockerfile" ] || die "нет $SCRIPT_DIR/Dockerfile — installer запускается из каталога deploy/cascade"
[ -f "$SCRIPT_DIR/entrypoint.sh" ] || die "нет $SCRIPT_DIR/entrypoint.sh"

if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    if [ -f "$SCRIPT_DIR/whitelists.conf" ] && [ ! -f "$DATA_DIR/whitelists.conf" ] && [ "$DRY_RUN" -eq 0 ]; then
        install -m 600 "$SCRIPT_DIR/whitelists.conf" "$DATA_DIR/whitelists.conf"
    fi
    # файл монтируется в контейнер как файл: docker не должен создать вместо него каталог
    if [ "$DRY_RUN" -eq 0 ] && [ ! -f "$DATA_DIR/whitelists.conf" ]; then
        : > "$DATA_DIR/whitelists.conf"
        chmod 600 "$DATA_DIR/whitelists.conf"
    fi
fi

log "сборка образа $IMAGE из $SCRIPT_DIR/Dockerfile"
run "$RUNTIME" build --pull=false -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

if [ "$DRY_RUN" -eq 1 ]; then
    run "$RUNTIME" network create --driver bridge "$NETWORK"
elif "$RUNTIME" network inspect "$NETWORK" >/dev/null 2>&1; then
    log "сеть $NETWORK уже есть — использую её (идемпотентность)"
else
    log "создаю сеть $NETWORK"
    run "$RUNTIME" network create --driver bridge "$NETWORK"
fi

# ---------------------------------------------------------------------------
# 2. Роли: конфиги и ключи (setup-скрипты идемпотентны)
# ---------------------------------------------------------------------------

SETUP_ARGS=()
[ -n "$TOKEN_FILE" ] && SETUP_ARGS+=(--token-file "$TOKEN_FILE")
[ "$DRY_RUN" -eq 1 ] && SETUP_ARGS+=(--dry-run)

EXIT_STATE="$DATA_DIR/exit/state.json"
BRIDGE_STATE="$DATA_DIR/bridge/state.json"

if [ "$ROLE" = "exit" ] || [ "$ROLE" = "both" ]; then
    log "настройка exit (только IPv6)"
    bash "$SCRIPT_DIR/cascade-exit-setup.sh" \
        --data-dir "$DATA_DIR/exit" \
        --port "$PORT" \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}"
fi

if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    EXIT_PUB_FOR_BRIDGE=$EXIT_PUBKEY
    if [ -z "$EXIT_PUB_FOR_BRIDGE" ] && [ -r "$EXIT_STATE" ]; then
        EXIT_PUB_FOR_BRIDGE=$(state_get "$EXIT_STATE" pubkey)
    fi
    [ -n "$EXIT_PUB_FOR_BRIDGE" ] || die "не известен публичный ключ exit: передайте --exit-pubkey"
    log "настройка bridge (IPv4 -> IPv6)"
    bash "$SCRIPT_DIR/cascade-bridge-setup.sh" \
        --data-dir "$DATA_DIR/bridge" \
        --exit-host "$EXIT_HOST" \
        --exit-pubkey "$EXIT_PUB_FOR_BRIDGE" \
        --port "$PORT" \
        --client-port "$CLIENT_PORT" \
        --web-port "$WEB_PORT" \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}"
fi

# для both: отдаём exit публичный ключ bridge-а (после того как bridge его создал)
if [ "$ROLE" = "both" ] && [ -r "$BRIDGE_STATE" ]; then
    BRIDGE_PUB=$(state_get "$BRIDGE_STATE" pubkey)
    if [ -n "$BRIDGE_PUB" ]; then
        log "регистрирую ключ bridge на exit"
        bash "$SCRIPT_DIR/cascade-exit-setup.sh" \
            --data-dir "$DATA_DIR/exit" \
            --port "$PORT" \
            --add-peer "$BRIDGE_PUB" \
            --allowed-ips "10.201.0.2/32,10.202.0.0/24" \
            "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}"
    fi
fi
if [ "$ROLE" = "exit" ] && [ -n "$PEER_PUBKEY" ]; then
    bash "$SCRIPT_DIR/cascade-exit-setup.sh" \
        --data-dir "$DATA_DIR/exit" --port "$PORT" \
        --add-peer "$PEER_PUBKEY" --allowed-ips "10.201.0.2/32,10.202.0.0/24" \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}"
fi

# ---------------------------------------------------------------------------
# 3. Контейнеры
# ---------------------------------------------------------------------------

container_exists() {
    "$RUNTIME" container inspect "$1" >/dev/null 2>&1
}

container_running() {
    [ "$("$RUNTIME" inspect -f '{{.State.Running}}' "$1" 2>/dev/null || printf 'false')" = "true" ]
}

start_or_create() {
    local name=$1
    shift
    if container_exists "$name"; then
        if [ "$RECREATE" -eq 1 ]; then
            log "пересоздаю контейнер $name (--recreate)"
            run "$RUNTIME" rm -f "$name"
        else
            if container_running "$name"; then
                log "контейнер $name уже запущен — не трогаю"
            else
                log "контейнер $name существует, но остановлен — запускаю"
                run "$RUNTIME" start "$name"
            fi
            return 0
        fi
    fi
    log "создаю контейнер $name"
    run "$RUNTIME" run -d --name "$name" \
        --restart unless-stopped \
        --network "$NETWORK" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun \
        "$@"
}

if [ "$ROLE" = "exit" ] || [ "$ROLE" = "both" ]; then
    start_or_create "$EXIT_CONTAINER" \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        -p "$PORT:$PORT/udp" \
        -v "$DATA_DIR/exit:/data" \
        -e CASCADE_ROLE=exit \
        -e CASCADE_TUNNEL_PORT="$PORT" \
        "$IMAGE"
fi

if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    start_or_create "$BRIDGE_CONTAINER" \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        -p "$CLIENT_PORT:$CLIENT_PORT/udp" \
        -p "$WEB_PORT:8443/tcp" \
        -v "$DATA_DIR/bridge:/data" \
        -v "$DATA_DIR/whitelists.conf:/etc/xio/whitelists.conf:ro" \
        -e CASCADE_ROLE=bridge \
        -e CASCADE_TUNNEL_PORT="$PORT" \
        -e CASCADE_CLIENT_PORT="$CLIENT_PORT" \
        "$IMAGE"
fi

# whitelists: еженедельный таймер (живёт на хосте, nft применяет внутри контейнера)
if [ "$ENABLE_WHITELISTS" -eq 1 ] && { [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; }; then
    log "ставлю еженедельное обновление белых списков"
    bash "$SCRIPT_DIR/whitelist-update.sh" \
        --config "$DATA_DIR/whitelists.conf" \
        --data-dir "$DATA_DIR/bridge" \
        --container "$BRIDGE_CONTAINER" \
        --runtime "$RUNTIME" \
        --install-timer \
        "${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}"
fi

# ---------------------------------------------------------------------------
# 4. Итоговая JSON-сводка
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" -eq 0 ]; then
    sleep 2
fi

EXIT_IPV6=""
EXIT_PUB=""
EXIT_FP=""
BRIDGE_IPV4=""
BRIDGE_PUB=""
BRIDGE_WEB=""
EXIT_TUNNEL_ADDR="10.201.0.1"

if [ -r "$EXIT_STATE" ]; then
    EXIT_IPV6=$(state_get "$EXIT_STATE" ipv6)
    EXIT_PUB=$(state_get "$EXIT_STATE" pubkey)
    EXIT_FP=$(state_get "$EXIT_STATE" fingerprint)
fi
if [ -r "$BRIDGE_STATE" ]; then
    BRIDGE_IPV4=$(state_get "$BRIDGE_STATE" ipv4)
    BRIDGE_PUB=$(state_get "$BRIDGE_STATE" pubkey)
    BRIDGE_WEB=$(state_get "$BRIDGE_STATE" web)
fi
if [ -z "$EXIT_IPV6" ] && [ -n "$EXIT_HOST" ]; then EXIT_IPV6=$EXIT_HOST; fi
if [ -z "$BRIDGE_WEB" ] && [ -n "$BRIDGE_IPV4" ]; then BRIDGE_WEB="http://$BRIDGE_IPV4:$WEB_PORT/"; fi

if [ "$DRY_RUN" -eq 1 ]; then
    SUMMARY_DRY=true
else
    SUMMARY_DRY=false
fi

cat <<EOF
{
  "role": "$(json_escape "$ROLE")",
  "dry_run": $SUMMARY_DRY,
  "runtime": "$(json_escape "$RUNTIME")",
  "image": "$(json_escape "$IMAGE")",
  "network": "$(json_escape "$NETWORK")",
  "data_dir": "$(json_escape "$DATA_DIR")",
  "containers": {
    "exit": "$(json_escape "$EXIT_CONTAINER")",
    "bridge": "$(json_escape "$BRIDGE_CONTAINER")"
  },
  "exit": {
    "ipv6": "$(json_escape "$EXIT_IPV6")",
    "port": $PORT,
    "pubkey": "$(json_escape "$EXIT_PUB")",
    "fingerprint": "$(json_escape "$EXIT_FP")",
    "tunnel_addr": "$(json_escape "$EXIT_TUNNEL_ADDR")"
  },
  "bridge": {
    "ipv4": "$(json_escape "$BRIDGE_IPV4")",
    "port": $PORT,
    "client_port": $CLIENT_PORT,
    "pubkey": "$(json_escape "$BRIDGE_PUB")",
    "web": "$(json_escape "$BRIDGE_WEB")",
    "gateway": "127.0.0.1:17443"
  },
  "whitelists": $ENABLE_WHITELISTS
}
EOF

cat >&2 <<EOF

Дальше:
  1) если это bridge: передайте его pubkey на exit и выполните там
     ./cascade-exit-setup.sh --add-peer $BRIDGE_PUB --allowed-ips 10.201.0.2/32,10.202.0.0/24
  2) проверка: ./cascade-healthcheck.sh --role $ROLE

EOF

log "готово"
