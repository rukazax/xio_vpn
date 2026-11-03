#!/usr/bin/env bash
# XIO Cascade — healthcheck последовательной схемы bridge -> exit.
#
# Проверяет и печатает JSON {"ok": true|false, "checks": [...]} в stdout.
# В stderr — только человекочитаемый прогресс. Ключи и секреты не печатаются.
#
# Проверки:
#   1. контейнерный движок и контейнеры роли запущены;
#   2. туннельные интерфейсы существуют (wg0 на exit, wg0+wg1 на bridge);
#   3. в туннеле есть peers;
#   4. рукопожатие свежее (по умолчанию не старше 180 секунд);
#   5. у exit есть глобальный IPv6;
#   6. выходной IPv6 реальный: exit сам ходит в IPv6-интернет;
#   7. на bridge: маршрут до exit по IPv6 и непустой nft-сет xio_whitelist4.
#
# Запуск:
#   ./cascade-healthcheck.sh                    # автоопределение роли по ./data
#   ./cascade-healthcheck.sh --role bridge --max-handshake 300
#   ./cascade-healthcheck.sh --json-strict      # только JSON, без логов в stderr
#
# Коды выхода: 0 — ok=true, 1 — ok=false, 2 — ошибка аргументов.

set -eu
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1

ROLE=""
DATA_DIR="$SCRIPT_DIR/data"
RUNTIME=""
EXIT_CONTAINER="xio-cascade-exit"
BRIDGE_CONTAINER="xio-cascade-bridge"
EXIT_HOST=""
MAX_HANDSHAKE=180
TIMEOUT=8
EGRESS_URL="https://ifconfig.co/ip"
STRICT_QUIET=0
CHECK_WHITELIST=1

log() { [ "$STRICT_QUIET" -eq 1 ] || printf '[health] %s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 2; }
need_arg() { [ "$#" -ge 2 ] || die "опция $1 требует значение"; }

usage() {
    cat <<'EOF'
healthcheck — проверка схемы XIO Cascade

  --role bridge|exit|both   какую часть проверять (по умолчанию — по каталогу ./data)
  --data-dir <path>         каталог состояния (по умолчанию ./data)
  --runtime docker|podman   движок (по умолчанию — автоопределение)
  --exit-container <name>   имя контейнера exit (xio-cascade-exit)
  --bridge-container <name> имя контейнера bridge (xio-cascade-bridge)
  --exit-host <ipv6>        IPv6 exit (если не читается из state.json)
  --max-handshake <sec>     допустимый возраст рукопожатия (по умолчанию 180)
  --timeout <sec>           таймаут сетевых проверок (по умолчанию 8)
  --egress-url <url>        URL для проверки выходного IPv6
  --no-whitelist-check      не проверять nft-сет белых списков
  --json-strict             не писать ничего в stderr, только JSON в stdout
  -h, --help                справка
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --role)             need_arg "$@"; ROLE=$2; shift 2 ;;
        --role=*)           ROLE=${1#*=}; shift ;;
        --data-dir)         need_arg "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*)       DATA_DIR=${1#*=}; shift ;;
        --runtime)          need_arg "$@"; RUNTIME=$2; shift 2 ;;
        --runtime=*)        RUNTIME=${1#*=}; shift ;;
        --exit-container)   need_arg "$@"; EXIT_CONTAINER=$2; shift 2 ;;
        --bridge-container) need_arg "$@"; BRIDGE_CONTAINER=$2; shift 2 ;;
        --exit-host)        need_arg "$@"; EXIT_HOST=$2; shift 2 ;;
        --exit-host=*)      EXIT_HOST=${1#*=}; shift ;;
        --max-handshake)    need_arg "$@"; MAX_HANDSHAKE=$2; shift 2 ;;
        --max-handshake=*)  MAX_HANDSHAKE=${1#*=}; shift ;;
        --timeout)          need_arg "$@"; TIMEOUT=$2; shift 2 ;;
        --timeout=*)        TIMEOUT=${1#*=}; shift ;;
        --egress-url)       need_arg "$@"; EGRESS_URL=$2; shift 2 ;;
        --egress-url=*)     EGRESS_URL=${1#*=}; shift ;;
        --no-whitelist-check) CHECK_WHITELIST=0; shift ;;
        --json-strict)      STRICT_QUIET=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *) die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

case "$MAX_HANDSHAKE" in ''|*[!0-9]*) die "--max-handshake должен быть числом" ;; esac
case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout должен быть числом" ;; esac

# --- определение роли -------------------------------------------------------
if [ -z "$ROLE" ]; then
    if [ -r "$DATA_DIR/bridge/state.json" ]; then
        ROLE="bridge"
    elif [ -r "$DATA_DIR/exit/state.json" ]; then
        ROLE="exit"
    else
        ROLE="both"
    fi
    log "роль определена по данным: $ROLE"
fi
case "$ROLE" in bridge|exit|both) ;; *) die "--role: ожидается bridge, exit или both" ;; esac

# --- движок -----------------------------------------------------------------
detect_runtime() {
    local c
    for c in docker podman; do
        if command -v "$c" >/dev/null 2>&1 && "$c" info >/dev/null 2>&1; then
            RUNTIME=$c
            return 0
        fi
    done
    return 1
}
if [ -z "$RUNTIME" ]; then
    if ! detect_runtime; then
        printf '{"ok": false, "error": "не найден рабочий docker/podman", "checks": []}\n'
        exit 1
    fi
fi
command -v "$RUNTIME" >/dev/null 2>&1 || die "движок $RUNTIME не найден в PATH"

state_get() {
    local file=$1 key=$2
    [ -r "$file" ] || return 0
    sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n 1
}
[ -n "$EXIT_HOST" ] || EXIT_HOST=$(state_get "$DATA_DIR/exit/state.json" ipv6)
[ -n "$EXIT_HOST" ] || EXIT_HOST=$(state_get "$DATA_DIR/bridge/state.json" exit_host)

json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/ }
    s=${s//$'\t'/ }
    printf '%s' "$s"
}

CHECKS=""
FAILED=0
check() {
    local name=$1 ok=$2 detail=$3
    [ "$ok" -eq 1 ] || FAILED=1
    if [ -n "$CHECKS" ]; then CHECKS="$CHECKS,"; fi
    CHECKS="$CHECKS{\"name\":\"$(json_escape "$name")\",\"ok\":$([ "$ok" -eq 1 ] && printf true || printf false),\"detail\":\"$(json_escape "$detail")\"}"
    log "$([ "$ok" -eq 1 ] && printf 'ok  ' || printf 'FAIL') $name: $detail"
}

c_run() { # c_run <container> <cmd...> — stdout+stderr, статус возвращается
    "$RUNTIME" exec "$1" "${@:2}" 2>&1
}

container_running() {
    [ "$("$RUNTIME" inspect -f '{{.State.Running}}' "$1" 2>/dev/null || printf 'false')" = "true" ]
}

# Возраст самого свежего рукопожатия в секундах (-1 — рукопожатий не было).
handshake_age() {
    local container=$1 iface=$2 raw now
    raw=$(c_run "$container" sh -c "wg show $iface latest-handshakes 2>/dev/null" || true)
    [ -n "$raw" ] || { printf '%s' "-1"; return 0; }
    now=$(date +%s)
    printf '%s\n' "$raw" | awk -v now="$now" '
        NF >= 2 { t = $2 + 0; if (t > 0) { a = now - t; if (m < 0 || a < m) m = a } }
        END { if (m < 0) print -1; else print m }
    '
}

if [ "$ROLE" = "exit" ] || [ "$ROLE" = "both" ]; then
    if container_running "$EXIT_CONTAINER"; then
        check "exit.container" 1 "$EXIT_CONTAINER запущен"
    else
        check "exit.container" 0 "контейнер $EXIT_CONTAINER не запущен"
    fi
fi
if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    if container_running "$BRIDGE_CONTAINER"; then
        check "bridge.container" 1 "$BRIDGE_CONTAINER запущен"
    else
        check "bridge.container" 0 "контейнер $BRIDGE_CONTAINER не запущен"
    fi
fi

# --- проверки exit ----------------------------------------------------------
if [ "$ROLE" = "exit" ] || [ "$ROLE" = "both" ]; then
    if container_running "$EXIT_CONTAINER"; then
        ifaces=$(c_run "$EXIT_CONTAINER" sh -c 'wg show interfaces 2>/dev/null || true')
        case " $ifaces " in
            *" wg0 "*)
                check "exit.tunnel" 1 "интерфейс wg0 поднят" ;;
            *)
                check "exit.tunnel" 0 "интерфейс wg0 отсутствует (wg: ${ifaces:-нет})" ;;
        esac

        peers=$(c_run "$EXIT_CONTAINER" sh -c 'wg show wg0 peers 2>/dev/null | wc -l | tr -d " "' || printf '0')
        if [ "${peers:-0}" -gt 0 ]; then
            check "exit.peers" 1 "peers в туннеле: $peers"
        else
            check "exit.peers" 0 "нет ни одного peer — bridge не зарегистрирован"
        fi

        global6=$(c_run "$EXIT_CONTAINER" sh -c 'ip -6 -o addr show scope global 2>/dev/null | awk "{print \$4}" | cut -d/ -f1 | head -n 1' || true)
        case "$global6" in
            fe80:*|'') check "exit.ipv6" 0 "у exit нет глобального IPv6" ;;
            *) check "exit.ipv6" 1 "глобальный IPv6: $global6" ;;
        esac

        egress=$(c_run "$EXIT_CONTAINER" sh -c "curl -6 -sS --max-time $TIMEOUT '$EGRESS_URL' 2>/dev/null | tr -d '\\n'" || true)
        case "$egress" in
            *:*) check "exit.egress6" 1 "выходной IPv6: $egress" ;;
            '')  check "exit.egress6" 0 "нет ответа по IPv6 от $EGRESS_URL (curl/timeout)" ;;
            *)   check "exit.egress6" 0 "в ответе не IPv6: $egress" ;;
        esac
    fi
fi

# --- проверки bridge --------------------------------------------------------
if [ "$ROLE" = "bridge" ] || [ "$ROLE" = "both" ]; then
    if container_running "$BRIDGE_CONTAINER"; then
        ifaces=$(c_run "$BRIDGE_CONTAINER" sh -c 'wg show interfaces 2>/dev/null || true')
        TUN_UP=0
        case " $ifaces " in *" wg0 "*) case " $ifaces " in *" wg1 "*) TUN_UP=1 ;; esac ;; esac
        if [ "$TUN_UP" -eq 1 ]; then
            check "bridge.tunnel" 1 "интерфейсы wg0 (exit) и wg1 (устройства) подняты"
        else
            check "bridge.tunnel" 0 "не все интерфейсы подняты (wg: ${ifaces:-нет})"
        fi

        if [ -n "$EXIT_HOST" ]; then
            reach=$(c_run "$BRIDGE_CONTAINER" sh -c "ip -6 route get $EXIT_HOST 2>/dev/null | head -n 1" || true)
            if [ -n "$reach" ]; then
                check "bridge.exit_route" 1 "маршрут до [$EXIT_HOST] есть"
            else
                check "bridge.exit_route" 0 "нет IPv6-маршрута до [$EXIT_HOST]"
            fi
        else
            check "bridge.exit_route" 0 "не известен IPv6 exit (--exit-host или state.json)"
        fi

        age=$(handshake_age "$BRIDGE_CONTAINER" wg0)
        if [ "${age:--1}" -ge 0 ] && [ "${age:--1}" -le "$MAX_HANDSHAKE" ]; then
            check "bridge.handshake" 1 "рукопожатие ${age}с назад (лимит ${MAX_HANDSHAKE}с)"
        elif [ "${age:--1}" -lt 0 ]; then
            check "bridge.handshake" 0 "рукопожатия не было — туннель до exit не установлен"
        else
            check "bridge.handshake" 0 "рукопожатие устарело: ${age}с > ${MAX_HANDSHAKE}с"
        fi

        if [ "$CHECK_WHITELIST" -eq 1 ]; then
            wl=$(c_run "$BRIDGE_CONTAINER" sh -c 'nft list set inet xio_cascade xio_whitelist4 2>/dev/null | grep -c "elements"' || true)
            if [ "${wl:-0}" -ge 1 ]; then
                check "bridge.whitelist" 1 "nft-сет xio_whitelist4 существует"
            else
                check "bridge.whitelist" 0 "нет сета xio_whitelist4 (правила split-tunneling не применены)"
            fi
        fi
    fi
fi

if [ "$ROLE" = "exit" ] || [ "$ROLE" = "both" ]; then
    if container_running "$EXIT_CONTAINER"; then
        age=$(handshake_age "$EXIT_CONTAINER" wg0)
        if [ "${age:--1}" -ge 0 ] && [ "${age:--1}" -le "$MAX_HANDSHAKE" ]; then
            check "exit.handshake" 1 "рукопожатие ${age}с назад"
        else
            check "exit.handshake" 0 "нет свежего рукопожатия с bridge (${age}с)"
        fi
    fi
fi

NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
if [ "$FAILED" -eq 0 ]; then
    OK_JSON=true
else
    OK_JSON=false
fi

printf '{"ok": %s, "role": "%s", "time": "%s", "runtime": "%s", "exit_host": "%s", "checks": [%s]}\n' \
    "$OK_JSON" "$(json_escape "$ROLE")" "$NOW" "$(json_escape "$RUNTIME")" \
    "$(json_escape "$EXIT_HOST")" "$CHECKS"

[ "$FAILED" -eq 0 ] || exit 1
exit 0
