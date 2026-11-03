#!/usr/bin/env bash
# XIO Cascade — раздельное туннелирование по белым спискам (на bridge, IPv4).
#
# Скрипт скачивает списки по URL из whitelists.conf, разворачивает домены в IPv4,
# собирает nft-сет xio_whitelist4 и применяет его одной атомарной транзакцией
# внутри контейнера bridge. Правила split-tunneling уже ссылаются на этот сет
# (см. nft-bridge.sh, создаётся cascade-bridge-setup.sh):
#   помеченный трафик -> таблица 200 -> default dev wg0 -> exit.
#
# Атомарность и откат:
#   * новый набор готовится в файле и применяется `nft -f` одной транзакцией:
#     либо весь новый список, либо прежний — промежуточного состояния нет;
#   * предыдущая версия сохраняется рядом (whitelist-previous.nft), откат — --rollback.
#
# Обновление по расписанию:
#   * --install-timer   systemd timer (воскресенье, 04:17) или cron.d, если systemd нет;
#   * --remove-timer    снять таймер.
#
# Примеры:
#   ./whitelist-update.sh --dry-run
#   ./whitelist-update.sh --config ./data/whitelists.conf --runtime docker
#   ./whitelist-update.sh --install-timer
#   ./whitelist-update.sh --rollback

set -eu
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P) || exit 1

DATA_DIR="$SCRIPT_DIR/data/bridge"
CONFIG="$SCRIPT_DIR/data/whitelists.conf"
RUNTIME=""
CONTAINER="xio-cascade-bridge"
DRY_RUN=0
INSTALL_TIMER=0
REMOVE_TIMER=0
ROLLBACK=0
TIMEOUT=30
MAX_ENTRIES=200000
VERBOSE=0
TMP_DIR=""

log() { printf '[whitelist] %s\n' "$*" >&2; }
warn() { printf '[whitelist] warning: %s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }
need_arg() { [ "$#" -ge 2 ] || die "опция $1 требует значение"; }

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf -- "$TMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
whitelist-update — белые списки XIO Cascade на bridge (IPv4)

  --config <path>        whitelists.conf (URL-ы построчно)
  --data-dir <path>      каталог состояния bridge (для current/previous и лога)
  --runtime docker|podman
  --container <name>     контейнер bridge (по умолчанию xio-cascade-bridge)
  --timeout <sec>        таймаут скачивания одного списка (по умолчанию 30)
  --max-entries <n>      предохранитель от гигантских списков (по умолчанию 200000)
  --dry-run              скачать и собрать, но не применять
  --rollback             вернуть предыдущий применённый набор
  --install-timer        поставить еженедельное обновление (systemd timer / cron)
  --remove-timer         снять таймер
  --verbose              печатать прогресс по каждому источнику
  -h, --help             справка

Формат whitelists.conf:
  # комментарий
  https://example.org/list.txt          просто URL
  ru-direct=https://example.org/ru.txt  имя=URL (имя попадает в лог)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)        need_arg "$@"; CONFIG=$2; shift 2 ;;
        --config=*)      CONFIG=${1#*=}; shift ;;
        --data-dir)      need_arg "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*)    DATA_DIR=${1#*=}; shift ;;
        --runtime)       need_arg "$@"; RUNTIME=$2; shift 2 ;;
        --runtime=*)     RUNTIME=${1#*=}; shift ;;
        --container)     need_arg "$@"; CONTAINER=$2; shift 2 ;;
        --container=*)   CONTAINER=${1#*=}; shift ;;
        --timeout)       need_arg "$@"; TIMEOUT=$2; shift 2 ;;
        --max-entries)   need_arg "$@"; MAX_ENTRIES=$2; shift 2 ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --rollback)      ROLLBACK=1; shift ;;
        --install-timer) INSTALL_TIMER=1; shift ;;
        --remove-timer)  REMOVE_TIMER=1; shift ;;
        --verbose)       VERBOSE=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout должен быть числом" ;; esac
case "$MAX_ENTRIES" in ''|*[!0-9]*) die "--max-entries должен быть числом" ;; esac

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "не найдена команда «$1»"; }

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
        RUNTIME=docker
        warn "docker/podman не отвечает: будут доступны только --dry-run/--install-timer"
    fi
fi

require_root_for_write() {
    [ "$(id -u)" -eq 0 ] || die "нужны права root (nft внутри контейнера и системный таймер)"
}

mkdir -p -- "$DATA_DIR"
chmod 700 "$DATA_DIR"
LOG_FILE="$DATA_DIR/whitelist.log"

logline() {
    local msg=$1
    printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/ }
    printf '%s' "$s"
}

# --- снятие/установка таймера ----------------------------------------------
install_timer() {
    require_root_for_write
    local script_path="$SCRIPT_DIR/$SCRIPT_NAME"
    local unit_service="/etc/systemd/system/xio-whitelist-update.service"
    local unit_timer="/etc/systemd/system/xio-whitelist-update.timer"
    local exec_line="/bin/bash $script_path --config $CONFIG --data-dir $DATA_DIR --container $CONTAINER --runtime $RUNTIME"

    if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
        cat > "$unit_service" <<EOF
[Unit]
Description=XIO Cascade: обновление белых списков (nft xio_whitelist4)
Documentation=file://$SCRIPT_DIR/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$exec_line
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=yes
EOF
        cat > "$unit_timer" <<'EOF'
[Unit]
Description=XIO Cascade: еженедельное обновление белых списков

[Timer]
OnCalendar=Sun *-*-* 04:17:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now xio-whitelist-update.timer >/dev/null 2>&1 || \
            warn "не удалось включить таймер, проверьте: systemctl status xio-whitelist-update.timer"
        log "таймер systemd установлен: Sun 04:17, Persistent=true ($unit_timer)"
        logline "timer installed: systemd"
    elif [ -d /etc/cron.d ]; then
        printf '# XIO Cascade: еженедельное обновление белых списков\n17 4 * * 0 root %s\n' "$exec_line" \
            > /etc/cron.d/xio-whitelist
        chmod 644 /etc/cron.d/xio-whitelist
        log "cron.d установлен: /etc/cron.d/xio-whitelist (Sun 04:17)"
        logline "timer installed: cron"
    else
        die "ни systemd, ни cron.d не найдены: поставьте обновление вручную"
    fi
}

remove_timer() {
    require_root_for_write
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now xio-whitelist-update.timer >/dev/null 2>&1 || true
    fi
    rm -f -- /etc/systemd/system/xio-whitelist-update.service \
        /etc/systemd/system/xio-whitelist-update.timer /etc/cron.d/xio-whitelist 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    log "таймер обновления снят"
    logline "timer removed"
}

if [ "$INSTALL_TIMER" -eq 1 ]; then
    [ "$ROLLBACK" -eq 0 ] || die "--install-timer и --rollback несовместимы"
    [ -f "$CONFIG" ] || die "конфиг не найден: $CONFIG (таймер будет запускать именно его)"
    install_timer
    exit 0
fi
if [ "$REMOVE_TIMER" -eq 1 ]; then
    remove_timer
    exit 0
fi

# --- откат ------------------------------------------------------------------
CURRENT="$DATA_DIR/whitelist-current.nft"
PREVIOUS="$DATA_DIR/whitelist-previous.nft"

apply_nft_file() {
    local file=$1
    [ -s "$file" ] || die "пустой nft-файл: $file"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: применил бы $file ($(wc -l < "$file" | tr -d ' ') строк)"
        return 0
    fi
    require_root_for_write
    "$RUNTIME" container inspect "$CONTAINER" >/dev/null 2>&1 \
        || die "контейнер $CONTAINER не найден: сначала запустите cascade-install.sh"
    [ "$("$RUNTIME" inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || printf false)" = "true" ] \
        || die "контейнер $CONTAINER не запущен"
    if ! "$RUNTIME" exec -i "$CONTAINER" nft -f - < "$file" 2>>"$LOG_FILE"; then
        die "nft -f завершился ошибкой (см. $LOG_FILE); прежний набор не изменён"
    fi
    log "применено: $file"
}

if [ "$ROLLBACK" -eq 1 ]; then
    [ -s "$PREVIOUS" ] || die "нет предыдущего набора ($PREVIOUS): откатывать нечего"
    log "откат на предыдущий набор"
    apply_nft_file "$PREVIOUS"
    if [ "$DRY_RUN" -eq 0 ]; then cp -f -- "$PREVIOUS" "$CURRENT"; chmod 600 "$CURRENT"; fi
    logline "rollback applied"
    printf '{"ok": true, "action": "rollback", "file": "%s", "dry_run": %s}\n' \
        "$(json_escape "$PREVIOUS")" "$([ "$DRY_RUN" -eq 1 ] && printf true || printf false)"
    exit 0
fi

# --- сборка списка ----------------------------------------------------------
[ -f "$CONFIG" ] && [ -r "$CONFIG" ] || die "не читается конфиг: $CONFIG (пример — whitelists.conf в репозитории)"
need_cmd sed
need_cmd sort
need_cmd wc
need_cmd awk

DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER=wget
else
    die "нужен curl или wget для скачивания списков"
fi

RESOLVER=""
if command -v getent >/dev/null 2>&1; then
    RESOLVER=getent
fi

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xio-whitelist.XXXXXX")
chmod 700 "$TMP_DIR"
RAW="$TMP_DIR/raw.txt"
IPS="$TMP_DIR/ips.txt"
ADDRS="$TMP_DIR/addr.txt"
BODY="$TMP_DIR/set.nft"
: > "$RAW"
: > "$ADDRS"

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

SOURCE_COUNT=0
FETCH_FAILED=0
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*) continue ;; esac
    name=""
    url=$line
    case "$line" in
        *=http://*|*=https://*)
            name=${line%%=*}
            url=${line#*=}
            ;;
    esac
    url=$(trim "$url")
    name=$(trim "$name")
    [ -n "$name" ] || name="source$((SOURCE_COUNT + 1))"
    case "$url" in
        https://*|http://*) ;;
        *) warn "пропускаю не-http(s) строку: $line"; continue ;;
    esac
    SOURCE_COUNT=$((SOURCE_COUNT + 1))
    [ "$VERBOSE" -eq 1 ] && log "скачиваю [$name] $url"
    out="$TMP_DIR/list.$SOURCE_COUNT.txt"
    ok=0
    if [ "$DOWNLOADER" = "curl" ]; then
        if curl -fsSL --max-time "$TIMEOUT" --retry 2 --retry-delay 2 -o "$out" "$url" 2>>"$LOG_FILE"; then ok=1; fi
    else
        if wget -q -T "$TIMEOUT" -t 2 -O "$out" "$url" 2>>"$LOG_FILE"; then ok=1; fi
    fi
    if [ "$ok" -ne 1 ]; then
        FETCH_FAILED=$((FETCH_FAILED + 1))
        warn "не удалось скачать [$name] $url — список пропущен (прежние записи этого источника останутся в current)"
        logline "fetch failed: $name $url"
        continue
    fi
    # имя источника как комментарий, дальше — его строки
    printf '# source: %s %s\n' "$name" "$url" >> "$RAW"
    sed -e 's/#.*//' -e 's/\r$//' "$out" >> "$RAW"
done < "$CONFIG"

# --- нормализация -----------------------------------------------------------
DOMAINS="$TMP_DIR/domains.txt"
: > "$DOMAINS"
BAD=0
while IFS= read -r entry; do
    entry=$(trim "$entry")
    [ -n "$entry" ] || continue
    case "$entry" in
        *[!a-zA-Z0-9.\-_/:,]*) BAD=$((BAD + 1)); continue ;;
    esac
    if [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]; then
        printf '%s\n' "$entry" >> "$ADDRS"
    elif [[ $entry =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,62}$ ]]; then
        printf '%s\n' "$entry" >> "$DOMAINS"
    else
        BAD=$((BAD + 1))
    fi
done < "$RAW"

if [ "$RESOLVER" = "getent" ]; then
    : > "$IPS"
    RESOLVED=0
    while IFS= read -r domain; do
        [ -n "$domain" ] || continue
        [ "$RESOLVED" -lt 5000 ] || { warn "больше 5000 доменов: остальные не разворачиваю"; break; }
        getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' >> "$IPS" || true
        RESOLVED=$((RESOLVED + 1))
    done < "$DOMAINS"
    cat "$IPS" >> "$ADDRS"
else
    warn "getent недоступен: домены не развёрнуты в IPv4, в сет попадут только IP/CIDR"
fi

sort -u "$ADDRS" -o "$ADDRS"
ENTRIES=$(wc -l < "$ADDRS" | tr -d ' ')
if [ "$ENTRIES" -gt "$MAX_ENTRIES" ]; then
    die "записей $ENTRIES > --max-entries $MAX_ENTRIES: похоже на мусорный список, применение отменено"
fi
if [ "$ENTRIES" -eq 0 ]; then
    die "после нормализации не осталось ни одного адреса: пустой сет сломал бы split-tunneling"
fi

# --- nft-файл ---------------------------------------------------------------
{
    printf '# Сгенерировано whitelist-update.sh, %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '# источников: %s, записей: %s (домены развёрнуты в IPv4)\n' "$SOURCE_COUNT" "$ENTRIES"
    printf 'table inet xio_cascade {\n'
    printf '  flush set inet xio_cascade xio_whitelist4\n'
    printf '  add element inet xio_cascade xio_whitelist4 { '
    awk 'BEGIN{ORS=""} {if (n++) printf ", "; printf "%s", $0}' "$ADDRS"
    printf ' }\n'
    printf '}\n'
} > "$BODY"

log "источников: $SOURCE_COUNT (ошибок скачивания: $FETCH_FAILED), доменов: $(wc -l < "$DOMAINS" | tr -d ' '), записей: $ENTRIES, отброшено: $BAD"
logline "build: sources=$SOURCE_COUNT failed=$FETCH_FAILED entries=$ENTRIES bad=$BAD"

if [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run: файл nft ($(wc -l < "$BODY" | tr -d ' ') строк) НЕ применён"
    printf '{"ok": true, "dry_run": true, "sources": %s, "fetch_failed": %s, "entries": %s, "rejected": %s}\n' \
        "$SOURCE_COUNT" "$FETCH_FAILED" "$ENTRIES" "$BAD"
    exit 0
fi

require_root_for_write
if [ -s "$CURRENT" ]; then
    cp -f -- "$CURRENT" "$PREVIOUS"
    chmod 600 "$PREVIOUS"
fi
cp -f -- "$BODY" "$CURRENT.tmp"
chmod 600 "$CURRENT.tmp"
apply_nft_file "$CURRENT.tmp"
mv -f -- "$CURRENT.tmp" "$CURRENT"
chmod 600 "$CURRENT"

# контроль: сет реально существует и непуст
if "$RUNTIME" exec "$CONTAINER" nft list set inet xio_cascade xio_whitelist4 >/dev/null 2>&1; then
    log "сет xio_whitelist4 применён и виден в контейнере"
else
    warn "после применения сет не читается — проверьте nft-bridge.sh и таблицу inet xio_cascade"
fi
logline "applied: entries=$ENTRIES"

printf '{"ok": true, "dry_run": false, "sources": %s, "fetch_failed": %s, "entries": %s, "rejected": %s, "file": "%s"}\n' \
    "$SOURCE_COUNT" "$FETCH_FAILED" "$ENTRIES" "$BAD" "$(json_escape "$CURRENT")"
