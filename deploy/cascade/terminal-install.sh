#!/usr/bin/env bash
# XIO Cascade — установка «одной командой» из терминала.
#
# Пример:
#   curl -fsSL https://raw.githubusercontent.com/rukazax/xio_vpn/main/deploy/cascade/terminal-install.sh \
#     | sudo bash -s -- --unattended --role bridge --exit-host 2a01:4f8::10 --exit-pubkey <b64>
#
# Что делает:
#   1. скачивает cascade-install.sh по HTTPS (не запускает поток curl|bash напрямую);
#   2. проверяет sha256 скачанного файла (пин встроен, переопределяется --sha256);
#   3. только после совпадения запускает установщик и пишет полный лог
#      в /var/log/xio-cascade-install.log (права 600);
#   4. возвращает код установщика.
#
# --unattended отключает подтверждение и делает запуск неинтерактивным.
# В лог не попадают секреты: скрипты не печатают ключи, а --token-file читается
# целевым установщиком, а не этим логгером.
#
# Коды выхода: 0 — успех, 1 — ошибка проверки/скачивания, 2 — неверные аргументы,
#              иначе — код, который вернул cascade-install.sh.

set -eu
set -o pipefail
umask 077
export LC_ALL=C

SCRIPT_NAME=${0##*/}

DEFAULT_URL="https://raw.githubusercontent.com/rukazax/xio_vpn/main/deploy/cascade/cascade-install.sh"

# Пин на конкретную ревизию установщика. Обновляется вместе с файлом;
# пока стоит заглушка, запуск требует --sha256 или явного --allow-unpinned.
PINNED_SHA256="0000000000000000000000000000000000000000000000000000000000000000"

URL=$DEFAULT_URL
EXPECTED_SHA=${CASCADE_SHA256:-}
LOG_FILE=/var/log/xio-cascade-install.log
UNATTENDED=0
ALLOW_UNPINNED=0
INSTALL_ARGS=""

log() { printf '[terminal-install] %s\n' "$*"; }
warn() { printf '[terminal-install] warning: %s\n' "$*" >&2; }
die() { printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }
need_arg() { [ "$#" -ge 2 ] || die "опция $1 требует значение"; }

usage() {
    cat <<EOF
terminal-install — одна команда для установки XIO Cascade

  --sha256 <hex>     ожидаемая sha256-сумма cascade-install.sh (обязательна,
                     если встроенный пин — заглушка)
  --url <url>        откуда скачивать установщик (по умолчанию raw.githubusercontent.com)
  --log <path>       файл лога (по умолчанию /var/log/xio-cascade-install.log)
  --unattended       без подтверждений, неинтерактивно
  --allow-unpinned   разрешить запуск без совпавшей контрольной суммы (опасно)
  -h, --help         справка

Всё, что не опознано как опция этого скрипта, передаётся установщику,
например: --role bridge --exit-host 2a01:4f8::10 --port 9443
EOF
}

TMP_DIR=""
cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf -- "$TMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --sha256)        need_arg "$@"; EXPECTED_SHA=$2; shift 2 ;;
        --sha256=*)      EXPECTED_SHA=${1#*=}; shift ;;
        --url)           need_arg "$@"; URL=$2; shift 2 ;;
        --url=*)         URL=${1#*=}; shift ;;
        --log)           need_arg "$@"; LOG_FILE=$2; shift 2 ;;
        --log=*)         LOG_FILE=${1#*=}; shift ;;
        --unattended)    UNATTENDED=1; shift ;;
        --allow-unpinned) ALLOW_UNPINNED=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        --)              shift
                         while [ "$#" -gt 0 ]; do INSTALL_ARGS="$INSTALL_ARGS $1"; shift; done
                         break ;;
        *)               INSTALL_ARGS="$INSTALL_ARGS $1"; shift ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "нужны права root: sudo bash -s -- ..."
command -v curl >/dev/null 2>&1 || die "не найден curl (apt-get install -y curl)"
command -v sha256sum >/dev/null 2>&1 || die "не найден sha256sum (пакет coreutils)"

case "$URL" in
    https://*) ;;
    http://*) die "только https: установщик с http запускать нельзя" ;;
    *) die "неподдерживаемая схема URL: $URL" ;;
esac

case "$EXPECTED_SHA" in
    '')
        if [ "$PINNED_SHA256" = "0000000000000000000000000000000000000000000000000000000000000000" ]; then
            if [ "$ALLOW_UNPINNED" -eq 1 ]; then
                warn "контрольная сумма не задана и пин — заглушка; запуск разрешён --allow-unpinned"
            else
                die "нет ожидаемой sha256: передайте --sha256 <hex> (или --allow-unpinned, если доверяете каналу)"
            fi
        else
            EXPECTED_SHA=$PINNED_SHA256
        fi
        ;;
    *)
        case "$EXPECTED_SHA" in
            *[!0-9a-fA-F]*) die "--sha256: ожидается hex-строка" ;;
        esac
        [ "${#EXPECTED_SHA}" -eq 64 ] || die "--sha256: ожидается 64 hex-символа"
        EXPECTED_SHA=$(printf '%s' "$EXPECTED_SHA" | tr 'A-F' 'a-f')
        ;;
esac

# --- подготовка лога --------------------------------------------------------
LOG_DIR=$(dirname -- "$LOG_FILE")
[ -d "$LOG_DIR" ] || mkdir -p -- "$LOG_DIR"
# log-файл не должен ломать работу, если файловая система только для чтения
if ! : >> "$LOG_FILE" 2>/dev/null; then
    warn "не удалось открыть $LOG_FILE на запись — продолжаю без лога"
    LOG_FILE=""
else
    chmod 600 "$LOG_FILE" 2>/dev/null || true
fi

logfile() {
    [ -n "$LOG_FILE" ] || return 0
    printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$LOG_FILE" || true
}

logfile "=== start: url=$URL sha256=${EXPECTED_SHA:-unpinned} args=${INSTALL_ARGS:-none} ==="
log "источник: $URL"

# --- скачивание -------------------------------------------------------------
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xio-terminal-install.XXXXXX")
chmod 700 "$TMP_DIR"
TARGET="$TMP_DIR/cascade-install.sh"

log "скачиваю установщик"
if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 120 --retry 2 --retry-delay 3 -o "$TARGET" "$URL"; then
    logfile "download failed"
    die "не удалось скачать $URL"
fi
[ -s "$TARGET" ] || die "скачанный файл пуст"
FIRST_LINE=$(head -n 1 "$TARGET" || true)
case "$FIRST_LINE" in
    '#!'*bash*) ;;
    *) die "скачанный файл не похож на bash-скрипт установщика (первая строка: $FIRST_LINE)" ;;
esac

ACTUAL_SHA=$(sha256sum "$TARGET" | awk '{print $1}')
log "sha256: $ACTUAL_SHA"
if [ -n "$EXPECTED_SHA" ]; then
    if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        logfile "sha256 mismatch: expected=$EXPECTED_SHA actual=$ACTUAL_SHA"
        die "sha256 не совпала (ожидалось $EXPECTED_SHA, получено $ACTUAL_SHA) — запуск отменён"
    fi
    log "контрольная сумма совпала"
    logfile "sha256 ok: $ACTUAL_SHA"
else
    warn "контрольная сумма не проверялась (--allow-unpinned)"
fi

# --- подтверждение ----------------------------------------------------------
if [ "$UNATTENDED" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
    printf 'Запустить установку XIO Cascade с аргументами:%s\n' "${INSTALL_ARGS:- (нет)}" >&2
    printf 'Продолжить? [y/N] ' >&2
    read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) die "отменено пользователем" ;;
    esac
fi

# --- запуск -----------------------------------------------------------------
chmod 700 "$TARGET"
if [ -n "$LOG_FILE" ]; then
    log "запускаю установщик, лог: $LOG_FILE"
    logfile "exec: bash cascade-install.sh $INSTALL_ARGS"
    # shellcheck disable=SC2086
    if bash "$TARGET" $INSTALL_ARGS 2>&1 | tee -a "$LOG_FILE"; then
        STATUS=0
    else
        STATUS=$?
    fi
else
    # shellcheck disable=SC2086
    if bash "$TARGET" $INSTALL_ARGS; then STATUS=0; else STATUS=$?; fi
fi
logfile "=== finish: status=$STATUS ==="

if [ "$STATUS" -eq 0 ]; then
    log "установка завершена успешно"
else
    log "установка завершилась с кодом $STATUS (см. $LOG_FILE)"
fi
exit "$STATUS"
