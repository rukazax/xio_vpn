#!/bin/sh
# XIO Cascade — entrypoint контейнера.
#
# Роль берётся из CASCADE_ROLE (bridge|exit), конфиги — из /data (том):
#   exit:   /data/wg0.conf                     — туннель до bridge
#   bridge: /data/wg0.conf (туннель до exit) и /data/wg1.conf (приём устройств)
#
# Скрипт ждёт появления конфигов, поднимает интерфейсы wg-quick, затем держит
# контейнер живым. По SIGTERM/SIGINT интерфейсы опускаются.
# Секреты (PrivateKey/PresharedKey) в логи не попадают.

set -eu
umask 077
export LC_ALL=C

LOG_PREFIX="xio-cascade"
log() { printf '%s: %s\n' "$LOG_PREFIX" "$*" >&2; }
die() { printf '%s: error: %s\n' "$LOG_PREFIX" "$*" >&2; exit 1; }

ROLE=${CASCADE_ROLE:-}
case "$ROLE" in
    bridge|exit) ;;
    '') die "не задан CASCADE_ROLE (bridge|exit)" ;;
    *) die "неизвестный CASCADE_ROLE=$ROLE (ожидается bridge или exit)" ;;
esac

DATA_DIR=${CASCADE_DATA_DIR:-/data}
CONFIG_TIMEOUT=${CASCADE_CONFIG_TIMEOUT:-120}

command -v wg >/dev/null 2>&1 || die "в образе нет wg (пересоберите образ)"
command -v wg-quick >/dev/null 2>&1 || die "в образе нет wg-quick"

case "$ROLE" in
    exit)   CONFIGS="wg0" ;;
    bridge) CONFIGS="wg0 wg1" ;;
esac

log "роль: $ROLE, данные: $DATA_DIR, конфиги: $CONFIGS"

# --- 1. ждём конфиги --------------------------------------------------------
wait_for_configs() {
    waited=0
    while :; do
        missing=""
        for iface in $CONFIGS; do
            conf="$DATA_DIR/$iface.conf"
            if [ ! -s "$conf" ]; then
                missing="$missing $iface.conf"
            fi
        done
        [ -z "$missing" ] && return 0
        if [ "$waited" -ge "$CONFIG_TIMEOUT" ]; then
            log "нет конфигов:$missing — время ожидания ${CONFIG_TIMEOUT}с истекло"
            return 1
        fi
        [ "$waited" -eq 0 ] && log "жду конфиги:$missing (до ${CONFIG_TIMEOUT}с)"
        sleep 2
        waited=$((waited + 2))
    done
}

wait_for_configs || die "конфигов нет: сначала выполните cascade-install.sh / cascade-${ROLE}-setup.sh на хосте"

# --- 2. сетевые предусловия ------------------------------------------------
if [ -c /dev/net/tun ]; then
    : # хорошо: TUN проброшен
else
    log "warning: /dev/net/tun не найден — контейнер запущен без --device /dev/net/tun"
fi

for sysctl_key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
    sysctl -qw "$sysctl_key=1" 2>/dev/null || log "warning: не удалось выставить $sysctl_key (нужен --cap-add NET_ADMIN)"
done

# IPv6 внутри контейнера нужен exit-роли для транспорта туннеля.
if [ "$ROLE" = "exit" ]; then
    if ! ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        log "warning: внутри контейнера нет глобального IPv6 — проверьте сеть docker/podman и IPv6 на хосте"
    fi
fi

# --- 3. подъём интерфейсов -------------------------------------------------
UP_IFACES=""
cleanup() {
    status=$?
    trap - TERM INT EXIT
    for iface in $UP_IFACES; do
        log "опускаю $iface"
        wg-quick down "$iface" >/dev/null 2>&1 || true
    done
    exit $status
}
trap 'cleanup' TERM INT EXIT

bring_up() {
    iface=$1
    conf="$DATA_DIR/$iface.conf"
    if ip link show "$iface" >/dev/null 2>&1; then
        log "интерфейс $iface уже существует — пропускаю подъём"
        UP_IFACES="$UP_IFACES $iface"
        return 0
    fi
    log "поднимаю $iface из $conf"
    if wg-quick up "$conf"; then
        UP_IFACES="$UP_IFACES $iface"
    else
        log "не удалось поднять $iface (см. вывод выше)"
        return 1
    fi
}

FAILED=0
for iface in $CONFIGS; do
    bring_up "$iface" || FAILED=1
done
if [ "$FAILED" -ne 0 ]; then
    die "не все интерфейсы поднялись; контейнер завершится, чтобы перезапуститься по restart policy"
fi

log "подняты:$UP_IFACES"
wg show interfaces 2>/dev/null || true

# --- 4. держим процесс ------------------------------------------------------
log "готово, супервизор запущен"
while :; do
    sleep 3600 &
    wait $!
done
