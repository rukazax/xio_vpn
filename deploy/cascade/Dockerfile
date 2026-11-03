# XIO Cascade — образ для bridge/exit.
#
# Минимальный Debian: iproute2/nftables/wireguard-tools + python3 для admin.py
# серверного пакета xio-server. curl оставлен намеренно: он нужен healthcheck-у
# (проверка выходного IPv6 изнутри exit) и whitelist-update (скачивание списков).
#
# Сборка: docker build -t xio-cascade:local -f Dockerfile .
# Запуск:  см. cascade-install.sh (роль задаётся CASCADE_ROLE=bridge|exit).

FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C \
    LANG=C \
    TZ=UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        nftables \
        wireguard-tools \
        openresolv \
        ca-certificates \
        python3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Каталоги состояния и служебных файлов (данные приходят томом).
RUN install -d -m 0700 /data /etc/xio \
    && install -d -m 0755 /usr/local/lib/xio-cascade

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

ENV CASCADE_ROLE=bridge \
    CASCADE_TUNNEL_PORT=9443 \
    CASCADE_CLIENT_PORT=51820 \
    CASCADE_CONFIG_TIMEOUT=120

VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD wg show interfaces 2>/dev/null | grep -q wg0 || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["supervise"]
