#!/usr/bin/env bash
# XIO MTProto-прокси (mtg) — установка и обновление, идемпотентно.
#
# Что делает:
#   1. скачивает официальный релиз mtg (github.com/9seconds/mtg) для linux-amd64;
#   2. кладёт бинарь в /usr/local/lib/xio-mtproto/mtg;
#   3. генерирует FakeTLS-секрет под домен маскировки (один раз, дальше переиспользует);
#   4. пишет /etc/xio-mtproto/config.toml и systemd-юнит xio-mtproto.service;
#   5. запускает службу с автоперезапуском и печатает ссылку tg://proxy?...
#
# Повторный запуск безопасен: уже установленная версия не перекачивается,
# существующий секрет не перегенерируется, служба перезапускается только
# если изменились бинарь, конфиг или юнит.
#
# Примеры:
#   sudo ./xio-mtproto-setup.sh                       # порт 8444, маскировка 79e.ru
#   sudo MTG_PORT=443 MTG_DOMAIN=example.org ./xio-mtproto-setup.sh
#   sudo ./xio-mtproto-setup.sh --print-link          # только напечатать ссылку
#   sudo ./xio-mtproto-setup.sh --uninstall           # снять службу и файлы
#
# Переменные окружения:
#   MTG_VERSION    версия релиза mtg                (по умолчанию 2.3.0)
#   MTG_PORT       TCP-порт прокси                  (по умолчанию 8444)
#   MTG_DOMAIN     домен маскировки FakeTLS         (по умолчанию 79e.ru)
#   MTG_PUBLIC_IP  публичный IPv4 для ссылки        (по умолчанию определяется)
#   MTG_IP_FAMILY  prefer-ip для mtg                (по умолчанию автотест)
#   MTG_SOCKS5     upstream socks5://host:port      (необязательно)
#   MTG_DNS        DNS для mtg, "" = системный      (по умолчанию пусто)
#
# Порт прокси НЕ занимает 443/8443: на бридже там nginx и xio-rivet.
#
# Секрет НЕ хранится в репозитории: он создаётся на сервере в /etc/xio-mtproto/secret.

set -euo pipefail

MTG_VERSION=${MTG_VERSION:-2.3.0}
MTG_PORT=${MTG_PORT:-8444}
MTG_DOMAIN=${MTG_DOMAIN:-79e.ru}
MTG_PUBLIC_IP=${MTG_PUBLIC_IP:-}
MTG_IP_FAMILY=${MTG_IP_FAMILY:-}
MTG_SOCKS5=${MTG_SOCKS5:-}
MTG_DNS=${MTG_DNS-}

MTG_LIB=/usr/local/lib/xio-mtproto
MTG_ETC=/etc/xio-mtproto
MTG_BIN=$MTG_LIB/mtg
MTG_CONF=$MTG_ETC/config.toml
MTG_SECRET_FILE=$MTG_ETC/secret
MTG_STATE=$MTG_ETC/state
MTG_USER=mtg
UNIT=/etc/systemd/system/xio-mtproto.service

log() { printf '\033[1;32m[xio-mtproto]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[xio-mtproto]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[xio-mtproto]\033[0m %s\n' "$*" >&2; exit 1; }

# Слушатели указанного TCP-порта: строка `ss` без заголовка или пусто.
# `ss` печатает wildcard как `*:8444` или `0.0.0.0:8444`, поэтому фильтр
# встроенным выражением `sport =` ненадёжен — разбираем поле локального адреса.
listeners_on_port() {
  ss -Hltnp 2>/dev/null | awk -v want=":$1\$" '$4 ~ want'
}

need_root() { [ "$(id -u)" = 0 ] || die "нужен root (sudo)"; }

detect_public_ip() {
  local ip
  for url in https://ifconfig.co https://api.ipify.org https://icanhazip.com; do
    ip=$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    if printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
      printf '%s' "$ip"
      return 0
    fi
  done
  return 1
}

print_link() {
  local secret ip port
  secret=$(sed -n 's/^secret *= *"\(.*\)"/\1/p' "$MTG_CONF" 2>/dev/null | head -1)
  [ -n "$secret" ] || die "конфиг $MTG_CONF не найден или в нём нет secret"
  ip=${MTG_PUBLIC_IP:-$(sed -n 's/^public-ipv4 *= *"\(.*\)"/\1/p' "$MTG_CONF" | head -1)}
  [ -n "$ip" ] || ip=$(detect_public_ip) || die "не удалось определить публичный IPv4"
  port=$(sed -n 's/^port=//p' "$MTG_STATE" 2>/dev/null | head -1)
  [ -n "$port" ] || port=$(sed -n 's/^bind-to *= *".*:\([0-9]*\)"/\1/p' "$MTG_CONF" | head -1)
  [ -n "$port" ] || port=$MTG_PORT
  printf 'tg://proxy?server=%s&port=%s&secret=%s\n' "$ip" "$port" "$secret"
}

uninstall() {
  need_root
  if systemctl list-unit-files | grep -q '^xio-mtproto.service'; then
    systemctl disable --now xio-mtproto.service || true
  fi
  rm -f "$UNIT"
  systemctl daemon-reload
  rm -rf "$MTG_LIB" "$MTG_ETC"
  if id "$MTG_USER" >/dev/null 2>&1; then userdel "$MTG_USER" 2>/dev/null || true; fi
  log "xio-mtproto удалён (юнит, бинарь, конфиг и секрет)"
}

main() {
  case "${1:-}" in
    --print-link)
      need_root
      print_link
      return 0
      ;;
    --uninstall)
      uninstall
      return 0
      ;;
    ''|--install) ;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
  esac

  need_root

  # 1. Зависимости.
  for bin in curl tar sha256sum; do
    command -v "$bin" >/dev/null 2>&1 || {
      log "устанавливаю $bin"
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl tar coreutils
      break
    }
  done

  # 2. Служебный пользователь.
  if ! id "$MTG_USER" >/dev/null 2>&1; then
    log "создаю системного пользователя $MTG_USER"
    useradd --system --home-dir "$MTG_LIB" --shell /usr/sbin/nologin "$MTG_USER"
  fi
  install -d -m 0755 "$MTG_LIB"
  install -d -m 0750 -o root -g "$MTG_USER" "$MTG_ETC"

  # 3. Бинарь mtg нужной версии.
  # checksums.txt хеширует ТАРБОЛ, а не бинарь, поэтому «уже установлено»
  # проверяем по своему state: версия + sha256 установленного бинаря.
  local want_sha current_sha archive dir state_ver state_sha
  state_ver=$(sed -n 's/^version=//p' "$MTG_STATE" 2>/dev/null | head -1 || true)
  state_sha=$(sed -n 's/^binary-sha256=//p' "$MTG_STATE" 2>/dev/null | head -1 || true)
  current_sha=$(sha256sum "$MTG_BIN" 2>/dev/null | awk '{print $1}' || true)

  if [ "$state_ver" = "$MTG_VERSION" ] && [ -n "$state_sha" ] && [ "$state_sha" = "$current_sha" ]; then
    log "бинарь mtg ${MTG_VERSION} уже установлен (sha256 совпал)"
    changed_bin=0
  else
    log "скачиваю mtg ${MTG_VERSION} (linux-amd64)"
    want_sha=$(curl -fsSL --max-time 20 \
      "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-checksums.txt" \
      | awk -v n="mtg-${MTG_VERSION}-linux-amd64.tar.gz" '$2==n || $2=="*"n {print $1}' | head -1)
    [ -n "$want_sha" ] || die "не нашёл контрольную сумму для mtg ${MTG_VERSION} (linux-amd64)"
    dir=$(mktemp -d)
    # `dir` объявлен local, а trap срабатывает после выхода из функции —
    # под set -u без :- присваивание падало бы на unbound variable.
    trap 'rm -rf "${dir:-}"' EXIT
    archive="$dir/mtg.tar.gz"
    curl -fsSL --max-time 120 -o "$archive" \
      "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-linux-amd64.tar.gz" \
      || die "не удалось скачать релиз mtg ${MTG_VERSION}"
    echo "$want_sha  $archive" | sha256sum -c --status - \
      || die "контрольная сумма релиза не совпала"
    tar -xzf "$archive" -C "$dir"
    install -m 0755 "$dir/mtg-${MTG_VERSION}-linux-amd64/mtg" "$MTG_BIN"
    install -m 0644 "$dir/mtg-${MTG_VERSION}-linux-amd64/LICENSE" "$MTG_LIB/LICENSE"
    printf '%s  %s\n' "$want_sha" "mtg-${MTG_VERSION}-linux-amd64.tar.gz" > "$MTG_ETC/release.sha256"
    log "бинарь обновлён до ${MTG_VERSION}"
    changed_bin=1
  fi

  # 4. Секрет FakeTLS. Генерируется один раз и привязывается к домену маскировки.
  local secret domain_prev
  domain_prev=$(sed -n 's/^domain=//p' "$MTG_SECRET_FILE" 2>/dev/null | head -1 || true)
  secret=$(sed -n 's/^secret=//p' "$MTG_SECRET_FILE" 2>/dev/null | head -1 || true)
  if [ -z "$secret" ] || [ "$domain_prev" != "$MTG_DOMAIN" ]; then
    log "генерирую FakeTLS-секрет для домена $MTG_DOMAIN"
    secret=$("$MTG_BIN" generate-secret --hex "$MTG_DOMAIN")
    [ -n "$secret" ] || die "mtg generate-secret не вернул секрет"
    printf 'secret=%s\ndomain=%s\n' "$secret" "$MTG_DOMAIN" > "$MTG_SECRET_FILE"
    log "секрет сохранён в $MTG_SECRET_FILE (0600)"
  else
    log "секрет для домена $MTG_DOMAIN уже есть — переиспользую"
    printf 'secret=%s\ndomain=%s\n' "$secret" "$MTG_DOMAIN" > "$MTG_SECRET_FILE"
  fi
  chown root:"$MTG_USER" "$MTG_SECRET_FILE"
  chmod 0640 "$MTG_SECRET_FILE"

  # 5. Конфиг mtg.
  if [ -z "$MTG_PUBLIC_IP" ]; then
    MTG_PUBLIC_IP=$(sed -n 's/^public-ipv4 *= *"\(.*\)"/\1/p' "$MTG_CONF" 2>/dev/null | head -1 || true)
  fi
  if [ -z "$MTG_PUBLIC_IP" ]; then
    MTG_PUBLIC_IP=$(detect_public_ip) || die "укажите MTG_PUBLIC_IP: сервер не отдал свой внешний IPv4"
  fi

  # Семейство IP для выхода к Telegram. На российском бридже IPv4 к DC
  # Telegram режется провайдером (SYN без ответа), а IPv6 идёт через туннель
  # каскада (xio-cascade → exit). Поэтому по умолчанию пробуем сами и берём
  # то семейство, которое реально отвечает.
  local family fronting_host fronting_line=""
  family=${MTG_IP_FAMILY:-}
  if [ -z "$family" ]; then
    local v4=0 v6=0
    timeout 5 bash -c 'echo > /dev/tcp/149.154.175.50/443' 2>/dev/null && v4=1
    timeout 5 bash -c 'echo > /dev/tcp/2001:b28:f23d:f001::a/443' 2>/dev/null && v6=1
    case "$v4$v6" in
      11) family=prefer-ipv6 ;;
      10) family=only-ipv4 ;;
      01) family=only-ipv6 ;;
      *)  family=prefer-ipv6 ;;
    esac
    log "проверка выхода к Telegram: IPv4 $([ $v4 = 1 ] && echo ок || echo недоступен), IPv6 $([ $v6 = 1 ] && echo ок || echo недоступен) → prefer-ip = ${family}"
    [ "$v4$v6" = "00" ] && warn "ни IPv4, ни IPv6 к Telegram не отвечают: прокси поднимется, но трафик не пойдёт (нужен туннель/egress)"
  fi

  # Если домен маскировки указывает на этот же сервер, fronting-соединение
  # лучше диалать по литеральному IP: тогда маскировка работает и при
  # only-ipv6 (DNS-AAAA у домена может отсутствовать).
  fronting_host=$(getent ahostsv4 "$MTG_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
  if [ "$fronting_host" = "$MTG_PUBLIC_IP" ]; then
    fronting_line="host = \"${MTG_PUBLIC_IP}\""
  fi

  local new_conf
  new_conf=$(mktemp)
  cat > "$new_conf" <<EOF
# XIO MTProto-прокси (mtg ${MTG_VERSION}). Файл создан xio-mtproto-setup.sh.
# Руками не редактировать: перезапуск скрипта перезапишет конфиг.
secret = "${secret}"
# hostname в bind-to запрещён: только литеральный IP.
bind-to = "0.0.0.0:${MTG_PORT}"
concurrency = 8192
# Определено автотестом выхода: IPv4 к Telegram на российском бридже режется,
# рабочий путь — IPv6 через туннель каскада до exit-сервера.
prefer-ip = "${family}"
public-ipv4 = "${MTG_PUBLIC_IP}"
auto-update = false
# Пустая строка = системный резолвер; DoH по умолчанию может быть недоступен.
dns = "${MTG_DNS}"
# Печать секрета в лог не нужна.
debug = false

[domain-fronting]
port = 443
${fronting_line}

[defense.blocklist]
enabled = false
EOF
  if [ -n "$MTG_SOCKS5" ]; then
    cat >> "$new_conf" <<EOF

# Весь исходящий трафик mtg идёт через этот socks5 (egress в сети, где
# Telegram не заблокирован). Пусто — прямой выход с этого хоста.
[network]
proxies = ["${MTG_SOCKS5}"]
EOF
  fi
  chown root:"$MTG_USER" "$new_conf"
  chmod 0640 "$new_conf"

  local changed_conf=0
  if ! cmp -s "$new_conf" "$MTG_CONF"; then
    mv "$new_conf" "$MTG_CONF"; changed_conf=1
    log "конфиг обновлён: $MTG_CONF"
  else
    rm -f "$new_conf"
    log "конфиг без изменений"
  fi

  # 6. systemd-юнит.
  local new_unit
  new_unit=$(mktemp)
  cat > "$new_unit" <<EOF
[Unit]
Description=XIO MTProto-прокси для Telegram (mtg)
Documentation=https://github.com/9seconds/mtg
After=network-online.target
Wants=network-online.target
# Больше 5 рестартов за минуту — что-то системное, дальше не долбим.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${MTG_USER}
Group=${MTG_USER}
ExecStart=${MTG_BIN} run ${MTG_CONF}
Restart=always
RestartSec=3
LimitNOFILE=65536
SyslogIdentifier=xio-mtproto
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF
  local changed_unit=0
  if ! cmp -s "$new_unit" "$UNIT"; then
    install -m 0644 "$new_unit" "$UNIT"; changed_unit=1
    log "юнит обновлён: $UNIT"
  else
    log "юнит без изменений"
  fi
  rm -f "$new_unit"
  systemctl daemon-reload

  # 7. Порт занят чужим процессом? Проверяем до запуска, чтобы не гадать по логам.
  if command -v ss >/dev/null 2>&1; then
    local busy
    busy=$(listeners_on_port "$MTG_PORT" | grep -v xio-mtproto || true)
    if [ -n "$busy" ] && ! systemctl is-active --quiet xio-mtproto; then
      die "порт ${MTG_PORT}/tcp уже занят: $busy — задайте другой MTG_PORT"
    fi
  fi

  # 8. Запуск и проверка. `is-active` становится true раньше, чем mtg
  # успевает занять порт, поэтому порт ждём отдельным опросом.
  systemctl enable xio-mtproto.service >/dev/null
  if [ "$changed_bin$changed_conf$changed_unit" != "000" ] || ! systemctl is-active --quiet xio-mtproto; then
    systemctl restart xio-mtproto.service
  fi

  local i listening=0
  for i in $(seq 1 40); do
    if systemctl is-active --quiet xio-mtproto.service &&
       { ! command -v ss >/dev/null 2>&1 || listeners_on_port "$MTG_PORT" | grep -q .; }; then
      listening=1
      break
    fi
    sleep 0.25
  done
  if ! systemctl is-active --quiet xio-mtproto.service; then
    journalctl -u xio-mtproto.service -n 30 --no-pager || true
    die "служба не поднялась (см. journalctl -u xio-mtproto -n 50)"
  fi
  if [ "$listening" != 1 ]; then
    journalctl -u xio-mtproto.service -n 30 --no-pager || true
    die "служба активна, но порт ${MTG_PORT}/tcp не слушается за 10 с"
  fi

  printf 'secret=%s\n' "$secret" > "$MTG_STATE"
  chmod 0600 "$MTG_STATE"
  printf 'version=%s\nport=%s\ndomain=%s\npublic-ipv4=%s\nbinary-sha256=%s\n' \
    "$MTG_VERSION" "$MTG_PORT" "$MTG_DOMAIN" "$MTG_PUBLIC_IP" \
    "$(sha256sum "$MTG_BIN" | awk '{print $1}')" >> "$MTG_STATE"

  log "служба активна, порт ${MTG_PORT}/tcp слушается"
  log "ссылка для Telegram:"
  print_link
  cat <<EOF

Дальше в Telegram: Настройки → Данные и память → Прокси → Добавить прокси →
MTProto → вставить ссылку выше → включить прокси.

Провека выхода к Telegram (без клиента):
  /usr/local/lib/xio-mtproto/mtg doctor /etc/xio-mtproto/config.toml

На этом бридже IPv4 к DC Telegram режет провайдер, рабочий путь — IPv6 через
туннель каскада (xio-cascade → exit). Если doctor показывает "i/o timeout",
проверьте, что туннель поднят: systemctl is-active xio-cascade и
ping6 -c1 2001:4860:4860::8888. Без туннеля прокси слушает порт, но до
Telegram не доходит.
EOF
}

main "$@"
