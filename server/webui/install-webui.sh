#!/usr/bin/env bash
# Установка XIO WebUI в /opt/xio-webui и запуск как systemd-службы.
# Использование:  sudo ./install-webui.sh [адрес:порт]
# По умолчанию: 127.0.0.1:10443
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/xio-webui"
UNIT_PATH="/etc/systemd/system/xio-webui.service"
LISTEN="${1:-127.0.0.1:10443}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Нужны права root: sudo $0 [адрес:порт]" >&2
  exit 1
fi

if ! [[ "$LISTEN" =~ ^[A-Za-z0-9.:-]+$ || "$LISTEN" =~ ^\[[0-9A-Fa-f:]+\]:[0-9]+$ ]]; then
  echo "Некорректный адрес: $LISTEN" >&2
  exit 2
fi

PYTHON="$(command -v python3 || true)"
if [[ -z "$PYTHON" ]]; then
  echo "python3 не найден" >&2
  exit 3
fi
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
  echo "Нужен Python 3.8 или новее" >&2
  exit 4
fi

for file in xio-webui.py index.html xio-webui.service README.md; do
  if [[ ! -f "$SRC_DIR/$file" ]]; then
    echo "Не найден файл: $SRC_DIR/$file" >&2
    exit 5
  fi
done

echo "==> Установка в $DEST_DIR"
install -d -m 0700 -o root -g root "$DEST_DIR"
install -m 0750 -o root -g root "$SRC_DIR/xio-webui.py" "$DEST_DIR/xio-webui.py"
install -m 0640 -o root -g root "$SRC_DIR/index.html" "$DEST_DIR/index.html"
install -m 0640 -o root -g root "$SRC_DIR/README.md" "$DEST_DIR/README.md"
# Токен и TLS-сертификат при повторной установке не трогаем.
chmod 0700 "$DEST_DIR"

echo "==> Юнит systemd: $UNIT_PATH"
sed "s|--listen 127.0.0.1:10443|--listen ${LISTEN}|" "$SRC_DIR/xio-webui.service" > "$UNIT_PATH"
chmod 0644 "$UNIT_PATH"

systemctl daemon-reload
systemctl enable xio-webui.service >/dev/null
systemctl restart xio-webui.service

echo "==> Ожидание первого запуска (генерация токена и сертификата)"
READY=0
for _ in $(seq 1 60); do
  if [[ -s "$DEST_DIR/token" && -s "$DEST_DIR/tls/cert.pem" ]]; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "$READY" -ne 1 ]]; then
  echo "Служба не подготовила token/tls за 60 с. Журнал:" >&2
  journalctl -u xio-webui.service -n 40 --no-pager >&2 || true
  exit 6
fi
if ! systemctl is-active --quiet xio-webui.service; then
  echo "Служба не запустилась. Журнал:" >&2
  journalctl -u xio-webui.service -n 40 --no-pager >&2 || true
  exit 7
fi

TOKEN="$(cat "$DEST_DIR/token")"
FINGERPRINT="$("$PYTHON" - "$DEST_DIR/tls/cert.pem" <<'PY'
import base64, hashlib, sys
text = open(sys.argv[1], "r", encoding="ascii").read()
der = base64.b64decode("".join(l for l in text.splitlines() if not l.startswith("-----")))
digest = hashlib.sha256(der).hexdigest().upper()
print(":".join(digest[i:i + 2] for i in range(0, len(digest), 2)))
PY
)"

HOST_PART="${LISTEN%:*}"
DISPLAY_HOST="$HOST_PART"
if [[ "$HOST_PART" == "0.0.0.0" || "$HOST_PART" == "::" || "$HOST_PART" == "[::]" ]]; then
  DISPLAY_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$DISPLAY_HOST" ]] || DISPLAY_HOST="127.0.0.1"
fi
PORT_PART="${LISTEN##*:}"

echo
echo "=============================================================="
echo " XIO WebUI установлен и запущен"
echo "--------------------------------------------------------------"
echo " URL:      https://${DISPLAY_HOST}:${PORT_PART}/?token=${TOKEN}"
echo " Токен:    ${TOKEN}"
echo " Сертифик: SHA-256 ${FINGERPRINT}"
echo " Файлы:    ${DEST_DIR} (token, tls/cert.pem, tls/key.pem, webui.log)"
echo " Служба:   systemctl status xio-webui"
echo "--------------------------------------------------------------"
echo " Сертификат самоподписанный: браузер покажет предупреждение."
echo " Сверьте отпечаток SHA-256 с тем, что напечатан выше, и только"
echo " потом принимайте исключение. Наружу открывайте через обратный"
echo " прокси (см. README.md), сам порт 10443 в интернет не публикуйте."
echo "=============================================================="
