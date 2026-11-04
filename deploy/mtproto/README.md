# MTProto-прокси для Telegram (mtg)

Прокси-сервер MTProto для Telegram на бридже XIO. Клиент Telegram подключается к
`81.177.142.37:8444` по FakeTLS и видит обычный HTTPS к сайту `79e.ru`, а прокси
передаёт трафик в дата-центры Telegram.

```
Telegram (телефон)                 bridge 81.177.142.37                    exit (FR)
      │                                    │                                  │
      │  FakeTLS, SNI 79e.ru               │                                  │
      ├────────────── 8444 ───────────────►│ mtg 2.3.0                        │
      │                                    │   │ IPv6 (fd00:201::1)           │
      │                                    │   └──── туннель каскада ────────►│
      │                                    │        xio-cascade.service       │ 2001:…
      │                                    │                                  └──► DC Telegram
```

**Почему IPv6.** Провайдер бриджа режет IPv4 к сетям Telegram: TCP на 443/80/5222
до `149.154.*`, `91.108.*`, `95.161.*`, `91.105.192.*` уходит в никуда (SYN без
ответа, ICMP при этом проходит). Проверено 14 адресами DC. Рабочий выход —
IPv6 через уже поднятый туннель каскада `xio-cascade.service` → exit-сервер во
Франции. `mtg doctor` подтверждает RPC-рукопожатие со всеми шестью DC.

**Без туннеля каскада прокси слушает порт, но до Telegram не доходит.** Если
`xio-cascade` остановлен, пропадает IPv6-маршрут по умолчанию — прокси
перестаёт работать, хотя `systemctl is-active xio-mtproto` остаётся `active`.

## Установка

```bash
scp deploy/mtproto/xio-mtproto-setup.sh root@81.177.142.37:/root/
ssh root@81.177.142.37 'MTG_PORT=8444 MTG_DOMAIN=79e.ru bash /root/xio-mtproto-setup.sh'
```

Скрипт идемпотентен: повторный запуск не перекачивает уже установленный бинарь,
не перегенерирует секрет, не трогает службу, если конфиг и юнит не изменились.

Параметры (переменные окружения):

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `MTG_VERSION` | `2.3.0` | версия релиза [9seconds/mtg](https://github.com/9seconds/mtg) |
| `MTG_PORT` | `8444` | TCP-порт прокси (443 и 8443 на бридже заняты nginx и xio-rivet) |
| `MTG_DOMAIN` | `79e.ru` | домен маскировки FakeTLS |
| `MTG_PUBLIC_IP` | автоопределение | IPv4 в ссылке `tg://proxy` |
| `MTG_IP_FAMILY` | автотест | `prefer-ip` для mtg: `only-ipv6`, `only-ipv4`, `prefer-ipv6` |
| `MTG_SOCKS5` | пусто | upstream `socks5://host:port`, если нужен другой egress |
| `MTG_DNS` | пусто (системный) | DNS для mtg |

Служебные пути:

| Что | Где |
|---|---|
| бинарь | `/usr/local/lib/xio-mtproto/mtg` |
| конфиг | `/etc/xio-mtproto/config.toml` (0640 root:mtg) |
| секрет | `/etc/xio-mtproto/secret` (0640 root:mtg) |
| порт для ссылки | `/etc/xio-mtproto/port` (0640 root:mtg) |
| адрес для ссылки | `/etc/xio-mtproto/domain` (0640 root:mtg) |
| состояние | `/etc/xio-mtproto/state` (0600) |
| юнит | `/etc/systemd/system/xio-mtproto.service` |

`port` и `domain` скрипт обновляет идемпотентно (пишет только при изменении
значения): по ним сервер и приложение собирают ссылку `tg://proxy` без ручного
ввода. `domain` — адрес, который попадёт в ссылку (публичный IPv4 из
`public-ipv4`, то же значение печатает `--print-link`); домен маскировки
FakeTLS остаётся в `MTG_DOMAIN` и в строке `domain=` файла секрета.

Секрет **не хранится в репозитории**: он генерируется на сервере
(`mtg generate-secret --hex 79e.ru`) и переиспользуется при повторных запусках.
Смена `MTG_DOMAIN` перегенерирует секрет — после этого старая ссылка перестаёт
работать, а в приложении нужно обновить ссылку.

## Проверка

```bash
systemctl is-active xio-mtproto            # active
systemctl is-enabled xio-mtproto           # enabled
ss -Hltnp | grep 8444                      # *:8444 users:(("mtg",...))
journalctl -u xio-mtproto -n 20 --no-pager # без ошибок
/usr/local/lib/xio-mtproto/mtg doctor /etc/xio-mtproto/config.toml
```

`mtg doctor` — единственная проверка «живьём» без клиента Telegram: он делает
настоящее MTProto-рукопожатие (`resPQ`) с каждым DC через прокси-путь. Ожидаемый
результат на бридже:

```
Validate native network connectivity
  ✅ DC 1 (rpc 164.867ms) … ✅ DC 203 (rpc 105.4ms)
Validate fronting domain connectivity
  ✅ 81.177.142.37:443 is reachable
  ✅ TLS certificate for 79e.ru is valid
Validate SNI-DNS match
  ✅ IP address 81.177.142.37 matches secret domain
```

Маскировка проверяется снаружи: обычный HTTPS-запрос на порт прокси с SNI
`79e.ru` должен отдать настоящую страницу `79e.ru` с валидным сертификатом:

```bash
curl -k --connect-to 79e.ru:443:81.177.142.37:8444 https://79e.ru/ -o /dev/null -w '%{http_code}\n'   # 200
```

## Ссылка и настройка Telegram

Ссылку печатает сам скрипт (и `--print-link` в любой момент):

```bash
ssh root@81.177.142.37 'bash /root/xio-mtproto-setup.sh --print-link'
tg://proxy?server=81.177.142.37&port=8444&secret=ee…
```

В Telegram на телефоне:

1. **Настройки → Данные и память → Прокси**.
2. **Добавить прокси → MTProto** (в старых версиях: «Добавить прокси» сразу
   открывает поле для ссылки).
3. Вставить ссылку `tg://proxy?server=…&port=…&secret=…` и сохранить. Поля
   «Сервер», «Порт», «Секрет» заполнятся сами, если ссылку вставить в поле
   «Ссылка на прокси».
4. Включить переключатель **«Использовать прокси»**.

Прокси-ссылка не является секретом и не даёт доступа к аккаунту: она только
указывает адрес прокси и общий секрет FakeTLS. Кто знает ссылку — может
пользоваться прокси, поэтому не публикуйте её в открытых каналах.

Та же ссылка хранится в приложении XIO: **Настройки → Telegram-прокси (MTProto)**,
её можно отредактировать, скопировать и открыть в Telegram одной кнопкой.

## Обновление и удаление

```bash
# обновить mtg до новой версии
ssh root@81.177.142.37 'MTG_VERSION=2.4.0 bash /root/xio-mtproto-setup.sh'
# снять службу, бинарь, конфиг и секрет
ssh root@81.177.142.37 'bash /root/xio-mtproto-setup.sh --uninstall'
```

Юнит: `Restart=always`, `RestartSec=3`, `StartLimitBurst=5` — после аварийного
выхода mtg поднимается сам; после пяти падений за минуту systemd перестаёт
долбить и служба остаётся failed (смотреть `journalctl`).

## Ограничения и что не проверено

- **Реальное подключение Telegram с телефона не проверено.** Доступного клиента
  с поддержкой FakeTLS под рукой не было: Telethon 1.45 умеет только режим
  MTProxy `dd`, а mtg принимает исключительно `ee` (FakeTLS) — сервер честно
  отвечает `incorrect first byte of secret: 0xdd`. Сквозной путь подтверждён
  `mtg doctor` (RPC до всех DC) и маскировкой снаружи, но не живым клиентом.
- Порт 8444, а не 443: 443 на бридже занят nginx (fastpanel), 8443 — xio-rivet.
  Перенос на 443 требует SNI-роутинга (nginx stream `ssl_preread`) и здесь не
  делался, чтобы не трогать существующие сайты.
- Прокси зависит от `xio-cascade.service` (IPv6-туннель до exit).
- Блоклист FireHOL (`[defense.blocklist]`) выключен: прокси не публичный сервис,
  а снятие внешней зависимости убирает лишние запросы в журнале.
- IPv6 у бриджа только в туннеле (`fd00:201::/126`); снаружи прокси доступен по
  IPv4 `81.177.142.37:8444`.
