# XIO NAT64 → IPv4 для клиентов AmneziaWG (`vpn4`)

Состояние: **развёрнуто и проверено на VPS-721137 2026-11-05** (см. `work/nat64-vpn4-20261105.md` в репозитории и `docs/`).

## Задача

Сервер VPS-721137 — LXC без IPv4-маршрута вообще (`ip -4 route show default` пуст,
`ping -4 1.1.1.1` → `Network is unreachable`). Провайдер даёт NAT64, который пропускает
**только трафик, открытый нашим же процессом с нашего IPv6**:

```
наш IPv6 → 2a01:4f8:c2c:123f:64:5::/96 + <IPv4 цели>   (провайдер транслирует)
```

AmneziaWG-клиенты (`awg0`, UDP 51830, `fd90:1::1/64`) получали только IPv6, поэтому
IPv4-сайты у них не открывались. Нужно было выдать им IPv4, не заводя IPv4-маршрут
и не трогая существующие стеки (`xio-managed-awg`, `xio-rivet`, `xio-stack`, `mtg`, `dc6`).

## Схема

```
 клиент AWG (телефон)                 VPS-721137 (LXC, только IPv6)
 ┌──────────────────┐                ┌──────────────────────────────────────────────┐
 │ 10.90.0.2/24     │  UDP 51830     │ awg0  fd90:1::1/64 + 10.90.0.1/24            │
 │ fd90:1::2/128    │───────────────▶│   │                                          │
 │ AllowedIPs 0/0   │                │   │ netfilter: nat PREROUTING -i awg0        │
 └──────────────────┘                │   ├─ tcp           → REDIRECT 127.0.0.1:19192│
        ▲                            │   └─ udp dport 53  → REDIRECT 127.0.0.1:5353 │
        │                            │            │                                 │
        │                            │            ▼                                 │
        │                            │   vpn4 (userspace, CGO off)                  │
        │                            │     • getsockopt(SOL_IP, SO_ORIGINAL_DST)    │
        │                            │     • dial tcp6 [prefix::<IPv4>]:port         │
        │                            │     • UDP/53 → 1.1.1.1:53 через NAT64         │
        │                            │            │                                 │
        │                            │            ▼                                 │
        │                            │   eth0 2a0c:b641:1a0:800::2a2/128 ────────▶   │
        └────────────────────────────┤   провайдерский NAT64 → IPv4-интернет        │
             ответы приходят обратно└──────────────────────────────────────────────┘
```

Ключевая деталь: IPv4-пакетов на хосте не появляется. Ядро принимает TCP-соединение
клиента **после** DNAT (REDIRECT), процесс спрашивает netfilter, куда клиент на самом деле
шёл (`SO_ORIGINAL_DST`), и открывает новое — уже IPv6 — соединение к
`<prefix>/96 + <те 4 байта IPv4>`. Дальше всё делает NAT64 провайдера.

`ip -4 route replace <сеть> dev lo` нужен **только для локально сгенерированного трафика**
(так работает `dc6` для Telegram). Для трафика клиентов он не нужен: пакеты приходят
через `awg0` и уже маршрутизируются к нам.

## Состав

| Файл | Что делает |
|---|---|
| `xio-vpn4-setup.sh` | идемпотентная установка: бинарь, конфиг, `vpn4-rules.sh`, юниты, IPv4 у пира, профиль клиента |
| `vpn4-rules.sh` | адрес `10.90.0.1/24` на `awg0` и правила netfilter с комментарием `xio-vpn4` (все, без исключений) |
| `vpn4.service` | сам мост, `Restart=on-failure`, `EnvironmentFile=/etc/xio-vpn4.conf` |
| `vpn4-rules.service` | oneshot, применяет `vpn4-rules.sh` до старта моста |
| `src/vpn4/main.go` | мост: TCP 0.0.0.0:19192 + UDP 0.0.0.0:5353, stdlib + `syscall`, `CGO_ENABLED=0` |
| `build.sh` | кросс-сборка статического бинаря |
| `verify.sh` | проверки «здесь и сейчас» с печатью команд и результата, код возврата = число провалов |
| `e2e-netns-test.sh` | настоящий клиент AWG в `unshare -n`: `wget -4 …/cdn-cgi/trace`, `dig @10.90.0.1`, `ping -4` (должен падать) |

## Установка

```sh
# на сервере, root; бинарь рядом со скриптом (./vpn4) или соберётся локальным Go
cd /root/nat64
./xio-vpn4-setup.sh 2a01:4f8:c2c:123f:64:5 awg0 10.90.0.2 10.90.0.1
#   аргументы: PREFIX  AWG_IF  CLIENT_V4  TUN_V4
./verify.sh
./e2e-netns-test.sh accept
```

Повторный запуск ничего не меняет и никого не перезапускает — это проверено
(второй прогон печатает `unchanged` по всем пунктам, `ActiveEnterTimestamp` юнитов не меняется).

Кросс-сборка с машины разработчика:

```sh
./build.sh                     # linux/amd64, статический, ~2.2 МБ
scp vpn4 xio-vpn4-setup.sh vpn4-rules.sh vpn4.service vpn4-rules.service verify.sh \
    root@server:/root/nat64/
```

## Что меняется на сервере

Добавляется (ничего чужого не переписывается):

- `/usr/local/bin/vpn4`, `/usr/local/sbin/vpn4-rules.sh`, `/etc/xio-vpn4.conf`;
- `/etc/systemd/system/vpn4.service`, `vpn4-rules.service` (оба `enabled`);
- `ip -4 addr replace 10.90.0.1/24 dev awg0` — IPv6-роль интерфейса не меняется,
  `fd90:1::1/64` остаётся; то же самое делает `apply.py` при каждом старте `awg-owner`,
  поэтому адрес переживает `systemctl restart awg-owner`;
- в `/etc/awg-owner/awg0.setconf.conf` пиру добавляется `10.90.0.2/32` (резервная копия
  `.bak-xio-vpn4`), применяется через `awg set peer … allowed-ips` — без `setconf`
  и без перезапуска, живые сессии не рвутся;
- в `/etc/awg-owner/client-ipv4.conf` появляются `Address = 10.90.0.2/24, fd90:1::2/128`
  и `DNS = 10.90.0.1` (резервная копия `.bak-xio-vpn4`);
- правила netfilter **только** с комментарием `xio-vpn4`; нетегированные дубликаты,
  оставшиеся от ручных прогонов, скрипт удаляет.

## Ограничения

- Только **TCP** и **UDP/53**. UDP-QUIC, игровой UDP и прочее не поддерживаются:
  REDIRECT UDP на userspace-мост без полного NAT-состояния не сделать.
- **ICMP нет** (`ping -4` из туннеля не работает) — проверено в `e2e-netns-test.sh`.
- Endpoint туннеля остаётся IPv6 (`[2a0c:b641:1a0:800::2a2]:51830`), клиент должен иметь IPv6.
- Выходной IPv4 — адрес провайдерского NAT64 (`159.69.108.193` в проверке), не адрес сервера.
- DNS-релей форвардит на `1.1.1.1:53` (plain DNS через NAT64). Клиентам DNS64 не нужен:
  у них теперь есть настоящий IPv4 через туннель, A-записи работают напрямую.
- Клиент, у которого IPv4-адрес из `10.90.0.0/24` (один пир), получает IPv4 только после
  добавления `10.90.0.2/32` в `AllowedIPs` — это делает установщик.
- Один DNS-запрос = один UDP-сокет до апстрима (просто и без состояния; для телефона
  этого достаточно, но при десятках клиентов стоит добавить кэш/пул).
- Не все IPv4-адреса достижимы через NAT64 провайдера: часть сетей не транслируется.
  В журнале это видно как `… FAIL dial tcp6 […]: i/o timeout` (пример: `188.72.108.93:443`).
  Это ограничение NAT64, а не моста.

## Откат

```sh
systemctl disable --now vpn4 vpn4-rules
rm -f /usr/local/bin/vpn4 /usr/local/sbin/vpn4-rules.sh /etc/xio-vpn4.conf
rm -f /etc/systemd/system/vpn4.service /etc/systemd/system/vpn4-rules.service
systemctl daemon-reload
# правила только с нашим комментарием
for t in PREROUTING; do
  iptables -t nat -S $t | grep xio-vpn4 | sed 's/^-A /-D /' | while read -r r; do iptables -t nat $r; done
done
iptables -S FORWARD | grep xio-vpn4 | sed 's/^-A /-D /' | while read -r r; do iptables $r; done
# вернуть конфиги AWG
mv /etc/awg-owner/awg0.setconf.conf.bak-xio-vpn4 /etc/awg-owner/awg0.setconf.conf
mv /etc/awg-owner/client-ipv4.conf.bak-xio-vpn4 /etc/awg-owner/client-ipv4.conf
systemctl restart awg-owner
```

`ip -4 addr del 10.90.0.1/24 dev awg0` — по желанию: после отката адрес больше не нужен,
но и вреда от него нет.

## ⚠️ Не писать `/etc/resolv.conf` изнутри `nsenter -n` / `unshare -n`

Сетевой namespace **не** изолирует монтирования: `/etc/resolv.conf` внутри
`nsenter -t <pid> -n sh -c 'echo nameserver … > /etc/resolv.conf'` — это файл **хоста**.
Так на VPS-721137 уже был сломан DNS: тест записал `nameserver 10.90.0.1` (адрес сервера
в туннеле, где на 53 ничего не слушает), после чего весь сервер получал
`connection refused` на каждый запрос. Резолвер хоста — провайдерский DNS64
`2a01:4f8:c2c:123f::1` (он же отвечает на `ipv4only.arpa` адресом
`2a01:4f8:c2c:123f:64:5:c000:aa`, что и подтверждает префикс).

Для проверки DNS клиента используйте `dig @10.90.0.1 …` — он не трогает файл.

## Согласование на хосте

Порты `19192`/`5353` — общая точка входа для IPv4-over-NAT64 на этом сервере. Их же
использует **каскадный путь** — отдельная зона (`xio-nat64-exit.service`, правила
`-i tun0 … xio-nat64-tun0`, адресация `10.200.0.0/30`), её ставит и сопровождает другой
агент; файлы `xio-nat64-*.{sh,service,timer}` в этом каталоге — **не мои**. Поэтому:

- свои юниты перезапускайте поимённо: `systemctl restart vpn4 vpn4-rules`;
- `vpn4-rules.sh` удаляет нетегированные дубликаты **только** на своём интерфейсе
  (`$AWG_IF`), чужие правила (в том числе `tun0`) не затрагивает;
- `awg-owner` без нужды не перезапускать: это рвёт сессии живых клиентов.
