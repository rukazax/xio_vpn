# XIO Cascade — последовательная двухсерверная схема

Состояние: **черновик deploy-скриптов, в бою не проверялся** (см. «Что не проверено»).

## Схема

```
 устройство            bridge (IPv4)                         exit (только IPv6)
 10.202.0.x  ──UDP──▶   [ wg1 ] приём устройств
                        [ wg0 ] ── защищённый туннель ──▶    [ wg0 ] ──▶ IPv6-интернет
 fd42:201::x            NAT44 для «прямого» трафика          NAT66 / NAT46
                        split-tunneling: nft-сет xio_whitelist4
```

- **bridge** — единственная точка, куда подключается устройство. У него есть IPv4,
  он держит постоянный туннель до exit (UDP поверх IPv6) и решает, что отправить
  в туннель, а что выпустить напрямую.
- **exit** — сервер без IPv4. Принимает только туннель и выпускает трафик в IPv6-мир.
- Обе роли живут **в контейнере** (docker/podman): отдельная сеть, `--cap-add NET_ADMIN`,
  `/dev/net/tun`, наружу открыты только нужные порты. Остальной софт сервера не затрагивается.
- Состояние и конфиги — в `./data/` рядом со скриптами, монтируются в контейнер томом.

Почему не в host-network: изоляция nft-правил и маршрутов, чтобы cascade не ломал
чужие iptables/nft на сервере. Цена — трафик устройств проходит через docker NAT.

## Требования

- Debian/Ubuntu, root, ядро с WireGuard (5.6+) и модулем `tun`.
- docker (или podman) с запущенным демоном; `curl`; `sha256sum` (coreutils).
- exit: **глобальный IPv6** на хосте/в контейнере, входящий UDP `<port>` (по умолчанию 9443).
- bridge: IPv4, входящий UDP `<client-port>` (51820) для устройств и TCP `<web-port>`
  (8443) для web/admin entry; исходящий UDP до `[exit]:<port>`.
- На exit должен быть разрешён исходящий IPv6 в мир (проверяется healthcheck-ом).
- Порты на хосте: exit — `9443/udp`; bridge — `51820/udp` + `8443/tcp`.
  Внутри контейнера entry слушает `*:8443`, gateway — `127.0.0.1:17443`.

## Установка

```bash
# 1) exit (IPv6-сервер)
sudo ./cascade-install.sh --role exit --port 9443
#    в выводе появятся "pubkey" и "fingerprint" — их надо передать на bridge

# 2) bridge (IPv4-сервер)
sudo ./cascade-install.sh --role bridge \
    --exit-host 2a01:4f8:1:2::10 --exit-pubkey <b64> \
    --exit-fingerprint sha256:<...>        # необязательно, но рекомендуется
#    в выводе будет "pubkey" bridge — зарегистрируйте его на exit:
sudo ./cascade-exit-setup.sh --add-peer <bridge-pubkey> \
    --allowed-ips 10.201.0.2/32,10.202.0.0/24

# либо одной командой (скачивает установщик, проверяет sha256, пишет лог):
curl -fsSL https://raw.githubusercontent.com/rukazax/xio_vpn/main/deploy/cascade/terminal-install.sh \
  | sudo bash -s -- --unattended --sha256 <hex> --role bridge --exit-host 2a01:4f8::10 --exit-pubkey <b64>
```

Устройство подключается к bridge: `[bridge-ipv4]:51820/udp`, адрес из `10.202.0.0/24`
(и `fd42:201::/64` для IPv6), тот же PresharedKey, если задан `--token-file`.

Проверка: `sudo ./cascade-healthcheck.sh --role bridge|exit|both` → JSON `{"ok": true,...}`,
код выхода 0/1.

## Белые списки (split-tunneling) — только на bridge

```bash
sudo ./whitelist-update.sh --dry-run                 # скачать и посмотреть, не применять
sudo ./whitelist-update.sh --config ./data/whitelists.conf
sudo ./whitelist-update.sh --install-timer            # Sun 04:17, systemd timer или cron.d
sudo ./whitelist-update.sh --rollback                 # вернуть предыдущий набор
```

- Источники — в `whitelists.conf` (URL построчно). Домены разворачиваются в IPv4 через `getent`.
- Собирается nft-сет `inet xio_cascade xio_whitelist4`; правила в `nft-bridge.sh` помечают
  пакеты к этим адресам и отправляют их в таблицу 200 → `default dev wg0` → exit.
- Всё остальное идёт напрямую (NAT44 на bridge).
- Замена **атомарная**: `flush set` + `add element` в одной транзакции `nft -f`;
  промежуточного пустого сета не бывает. Предыдущая версия — `whitelist-previous.nft`.
- Весь IPv6 от устройств уходит в туннель всегда (у bridge нет IPv6-аплинка).

## Откат

1. **Таймер списков:** `whitelist-update.sh --remove-timer`.
2. **Белые списки:** `whitelist-update.sh --rollback` (или удалить сет/правила:
   `docker exec -it xio-cascade-bridge nft delete table inet xio_cascade`).
3. **Контейнеры:** `docker rm -f xio-cascade-bridge xio-cascade-exit`
   (данные в `./data/` остаются; повторная установка их переиспользует).
4. **Полный откат:** удалить `./data/`, контейнеры и сеть
   `docker network rm xio-cascade`; образ — `docker rmi xio-cascade:local`.
5. Удаление peer-а на exit: `cascade-exit-setup.sh --remove-peer <pubkey>` + перезапуск контейнера.

## Безопасность

- Приватные ключи и PresharedKey лежат в `./data/` с правами 600 (каталог 700),
  в логи и в JSON-сводки **не попадают** — только публичные ключи и отпечаток.
- `--token-file`: произвольный секрет приводится к валидному 32-байтному PSK
  (sha256 → base64) одинаково на обеих сторонах; поддерживается и готовый wg-ключ.
- `--exit-fingerprint` пинит личность exit (`sha256` от IPv6+порт+pubkey):
  несовпадение — установка bridge прерывается.
- Контейнеры получают только `NET_ADMIN`, `/dev/net/tun` и нужные порты,
  без `--privileged` и без host-network.
- `terminal-install.sh` скачивает установщик по HTTPS, проверяет sha256 **до** запуска,
  требует root и пишет лог в `/var/log/xio-cascade-install.log` (600).
- В bash-скриптах нет `eval`, все переменные в кавычках, внешние команды проверяются
  через `command -v`, временные каталоги убираются по `trap`.
- Остаточные риски: root в контейнере = root на хосте при побеге из namespace;
  компрометация bridge = доступ к туннелю; списки из интернета — недоверенные данные.

## Что не проверено / не реализовано

- **Скрипты не запускались ни на одном сервере**: нет живой пары IPv4+IPv6,
  поэтому проверен только синтаксис bash и логика ветвлений.
- **NAT46 на exit** (`ip saddr 10.202.0.0/24 snat ip6 to <exit-v6>`) зависит от ядра
  и версии nftables; при неподдержке exit пишет предупреждение, IPv4-клиенты
  остаются без выхода — нужен реальный тест.
- **Aвтоматическая регистрация ключа bridge на exit** не сделана: шаг `--add-peer`
  выполняется вручную (в `--role both` — автоматически).
- **Домены в белых списках** разворачиваются в IPv4 на момент обновления; CDN меняет
  адреса, поэтому между запусками таймера часть доменов может «протухнуть».
  Кэш DNS и маршрутизация по именам (dnsmasq/ipset) не реализованы.
- **xio-server (`admin.py`, entry 8443, gateway 17443) в образ не входит**: контейнер
  даёт туннель и правила, а серверный пакет `xio-server-<version>.tar.gz` нужно
  ставить отдельно; web-адрес в сводке — предполагаемое место entry, не проверено.
- Не реализованы: ротация ключей, ограничение числа устройств, метрики/Prometheus,
  IPv6-белые списки (сет `xio_whitelist6`), проверка MTU/фрагментации на реальном
  мобильном канале, CI-тесты (shellcheck/`bash -n`) в репозитории.
