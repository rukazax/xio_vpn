# Каскад Android → VPS РФ → зарубежный VPS — 17.11.2026

Стенд: POCO X6 5G (23122PCD1G), Android 16, Wi-Fi `MY-NET` / Beeline LTE.
Телефон: клиент `app.xio.xio` 0.24.3+5020 (arm64).
Bridge: `81.177.142.37` (`nv-144442`, Debian 12, 958 МиБ RAM, IPv4-only).
Exit: `103.102.135.124` (VPS-721137, 1 ГиБ RAM, публичный IPv4 + IPv6
`2a0c:b641:1a0:800::2a2`).

## 1. Схема, которая реально работает

```
телефон 10.78.0.3 (AmneziaWG 3.1)
   │  UDP 51821, obfuscation Jc/Jmin/Jmax/S1/S2/H1..H4
   ▼
bridge 81.177.142.37  xioawg0 10.78.0.1/24
   │  policy: ip rule iif xioawg0 table 51888
   │  SNAT 10.78.0.0/24 → 10.250.0.1
   ▼
SSH TUN (TCP/22, aes128-gcm, без сжатия)
   tun0: 10.250.0.1/30  ⇄  10.250.0.2/30
   IPv6: fd78:2::1/64   ⇄  fd78:2::2/64
   ▼
exit 103.102.135.124  tun0 10.250.0.2/30
   │  NAT44 10.250.0.0/30 → eth0
   │  NAT66 fd78:2::/64 → eth0
   ▼
Интернет: IPv4 103.102.135.124 / IPv6 2a0c:b641:1a0:800::2a2
```

Клиентский трафик с `xioawg0` уходит в таблицу `51888` по `iif`, а не по
`fwmark`. Это принципиально: `fwmark` на внутреннем пакете наследовался
инкапсулированным UDP-пакетом WireGuard и заворачивал его обратно в туннель
(петля). После перехода на `iif` данные пошли.

## 2. Установка

На exit (`103.102.135.124`):

```bash
install -m 700 xio-cascade-exit-up.sh /usr/local/sbin/
install -m 700 xio-cascade-exit-down.sh /usr/local/sbin/
install -m 644 xio-cascade-exit.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now xio-cascade-exit.service
```

На bridge (`81.177.142.37`):

```bash
install -m 700 xio-cascade-bridge-up.sh /usr/local/sbin/
install -m 700 xio-cascade-bridge-down.sh /usr/local/sbin/
install -m 644 xio-cascade-bridge.service /etc/systemd/system/
printf 'XIO_CASCADE_EXIT_HOST=103.102.135.124\n' > /etc/xio-cascade/bridge.env
systemctl daemon-reload
systemctl enable --now xio-cascade-bridge.service
```

Один раз:

```bash
# на exit: разрешить SSH-туннель
grep -q '^PermitTunnel yes' /etc/ssh/sshd_config || \
  echo 'PermitTunnel yes' >> /etc/ssh/sshd_config

# на bridge: ключ и авторизация на exit
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/xio_cascade
cat /root/.ssh/xio_cascade.pub   # добавить в /root/.ssh/authorized_keys на exit

# на bridge: sysctl + BBR
modprobe tcp_bbr
sysctl -w net.ipv4.tcp_congestion_control=bbr
```

Скрипты и юниты лежат в `deploy/cascade/native/`. Они идемпотентны:
повторный `systemctl restart xio-cascade-bridge` пересоздаёт правила, не плодит
дубликаты.

## 3. Проверки

| Проверка | Результат |
|---|---|
| systemd на bridge | `active (running)`, `NRestarts=0` |
| systemd на exit | `active (exited)` |
| `ping 10.250.0.2` с bridge | 3/3, 48–53 мс |
| IPv4-выход с телефона | `103.102.135.124` (`ipv4.icanhazip.com`) |
| IPv6-выход с телефона | `2a0c:b641:1a0:800::2a2` (`ipv6.icanhazip.com`) |
| Главная экран | «Каскад активен», 🇷🇺 Устройство → 🇷🇺 Bridge → 🇫🇷 Exit, «Выход: 103.102.135.124 FR» |

Скриншоты:

- `docs/screenshots/android-cascade-flags-20261117.png` — главная с флагами;
- `docs/screenshots/android-cascade-egress-ipv4-20261117.png` — IPv4-выход;
- `docs/screenshots/android-cascade-egress-ipv6-20261117.png` — IPv6-выход.

## 4. Производительность

Первый замер SSH TUN дал **1,5 Мбит/с**: на пути РФ → Франция около 8 %
потерь, cubic сбрасывал `cwnd` до 3 и уходил в ретрансмиссии. После включения
BBR на bridge, `tcp_mtu_probing=1` и буферов 16 МиБ:

```
20 МиБ через tun0: 2,309 с = 69,3 Мбит/с
```

Телефон при активном каскаде: `TOTAL PSS 274 611 КиБ`, `RSS 418 480 КиБ`,
`CPU 0,0 %` в простое, батарея 27,5 °C. Каскад целиком серверный, поэтому
дополнительной нагрузки на CPU/RAM телефона не создаёт; MTU 1280 и MSS-clamp
на bridge убирают фрагментацию.

## 5. Что изменено в приложении

- Главная карточка каскада показывает флаги устройства/bridge/exit, фактический
  выходной IP и страну; «Каскад активен» только при активном туннеле.
- Новые поля профиля `cascadeExitIp`, `cascadeBridgeCountry`,
  `cascadeExitCountry`; `DurableDocument.java` допускает их.
- Если SSH-сервер не сохранён, «Проверить каскад» честно проверяет фактический
  выход через `api.ipify.org` и сохраняет адрес/страну.
- Кнопка «Повторить согласование» больше не скрывается, пока сохранение
  считается незавершённым.
- `save()` публикует новый план, если изменился **документ**, а не только
  производный план: иначе смена адресов каскада оставляла старый native-receipt.

## 6. Тесты

| Прогон | Результат |
|---|---|
| `flutter test --no-pub` | **1138 passed, 23 skipped, 0 failed** |
| `flutter analyze --no-pub` | 0 ошибок (43 info, прежние) |
| `flutter build apk --release --target-platform android-arm64` | 79,4 МБ |
| APK | `XIO-0.24.3+5020-android-arm64-cascade-20261117.apk` |
| SHA-256 | `3d8e57db1f6f70cf30fa0897f50ae2abe1c75773c6be870eea21b3775c5338be` |

## 7. Ограничения (честно)

1. **Одна команда на оба сервера из UI не сделана.** В приложении по-прежнему
   показывается команда только для bridge; exit ставится отдельно. Серверные
   скрипты позволяют поставить оба узла, но кнопки «поставить пару» в телефоне
   нет.
2. **Обновление приложения поверх сохранённого плана.** Если адреса каскада
   изменить после первого подключения, старый native-receipt становится
   недействительным. Исправление «публиковать при изменении документа» входит
   в эту сборку, но уже испорченный receipt сам не чинится: нужен чистый
   профиль или явное восстановление. Чистая установка → адреса → подключение
   работает.
3. **SSH TUN — TCP-over-TCP.** Он выживает на потерях только с BBR, а BBR есть
   на bridge, но не на exit (ядро 6.8.12-43-pve без `tcp_bbr`). Один путь, без
   резерва; при росте потерь скорость деградирует.
4. **WireGuard между серверами не поднялся по данным.** Handshake проходит, но
   transport-пакеты на этом маршруте теряются (похоже на фильтрацию UDP), поэтому
   выбран SSH TUN. AmneziaWG-обфускация между серверами не проверялась.
5. **DNS — 9.9.9.9**, а не резолвер провайдера; запросы идут через каскад.
6. **Yandex Browser** на этом телефоне показывает пустую страницу при том же
   туннеле, Chrome — работает. Это поведение браузера, не каскада; в отчёте
   оно фиксируется, а не маскируется.
7. Долгий soak, смена Wi-Fi ↔ LTE и перезагрузка обоих серверов в этом прогоне
   не повторялись после включения BBR.
