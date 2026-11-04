# Передача контекста xio — 04.11.2026

Передача всех наработок и контекста сессии. Ниже — где что лежит, в каком состоянии, что решено,
что открыто и как проверять. Всё, что можно проверить командой, помечено командой.

## 1. Где что лежит

| Что | Путь |
|---|---|
| Репозиторий (ветка `release-0.24.0`) | `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit` |
| Рабочее пространство и отчёты | `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\` |
| Собранные артефакты | `…\repo-edit\releases\` |
| APK/AAR и Android-артефакты | `…\xio_vpn\work\apk-20261104\` |
| Журнал совместной работы | `…\repo-edit\work\xio-joint-log.md` |
| Скрипты сборки и проверки | `…\repo-edit\work\rebuild-all.ps1`, `work\verify-all.ps1`, `work\flutter-test-debian.ps1` |

Вершина ветки на момент передачи: **`99e5721`** (запушена). Тег **`v0.24.2`** существует, последний
предрелиз — **`v0.24.1-rc15`**.

Незакоммиченное в рабочем дереве: правки `app/lib/core.dart` и `app/test/*` от агента по watchdog
(readiness-проба вместо DNS) — он ещё работает, коммитить после его отчёта.

## 2. Архитектура (что реально работает)

- **bridge** `81.177.142.37` — Debian 12, только IPv4, XIO 0.24.1 (serverId `42c1788d-…`), протоколы
  awg/rivet-h3/rivet-s1/xray/cloak, 8 юнитов.
- **exit** `2a0c:b641:1a0:800::2a2` — Ubuntu 22.04 в LXC, только IPv6, за провайдерским IPv4-прокси
  (`vps-721137.ssh.vps1euro.fr:9046`).
- **Каскад**: `ssh -w 0:0` (tun) через прокси; `tun0` `fd00:201::1/126` ↔ `fd00:201::2/126`, NAT66 на exit.
  Все протоколы клиентов ходят через каскад, потому что XIO сам строит `FORWARD … -o tun0`.
- **Статичный AWG** для роутеров/телефонов: `add-awg` + `xio-peer.py` (QR), MTU 1280, изоляция клиентов.

## 3. Ключевые решения (не пересматривать без причины)

1. Транспорт каскада — **`ssh -w`**, не OpenVPN-TCP (TCP-over-TCP даёт meltdown). Вариант с OpenVPN
   собран, проверен и **отключён**.
2. На exit **NNP вместо ФС-изоляции**: `NoNewPrivileges=yes` молча срывает сборку unit-root, поэтому
   `ProtectSystem` там не материализуется; выбран NNP + seccomp/capabilities, exposure 62,0 → 33,9.
3. Хостовый `CapabilityBoundingSet` через drop-in **не перебивается** — не пытаться.
4. MTU: устройство **1280** (минимум IPv6), 1232 — PMTU пути. `tun0` каскада — 1400 под аплинк exit.
5. IPv6-резолвер `2620:fe::fe` выдаётся **только при живом каскаде** (проба, а не маршрут) — одно
   определение «IPv6 работает» на весь продукт (`dualstack.cascade_status()`).
6. `shadowsocks` этот форк xray не умеет: протокол убран из списка и из `profiles()`, inbound не
   эмитится даже на не-restricted установке.

## 4. Найденные и исправленные баги (самое ценное)

| Баг | Суть | Коммит |
|---|---|---|
| **fd double-close** | `tun.CreateUnmonitoredTUNFromFD` заворачивал fd в `*os.File` до валидации, `AwgTurnOn` закрывал номер повторно, финализатор позже закрывал **чужой сокет** → случайные `i/o timeout`. Фикс `F_DUPFD_CLOEXEC` + 2 теста | `c2b3338` |
| **`public` shadowing** | `dispatch()` присваивал `public`, из-за чего `inspect` не работал никогда, а `add` возвращал ошибку без `configs`, уже записав пользователя | `2943b94` (и `19afcae`) |
| **IPv6 по маршруту** | `ipv6=true`/v6-DNS выдавались при мёртвом каскаде → Android виснул на резолвере | `2943b94`, `0f924f1` |
| **shadowsocks в конфиге** | гейтвей падал `unknown config id: shadowsocks` | `4385d4a`, `1e6e188` |
| **`ProtectSystem=no`** | compat-режим снимал защиту целиком; теперь `full` + `ReadWritePaths`, drop-in 0644 | `3ffcb1e` |
| **boot-поломки** | после ребута: forwarding=0 (гонка с каскадом) и пропавший UAPI-симлинк | `0c579f9` |
| **сборка сервера** | `rivet-setup.py` получил `IndentationError` в `6835ed0` — падала упаковка | `2943b94` |
| **каскад-шторм** | `RestartSec=5` дал 480 рестартов за 40 минут; добавлены backoff и маркер отказа | `cae2e43` |

## 5. Открытые блокеры 0.24.1 (решение xio)

**D1 — утечка памяти при connect/disconnect (блокер).**
Факты: рост PSS **+9–10 МБ за цикл**, на 14-м цикле 0.24.1 Android убил процесс. Растёт строка
`Unknown` (анонимные mmap), `AppContexts` 6→9/10 при мёртвых сервисах. Разделение слоёв:
- Go-helper (тот же `protocol/rivet/mobile`, что в AAR) — **чист**: 30 циклов с настоящим handshake,
  heap ровный, RSS без тренда;
- Dart — **плоско**: +57 КБ/цикл с фейковым каналом, рост останавливается к 20-му циклу;
- значит виноват **Kotlin/JNI-слой** — агент ищет держателей `Context` (статические поля,
  `companion object`, слушатели, `VpnService`-биндинги).

**D2 — watchdog (блокер).** Корень один: `core.dart` проверял живость через
`InternetAddress.lookup('example.com')`, а системный резолвер Android кэширует → мёртвый туннель
выглядит живым. Отсюда авто-fallback 214 с вместо ≤30 и отсутствие восстановления после авиарежима.
Готова замена на readiness-пробу через туннель (`10.78.0.1`/`fd78:1::1`), +13 КБ, два теста; ждёт
прогона на телефоне.

**Критерий приёмки от xio:** не «выжил N циклов», а **плато** — PSS после 10-го и после 30-го
отличаются менее чем на 50 МБ, без монотонного роста; переключение транспорта ≤20 с, восстановление
после авиарежима ≤30 с.

## 6. E2E Android — что уже проверено (и чем это ограничено)

`work/e2e-android-20261104.md`. 33 цикла connect/disconnect на 0.24.1/0.24.2:
- **ноль** `bad file descriptor` / `EADDRINUSE` / `too many open files` по `app.xio` — фикс fd работает;
- каждый цикл даёт свежий handshake 5–7 с; IPv4 3/3 (34–52 мс); прокачано 1,4 МБ (tx +1 497 444 Б);
- **не пройдено** из-за D1, D2 и авиарежима; IPv6-проверки были невыполнимы, пока каскад лежал.

Важно: прогон был недействителен из-за **гонки двух акторов** на одном adb-устройстве (релизная линия
ставила APK). Протокол закрепления телефона — в отчёте: сверять `versionName`, `versionCode`,
`lastUpdateTime`, `sha256 base.apk` до и после; для диагностики использовать `versionCode 5030`.

## 7. Живое состояние (проверено на момент передачи)

```
bridge: xio-cascade enabled+active, tun0 fd00:201::1/126, default via fd00:201::2, ping6 2/2 72 мс
        8 юнитов XIO active, failed 0, AWG 3 пира, MemoryMin awg 64 МиБ
exit:   xio-cascade-exit active, forwarding 1, NAT66 fd00:201::/126
phone:  AmneziaVPN + статичный AWG (профиль router-jeton), IPv4 2/2
lab:    Debian 192.168.88.17 — IPv6 через каскад 3/3, 1,4 МБ
```

Доступы: bridge — ключ `C:\Users\er-ka\.ssh\id_ed25519_debian17` (root); exit — только с bridge,
ключ `/root/.ssh/id_ed25519_cascade` через прокси 9046; телефон — adb `909f194a`
(`C:\Users\er-ka\.dsh\bin\platform-tools\adb.exe`); Debian — тот же ключ, root.

## 8. Артефакты и релизы

`v0.24.1-rc15` (prerelease): windows zip `e5d95c2d…`, deb `701039f8…`, tar.gz `7ad8bd73…`, сервер
`1ea3112a…`, APK `2ccbdee8…`, client APK `6c57b0c6…`. Манифест `SHA256SUMS-0.24.1.txt` — 6 записей.
Тег `v0.24.2` — сборка релизной линии (Kot), не наша.

## 9. Инструменты проверки

```powershell
pwsh -File work\verify-all.ps1          # 16 проверок, ~2 мин; последний: OK 15 / WARN 1 / FAIL 0
pwsh -File work\rebuild-all.ps1         # пересборка сервера + Windows + Ubuntu (helper кросс-сборкой на Debian)
pwsh -File work\flutter-test-debian.ps1 -RepoRoot <repo>   # Flutter-тесты на Debian: 200/10/0
```

Локальные ограничения среды: **Smart App Control** блокирует `dartaotruntime.exe` и Go-тулчейн на этом
ПК, поэтому Flutter-тесты и эталонная сборка helper'а выполняются на Debian (192.168.88.17).

## 10. Инвентарь отчётов в `xio_vpn\work\`

Аудит и ревью: `release-audit-20261103.md`, `review-awg-20261103.md`, `cascade-resilience-20261103.md`.
Оптимизация: `opt-go-20261104.md`, `opt-app-20261104.md`, `opt-server-20261104.md`,
`opt-server2-20261104.md`, `opt-runtime-20261104.md`, `opt-helper-size-20261104.md`,
`opt-registry-trim-20261104.md`, `opt-xray-proto-20261104.md`, `opt-bundle-20261104.md`,
`opt-mobile-size-20261104.md`, `opt-mobile-power-20261104.md`.
Хосты: `opt-hosts-20261104.md`, `opt-legacy-20261104.md`, `root-cleanup-20261104.md`,
`memory-floor-20261104.md`, `panel-cpu-20261104.md`, `unit-hardening-20261104.md`,
`exit-hardening-20261104.md`.
Сервер: `cap-fix-20261104.md`, `v6dns-fix-20261104.md`.
Android: `android-build-20261104.md`, `e2e-android-20261104.md`, `selfupdate-20261104.md`.
Проверки: `verify-runner-20261104.md`, `flutter-test-fix-20261104.md`, `test-fix-20261104.md`.
Инцидент: `cascade-incident-20261104.md`.

## 11. Что осталось в работе у агентов

1. **D1** — поиск утечки в Kotlin/JNI, инструментированный APK (`versionCode 5030`), фикс в `app/android/**`.
2. **D2** — watchdog с readiness-пробой, прогон на телефоне против закрытого udp/51821 и авиарежима.

Обе задачи пришлют отчёты и патчи; после интеграции — пересборка, `verify-all`, повторный E2E по
восьми проверкам с числами и плато-критерием.

## 12. Известные ограничения (не блокеры, но помнить)

- **Автообновление приложения мертво с v0.22.2** — в релизах нет ассета `XIO-update.json`; в 0.24.1
  не чиним, зафиксировано в CHANGELOG.
- **Клиентский APK** проверялся только по заголовку (окно `FLAG_SECURE`, скриншоты чёрные).
- **Панель x1o**: очередь отключена (`work.enabled: false`), CPU 3,6 → 0,17 %; включать обратно — по
  решению владельца.
- **Exit**: `ProtectSystem` не материализуется из-за NNP; `CapabilityBoundingSet` через drop-in не
  перебивается; фактическая изоляция применится к работающим процессам только после рестарта.
- **Статичный AWG** не умеет перебор транспортов и watchdog — это осознанно.
- **Физический роутер Jeton** так и не проверялся: профиль готов, нужен девайс.
