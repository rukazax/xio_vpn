# XIO / XIO Client 0.24.0+5017

RU: 0.24.0 — исправление серверной установки и обновлённая витрина проекта. Серверный пакет 0.23.1 не устанавливался: правило `nat POSTROUTING` собиралось с входным интерфейсом, `iptables` отвечал `Can't use -i with POSTROUTING`, и установка падала на шаге `Network stack operation failed: iptables`. На хосте только с IPv6 дополнительно падали `status` и таймер статистики: `counters()` вызывал `wg show xio0` до появления интерфейса и получал `Command failed: wg`.

В 0.24.0 область `-i` осталась только в цепочке `FORWARD`, правило `MASQUERADE` в `POSTROUTING` собирается без входного интерфейса, а `counters()` пропускает ещё не созданные интерфейсы. Проверено живой установкой на Debian 13 (LXC, хост `fr-host.fr`, `restrictedNetwork`): bootstrap завершился с кодом 0, `init` вернул `ok` с `recipeVersion` 25, сервис `active`. До исправления та же установка падалаа на `iptables`.

Android: Full 0.24.0 ставится поверх 0.23.1 без удаления и без потери данных — подпись и имена пакетов не менялись. Проверено на POCO X6 5G (Android 16, ARM64): установка `adb install -r`, импорт профиля из файла, подключение к серверу `192.168.88.17:18443` по RIVET/S1, адрес в туннеле `10.79.0.250`, состояние «Туннель активен · DNS через туннель», счётчики растут. На сервере пользователь `online=true`; после отключения — `online=false`, после повторного подключения — снова `online=true` и рост счётчиков. Падений и ANR нет.

Также в этом выпуске: переоформлена страница проекта — функции, пять транспортов, IPv4/IPv6, установка и администрирование, двуязычный README со схемами.

**Состав выпуска.** Android: Full и Client по четыре APK (arm64-v8a, armeabi-v7a, x86_64, universal). Windows 11 x64: Full ZIP с встроенным серверным архивом. Ubuntu 22.04+ x64: `.deb` и переносимый `.tar.gz`, собраны на Debian 13 (запуск графического интерфейса не проверялся). Сервер: `xio-server-0.24.0.tar.gz`. Windows Client в этот выпуск не входит.

**Проверено:** серверный архив (живая установка), Android Full 0.24.0 (установка поверх, импорт профиля, подключение, отключение, повторное подключение), сборка Windows, сборка Ubuntu-пакетов, подпись и zipalign всех APK.

**Не проверено в 0.24.0:** транспорты RIVET/H3, AWG, Xray/REALITY и Cloak; публичный IPv6 от клиента до сервера; iOS не собирался.

[Методика и ограничения](https://github.com/rukazax/xio_vpn/blob/main/docs/compatibility/0.24.0.ru.md) · [Клиент и субклиенты](https://github.com/rukazax/xio_vpn/blob/main/client/README.ru.md)

---

EN: 0.24.0 fixes the server installer and refreshes the project landing page. The 0.23.1 server package could not be installed: the `nat POSTROUTING` rule was built with an input interface, `iptables` replied `Can't use -i with POSTROUTING`, and the install stopped at `Network stack operation failed: iptables`. On an IPv6-only host, `status` and the statistics timer also failed every 30 seconds because `counters()` ran `wg show xio0` before the interface existed and got `Command failed: wg`.

In 0.24.0 the `-i` scope stays only in the `FORWARD` chain, the `MASQUERADE` rule in `POSTROUTING` has no input interface, and `counters()` skips interfaces that do not exist yet. Verified by a live install on Debian 13 (LXC, host `fr-host.fr`, `restrictedNetwork`): the bootstrap exited 0, `init` returned `ok` with `recipeVersion` 25, and the unit is `active`. Before the fix the same install failed at `iptables`.

Android: XIO Full 0.24.0 installs in place over 0.23.1 with no uninstall and no data loss — the signer and the package names are unchanged. Verified on a POCO X6 5G (Android 16, ARM64): `adb install -r`, profile import from a file, connection to `192.168.88.17:18443` over RIVET/S1, tunnel address `10.79.0.250`, state "Tunnel active · DNS through the tunnel", counters growing. On the server the user shows `online=true`; after disconnecting `online=false`, after reconnecting `online=true` again with growing counters. No crashes or ANRs.

Also in this release: the landing page was rebuilt — features, five transports, IPv4/IPv6, installation and administration, a bilingual README with diagrams.

**Payload.** Android: Full and Client, four APKs each (arm64-v8a, armeabi-v7a, x86_64, universal). Windows 11 x64: Full ZIP with the server archive embedded. Ubuntu 22.04+ x64: `.deb` and a portable `.tar.gz`, built on Debian 13 (the GUI launch was not tested). Server: `xio-server-0.24.0.tar.gz`. The Windows Client is not part of this release.

**Verified:** the server archive (live install), XIO Full 0.24.0 on Android (in-place install, profile import, connect, disconnect, reconnect), the Windows build, the Ubuntu package build, APK signatures and zipalign.

**Not verified in 0.24.0:** RIVET/H3, AWG, Xray/REALITY and Cloak transports; public IPv6 from the client to the server; iOS was not built.

[Methodology and limitations](https://github.com/rukazax/xio_vpn/blob/main/docs/compatibility/0.24.0.en.md) · [Client and subclients](https://github.com/rukazax/xio_vpn/blob/main/client/README.en.md)
