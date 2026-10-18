# Сборки XIO 0.19

* `tools/build-linux.sh` — Flutter release. Скопируйте результат `go build ./cmd/xio-desktop` в `bundle/libexec/xio-tunnel`, затем `tooling/cross-platform/package-ubuntu.py`.
* `tools/build-windows.ps1` — стандартная нативная сборка на Windows с Visual Studio C++ workload. Пакетировать нужно и `libexec/xio-tunnel.exe`, и официальную amd64 `wintun.dll` с её неизменённой лицензией.
* `windows_runner.cpp` — дополнительный Win32 C API runner для MinGW; использует публичный API Flutter Windows engine. Исходники приложения и AOT должны собираться именно с target-os Windows; Linux app.so не подходит.
* `build-ios.sh` — сборка на Mac. Нужны Flutter 3.47.7, Go 1.27.2, Xcode с iOS SDK, ваша команда Apple Developer, настроенные App IDs/app group/keychain group и ExportOptions.plist. Стандартный идентификатор `app.xio.client`, расширение `app.xio.client.PacketTunnel`, app group `group.app.xio.client`. Если эти идентификаторы заняты в чужой команде, замените их согласованно в Swift, plist, entitlements и Xcode project перед сборкой.

В release не включается QA-entrypoint `app/tool/windows_crypto_smoke.dart`. Он отдельно проверяет DPAPI и хранилище в Windows-VM; production main его не импортирует.
