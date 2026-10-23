# XIO Client 0.22.4

Облегчённый клиент готовых серверов с жёлто-оранжевым оформлением. Полный XIO остаётся зелёным. [Скачать предварительные сборки](https://github.com/rukazax/xio_vpn/releases/tag/v0.22.4).

Android: 8.0+, ARM32/ARM64/x86-64. Windows и Ubuntu: x64, предварительные сборки без новой нативной сетевой приёмки. iOS: подготовка исходников, IPA отсутствует. Общий формат профиля переносится между платформами, **полная совместимость нативных протоколов ещё не реализована**: 5 движков на Android, 4 на desktop, 2 на iOS.

[Матрица, скриншоты, схема и границы проверки](https://github.com/rukazax/xio_vpn/blob/v0.22.4/docs/compatibility/0.22.4.ru.md). [Предыдущие Android-функции и физические тесты](https://github.com/rukazax/xio_vpn/blob/v0.22.4/docs/dualstack/0.22.3.ru.md): подключение, переключение, Android split tunnelling, субклиенты по серверной квоте. Root/admin-ключи клиенту не передаются. Сетевые проверки 0.22.3 не являются проверкой новых сборок 5013.

## Build / Сборка

Run from the repository root, with Flutter, Python, Go and the native toolchain already installed. Signing credentials are external and never included.

```sh
python3 client/build.py
python3 client/verify.py
python3 client/build_linux.py --go /path/to/go
python3 client/prepare_platform.py windows
python3 client/prepare_platform.py ios
python3 tools/check-protocol-parity.py --require-complete
```

The last command intentionally exits 2 until the missing engines are implemented. Linux packages do not install themselves or enable NAS services. Windows native build: use the prepared `.build-support/client-windows/app` project with `flutter build windows --release --target=lib/client_main.dart --dart-define=XIO_CLIENT_ONLY=true` and bundle the desktop helper/Wintun and dependency licenses. The optional `client/build_windows_on_linux.py --help` documents cross-build inputs; a cross-build is not a Windows network test. iOS requires Mac/Xcode, signing/provisioning and NetworkExtension entitlements; use the prepared client project and the same Dart entry/define. No iOS binary is included.

Exact Android native snapshot: `native-sources/android-runtime-0.22.3`; runtime/AAR is unchanged. Each release includes corresponding source and SHA-256 hashes.
