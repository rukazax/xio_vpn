# XIO 0.22.3 native runtime inputs / Исходники нативного runtime

The current protocol/rivet module adds IPv4/IPv6 physical endpoint selection and authenticated IPv6 RIVET packet forwarding. Unchanged modified dependency inputs remain under vendor. The exact build fingerprint and artifact hashes are in top-level vendor-metadata/rivet-build.json. Build with tools/build-rivet.py and the pinned Go 1.27.2 toolchain. SDKs and private signing keys are excluded.

Модуль protocol/rivet содержит выбор IPv4/IPv6 адресов и проверяемую передачу IPv6-пакетов RIVET. В vendor сохранены соответствующие исходники зависимостей и лицензии. Отпечаток сборки и хеши бинарников указаны в основном vendor-metadata/rivet-build.json. SDK и закрытые ключи подписи не включены.

Build5011 also verifies HTTPS through the selected Xray session before exposing TUN, independent of application/CIDR routing. Certificate/hostname checks and the fresh-remote-data guard remain enabled.

Сборка5011 дополнительно проверяет HTTPS через выбранный сеанс Xray до активации TUN, независимо от правил приложений/CIDR. Проверки сертификата, имени и свежих удалённых данных сохранены.
