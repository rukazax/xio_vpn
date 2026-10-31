# XIO: проверка двух семейств и тестовые сборки, 29.10.2026

Это порядок получения **тестовых кандидатов**, не утверждение готовности опубликованного 0.23.0 или прохождения VPN на устройстве. Не подменять этими результатами OS/data-plane приёмку.

## Изоляция исходников

- Полная рабочая копия остаётся источником. Client готовится `python client/build.py --prepare-only --stage <fresh-stage>`; Windows — `python client/prepare_platform.py windows --stage <fresh-stage>`.
- Версия проверяется до записей; каталог staging защищён marker-ом `xio-client-staging-v1`. Чужой/старый unowned каталог сохраняется: выбрать новый, а не удалять вслепую.
- Client не получает server assets, установочную permission или SSH/admin ветки UI. До отдельного решения владельца эта граница сохраняется.
- source-inputs содержит Dart, Android, assets, AAR, AWG Java и gradle.properties; после изменения native/vendor inputs обновить staging и его манифест.

## Android: ABI и native inputs

- Закреплённые инструменты: Go1.27.2, x/mobile из go.mod, NDK30.0.16248370. Android использует отдельную Go-copy с документированным CLOCK_BOOTTIME patch; установленный Go не переписывать.
- `go mod verify` проверяет кеш зависимостей. Отпечаток собственных Go inputs: `python tools/native_fingerprint.py`. Зафиксировать его до/после native build.
- При принятии проектной AWG-зависимости использовать контролируемый `vendor/amneziawg-go`, не общий кеш модулей. Отпечаток учитывает каждый файл этой необязательной зависимости, включая Go/C/assembly, go.mod/go.sum и лицензию; отсутствующий каталог сохраняет прежний алгоритм хеша. Неправильный module identity, символические ссылки и выход за проект отвергаются. Само добавление этого контроля НЕ означает, что новая зависимость уже принята или включена. Регрессии: `python -m unittest discover -s tools -p test_native_fingerprint.py -v` (9 чистых файловых тестов; проверки признака ссылки моделируются, не меняют права Windows).
- В этой проверке Windows gomobile сформировал arm64-v8a/armeabi-v7a/x86_64 AAR. Проверялись ELF machine и Java public API. Для 64-bit ABI требуется16KiB alignment, для32-bitARM исходная граница4KiB; не требовать16KiB от32-bit ошибочно.
- Одна `--target-platform android-arm64` НЕ убрала остальные JNI ABI из AAR: получился смешанный APK с Flutter/libapp толькоARM64. Для одиночного APK применять **также `--split-per-abi`**.
- `client/apk_abi.py` требует точный набор ABI и libapp/libflutter/libgojni/libxio_openvpn/libc++_shared в каждой. Неполные/лишние ABI и duplicate ZIP members отвергаются.
- `client/verify.py` по умолчанию требует все4APK. Частичный кандидат допустим только с явным `--architectures arm64-v8a`; это не all-architecture PASS. `--native-aar <candidate>` передаёт точный reference в check-native-payload, `--android-build-tools` — существующий SDK.
- Проверять подпись, launcher aliases, отсутствие server assets/admin markers, ZIP/ELF alignment и allocated-section equality после Gradle strip. Наличие APK не доказывает VPN.

## Подпись и приватность

Использовать только разрешённый ключ проекта; сертификат сверять с проверенным опубликованным APK. Значения ключей/паролей не выводить и не добавлять в source/package/межагентные сообщения. Временные signing.properties — вне app/assets, с ограниченным доступом; удалить в finally и проверить отсутствие. Совпадение сертификата не является отдельным pre/post hash-тестом файла keystore.

## Серверный кандидат

- Canonical tools/build-rivet.py сохраняет свою Linux/race release-процедуру; не убирать её guards ради удобства.
- Windows→Linux cross build, Linux unit tests и проверки help/invalid-arguments дают отдельный тестовый кандидат. Они не заменяют race, TUN, protocol traffic или production qualification.
- tools/prepare-native-candidate.py разрешает только root вне canonical source tree. Проверяет оба source snapshots, четыре native hashes, AAR/API evidence и Linux unit/entry evidence; вызывает обычный package-server с неизменёнными byte/fingerprint/recipe guards.
- Все реальные assets создаются только в изолированном candidate root, recipe25; исходные published/canonical release inputs не переписываются.
- AWG брать только из digest-verified owned source/asset. В старой source-поставке обнаружены4stale entries во внутреннем SOURCE-SHA256SUMS; восстановление подтверждено хешем всего опубликованного source ZIP и exact member bytes, а не молчаливым игнорированием checksum failure.
- Linux unit upload — только проверенные regular members, root identity+SSH pin, отдельная/run папка, TMPDIR внутри неё, cleanup и сравнение routes/forwarding до/после. Не загружать private/profile/signing files.
- В данной проверке67managed+5packaging fixtures прошли на Linux без skips; три native entrypoints проверены без запуска VPN services. Первый пакет пропустил bootstrap.sh, был исправлен и полностью перезапущен, а не объявлен PASS с пропуском.

## Windows

Собрать отдельный Client GUI, добавить текущий xio-tunnel helper и digest-verified официальный Wintun с лицензией. ПроверитьPEamd64, data/app.so/icudtl, отсутствие server assets/private signing files и digest каждого ZIP member. Сборка/ZIP не означают запуск GUI/драйвера, WFP/no-leak или VPN data-plane. Не выключать чужой VPN/firewall ради зелёного теста.

## Открытая приёмка

1. Android: эксклюзивное окно общего устройства до ADB/input/install/VPN; не принимать queued/interrupted за grant.
2. VPS: предоставленный провайдером TUN/capabilities; не обходить device/cgroup/LSM ограничения.
3. DNS64/NAT64 HTTPS не доказывает literalIPv4 или IPv4-packet egress; NAT66 не является NAT64.
4. Apple: действительные macOS/Xcode SDK/framework build и signed physical iPhone;24Swift source/reference checks и Go policy unit tests этого не заменяют.
5. Для каждого заявленного engine: outer IPv4/IPv6 отдельно от payload IPv4/IPv6, DNS, leaks, failure/failover и cleanup. Не превращать unavailable family safe-block в PASS этой семьи.

## Android AWG: дополнительная проверка DNS

Vendor dependency игнорируется Git: переносимый patch, исходные SHA256 и порядок повторного применения сохранены в `patches/amneziawg/`. На уже исправленном дереве выполнять reverse-check, не применять patch повторно.

`app/integration_test/dualstack_awg_jvm_checks.ps1 -Repeat 20` компилирует26productionJavafiles и выполняет23проверки ×20. Это отдельная проверка от Kotlin/APK build и от Android physical/protect runtime.

После Java-only fix пересобиратьAPK и обновлять source-inputs; GoAAR с неизменным отпечатком заново не требуется. Проверять наличие строки `xio-awg-physical-dns` в фактическомDEX вместе с подписями/ABI/ELF/ZIP, а не только наличие исходника в stage. В этой проверке получены все4ClientAPK; предыдущийARM64кандидат доAWGpatch сохранён отдельно и более не является актуальным.

Существующий AWG resolver выбирает первый пригодный физический адрес. Это НЕ переключение по неудачному handshake; не выдавать интерливинг DNS за доказательство failover или успешной связи с сервером.

FullAndroid готовится отдельно от Client, с собственным vendor-copy и recipe25assets; signing.properties только внутри защищённого owned-stage, не в pubspec/assets. Сравнивать весь source-inputs до/после, текущие canonical sources и candidate assets, сертификат, DEX patch marker и каждый упакованный server-asset. Для этого этапа исходный keystore дополнительно сравнивается по хешу до/после без вывода значений ключа.
