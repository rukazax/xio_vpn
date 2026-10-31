# XIO AWG: начальная аутентифицированная активация, 30.10.2026

Статус: исходники и локальные проверки; не приёмка VPN на устройстве. Старая
квалифицированная EA067 generation (8 APK + 2 Windows ZIP) сохранена. Канонические
AAR, native inputs и server assets не заменены. Коммит/публикация не выполнялись.

## Контролируемая зависимость и доказательство соединения

Проект использует vendor/amneziawg-go (локальный replace из protocol/rivet/go.mod),
копию pinned v3.1.20260814. Общий modcache не редактировался. Происхождение и
добавочные API описаны в vendor/amneziawg-go/XIO-CHANGES.md.

internal/awgactivation принимает только bounded numeric candidates, нормализует
mapped IPv4, отвергает unspecified/multicast/link-local/broadcast/zone/injection.
Для каждого кандидата новый baseline берётся ДО изменения endpoint. Успех требует
immutable event с actual packet source, нужным public key, новым sequence и
неизменными lifetime/peer identity; повторно проверяется отмена. Ни Up, ни
IpcGet timestamp/endpoint snapshot, ни счётчики не являются доказательством.

Endpoint меняется typed API без общего IPC post-hook: IpcSet может вызывать
SendStagedPackets и сбрасывать attempts через SendHandshakeInitiation(false),
когда initial traffic уже в очереди. Новый setter не заменяет peer/keypairs,
не проигрывает PSK/AllowedIPs/keepalive snapshot и не трогает send.go/timers.go.
Начальные retry requests используют true и штатный rate gate. Если общий budget
короче суммы dwell, прохождение всех 16 кандидатов НЕ гарантируется.

При отмене неудачной initial activation устройство закрывается. Сперва напрямую
закрывается неизменяемый bind, затем Device.Close: и Close, и Bind() могут ждать
net/IPC locks, занятые заблокированной отправкой. Проверка с настоящим device и
управляемым memory-bind Send воспроизводит это окно и требует join до return.
Успешный fallback сохраняет TUN/device/bind/peer и конфигурацию.

## Native registry и desktop

Production awg_registry хранит reservation до device close И join операции;
успех, cancel и TurnOff линеаризованы одним mutex. Stale handle не освобождает
слот нового устройства. Канонический decoded key предотвращает повторную
активацию через смену регистра hex. Harness использует этот production registry,
а не дублирующую реализацию. Тестовые close callbacks — только чистый тест gate,
не fake generated binding и не приёмка Android.

Desktop сохраняет все resolved numeric candidates и все bypass routes, ждёт
аутентификацию до публикации active/session и позволяет Disconnect отменить
pending AWG до ожидания runtime mutex. Неполный профиль не возвращает success.
Windows-only socket-regression test получил явный build tag для Linux crosscompile.

## Android Java

c325/c326/c327 и их patches/backups сохранены в owned verification workspace.
Parent c328 дополняет c327: AwgServicePublication атомарно выполняет publish,
adopt и compare-by-instance retire статического future; foreign/never-adopted
onDestroy не сбрасывает future новой службы. Owner assignment входит в epoch
adoption gate. Execution/Teardown completion используют атомарный once token.
UP по-прежнему публикуется под lifecycle lock; native close и ожидания — вне его.
Реальный async onDestroy после stopSelf не заменяется JVM моделью.

## Проверка и ограничения

Логи и receipts: workspace-xio/work/dualstack-20261029. JVM c328: 20 прогонов
по 105 проверок; production-registry: 20 повторов 5 regression scenarios;
blocked Send/direct validation: 10 повторов, exit0. Selected Go vet/unit gates,
реальная memory cryptography и Linux/Windows crosscompile проверяются отдельно.
Native/AAR generation: native-awg-20261030-v2, неизменяемые source-before/after,
ELF ABI/alignment и отдельное точное additive Java ABI approval по обоим AAR hash.
Full vendor javac проверяется только против свежего настоящего AAR через AarPath.

Memory tests не доказывают IPv6 physical carrier, payload, DNS, leak prevention,
доставку Android callbacks или работу на телефоне. Public source observation не
доказывает физический путь при relay. Для принятия нужны разрешённые платформы,
реальные IPv4/IPv6 uplinks и отдельные data-plane/cleanup проверки. iOS SDK и
подписанный iPhone, provider TUN и окно Android устройства остаются отдельными
условиями, а не причинами ослаблять сборочные защиты.

## Windows: сохранённая сборка и текущий интерфейс

Windows Client AWG ZIP `2183628c…eb56b47` (38 771 206 байт, 60 файлов)
прошёл родительские 64/64 проверки и повторный контроль после перезапуска 10/10.
В нём новый helper `f79435b4…65a5` (native FP `8b7fdda0…ba01ca`) и прежний
принятый AOT-интерфейс из w138. Это frozen-artifact acceptance, не сборка
текущего GUI и не проверка живого VPN. Последующие правки пяти Dart-файлов
сохранены; их нельзя откатывать ради совпадения с готовым архивом.

Порядок повторной приёмки:

1. После перезапуска проверить terminal status и сохранённый результат child,
   реальные SHA/CRC/member bytes и уже созданный receipt. Не повторять сборку
   или проверяющий скрипт с записью exclusive `x` вслепую.
2. Сравнивать подготовленный Windows GUI с post-transform `guiInputs`, а не
   безусловно с исходным `source-inputs.json`: prepare_platform заменяет четыре
   legal/privacy файла portable-шаблонами ПОСЛЕ записи исходного manifest.
   Доказывать обе цепочки хэшей и точное множество исключений, не blanket skip.
3. Исторические Android-only vendor расхождения учитывать отдельно; они не
   доказывают Android compile/runtime и не входят в Windows AOT.
4. Если текущие Dart-входы отличаются от frozen manifest — результат не может
   называться latest-source release. Нужна новая отдельная staging-сборка с
   фактической Flutter Windows компиляцией, новым app.so и manifest до/после.
   Старые ZIP, w138/w30h, канонические AAR/assets и credentials не менять.
5. Hash state.json в старом receipt относится к моменту проверки до merge
   checkpoint. После намеренного merge это не текущий инвариант. Не исправлять
   исторический receipt и не заявлять неизменность всей папки по восьми файлам.
6. Даже удачная новая компиляция не заменяет разрешённые runtime-проверки
   IPv4/IPv6 transport/payload, DNS, cleanup и предотвращения утечек.

Доказательства: workspace-xio/work/dualstack-20261029/
`windows-client-handshake-parent-verification-scoped.json`,
`windows-client-handshake-restart-verification-20261030.json`,
`windows-scope-review-7fade.json`; новые результаты GUI — отдельно в
`windows-client-current-gui/`, только после фактического завершения.


## Шаг39: новый AOT-снимок и восстановление артефакта

Новый Windows Client current-gui ZIP 3feb03f2…101c08b (38 796 052 байта,
60 файлов) создан до рестарта. Родитель после восстановления проверил 51/51,
97/97 stage inputs; новый app.so c75d95bb…9154a. Client-mode тесты с
--no-pub --dart-define=XIO_CLIENT_ONLY=true: 19 passed / 0 skipped.
Артефакт соответствует снимку 30.10 01:54:02 МСК, не нынешним исходникам:
позже изменились client_main.dart, core.dart, workspace_ui.dart.

Для повторения процедуры:
- Сначала сверять сохранённый результат; не пересобирать готовый архив ради ответа.
- PE считать после полного формирования bundle, включая helper и Wintun.
- Client-only тест требует XIO_CLIENT_ONLY=true, иначе он пропускается. Он пишет
  PNG в ../.build-support/client-preview: запускать только в owned stage.
- Сохранять обе canonical карты и время до/после упаковки отдельно: union
  snapshotDrift не восстанавливает drift_before/drift_after. Старый флаг
  snapshotMovedDuringBuild фактически относится к интервалу УПАКОВКИ.
- Новый digest/mtime и успешный build log не являются криптографической
  привязкой исходников к AOT или доказательством воспроизводимости.

Доказательства: windows-client-current-gui/REPORT.ru.md,
parent-recovery-verification-20261030.json, parent-client-mode-tests-20261030.log,
RECOVERY-REVIEW.ru.md. Исходная owner138 VPN/data-plane задача остаётся открытой.
