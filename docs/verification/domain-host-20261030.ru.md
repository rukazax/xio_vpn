# XIO VPN — домен наравне с IPv4/IPv6

Задача: TG202 (30.10.2026 23:19 МСК), уточнение TG204: тот же VPS-721137. Итог проверки родителем: **PASS_SOURCE_FEATURE_AND_LIVE_SSH_ONLY**. Это принятие исходников и живого SSH, не новый выпуск/установка и не полная VPN-приёмка.

## Сделано
- Единые проверки голого хоста и host:port: домен, IPv4, IPv6; скобки только у IPv6 endpoint. Порт SSH вводится отдельно. Поддерживаются ASCII DNS, Punycode и завершающая точка; Unicode-домен сначала должен быть переведён в Punycode. Схемы, userinfo, пути и инъекции отвергаются.
- Домен сохраняется в управлении, импорте/экспорте, AWG/RIVET/extended и выдаче субклиентам. Управляющий SSH proxy и публичный VPN-хост независимы.
- Приложение запрашивает A/AAAA параллельно через платформу, перемежает IPv4/IPv6 перед попытками; литералы идут без DNS. DNS до 8 с, затем отдельный TCP-бюджет 12 с, до 5 с на кандидата при нескольких ответах. Полного параллельного happy-eyeballs нет.
- SSH доверяет настроенному имени и сохранённому ключу, не DNS-алиасу/IP. После установленного сокета mismatch ключа останавливает вход до аутентификации, без переключения на другой адрес.
- Ядро проверяет endpoint до DNS/bypass. Protected VPN получает numeric-кандидаты от физического резолвера, без запасного системного DNS. Для отдельной диагностики добавлен bounded DialDiagnostic; rivet probe снова принимает домен. ServerName/SNI, сертификат и pin не заменяются выбранным IP.

## Найдено и исправлено при приёмке
1. Несколько A-записей могли исчерпать TCP-бюджет до единственного AAAA — добавлены перемежение и проверки реального порядка вызовов коннектора.
2. Новый numeric-only gate сломал домен в CLI probe — выделен явный диагностический lookup; защищённый путь не ослаблен. Исправлен захват срока жизни сессии временным context.
3. Финальная правка родителя в endpoint.go: общий diagnostic deadline начинается до DNS, предварительно отменённый запрос не запускает lookup/не обходит отмену для IP-литерала. Добавлены две регрессии. Точный diff и предыдущие байты: parent-native-final.patch / parent-native-before/. Это единственные два отличия от финального native-манифеста субагента.
4. Проверено по коду и тестам: GenerateOuter уже использовал IPAddresses SAN для IPv4/IPv6. Генерация IP SAN не выдумывается как новая правка; добавлены проверки VerifyHostname.

## Независимые проверки родителя
- Изолированный снимок приложения: **153/153 входных файла** совпадают с canonical после тестов; lib/test/assets/pubspec/analysis. Платформы и signing-материалы в stage не копировались.
- flutter analyze --no-pub: **No issues found**.
- flutter test --no-pub --dart-define=XIO_CLIENT_ONLY=true: **99 PASS, 0 FAIL, 0 SKIP** (12 файлов: domain_host/server_address/rivet_profile/extended_profile/security/managed_models/ssh_trust/protocol_compatibility/client_import/client_only/desktop_adapter/legal_consent).
- Go, шесть пакетов: **129 верхнеуровневых PASS**, 191 PASS с подтестами, 0 FAIL, **3 SKIP**. Пропуски только TestVPSPacketFlow, TestVPSProfiles, TestVPSCloakAuth (private fixtures). go vet: exit 0. Снимок Go-файлов не изменился между тестами и итоговой проверкой.
- GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...: **exit 0**, включая CLI; не запускалось и не устанавливалось. Полный Windows go test ./... отдельно не считается зелёным: известное Linux-only ограничение cmd/rivet/OpenTUN/unix.Flock остаётся (в исходном child-журнале).
- Python: **35 PASS, 0 FAIL, 0 SKIP**; test_rivet_public/test_host_validation/test_update_ipv6/test_admin. На Windows использован import-only fcntl shim; это не доказательство POSIX-lock или живого Linux installer. Исходники после тестов совпали.
- JVM: **25 CIDR + 10 физических DNS helper-проверок PASS**, без ADB/телефона.
- Живой **код VpsService** из проверенного stage: **2 PASS, 0 SKIP** — домен vps-721137.ssh.vps1euro.fr:9046 и IPv4-литерал. Ключ ED25519 строго совпал с прежним TOFU pin; UID0, VPS-721137 и assigned IPv6 подтверждены read-only командами. Это SSH-доступ, не VPN/data-plane.

## Тестовый VPS и границы
fr-host.fr проверен локально и с самого VPS: A=103.102.135.112, AAAA=2a0c:b641:1a0:800::1. Assigned VPS=2a0c:b641:1a0:800::2a2. Поэтому fr-host.fr не используется как доказательство соединения именно с этим VPS. DNS-записи не менялись. Положительный тестовый DNS-алиас sslip.io разрешился в assigned адрес, но с этого Windows-хоста прямой IPv6 дал socket error10057; работающий AmneziaVPN/защита/маршруты не отключались и не менялись.

Свежая проверка снимает старое наблюдение «TUN отсутствует»: сейчас /dev/net/tun — char10:200, работают xio-entry.service/xio-gw.service и xioacc0. До/после SSH-тестов совпали ограниченные наблюдения служб, listeners с PID, адресов и default routes; службы/сеть сервера не менялись. Это не полная аттестация всего хоста.

Предоставленный root-пароль использован для SSH-проверок. При повторных прогонах он расшифровывался из существующей owner-scoped DPAPI записи только в память и временное окружение; значение не записывалось в код/отчёт и не передавалось субагентам. Ключи подписи не читались.

## Статус и доказательства
sourceFeatureAccepted=true; newReleaseBuilt=false; newBuildInstalled=false; fullLiveVpnTested=false; suppliedFrHostFrVpnTested=false; deviceTested=false.

Общая owner138 остаётся открытой. Для живого VPN через конкретный fr-host.fr нужна корректная привязка DNS к assigned VPS и доступный IPv6-транспорт; существующий SSH proxy обслуживает SSH, не VPN. Новые APK/Windows-архивы в этой задаче не собирались, существующие кандидаты не переименовывались.

Основная квитанция: parent-final-verification.json, SHA-256 **8dbaaffa7eb9d4bcc71cd2b2757aaea9b4ff8ef7f6fc11346ece3bf33640b886**. В ней хеши файлов, журналов и исходников. Родительские доказательства: C:/Users/er-ka/.openclaw/workspace-xio/work/domain-host-20261030/. Отчёты субагентов: docs/verification/domain-host-app-20261030.ru.md и domain-host-native-20261030.ru.md; их бэкапы/диффы: canonical work/domain-host-20261030/app/ и native/. Финальная квитанция родителя приоритетнее ранних счётчиков и двух поздних исправлений.
