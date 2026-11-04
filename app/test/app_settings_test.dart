import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/app_settings.dart';
import 'package:xio/core.dart';

/// Настройки приложения: сторонний DNS-резолвер, автозапуск, автоподключение и
/// разрешение скриншотов. Проверяются и валидация адресов, и реальный цикл
/// `AppStore.save()` → `AppStore.load()` на временном каталоге: парсер и writer
/// не должны расходиться молча.
///
/// В widget-тестах запись в файл подменяется: настоящий `save()` ждёт реального
/// ввода-вывода (`writeAsString`, `Process.run('chmod')`), а тело `testWidgets`
/// работает в поддельном времени и на таком ожидании останавливается. Файловый
/// круг проверяют обычные тесты ниже.
class _MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-app-settings-');
  });
  tearDown(() async {
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  Future<Map<String, dynamic>> savedJson() async => jsonDecode(
    await File('${directory.path}/profiles.json').readAsString(),
  );

  test('defaults: screenshots off, autostart off, Quad9 resolver', () {
    final store = AppStore();
    expect(store.dnsServers, ['9.9.9.9', '2620:fe::fe']);
    expect(store.autostart, isFalse);
    expect(store.autoConnectOnStart, isFalse);
    // Скриншоты выключены по умолчанию: экран с ключами защищён FLAG_SECURE.
    expect(store.allowScreenshots, isFalse);
    store.dispose();
  });

  test('dns, autostart, auto-connect and screenshots survive a restart', () async {
    final store = AppStore()..directory = directory;
    await store.setDnsServers(['1.1.1.1', '2606:4700:4700::1111']);
    await store.setAutostart(true);
    await store.setAutoConnectOnStart(true);
    await store.setAllowScreenshots(true);

    final data = await savedJson();
    expect(data['dnsServers'], ['1.1.1.1', '2606:4700:4700::1111']);
    expect(data['autostart'], isTrue);
    expect(data['autoConnectOnStart'], isTrue);
    expect(data['allowScreenshots'], isTrue);

    final reloaded = AppStore()..directory = directory;
    await reloaded.load();
    expect(reloaded.dnsServers, ['1.1.1.1', '2606:4700:4700::1111']);
    expect(reloaded.autostart, isTrue);
    expect(reloaded.autoConnectOnStart, isTrue);
    expect(reloaded.allowScreenshots, isTrue);
    // Existing connection settings are untouched by the new fields.
    expect(reloaded.checkSite, 'https://youtube.com');
    expect(reloaded.siteCheckEnabled, isFalse);

    // Switching back to the default preset is persisted as well.
    await reloaded.setDnsServers(['9.9.9.9', '2620:fe::fe']);
    await reloaded.setAllowScreenshots(false);
    final again = AppStore()..directory = directory;
    await again.load();
    expect(again.dnsServers, ['9.9.9.9', '2620:fe::fe']);
    expect(again.allowScreenshots, isFalse);

    store.dispose();
    reloaded.dispose();
    again.dispose();
  });

  test('custom DNS validation accepts IPv4, IPv6 and domain names', () {
    expect(validateDnsServer('1.1.1.1'), '1.1.1.1');
    expect(validateDnsServer(' 9.9.9.9 '), '9.9.9.9');
    expect(validateDnsServer('2620:fe::fe'), '2620:fe::fe');
    expect(validateDnsServer('2a10:50c0::ad1:ff'), '2a10:50c0::ad1:ff');
    expect(validateDnsServer('DNS.Example.ORG'), 'dns.example.org');
    expect(validateDnsServers(['1.1.1.1', '']), ['1.1.1.1']);
    // Duplicates collapse instead of producing a repeated profile line.
    expect(validateDnsServers(['1.1.1.1', '1.1.1.1']), ['1.1.1.1']);
    expect(validateDnsServers(['1.1.1.1', '2620:fe::fe']), [
      '1.1.1.1',
      '2620:fe::fe',
    ]);
  });

  test('custom DNS validation rejects ports, schemes and extra entries', () {
    for (final bad in [
      '',
      '   ',
      '1.1.1.1:53',
      'http://1.1.1.1',
      'https://dns.example.org/dns-query',
      'user@dns.example.org',
      '999.1.1.1',
      'dns example',
      'example',
      'a..b',
      '${'a' * 260}.org',
    ]) {
      expect(
        () => validateDnsServer(bad),
        throwsFormatException,
        reason: 'должен быть отклонён: $bad',
      );
    }
    expect(() => validateDnsServers([]), throwsFormatException);
    expect(
      () => validateDnsServers(['1.1.1.1', '8.8.8.8', '9.9.9.9']),
      throwsFormatException,
    );
  });

  test('a damaged resolver list falls back to the Quad9 default', () async {
    File('${directory.path}/profiles.json').writeAsStringSync(
      jsonEncode({
        'schema': 2,
        'profiles': <Object>[],
        'dnsServers': ['1.1.1.1:53', 'http://bad'],
        'autostart': 'yes',
      }),
    );
    final store = AppStore()..directory = directory;
    await store.load();
    expect(store.dnsServers, ['9.9.9.9', '2620:fe::fe']);
    // «yes» is not a bool, so the flag stays off instead of being truthy.
    expect(store.autostart, isFalse);
    store.dispose();
  });

  test('AWG profile DNS follows the selection and the IPv6 capability', () {
    // No IPv6 egress: the IPv6 resolver from the mixed pair is dropped, exactly
    // as before the setting existed.
    expect(managedDnsServers({}), '9.9.9.9');
    expect(managedDnsServers({}, ['8.8.8.8', '2001:4860:4860::8888']), '8.8.8.8');
    expect(
      managedDnsServers({'rivet': {'ipv6': true}}, [
        '8.8.8.8',
        '2001:4860:4860::8888',
      ]),
      '8.8.8.8, 2001:4860:4860::8888',
    );
    // An explicit IPv6-only choice is kept: the owner picked it, the settings
    // screen warns about the missing IPv6 uplink.
    expect(
      managedDnsServers({}, ['2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff']),
      '2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff',
    );
    expect(
      managedDnsServers({'rivet': {'ipv6': 'true'}}),
      '9.9.9.9',
      reason: 'строка «true» не подтверждает IPv6-выход',
    );
  });

  test('preset id and label follow the selected addresses', () {
    expect(dnsPresetIdFor(['9.9.9.9', '2620:fe::fe']), 'quad9');
    expect(dnsPresetIdFor(['2620:fe::fe', '9.9.9.9']), 'quad9');
    expect(dnsPresetIdFor(['1.1.1.1', '2606:4700:4700::1111']), 'cloudflare');
    expect(dnsPresetIdFor(['2a10:50c0::ad1:ff']), customDnsPreset);
    expect(dnsServersLabel(['1.1.1.1', '2606:4700:4700::1111']), contains(
      'Cloudflare',
    ));
    expect(dnsServersLabel(['192.0.2.1']), contains('Свои'));
  });

  testWidgets('the three settings switches persist immediately', (tester) async {
    final store = _MemoryStore();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(child: AppBehaviorSettings(store: store)),
        ),
      ),
    );
    await tester.pumpAndSettle();
    // Автозапуск реализован только в Android-сборке: вне Android переключатель
    // выключен, чтобы не обещать невозможное.
    final autostartTile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Автозапуск при загрузке устройства'),
    );
    expect(autostartTile.value, isFalse);
    expect(autostartTile.onChanged, isNull);

    await tester.tap(find.text('Автоподключение после запуска'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Разрешить скриншоты'));
    await tester.pumpAndSettle();
    expect(store.autoConnectOnStart, isTrue);
    expect(store.allowScreenshots, isTrue);

    // Состояние переключателей отражает сохранённые поля: повторное открытие
    // экрана показывает те же значения.
    final autoTile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Автоподключение после запуска'),
    );
    expect(autoTile.value, isTrue);
    final screenshotsTile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Разрешить скриншоты'),
    );
    expect(screenshotsTile.value, isTrue);

    await tester.tap(find.text('Разрешить скриншоты'));
    await tester.pumpAndSettle();
    expect(store.allowScreenshots, isFalse);

    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });

  testWidgets('resolver page saves a preset and rejects a bad custom address', (
    tester,
  ) async {
    final store = _MemoryStore();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => DnsSettingsPage(store: store),
                ),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    // The default Quad9 set is shown as selected.
    expect(find.text('Quad9'), findsOneWidget);
    expect(find.text('9.9.9.9, 2620:fe::fe'), findsOneWidget);

    await tester.tap(find.text('Cloudflare'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Сохранить'));
    await tester.pumpAndSettle();
    expect(store.dnsServers, ['1.1.1.1', '2606:4700:4700::1111']);

    // «Свои» с портом в адресе не сохраняется.
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Свои'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, '9.9.9.9:53');
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Сохранить'));
    await tester.tap(find.text('Сохранить'));
    await tester.pumpAndSettle();
    expect(store.dnsServers, ['1.1.1.1', '2606:4700:4700::1111']);
    expect(find.textContaining('без порта'), findsOneWidget);

    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
