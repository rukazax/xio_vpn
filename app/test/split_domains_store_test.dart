import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

import 'support/domain_lookup.dart';

/// Доменные правила живут рядом со сплит-туннелем: список в [AppStore],
/// сохранение в профиле и адреса для нативной политики.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-split-domains-');
  });
  tearDown(() async {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  test('домены сохраняются в профиле и читаются после перезапуска', () async {
    final store = AppStore()..directory = directory;
    await store.setSplitDomains([
      'YouTube.com',
      '*.Example.COM',
      'youtube.com',
    ]);
    expect(store.splitDomains, ['youtube.com', '*.example.com']);

    final decoded =
        jsonDecode(File('${directory.path}/profiles.json').readAsStringSync())
            as Map<String, dynamic>;
    expect(decoded['splitDomains'], ['youtube.com', '*.example.com']);

    final reloaded = AppStore()..directory = directory;
    await reloaded.load();
    expect(reloaded.splitDomains, ['youtube.com', '*.example.com']);
    reloaded.dispose();
  });

  test('некорректный домен не сохраняется и не меняет список', () async {
    final store = AppStore()..directory = directory;
    await store.setSplitDomains(['youtube.com']);
    await expectLater(
      store.setSplitDomains(['youtube.com', 'https://rutube.ru']),
      throwsFormatException,
    );
    expect(store.splitDomains, ['youtube.com']);
  });

  test('домены читаются из нативной политики, мусор отбрасывается', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          if (call.method == 'routingGet') {
            return {
              'mode': 'ipInclude',
              'packages': <String>[],
              'networks': <String>[],
              'domains': ['youtube.com', 'https://bad.example', '*.example.org'],
            };
          }
          return null;
        });
    final store = AppStore();
    await store.loadSplitDomains();
    expect(store.splitDomains, ['youtube.com', '*.example.org']);
  });

  test('syncSplitDomains разрешает домены и передаёт адреса нативной стороне',
      () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    final applied = <List<String>>[];
    var domains = <String>['youtube.com', '*.example.com'];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          switch (call.method) {
            case 'routingGet':
              return {
                'mode': 'ipInclude',
                'packages': <String>[],
                'networks': <String>[],
                'domains': domains,
              };
            case 'routingResolved':
              applied.add(
                ((call.arguments as Map)['networks'] as List).cast<String>(),
              );
              return null;
          }
          return null;
        });
    final lookup = FakeDomainLookup({
      'youtube.com': ['203.0.113.5'],
      'example.com': ['198.51.100.1'],
      'mail.example.com': ['198.51.100.2'],
    });
    final store = AppStore(domainLookup: lookup, nativeTunnelOverride: true);

    await store.syncSplitDomains();
    expect(applied, [
      ['198.51.100.1', '203.0.113.5'],
    ]);
    expect(store.splitDomains, ['youtube.com', '*.example.com']);
    expect(store.splitResolvedAddresses, ['198.51.100.1', '203.0.113.5']);

    // Повторно в пределах десяти минут DNS не спрашиваем и политику не пишем.
    await store.syncSplitDomains();
    expect(applied, hasLength(1));
    expect(lookup.calls, ['example.com', 'youtube.com']);

    // Список доменов очищен — нативная сторона получает пустой набор,
    // старые маршруты снимаются.
    domains = <String>[];
    await store.syncSplitDomains();
    expect(applied.last, isEmpty);
    expect(store.splitResolvedAddresses, isEmpty);

    // force игнорирует кэш: адреса пересчитываются принудительно.
    domains = ['youtube.com'];
    await store.syncSplitDomains(force: true);
    expect(applied.last, ['203.0.113.5']);
    store.dispose();
  });

  test('без Android домены не трогают нативную сторону', () async {
    // flutter_test по умолчанию сообщает android как целевую платформу, поэтому
    // настольную сборку эмулируем явно.
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    addTearDown(() => debugDefaultTargetPlatformOverride = null);
    final calls = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          calls.add(call.method);
          return null;
        });
    final store = AppStore();
    await store.loadSplitDomains();
    await store.syncSplitDomains();
    expect(calls, isEmpty);
    store.dispose();
  });
}
