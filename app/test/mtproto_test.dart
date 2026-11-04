import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/mtproto_remote.dart';
import 'package:xio/mtproto_ui.dart';

/// Хранилище без файла: экранные тесты проверяют форму, а не запись профиля.
class _MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

/// Сервер, который отвечает заранее заданными состояниями: настоящий SSH в
/// тесте не нужен, а поведение экрана от него не зависит.
class _FakeRemote implements MtprotoRemote {
  _FakeRemote(this._answers);

  final List<Object> _answers;
  int fetches = 0;
  int installs = 0;

  @override
  Future<MtprotoServerState> fetch() async {
    final answer = _answers[fetches < _answers.length ? fetches : _answers.length - 1];
    fetches++;
    if (answer is MtprotoServerState) return answer;
    throw answer;
  }

  @override
  Future<String> install() async {
    installs++;
    return 'служба активна';
  }
}

/// Ответ сервера до конца ожидания: так проверяется индикатор загрузки.
class _PendingRemote implements MtprotoRemote {
  final Completer<MtprotoServerState> answer = Completer<MtprotoServerState>();
  int installs = 0;
  @override
  Future<MtprotoServerState> fetch() => answer.future;
  @override
  Future<String> install() async {
    installs++;
    return '';
  }
}

/// Сервер для экранных тестов: без него автоподстановка не запускается.
ManagedServer _server() =>
    ManagedServer(id: 'a' * 32, host: 'bridge.example.org');

// Синтетический FakeTLS-секрет: ee + 16 байт секрета + hex домена
// "example.org". Настоящий секрет прокси в репозиторий не попадает.
const _secret = 'ee000102030405060708090a0b0c0d0e0f6578616d706c652e6f7267';
const _legacySecret = 'dd0123456789abcdef0123456789abcdef';
const _link = 'tg://proxy?server=81.177.142.37&port=8444&secret=$_secret';
const _installedState = MtprotoServerState(
  installed: true,
  host: '81.177.142.37',
  port: 8444,
  link: MtprotoProxyLink(
    server: '81.177.142.37',
    port: 8444,
    secret: _secret,
  ),
);
const _notInstalledState = MtprotoServerState(
  installed: false,
  host: 'bridge.example.org',
  port: 8444,
);

void main() {
  group('формат ссылки', () {
    test('принимает FakeTLS, legacy и t.me-ссылку', () {
      final fakeTls = parseMtprotoLink(_link);
      expect(fakeTls, isNotNull);
      expect(fakeTls!.server, '81.177.142.37');
      expect(fakeTls.port, 8444);
      expect(fakeTls.address, '81.177.142.37:8444');
      expect(fakeTls.link, _link);
      expect(validateMtprotoLink(_link), isNull);

      expect(
        parseMtprotoLink('tg://proxy?server=proxy.example.org&port=443&secret=$_legacySecret')
            ?.server,
        'proxy.example.org',
      );

      // t.me-ссылка из буфера приводится к tg://, иначе кнопки вели бы себя
      // по-разному на телефоне и на десктопе.
      final web = parseMtprotoLink(
        'https://t.me/proxy?server=proxy.example.org&port=443&secret=$_secret',
      );
      expect(web?.link, 'tg://proxy?server=proxy.example.org&port=443&secret=$_secret');
    });

    test('принимает base64-секрет и домен в верхнем регистре', () {
      final bytes = <int>[0xee, ...List<int>.generate(16, (i) => i)];
      final base64Secret = base64Url.encode(bytes).replaceAll('=', '');
      final parsed = parseMtprotoLink(
        'tg://proxy?server=Proxy.Example.Org&port=443&secret=$base64Secret',
      );
      expect(parsed, isNotNull);
      expect(parsed!.secret, base64Secret);
      expect(parsed.server, 'Proxy.Example.Org');
    });

    test('отклоняет пустую и чужую схему', () {
      expect(parseMtprotoLink(''), isNull);
      expect(validateMtprotoLink('   '), isNotNull);
      expect(validateMtprotoLink('https://example.org/proxy?server=a&port=1'), isNotNull);
      expect(validateMtprotoLink('tg://socks?server=1.2.3.4&port=443&secret=$_secret'), isNotNull);
      expect(
        validateMtprotoLink('https://user@t.me/proxy?server=1.2.3.4&port=443&secret=$_secret'),
        isNotNull,
      );
    });

    test('отклоняет неполные и лишние параметры', () {
      expect(
        validateMtprotoLink('tg://proxy?port=443&secret=$_secret'),
        'В ссылке нет адреса сервера',
      );
      expect(
        validateMtprotoLink('tg://proxy?server=1.2.3.4&secret=$_secret'),
        'В ссылке нет порта',
      );
      expect(
        validateMtprotoLink('tg://proxy?server=1.2.3.4&port=443'),
        'В ссылке нет секрета',
      );
      expect(
        validateMtprotoLink('tg://proxy?server=1.2.3.4&port=443&secret=$_secret&mode=1'),
        contains('Лишний параметр'),
      );
      expect(
        validateMtprotoLink('tg://proxy?server=1.2.3.4&server=5.6.7.8&port=443&secret=$_secret'),
        'В ссылке повторяется параметр',
      );
    });

    test('отклоняет некорректный сервер, порт и секрет', () {
      for (final server in ['', 'localhost', '256.1.1.1', '10.0.0.1 443', 'a b']) {
        expect(
          validateMtprotoLink('tg://proxy?server=$server&port=443&secret=$_secret'),
          isNotNull,
          reason: server,
        );
      }
      for (final port in ['0', '65536', 'abc', '-1', '443443']) {
        expect(
          validateMtprotoLink('tg://proxy?server=1.2.3.4&port=$port&secret=$_secret'),
          isNotNull,
          reason: port,
        );
      }
      for (final secret in ['hello', 'ee123', 'ff$_secret', 'ee${'a' * 31}']) {
        expect(
          validateMtprotoLink('tg://proxy?server=1.2.3.4&port=443&secret=$secret'),
          isNotNull,
          reason: secret,
        );
      }
    });
  });

  group('хранение', () {
    test('ссылка переживает перезапуск и очищается', () async {
      final dir = await Directory.systemTemp.createTemp('xio_mtproto_store');

      final first = AppStore();
      first.directory = dir;
      await first.load();
      expect(first.mtprotoLink, isEmpty);

      expect(await first.setMtprotoLink(_link), isTrue);
      expect(first.mtprotoLink, _link);

      final second = AppStore();
      second.directory = dir;
      await second.load();
      expect(second.mtprotoLink, _link);

      final raw = jsonDecode(
        await File('${dir.path}/profiles.json').readAsString(),
      ) as Map<String, dynamic>;
      expect(raw['mtprotoLink'], _link);

      // Некорректная ссылка не сохраняется и не затирает рабочую.
      expect(await second.setMtprotoLink('tg://proxy?server=1.2.3.4'), isFalse);
      expect(second.mtprotoLink, _link);

      // t.me-форма приводится к tg:// перед записью.
      expect(
        await second.setMtprotoLink(
          'https://t.me/proxy?server=81.177.142.37&port=8444&secret=$_secret',
        ),
        isTrue,
      );
      expect(second.mtprotoLink, _link);

      expect(await second.setMtprotoLink(''), isTrue);
      expect(second.mtprotoLink, isEmpty);

      final third = AppStore();
      third.directory = dir;
      await third.load();
      expect(third.mtprotoLink, isEmpty);

      await dir.delete(recursive: true);
    });

    test('битая ссылка в профиле не мешает загрузке', () async {
      final dir = await Directory.systemTemp.createTemp('xio_mtproto_broken');
      await File('${dir.path}/profiles.json').writeAsString(
        jsonEncode({'schema': 2, 'mtprotoLink': 'не ссылка'}),
      );

      final store = AppStore();
      store.directory = dir;
      await store.load();
      expect(store.mtprotoLink, isEmpty);
      expect(store.ready, isTrue);

      await dir.delete(recursive: true);
    });
  });

  group('команды SSH', () {
    test('запрос и установка собираются без подстановок Dart', () {
      expect(
        mtprotoProbeCommand,
        'python3 /usr/local/lib/xio-managed/admin.py',
      );
      expect(
        mtprotoInstallCommand,
        contains('deploy/mtproto/xio-mtproto-setup.sh'),
      );
      // Доллар обязан дойти до сервера как доллар: иначе bash увидел бы литерал
      // и код возврата установщика не попал бы в ответ.
      expect(mtprotoInstallCommand, contains(r'curl -fsSL "$url"'));
      expect(mtprotoInstallCommand, contains(r'rc=$?'));
      expect(mtprotoInstallCommand, contains(r'echo "XIO_MTINSTALL_RC=$rc"'));
      expect(mtprotoInstallCommand, isNot(contains(r'\$')));
    });
  });

  group('ответ сервера mtproto', () {
    test('установленный прокси отдаёт каноническую ссылку', () {
      final state = MtprotoServerState.parse({
        'ok': true,
        'installed': true,
        'host': '81.177.142.37',
        'port': 8444,
        'secret': _secret,
        'link': _link,
      });
      expect(state.installed, isTrue);
      expect(state.host, '81.177.142.37');
      expect(state.port, 8444);
      expect(state.link?.link, _link);
      expect(state.link?.address, '81.177.142.37:8444');
    });

    test('t.me-вид приводится к tg://, строка-порт принимается', () {
      final state = MtprotoServerState.parse({
        'installed': true,
        'host': 'proxy.example.org',
        'port': '443',
        'link':
            'https://t.me/proxy?server=proxy.example.org&port=443&secret=$_secret',
      });
      expect(state.port, 443);
      expect(
        state.link?.link,
        'tg://proxy?server=proxy.example.org&port=443&secret=$_secret',
      );
    });

    test('без секрета прокси не установлен, ссылки нет', () {
      final state = MtprotoServerState.parse({
        'ok': true,
        'installed': false,
        'host': 'bridge.example.org',
        'port': 8444,
        'secret': null,
        'link': null,
      });
      expect(state.installed, isFalse);
      expect(state.link, isNull);
      expect(state.host, 'bridge.example.org');
      expect(state.port, 8444);
    });

    test('установленный прокси без рабочей ссылки — ошибка', () {
      for (final link in <Object?>[
        null,
        '',
        'не ссылка',
        'tg://proxy?server=1.2.3.4',
      ]) {
        expect(
          () => MtprotoServerState.parse({
            'installed': true,
            'host': 'bridge.example.org',
            'port': 8444,
            'link': link,
          }),
          throwsA(isA<FormatException>()),
          reason: '$link',
        );
      }
    });

    test('некорректный ответ сервера отклоняется', () {
      for (final raw in <Object?>[null, 'строка', 42]) {
        expect(
          () => MtprotoServerState.parse(raw),
          throwsA(isA<FormatException>()),
          reason: '$raw',
        );
      }
      for (final port in <Object?>[0, 70000, 'abc', null]) {
        expect(
          () => MtprotoServerState.parse({
            'installed': false,
            'host': 'bridge.example.org',
            'port': port,
          }),
          throwsA(isA<FormatException>()),
          reason: '$port',
        );
      }
    });
  });

  group('автоподстановка', () {
    test('ссылка из ответа сервера сохраняется и переживает перезапуск',
        () async {
      final dir = await Directory.systemTemp.createTemp('xio_mtproto_auto');
      final state = MtprotoServerState.parse({
        'installed': true,
        'host': '81.177.142.37',
        'port': 8444,
        'secret': _secret,
        'link': _link,
      });
      final store = AppStore();
      store.directory = dir;
      await store.load();
      expect(state.link, isNotNull);
      expect(await store.setMtprotoLink(state.link!.link), isTrue);
      expect(store.mtprotoLink, _link);

      final again = AppStore();
      again.directory = dir;
      await again.load();
      expect(again.mtprotoLink, _link);
      await dir.delete(recursive: true);
    });

    test('не установленный прокси не трогает сохранённую ссылку', () async {
      final dir = await Directory.systemTemp.createTemp('xio_mtproto_nolink');
      final store = AppStore();
      store.directory = dir;
      await store.load();
      await store.setMtprotoLink(_link);

      final state = MtprotoServerState.parse({
        'installed': false,
        'host': 'bridge.example.org',
        'port': 8444,
        'link': null,
      });
      // Тот же путь, что в ManagedService.refreshMtprotoLink: сохраняем только
      // готовую ссылку, а «не установлен» оставляет профиль как есть.
      final link = state.link;
      if (link != null) await store.setMtprotoLink(link.link);
      expect(store.mtprotoLink, _link);
      await dir.delete(recursive: true);
    });
  });

  testWidgets('экран сам подставляет ссылку с сервера', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore();
    store.servers.add(_server());
    addTearDown(store.dispose);
    final remote = _FakeRemote([_installedState]);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: MtprotoProxyScreen(store: store, remote: remote),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(remote.fetches, 1);
    expect(store.mtprotoLink, _link);
    expect(find.text('Прокси настроен'), findsOneWidget);
    expect(find.text('Ссылка получена с сервера автоматически'), findsOneWidget);
    expect(find.byKey(const ValueKey('mtproto-install')), findsNothing);
    expect(find.byKey(const ValueKey('mtproto-progress')), findsNothing);
    final field = tester.widget<TextField>(
      find.byKey(const ValueKey('mtproto-link-field')),
    );
    expect(field.controller!.text, _link);
    expect(tester.takeException(), isNull);
  });

  testWidgets('индикатор загрузки и понятная ошибка запроса', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore();
    store.servers.add(_server());
    addTearDown(store.dispose);
    final remote = _PendingRemote();

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: MtprotoProxyScreen(store: store, remote: remote),
          ),
        ),
      ),
    );
    await tester.pump();

    expect(find.byKey(const ValueKey('mtproto-progress')), findsOneWidget);
    expect(find.text('Запрашиваю ссылку с сервера…'), findsOneWidget);

    remote.answer.completeError(
      StateError('Сервер bridge.example.org не ответил за 10 с'),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('mtproto-progress')), findsNothing);
    expect(find.byKey(const ValueKey('mtproto-auto-error')), findsOneWidget);
    expect(
      find.textContaining('не ответил за 10 с'),
      findsOneWidget,
    );
    // Ошибка запроса не мешает ручному вводу.
    await tester.enterText(
      find.byKey(const ValueKey('mtproto-link-field')),
      _link,
    );
    await tester.tap(find.byKey(const ValueKey('mtproto-save')));
    await tester.pumpAndSettle();
    expect(store.mtprotoLink, _link);
    expect(tester.takeException(), isNull);
  });

  testWidgets('без прокси на сервере — кнопка установки и повторный запрос',
      (tester) async {
    tester.view.physicalSize = const Size(390, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore();
    store.servers.add(_server());
    addTearDown(store.dispose);
    final remote = _FakeRemote([_notInstalledState, _installedState]);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: MtprotoProxyScreen(store: store, remote: remote),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      find.text('На сервере не установлен MTProto-прокси — установите кнопкой'),
      findsOneWidget,
    );
    final install = find.byKey(const ValueKey('mtproto-install'));
    expect(install, findsOneWidget);

    await tester.ensureVisible(install);
    await tester.tap(install);
    await tester.pumpAndSettle();

    expect(remote.installs, 1);
    expect(remote.fetches, 2);
    expect(store.mtprotoLink, _link);
    expect(find.byKey(const ValueKey('mtproto-install')), findsNothing);
    expect(find.text('Прокси настроен'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('экран показывает инструкцию и проверяет ввод', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore();
    addTearDown(store.dispose);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: MtprotoProxyScreen(store: store),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Как включить прокси в Telegram'), findsOneWidget);
    expect(find.textContaining('Данные и память'), findsOneWidget);
    expect(find.byKey(const ValueKey('mtproto-open')), findsOneWidget);
    expect(find.byKey(const ValueKey('mtproto-copy')), findsOneWidget);
    expect(find.text('Прокси не настроен'), findsOneWidget);
    expect(tester.takeException(), isNull);

    // Мусор в поле: сохранение отклонено, экран показывает причину.
    await tester.enterText(
      find.byKey(const ValueKey('mtproto-link-field')),
      'tg://proxy?server=1.2.3.4',
    );
    await tester.tap(find.byKey(const ValueKey('mtproto-save')));
    await tester.pumpAndSettle();
    expect(store.mtprotoLink, isEmpty);
    // Текст ошибки виден и в поле ввода, и в снекбаре — считаем оба.
    expect(find.text('В ссылке нет порта'), findsWidgets);

    // Корректная ссылка сохраняется и показывается как настроенная.
    await tester.enterText(
      find.byKey(const ValueKey('mtproto-link-field')),
      _link,
    );
    await tester.tap(find.byKey(const ValueKey('mtproto-save')));
    await tester.pumpAndSettle();
    expect(store.mtprotoLink, _link);
    expect(find.text('Прокси настроен'), findsOneWidget);
    expect(find.textContaining('81.177.142.37:8444'), findsWidgets);
    expect(tester.takeException(), isNull);
  });
}
