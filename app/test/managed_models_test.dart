import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/workspace_ui.dart';

class _SettingsStore extends AppStore {
  @override
  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
  }) async {
    checkSite = validateCheckSite(site).toString();
    priorityProtocol = priority;
    protocolTimeoutSeconds = timeoutSeconds ?? protocolTimeoutSeconds;
    siteCheckEnabled = siteCheck ?? siteCheckEnabled;
    autoReconnect = reconnect ?? autoReconnect;
    changed();
  }
}

void main() {
  test(
    'bundle round trip carries both protocol keys without SSH credentials',
    () {
      final b = UserBundle('Алиса', 'a' * 32, 'server-123', {
        'rivet-s1': 'private RIVET material',
        'awg': 'private AWG material',
      });
      final encoded = b.encode();
      final restored = UserBundle.decode(encoded);
      expect(restored.name, b.name);
      expect(restored.configs, b.configs);
      final json = jsonDecode(
        utf8.decode(base64Url.decode(encoded.substring(6))),
      ) as Map;
      expect(json.keys.toSet(), {
        'schema',
        'name',
        'userId',
        'serverId',
        'configs',
      });
      for (final raw in ['x1o://!', 'vpn://abc', 'x1o://${'a' * 200000}']) {
        expect(() => UserBundle.decode(raw), throwsFormatException);
      }
      for (final data in [
        {
          'schema': 2,
          'name': 'A',
          'userId': 'a' * 32,
          'serverId': 's',
          'configs': {'awg': 'x'},
        },
        {
          'schema': 1,
          'name': 'A',
          'userId': '../root',
          'serverId': 's',
          'configs': {'awg': 'x'},
        },
        {
          'schema': 1,
          'name': 'A',
          'userId': 'a' * 32,
          'serverId': 's',
          'configs': {'unsupported': 'x'},
        },
      ]) {
        expect(
          () => UserBundle.decode(
            'x1o://${base64Url.encode(utf8.encode(jsonEncode(data)))}',
          ),
          throwsFormatException,
        );
      }
    },
  );
  test(
    'invalid imported bundle cannot erase remotely discovered user metadata',
    () async {
      final store = AppStore();
      final user = ManagedUser(
        id: 'b' * 32,
        name: 'Remote',
        serverId: 's',
        profileIds: {},
        statistics: {'sampledAt': 123},
      );
      store.users.add(user);
      await expectLater(
        store.importBundle(
          UserBundle('Remote', 'b' * 32, 's', {'awg': 'broken configuration'}),
        ),
        throwsFormatException,
      );
      expect(store.users.single, same(user));
      expect(store.users.single.statistics['sampledAt'], 123);
      expect(store.profiles, isEmpty);
      store.dispose();
    },
  );
  test(
    'check site normalization rejects credentials and non HTTPS schemes',
    () {
      expect(
        validateCheckSite('youtube.com').toString(),
        'https://youtube.com',
      );
      for (final bad in [
        '',
        'http://example.org',
        'file:///tmp/a',
        'https://u:p@example.org',
        'https://example.org/#secret',
      ]) {
        expect(() => validateCheckSite(bad), throwsFormatException);
      }
    },
  );
  test(
    'settings and management metadata survive restart without private configs',
    () async {
      final dir = await Directory.systemTemp.createTemp('xio-settings-');
      final store = AppStore()..directory = dir;
      store.servers.add(ManagedServer(id: 's', host: 'vpn.example'));
      store.users.add(
        ManagedUser(
          id: 'a' * 32,
          name: 'A',
          serverId: 's',
          profileIds: {'awg': 'awg123'},
          statistics: {
            'sampledAt': 1,
            'protocols': {
              'awg': {'rx': 1234, 'tx': 5678},
            },
          },
        ),
      );
      await store.saveConnectionSettings(
        'example.org/check',
        'awg',
        timeoutSeconds: 30,
      );
      final data = jsonDecode(
        await File('${dir.path}/profiles.json').readAsString(),
      );
      expect(data['checkSite'], 'https://example.org/check');
      expect(data['priorityProtocol'], 'awg');
      expect(data['protocolTimeoutSeconds'], 30);
      expect(
        ManagedUser.fromJson(Map<String, dynamic>.from(data['users'][0]))
            .statistics['protocols']['awg']['rx'],
        1234,
      );
      expect(
        (await File(
          '${dir.path}/profiles.json',
        ).readAsString()).contains('PrivateKey'),
        isFalse,
      );
      await expectLater(
        store.saveConnectionSettings('http://bad', 'awg'),
        throwsFormatException,
      );
      expect(store.checkSite, 'https://example.org/check');
      store.dispose();
    },
  );
  testWidgets(
    'site check is off by default and saves the chosen HTTPS site when enabled',
    (tester) async {
      final store = _SettingsStore();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(child: ConnectionSettings(store: store)),
          ),
        ),
      );
      await tester.pumpAndSettle();
      // Off by default: the tunnel itself confirms the connection, so the
      // site field stays hidden until the owner opts in.
      expect(find.byType(TextField), findsNothing);
      await tester.tap(find.text('Проверять доступность сайта'));
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        'https://youtube.com',
      );
      await tester.enterText(find.byType(TextField), 'example.org');
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Сохранить'));
      await tester.tap(find.text('Сохранить'));
      await tester.pumpAndSettle();
      expect(store.checkSite, 'https://example.org');
      expect(store.siteCheckEnabled, isTrue);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
  testWidgets('SSH dialog does not restore the user-name keyboard on return', (
    tester,
  ) async {
    final store = AppStore()
      ..servers.add(ManagedServer(id: 's', host: 'vpn.example'));
    await tester.pumpWidget(MaterialApp(home: WorkspaceShell(store: store)));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(2));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Добавить пользователя'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, 'Alice');
    await tester.showKeyboard(find.byType(TextField).first);
    expect(tester.testTextInput.isVisible, isTrue);
    await tester.tap(find.text('Создать пользователя'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Закрыть'));
    await tester.pumpAndSettle();
    expect(tester.testTextInput.isVisible, isFalse);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
