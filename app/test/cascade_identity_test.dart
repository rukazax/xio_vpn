import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_health.dart';
import 'package:xio/cascade_model.dart';
import 'package:xio/cascade_probe.dart';
import 'package:xio/cascade_ui.dart';
import 'package:xio/core.dart';

void main() {
  for (final bad in [
    '::::',
    ':::',
    '1:::2',
    '1:2:3',
    '1::2::3',
    '[::::]',
    '2001:db8:1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:8::',
    ':1:2:3:4:5:6:7',
    '1:2:3:4:5:6:7:',
    '2001:db8::zz',
    'fe80::1%eth0',
    '[fe80::1%25eth0]',
    '[2001:db8::1]:9443',
    '2001:db8::1/64',
    '2001: db8::1',
    '2001:db8::1\n;id',
    '[192.0.2.1]',
    '01.2.3.4',
    '1.02.3.4',
    '256.2.3.4',
    '1.2.3.-1',
    '1.2.3.+1',
    '1.2.3',
    '1.2.3.4.5',
    '0x7f.0.0.1',
    '2130706433',
    '1.2.3.4:9443',
    '1.2.3.4/24',
    'exit.example',
    'https://exit.example',
    '[::1',
    '::1]',
    '',
  ]) {
    test('exit rejects malformed literal ${jsonEncode(bad)}', () {
      expect(validateCascadeExit(bad), isNull);
    });
  }

  test('valid IPv6 spellings normalize to one identity, no DNS', () {
    expect(
      validateCascadeExit('  [2001:0DB8:0:0:0:0:0:1]  '),
      validateCascadeExit('2001:db8::1'),
    );
    for (final host in [
      '::',
      '::1',
      'fd79:1::fe',
      '2001:db8::1',
      '1:2:3:4:5:6:7:8',
      '::ffff:192.0.2.1',
    ]) {
      expect(validateCascadeExit(host), isNotNull, reason: host);
    }
    expect(validateCascadeExit('  103.102.135.124 '), '103.102.135.124');
  });

  test('bridge rejects legacy IPv4 aliases and invalid DNS label lengths', () {
    for (final bad in [
      '01.2.3.4',
      '0x7f.0.0.1',
      '127.1',
      '256.0.0.1',
      '2130706433',
      'abc.123',
      '${'a' * 64}.example',
    ]) {
      expect(validateCascadeBridge(bad), isNull, reason: bad);
    }
    expect(validateCascadeBridge('${'a' * 63}.example'), isNotNull);
    expect(validateCascadeBridge('  BRIDGE.Example  '), 'bridge.example');
  });

  test(
    'IPv4 exit persists; malformed replacements cannot mutate saved route',
    () async {
      final dir = await Directory.systemTemp.createTemp(
        'xio-cascade-identity-',
      );
      addTearDown(() => dir.delete(recursive: true));
      final first = AppStore()..directory = dir;
      await first.load();
      expect(
        await first.setCascadeServers(
          bridge: '81.177.142.37',
          exit: '103.102.135.124',
        ),
        isTrue,
      );
      expect(
        await first.setCascadeServers(bridge: 'other.example', exit: '1::2::3'),
        isFalse,
      );
      expect(first.cascadeBridge, '81.177.142.37');
      expect(first.cascadeExit, '103.102.135.124');
      final second = AppStore()..directory = dir;
      await second.load();
      expect(second.cascadeBridge, '81.177.142.37');
      expect(second.cascadeExit, '103.102.135.124');
    },
  );

  test('IPv4 exit is a configured route, not a successful healthcheck', () {
    final route = cascadeRouteFromAddresses(
      bridge: 'bridge.example',
      exit: '103.102.135.124',
    );
    expect(route.exit.address, '103.102.135.124');
    expect(route.stage, CascadeStage.idle);
    expect(route.isTunnelActive, isFalse);
  });

  test('probe target must be unique and exact, never guessed', () {
    final a = ManagedServer(
      id: 'a',
      host: '81.177.142.37',
      publicHost: 'bridge.example',
    );
    final b = ManagedServer(
      id: 'b',
      host: '192.0.2.2',
      publicHost: 'bridge.example',
    );
    expect(selectCascadeServer([a], 'BRIDGE.EXAMPLE'), same(a));
    expect(selectCascadeServer([a, b], 'bridge.example'), isNull);
    expect(selectCascadeServer([a, b], '81.177.142.37'), same(a));
    expect(selectCascadeServer([a], 'unknown.example'), isNull);
    expect(selectCascadeServer([a], '01.2.3.4'), isNull);
    expect(selectCascadeServer([a], ''), isNull);
  });

  CascadeHealth healthy(String? exit) => CascadeHealth(
    verdict: CascadeHealthVerdict.ok,
    checkedAt: DateTime.utc(2026),
    latencyMs: 12,
    exitHost: exit,
    checks: const [CascadeHealthCheck(name: 'bridge.tunnel', ok: true)],
  );

  test('positive health must confirm the configured exit identity', () {
    final ipv6 = healthy('2001:0db8:0:0:0:0:0:1');
    expect(ipv6.forExit('[2001:db8::1]'), same(ipv6));
    final ipv4 = healthy('103.102.135.124');
    expect(ipv4.forExit('103.102.135.124'), same(ipv4));
    for (final actual in [null, '::::', '1:2:3', '2001:db8::2', '192.0.2.2']) {
      final result = healthy(actual).forExit('2001:db8::1');
      expect(result.alive, isFalse, reason: '$actual');
      expect(result.failures.last.name, 'exit.identity');
      expect(result.stage, isNot(CascadeStage.active));
      expect(result.latencyMs, 12);
    }
    expect(ipv4.forExit('bad').alive, isFalse);
  });

  test('exit binding never upgrades a previous failure', () {
    final failed = CascadeHealth.failure('SSH timed out');
    expect(failed.forExit('192.0.2.1'), same(failed));
  });

  for (final actual in <String?>['192.0.2.2', null]) {
    testWidgets(
      'screen refuses positive verdict for unconfirmed exit $actual',
      (tester) async {
        await tester.pumpWidget(
          MaterialApp(
            home: CascadeScreen(
              bridgeAddress: '81.177.142.37',
              exitAddress: '2001:db8::1',
              healthProbe: (_) async => healthy(actual),
            ),
          ),
        );
        await tester.tap(find.text('Проверить каскад'));
        await tester.pump();
        await tester.pump();
        expect(
          find.text(cascadeStatusCaption(CascadeStage.active)),
          findsNothing,
        );
        expect(
          find.textContaining(
            actual == null
                ? 'Проверка не подтвердила адрес выбранного exit'
                : 'Проверен другой exit',
          ),
          findsWidgets,
        );
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox());
      },
    );
  }

  testWidgets(
    'late prior success cannot finish a new poll or cancel its deadline',
    (tester) async {
      final old = Completer<CascadeHealth>();
      final current = Completer<CascadeHealth>();
      var calls = 0;
      await tester.pumpWidget(
        MaterialApp(
          home: CascadeScreen(
            bridgeAddress: '81.177.142.37',
            exitAddress: '2001:db8::1',
            healthProbe: (_) => ++calls == 1 ? old.future : current.future,
          ),
        ),
      );
      await tester.tap(find.text('Проверить каскад'));
      await tester.pump();
      await tester.pump(const Duration(seconds: 16));
      expect(find.textContaining('Проверка не уложилась в 15 с'), findsWidgets);
      await tester.tap(find.text('Проверить каскад'));
      await tester.pump();
      expect(calls, 2);
      old.complete(healthy('2001:db8::1'));
      await tester.pump();
      await tester.pump();
      expect(find.text('Проверка…'), findsOneWidget);
      expect(
        find.text(cascadeStatusCaption(CascadeStage.active)),
        findsNothing,
      );
      await tester.pump(const Duration(seconds: 16));
      expect(find.textContaining('Проверка не уложилась в 15 с'), findsWidgets);
      current.complete(healthy('2001:db8::1'));
      await tester.pump();
      expect(
        find.text(cascadeStatusCaption(CascadeStage.active)),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox());
      expect(tester.takeException(), isNull);
    },
  );

  for (final bad in [
    '1:::2',
    '1::2::3',
    '::::',
    '20:41:07',
    '1:2:3:4:5:6:7:8:9:0:1:2:3:4:5:6:7',
    'fe80::1%eth0',
    'bad2001::1host',
  ]) {
    test('egress cannot extract a valid prefix from $bad', () {
      final parsed = CascadeHealth.parse(
        jsonEncode({'ok': true, 'egress6': bad}),
      );
      expect(parsed.egressIpv6, isNull);
    });
  }
  test('egress extracts a complete IPv6 token from human detail', () {
    final parsed = CascadeHealth.parse(
      jsonEncode({
        'ok': true,
        'checks': [
          {
            'name': 'exit.egress6',
            'ok': true,
            'detail': 'выходной IPv6: [2001:db8::123]',
          },
        ],
      }),
    );
    expect(parsed.egressIpv6, '2001:db8::123');
  });
}
