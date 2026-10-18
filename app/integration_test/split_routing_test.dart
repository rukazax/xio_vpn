import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';

Future<bool> tunnelHttp(String payload) async {
  Socket? socket;
  try {
    socket = await Socket.connect(
      '10.77.0.1',
      8080,
      timeout: const Duration(seconds: 3),
    );
    socket.write(
      'GET / HTTP/1.1\r\nHost: x1o-lab\r\nConnection: close\r\n\r\n',
    );
    await socket.flush();
    final body = await socket
        .cast<List<int>>()
        .transform(utf8.decoder)
        .join()
        .timeout(const Duration(seconds: 3));
    return body.contains(payload);
  } on IOException {
    return false;
  } on TimeoutException {
    return false;
  } finally {
    socket?.destroy();
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'Android per-app routing governs actual encrypted HTTP and fails closed',
    (tester) async {
      final store = AppStore();
      await store.load();
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      const own = 'app.x1o.x1o';
      final apps = await native.invokeListMethod<dynamic>('routingApps');
      expect(apps!.any((a) => a['package'] == own), isTrue);
      final other =
          apps.firstWhere((a) => a['package'] != own)['package'] as String;
      final cases = <Map<String, dynamic>>[];
      try {
        for (final awg in [false, true]) {
          final encoded = awg
              ? const String.fromEnvironment('LAB_AWG_CONFIG')
              : const String.fromEnvironment('LAB_WG_CONFIG');
          expect(encoded, isNotEmpty);
          await store.addWireGuard(
            'Split routing lab',
            utf8.decode(base64Decode(encoded)),
            amnezia: awg,
          );
          final id = store.selectedId!;
          for (final entry in [
            ('include', <String>[own], true),
            ('include', <String>[other], false),
            ('exclude', <String>[own], false),
            ('exclude', <String>[other], true),
            ('all', <String>[], true),
          ]) {
            await native.invokeMethod('routingSave', {
              'mode': entry.$1,
              'packages': entry.$2,
            });
            final policy = await native.invokeMapMethod<String, dynamic>(
              'routingGet',
            );
            expect(policy!['mode'], entry.$1);
            expect(policy['packages'], entry.$2);
            await store.connect().timeout(const Duration(seconds: 90));
            expect(store.error, isNull);
            expect(store.status.active, isTrue);
            await expectLater(
              native.invokeMethod('routingSave', {
                'mode': 'all',
                'packages': <String>[],
              }),
              throwsA(isA<PlatformException>()),
            );
            // Android publishes the per-UID network asynchronously after TUN establishment.
            await Future<void>.delayed(const Duration(seconds: 1));
            final routed = await tunnelHttp(
              awg ? 'x1o-amneziawg-lab-ok' : 'x1o-wireguard-lab-ok',
            );
            expect(
              routed,
              entry.$3,
              reason: '${awg ? 'AWG' : 'WG'} ${entry.$1}',
            );
            cases.add({
              'engine': awg ? 'awg' : 'wg',
              'mode': entry.$1,
              'selfSelected': entry.$2.contains(own),
              'tunnelHttp': routed,
              'activeRuleChangeRejected': true,
            });
            await store.disconnect();
            expect(store.status.active, isFalse);
          }
          for (final entry in [
            ('ipInclude', '10.77.0.1/32', true),
            ('ipInclude', '10.77.0.99/32', false),
            ('ipExclude', '10.77.0.1/32', false),
            ('ipExclude', '10.77.0.99/32', true),
          ]) {
            await native.invokeMethod('routingSave', {
              'mode': entry.$1,
              'packages': <String>[],
              'networks': [entry.$2],
            });
            await store.connect();
            expect(store.error, isNull);
            expect(store.status.active, isTrue);
            // Android publishes the per-UID network asynchronously after TUN establishment.
            await Future<void>.delayed(const Duration(seconds: 1));
            final routed = await tunnelHttp(
              awg ? 'x1o-amneziawg-lab-ok' : 'x1o-wireguard-lab-ok',
            );
            expect(
              routed,
              entry.$3,
              reason: '${awg ? 'AWG' : 'WG'} ${entry.$1} ${entry.$2}',
            );
            cases.add({
              'engine': awg ? 'awg' : 'wg',
              'mode': entry.$1,
              'subnet': entry.$2,
              'tunnelHttp': routed,
            });
            await store.disconnect();
          }
          await native.invokeMethod('routingSave', {
            'mode': 'ipInclude',
            'packages': <String>[],
            'networks': ['203.0.113.1/32'],
          });
          await store.connect();
          expect(store.error, isNotNull);
          expect(store.status.active, isFalse);
          for (final invalid in [
            {'mode': 'include', 'packages': <String>[]},
            {'mode': 'unknown', 'packages': <String>[]},
            {'mode': 'ipInclude', 'networks': <String>[]},
            {
              'mode': 'ipExclude',
              'networks': ['example.com'],
            },
            {
              'mode': 'include',
              'packages': ['org.x1o.not.installed'],
            },
          ]) {
            await expectLater(
              native.invokeMethod('routingSave', invalid),
              throwsA(isA<PlatformException>()),
            );
          }
          final file = File(
            '${store.directory!.parent.path}/no_backup/split-routing.json',
          );
          await file.writeAsString('{broken');
          await store.connect();
          expect(store.status.active, isFalse);
          expect(store.error, isNotNull);
          await native.invokeMethod('routingSave', {
            'mode': 'all',
            'packages': <String>[],
          });
          await store.remove(id);
        }
        // No installed-app inventory or routing rules in portable profile metadata.
        final metadata = await File('${store.directory!.path}/profiles.json')
            .readAsString();
        expect(metadata, isNot(contains(own)));
        // ignore: avoid_print
        print(
          'X1O_SPLIT_VERIFICATION=${jsonEncode({'cases': cases, 'invalidRulesRejected': true, 'corruptPolicyBlocksActivation': true, 'scope': 'Android API35 emulator / isolated netstack, own application UID requests'})}',
        );
      } finally {
        await store.disconnect();
        await native.invokeMethod('routingSave', {
          'mode': 'all',
          'packages': <String>[],
        });
        store.dispose();
      }
    },
  );
}
