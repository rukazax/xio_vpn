import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_plan.dart';
import 'package:xio/core.dart';

const _awg = '[Interface]\nAddress = 10.7.0.2/32\nPrivateKey = priv\n'
    '[Peer]\nPublicKey = pub\nEndpoint = 203.0.113.9:51820\n';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(native, null));

  void serveStore({List<MethodCall>? calls}) {
    messenger.setMockMethodCallHandler(native, (call) async {
      calls?.add(call);
      return switch (call.method) {
        'readConfig' => _awg,
        'routingGet' => {
          'mode': 'ipInclude',
          'packages': <String>[],
          'networks': ['192.168.1.0/24', '10.0.0.0/8'],
          'domains': ['b.example.com', 'A.example.com'],
          'revision': 'r1',
        },
        _ => null,
      };
    });
  }

  for (final enabled in [false, true]) {
    test(
      'actual native plan is the immutable v2 plan with typed site opt-in $enabled',
      () async {
        final calls = <MethodCall>[];
        serveStore(calls: calls);
        final store = AppStore(nativeTunnelOverride: true)
          ..siteCheckEnabled = enabled
          ..checkSite = 'https://probe.invalid/example'
          ..selectedId = 'awg1';
        store.profiles.add(
          const Profile(
            id: 'awg1',
            name: 'fixture',
            protocol: 'awg',
            endpoint: 'fixture.invalid:51821',
          ),
        );
        try {
          await store.saveNativePlan(androidForTesting: true);
          final published = calls
              .where((call) => call.method == 'saveConnectionPlan')
              .toList();
          expect(published, hasLength(1));
          final plan =
              jsonDecode(published.single.arguments as String) as Map;
          expect(plan['schema'], 2);
          expect(plan['siteCheckEnabled'], isA<bool>());
          expect(plan['siteCheckEnabled'], enabled);
          expect(plan['site'], store.checkSite);
          expect(plan['ids'], ['awg1']);
          expect(plan['timeoutSeconds'], store.protocolTimeoutSeconds);
          expect(plan['policy'], store.connectionPolicy.toJson());
          expect(plan['roundMillis'], 30000);
          expect(plan['priorityProtocol'], store.priorityProtocol);
          expect(plan['routing'], {
            'mode': 'ipInclude',
            'packages': <String>[],
            'networks': ['10.0.0.0/8', '192.168.1.0/24'],
            'domains': ['a.example.com', 'b.example.com'],
          });
          expect(plan['profiles'], [
            {
              'id': 'awg1',
              'protocol': 'awg',
              'endpoint': 'fixture.invalid:51821',
              'configDigest': ConnectionPlan.configDigest(_awg),
            },
          ]);
        } finally {
          store.dispose();
        }
      },
    );
  }

  test('unreadable routing policy blocks the plan instead of guessing', () async {
    messenger.setMockMethodCallHandler(native, (call) async {
      if (call.method == 'readConfig') return _awg;
      return null; // routingGet missing
    });
    final store = AppStore(nativeTunnelOverride: true)..selectedId = 'awg1';
    store.profiles.add(
      const Profile(
        id: 'awg1',
        name: 'fixture',
        protocol: 'awg',
        endpoint: 'fixture.invalid:51821',
      ),
    );
    try {
      await expectLater(
        store.saveNativePlan(androidForTesting: true),
        throwsFormatException,
      );
    } finally {
      store.dispose();
    }
  });

  test('platform gate stays off when Android is not selected', () async {
    final calls = <MethodCall>[];
    serveStore(calls: calls);
    final store = AppStore(nativeTunnelOverride: true);
    try {
      await store.saveNativePlan(androidForTesting: false);
      expect(calls, isEmpty);
      expect(store.siteCheckEnabled, isFalse);
    } finally {
      store.dispose();
    }
  });
}
