import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/desktop_engine.dart';

// Actual AppStore load/connect/save; only the native boundary and opted-in
// website probe are fakes. No desktop helper, external DNS or HTTP is used.
class _Bridge {
  final calls = <String>[];
  final gates = <String, Completer<void>>{};
  final entered = <String, Completer<void>>{};
  bool active = false;
  bool? busy = false;
  String? failure;
  Map<String, Object?>? snapshot;
  List<String>? protocols = ['awg'];

  Completer<void> hold(String method) {
    entered[method] = Completer<void>();
    return gates[method] = Completer<void>();
  }

  int get connections => calls.where((m) => m == 'connect').length;

  Future<Object?> handle(MethodCall call) async {
    calls.add(call.method);
    final gate = gates.remove(call.method);
    if (gate != null) {
      entered[call.method]!.complete();
      await gate.future;
    }
    if (failure == call.method) throw PlatformException(code: 'FAKE_FAILURE');
    switch (call.method) {
      case 'supportedProtocols':
        return protocols;
      case 'activeId':
        return active ? 'awg1' : null;
      case 'connectionBusy':
        return busy;
      case 'status':
        return snapshot ??
            {
              'active': active,
              'phase': active ? 'connected' : 'disconnected',
              'id': active ? 'awg1' : null,
              'protocol': 'awg',
              'handshake': DateTime.now().millisecondsSinceEpoch,
              'tx': 100,
              'rx': 100,
            };
      case 'connect':
        active = true;
        return {'connectMillis': 0};
      case 'disconnect':
        active = false;
        return null;
      default:
        throw StateError('Unexpected native call: ${call.method}');
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  late AppStore store;
  late _Bridge engine;
  late bool disposed;

  setUp(() async {
    // flutter_test defaults UI platform to Android even on a Linux host.
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    directory = await Directory.systemTemp.createTemp('c6-startup-');
    engine = _Bridge();
    disposed = false;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, engine.handle);
    store = AppStore(nativeTunnelOverride: true, siteProbe: (_) async => true)
      ..directory = directory;
  });
  tearDown(() async {
    if (!disposed) store.dispose();
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
    await directory.delete(recursive: true);
  });

  Future<void> persist({
    Object? enabled = true,
    Map<String, Object?>? extra,
  }) async {
    await File('${directory.path}/profiles.json').writeAsString(
      jsonEncode({
        'profiles': [
          const Profile(
            id: 'awg1',
            name: 'fake desktop',
            protocol: 'awg',
            endpoint: '192.0.2.1:51820',
          ).toJson(),
        ],
        'selected': 'awg1',
        'autoConnectOnStart': enabled,
        'siteCheckEnabled': true,
        'autoReconnect': false,
        ...?extra,
      }),
    );
  }

  test('persisted enabled desktop startup connects exactly once', () async {
    await persist();
    await store.load();
    expect(store.ready, isTrue);
    expect(engine.connections, 1);
    expect(store.status.active, isTrue);
  });
  for (final intent in [false, null, 'true']) {
    test('only boolean true authorizes startup: $intent', () async {
      await persist(enabled: intent, extra: {'autostart': true});
      await store.load();
      expect(engine.connections, 0);
      expect(engine.calls, isNot(contains('setAutostart')));
    });
  }
  test(
    'explicit DOWN before load supersedes persisted startup intent',
    () async {
      await persist();
      await store.disconnect();
      await store.load();
      expect(engine.connections, 0);
    },
  );
  test('missing storage does not imply intent', () async {
    await store.load();
    expect(engine.connections, 0);
    expect(store.autoConnectOnStart, isFalse);
  });
  test(
    'in-memory intent without persisted intent cannot auto-connect',
    () async {
      store.profiles.add(
        const Profile(
          id: 'awg1',
          name: 'not persisted',
          protocol: 'awg',
          endpoint: '192.0.2.1:1',
        ),
      );
      store.selectedId = 'awg1';
      store.autoConnectOnStart = true;
      await store.load();
      expect(engine.connections, 0);
    },
  );
  test(
    'actual desktop adapter without hydrated worker is unknown, not idle',
    () async {
      await persist();
      store.dispose();
      final enabled = DesktopEngine.enabled;
      final supported = DesktopEngine.supported;
      DesktopEngine.enabled = true;
      DesktopEngine.supported = {'awg'};
      try {
        store = AppStore(siteProbe: (_) async => true)..directory = directory;
        expect(await native.invokeMethod<Object>('status'), {
          'active': false,
          'phase': 'unknown',
        });
        await store.load();
        expect(store.ready, isTrue);
        expect(store.error, isNull);
        expect(store.events, isEmpty);
        expect(engine.calls, isEmpty); // Real adapter, not MethodChannel mock.
      } finally {
        DesktopEngine.enabled = enabled;
        DesktopEngine.supported = supported;
      }
    },
  );
  test('already connected is not reconnected', () async {
    await persist();
    engine.active = true;
    await store.load();
    expect(engine.connections, 0);
    expect(store.status.active, isTrue);
  });
  for (final snapshot in <Map<String, Object?>>[
    {},
    {'active': false, 'rx': 'invalid'},
    {'active': false, 'phase': 'unknown'},
    {'active': false, 'phase': 'pending'},
    {'active': false, 'phase': 'connecting'},
    {'active': false, 'phase': 'reconnecting'},
    {'active': false, 'phase': 'stopping'},
    {'active': false, 'recoveryPending': true},
    {'active': false, 'cleanupPending': true},
    {'active': false, 'recoveryPending': 'invalid'},
    {'active': false, 'cleanupPending': 'invalid'},
  ]) {
    test('unknown or pending status suppresses startup: $snapshot', () async {
      await persist();
      engine.snapshot = snapshot;
      await store.load();
      expect(engine.connections, 0);
    });
  }
  for (final failure in [
    'status',
    'activeId',
    'supportedProtocols',
    'connectionBusy',
  ]) {
    test('native $failure failure cannot activate startup', () async {
      await persist();
      engine.failure = failure;
      await store.load();
      expect(store.ready, isTrue);
      expect(engine.connections, 0);
    });
  }
  test('native busy is not a second owner', () async {
    await persist();
    engine.busy = true;
    await store.load();
    expect(engine.connections, 0);
    expect(store.busy, isFalse);
  });
  test('unknown native busy state cannot authorize startup', () async {
    await persist();
    engine.busy = null;
    await store.load();
    expect(engine.connections, 0);
  });
  test('UI busy suppresses startup', () async {
    await persist();
    store.addListener(() {
      if (store.ready) store.busy = true;
    });
    await store.load();
    expect(engine.connections, 0);
  });
  test('consent gate is preserved', () async {
    await persist();
    store.enforceConsent = true;
    await store.load();
    expect(engine.connections, 0);
  });
  for (final method in ['activeId', 'status', 'connectionBusy']) {
    test('current consent is required after startup awaits $method', () async {
      await persist();
      store.enforceConsent = true;
      // Hydration has read the file before activeId/status. For the later busy
      // gate, establish real persisted consent while initial status is held.
      final state = engine.hold(method == 'connectionBusy' ? 'status' : method);
      final load = store.load();
      await engine
          .entered[method == 'connectionBusy' ? 'status' : method]!
          .future;
      await store.acknowledgeLegal('fixture terms', 'en');
      await store.acknowledgeVpn();
      expect(store.consentReady, isTrue);
      if (method == 'connectionBusy') {
        final busy = engine.hold('connectionBusy');
        state.complete();
        await engine.entered['connectionBusy']!.future;
        store.vpnDisclosure = null;
        busy.complete();
      } else {
        store.vpnDisclosure = null;
        state.complete();
      }
      await load;
      expect(engine.connections, 0);
      expect(store.busy, isFalse);
    });
  }
  test(
    'consent enforcement changed during capabilities is rechecked',
    () async {
      await persist();
      final gate = engine.hold('supportedProtocols');
      final load = store.load();
      await engine.entered['supportedProtocols']!.future;
      store.enforceConsent = true;
      gate.complete();
      await load;
      expect(engine.connections, 0);
    },
  );
  test(
    'current consent is rechecked after startup candidate notification',
    () async {
      await persist();
      store.enforceConsent = true;
      final state = engine.hold('status');
      final load = store.load();
      await engine.entered['status']!.future;
      await store.acknowledgeLegal('fixture terms', 'en');
      await store.acknowledgeVpn();
      final busy = engine.hold('connectionBusy');
      state.complete();
      await engine.entered['connectionBusy']!.future;
      var revoked = false;
      store.addListener(() {
        if (!revoked && store.busy) {
          revoked = true;
          store.vpnDisclosure = null;
        }
      });
      busy.complete();
      await load;
      expect(revoked, isTrue);
      expect(engine.connections, 0);
      expect(store.error, isNull);
    },
  );
  test(
    'late startup consent loss cannot tear down a newer manual owner',
    () async {
      await persist();
      store.enforceConsent = true;
      final state = engine.hold('status');
      final load = store.load();
      await engine.entered['status']!.future;
      await store.acknowledgeLegal('fixture terms', 'en');
      await store.acknowledgeVpn();
      final busy = engine.hold('connectionBusy');
      state.complete();
      await engine.entered['connectionBusy']!.future;
      await store.connect();
      expect(store.status.active, isTrue);
      final downCalls = engine.calls.where((m) => m == 'disconnect').length;
      store.vpnDisclosure = null;
      busy.complete();
      await load;
      expect(engine.connections, 1);
      expect(store.status.active, isTrue);
      expect(store.busy, isFalse);
      expect(
        engine.calls.where((m) => m == 'disconnect'),
        hasLength(downCalls),
      );
    },
  );
  test('null capabilities are unknown', () async {
    await persist();
    engine.protocols = null;
    await store.load();
    expect(engine.connections, 0);
  });
  for (final profiles in [
    [],
    [
      {
        'id': 'bad',
        'name': 'unsupported',
        'protocol': 'unknown',
        'endpoint': '192.0.2.1:1',
      },
    ],
    [
      {
        'id': 123,
        'name': 'malformed',
        'protocol': 'awg',
        'endpoint': '192.0.2.1:1',
      },
    ],
  ]) {
    test('missing or unsupported profile cannot activate: $profiles', () async {
      await persist(extra: {'profiles': profiles});
      await store.load();
      expect(engine.connections, 0);
    });
  }
  test('revoked account has no allowed startup candidates', () async {
    await persist(
      extra: {
        'users': [
          ManagedUser(
            id: 'revoked',
            name: 'revoked',
            serverId: 'fixture',
            profileIds: {'awg': 'awg1'},
            revoked: true,
          ).toJson(),
        ],
      },
    );
    await store.load();
    expect(engine.connections, 0);
    expect(store.connectionCandidates(store.selected), isEmpty);
  });
  test('stale selected ID uses existing hydration fallback', () async {
    await persist(extra: {'selected': 'removed'});
    await store.load();
    expect(store.selectedId, 'awg1');
    expect(engine.connections, 1);
  });
  test(
    'load failure after reading intent fails closed and preserves bytes',
    () async {
      await persist(extra: {'cascadeBridge': 123});
      final file = File('${directory.path}/profiles.json');
      final before = await file.readAsString();
      await store.load();
      expect(store.autoConnectOnStart, isTrue);
      expect(engine.connections, 0);
      expect(store.error, isNotNull);
      expect(await file.readAsString(), before);
    },
  );
  test(
    'duplicate concurrent and subsequent loads/status callbacks are one-shot',
    () async {
      await persist();
      final gate = engine.hold('status');
      final first = store.load();
      await engine.entered['status']!.future;
      final second = store.load();
      gate.complete();
      await Future.wait([first, second]);
      await store.load();
      await store.refresh();
      expect(engine.connections, 1);
      expect(store.profiles, hasLength(1));
      expect(
        engine.calls.where((m) => m == 'supportedProtocols'),
        hasLength(1),
      );
    },
  );
  for (final method in [
    'supportedProtocols',
    'activeId',
    'status',
    'connectionBusy',
  ]) {
    for (final action in ['down', 'intent', 'dispose']) {
      test(
        '$action while startup awaits $method cannot activate later',
        () async {
          await persist();
          final gate = engine.hold(method);
          final load = store.load();
          await engine.entered[method]!.future;
          switch (action) {
            case 'down':
              await store.disconnect();
            case 'intent':
              await store.setAutoConnectOnStart(false);
            case 'dispose':
              store.dispose();
              disposed = true;
          }
          gate.complete();
          await load;
          expect(engine.connections, 0);
          expect(store.status.active, isFalse);
        },
      );
    }
  }
  test(
    'explicit no-op intent before hydration cancels persisted true',
    () async {
      await persist();
      final gate = engine.hold('supportedProtocols');
      final load = store.load();
      await engine.entered['supportedProtocols']!.future;
      await store.setAutoConnectOnStart(false);
      gate.complete();
      await load;
      expect(engine.connections, 0);
    },
  );
  test(
    'new manual owner during old startup status is not duplicated',
    () async {
      await persist();
      final gate = engine.hold('status');
      final load = store.load();
      await engine.entered['status']!.future;
      final connect = store.connect();
      gate.complete();
      await Future.wait([load, connect]);
      expect(engine.connections, 1);
      expect(store.status.active, isTrue);
    },
  );
  for (final action in ['intent', 'downThenNewOwner']) {
    test(
      '$action while startup verification awaits cannot publish stale success',
      () async {
        await persist();
        store.dispose();
        final entered = Completer<void>();
        final probe = Completer<bool>();
        var first = true;
        store = AppStore(
          nativeTunnelOverride: true,
          siteProbe: (_) async {
            if (!first) return true;
            first = false;
            entered.complete();
            return probe.future;
          },
        )..directory = directory;
        final load = store.load();
        await entered.future;
        if (action == 'intent') {
          await store.setAutoConnectOnStart(false);
        } else {
          await store.disconnect();
          await store.connect();
          // Disabling startup intent must not cancel a newer manual owner.
          await store.setAutoConnectOnStart(false);
        }
        probe.complete(true);
        await load;
        expect(store.status.active, action != 'intent');
        expect(engine.connections, action == 'intent' ? 1 : 2);
        expect(engine.calls, contains('disconnect'));
        expect(store.busy, isFalse);
        expect(store.error, isNull);
      },
    );
  }
  test('explicit new connect supersedes pending startup owner', () async {
    await persist();
    final gate = engine.hold('connectionBusy');
    final load = store.load();
    await engine.entered['connectionBusy']!.future;
    await store.connect();
    gate.complete();
    await load;
    expect(engine.connections, 1);
    expect(engine.calls, contains('disconnect'));
    expect(store.status.active, isTrue);
    expect(store.busy, isFalse);
  });
  test('DOWN then new owner supersedes startup native-busy await', () async {
    await persist();
    final gate = engine.hold('connectionBusy');
    final load = store.load();
    await engine.entered['connectionBusy']!.future;
    await store.disconnect();
    await store.connect();
    gate.complete();
    await load;
    expect(engine.connections, 1);
    expect(store.status.active, isTrue);
    expect(store.busy, isFalse);
  });
  test('DOWN then new owner during startup status survives its late reply', () async {
    await persist();
    final gate = engine.hold('status');
    final load = store.load();
    await engine.entered['status']!.future;
    await store.disconnect();
    // StatusPoll serializes refreshes: release the obsolete reply after the new
    // owner's activation starts, not by awaiting connect before releasing it.
    final connect = store.connect();
    gate.complete();
    await Future.wait([load, connect]);
    expect(engine.connections, 1);
    expect(store.status.active, isTrue);
  });
}
