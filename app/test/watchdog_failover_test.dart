import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

/// The engine as seen through `app.xio/engine`, with one knob for reality:
/// [silent] transports report an active tunnel, a fresh handshake and growing
/// counters — exactly what the old DNS-based check accepted — while nothing
/// actually crosses them.
class FakeEngine {
  FakeEngine(this.protocols);
  final Map<String, String> protocols;
  final Set<String> silent = {};
  final List<String> attempts = [];
  String? current;
  bool radio = true;

  Future<Object?> handle(MethodCall call) async {
    switch (call.method) {
      case 'connectionBusy':
        return false;
      case 'connect':
        final id = (call.arguments as Map)['id'] as String;
        attempts.add(id);
        if (!radio) {
          throw PlatformException(code: 'EGRESS', message: 'нет сети');
        }
        current = id;
        return {'connectMillis': 40};
      case 'disconnect':
        current = null;
        return null;
      case 'status':
        final id = current;
        if (id == null) return {'active': false};
        return {
          'active': true,
          'phase': 'up',
          'protocol': protocols[id] ?? 'awg',
          'rx': 4096,
          'tx': 4096,
          'handshake': DateTime.now().millisecondsSinceEpoch,
          'id': id,
        };
      default:
        return null;
    }
  }
}

class TestStore extends AppStore {
  TestStore({super.tunnelProbe}) : super(nativeTunnelOverride: true);
  @override
  Future<void> save() async {}
}

/// Verifies the tunnel from a fixed status: the probe is the only thing that
/// tells a live data path from a handshake-only one.
class FixedStatusStore extends AppStore {
  FixedStatusStore({
    super.tunnelProbe,
    this.active = true,
    this.tx = 0,
    this.handshake = 1,
  }) : super(nativeTunnelOverride: true) {
    profiles.add(
      const Profile(
        id: 'awg1',
        name: 'Мой AmneziaWG',
        protocol: 'awg',
        endpoint: 'bridge.example:51821',
      ),
    );
    selectedId = 'awg1';
  }
  final bool active;
  final int tx, handshake;
  @override
  Future<void> save() async {}
  @override
  Future<void> refresh({bool fresh = false}) async {
    status = TunnelStatus(active: active, tx: tx, handshake: handshake);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late FakeEngine engine;
  late TestDefaultBinaryMessenger messenger;
  late List<Profile> profiles;
  late Map<String, bool> protocolAlive;

  setUp(() {
    profiles = [
      const Profile(
        id: 'awg1',
        name: 'Мой AmneziaWG',
        protocol: 'awg',
        endpoint: 'bridge.example:51821',
      ),
      const Profile(
        id: 'rv1',
        name: 'E2E rivet',
        protocol: 'rivet-s1',
        endpoint: 'bridge.example:8443',
      ),
    ];
    protocolAlive = {'awg': true, 'rivet-s1': true};
    engine = FakeEngine({for (final p in profiles) p.id: p.protocol});
    messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(
      const MethodChannel('app.xio/engine'),
      engine.handle,
    );
  });

  tearDown(() {
    messenger.setMockMethodCallHandler(
      const MethodChannel('app.xio/engine'),
      null,
    );
  });

  Future<TunnelProbeResult> probe(Profile? profile, Duration timeout) async {
    if (profile == null) return TunnelProbeResult.dead;
    return protocolAlive[profile.protocol] == false
        ? TunnelProbeResult.dead
        : TunnelProbeResult.confirmed;
  }

  Future<TestStore> connected() async {
    final store = TestStore(tunnelProbe: probe);
    store.profiles.addAll(profiles);
    store.selectedId = 'awg1';
    addTearDown(store.dispose);
    await store.connect();
    expect(store.status.active, isTrue, reason: 'туннель должен быть поднят');
    expect(store.selectedId, 'awg1');
    return store;
  }

  test('a failed data-path probe switches to the next transport', () async {
    final store = await connected();
    // The old check would have believed this transport: the engine reports a
    // fresh handshake and counters, only the probe through the tunnel fails.
    protocolAlive['awg'] = false;

    // The first check after a reconnect runs in 3-5 s, not in a full interval.
    expect(store.watchdogDelayForTest, watchdogFirstProbeDelay);
    expect(watchdogFirstProbeDelay.inSeconds, inInclusiveRange(3, 5));

    await store.watchdogTickForTest();

    expect(
      store.selectedId,
      'rv1',
      reason: 'должен выбраться другой транспорт',
    );
    expect(store.activeProfile?.id, 'rv1');
    expect(store.status.active, isTrue);
    expect(
      store.events.any((e) => e.contains('Проба через туннель не прошла')),
      isTrue,
    );
    expect(
      store.events.any((e) => e.contains('Переключаюсь на rivet-s1')),
      isTrue,
      reason: 'переключение должно быть видно в журнале',
    );
    expect(
      store.events.any((e) => e.contains('Автоматически выбран rivet-s1')),
      isTrue,
    );
    // The transport that just failed is not retried first: the plan starts with
    // the alternative and only then comes back to the dead one.
    expect(engine.attempts.first, 'awg1');
    expect(engine.attempts.last, 'rv1');
    expect(engine.attempts.where((id) => id == 'awg1').length, 1);
  });

  test('a live probe keeps the tunnel untouched', () async {
    final store = await connected();
    final before = List<String>.from(engine.attempts);

    await store.watchdogTickForTest();
    await store.watchdogTickForTest();

    expect(engine.attempts, before, reason: 'живой туннель не переподключают');
    expect(store.selectedId, 'awg1');
    expect(store.events.any((e) => e.contains('Связь потеряна')), isFalse);
    // A confirmed transport is checked on the visible cadence, not every tick.
    expect(store.watchdogDelayForTest, watchdogVisibleInterval);
  });

  test('a dead endpoint is retried only after the other endpoints', () async {
    // Two peers on the blocked port (51821) and one transport on another port:
    // the failover must not spend a full attempt on the dead endpoint first.
    final store = await connected();
    store.profiles.add(
      const Profile(
        id: 'awg2',
        name: 'Второй пир того же порта',
        protocol: 'awg',
        endpoint: 'bridge.example:51821',
      ),
    );
    protocolAlive['awg'] = false;
    engine.protocols['awg2'] = 'awg';
    await store.watchdogTickForTest();
    expect(store.selectedId, 'rv1');
    // Connected once on awg1, then the failover plan: rv1 first, and neither
    // peer on the dead endpoint is tried before it.
    expect(engine.attempts, ['awg1', 'rv1']);
    expect(
      store.events.any((e) => e.contains('Переключаюсь на rivet-s1')),
      isTrue,
    );
  });

  test('background keeps the 15/20 s backoff', () async {
    final store = await connected();
    store.setForeground(false);
    for (var i = 0; i < 6; i++) {
      await store.watchdogTickForTest();
    }
    expect(
      store.watchdogDelayForTest,
      const Duration(seconds: 20),
      reason: 'шесть удачных проверок подряд включают щадящий интервал',
    );
    expect(
      watchdogDelayFor(primed: true, foreground: false, healthyChecks: 1),
      const Duration(seconds: 15),
    );
  });

  test('airplane mode: the tunnel comes back on its own inside 30 s', () async {
    final store = await connected();

    // Airplane mode: the radio is gone and the engine loses the interface.
    engine.radio = false;
    engine.current = null;
    await store.refresh();
    expect(store.status.active, isFalse);

    final clock = Stopwatch()..start();
    await store.watchdogTickForTest();
    expect(store.error, isNotNull, reason: 'первая попытка без радио падает');

    // The radio is back while the retry timer is still running. Six 5 s attempts
    // cover the first half-minute, so the next one cannot be far away.
    expect(reconnectRetryDelay(1), const Duration(seconds: 5));
    engine.radio = true;
    while (!store.status.active &&
        clock.elapsed < const Duration(seconds: 12)) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }

    expect(
      store.status.active,
      isTrue,
      reason: 'туннель должен восстановиться',
    );
    expect(
      clock.elapsed,
      lessThan(const Duration(seconds: 30)),
      reason: 'бюджет восстановления после авиарежима',
    );
  });

  test('verification never accepts a handshake-only tunnel', () async {
    protocolAlive['awg'] = false;
    final dead = FixedStatusStore(tunnelProbe: probe, tx: 0, handshake: 1);
    addTearDown(dead.dispose);
    expect(
      await dead.verifyTunnel(timeout: const Duration(milliseconds: 300)),
      isFalse,
    );

    protocolAlive['awg'] = true;
    final alive = FixedStatusStore(tunnelProbe: probe, tx: 0, handshake: 1);
    addTearDown(alive.dispose);
    expect(
      await alive.verifyTunnel(timeout: const Duration(milliseconds: 300)),
      isTrue,
    );
    expect(alive.connectionCheck, contains('пакеты проходят через туннель'));
  });

  test(
    'the resolver-based probe is gone from the watchdog (design guard)',
    () async {
      File? source;
      var dir = Directory.current;
      for (var i = 0; i < 3 && source == null; i++) {
        final candidate = File('${dir.path}/lib/core.dart');
        if (candidate.existsSync()) {
          source = candidate;
        } else {
          dir = dir.parent;
        }
      }
      expect(source, isNotNull, reason: 'исходник core.dart должен быть рядом');
      final text = await source!.readAsString();
      // A cached DNS answer looks exactly like a live tunnel, which is the bug
      // this change removes: the watchdog must not be able to ask a resolver.
      expect(text.contains('InternetAddress.lookup'), isFalse);
      expect(text.contains('TunnelReadinessProbe'), isTrue);
      expect(text.contains('watchdogProbeTimeout'), isTrue);
    },
  );

  test('the retry schedule covers the airplane-mode window', () {
    for (var attempt = 1; attempt <= 6; attempt++) {
      expect(reconnectRetryDelay(attempt), const Duration(seconds: 5));
    }
    expect(reconnectRetryDelay(7), const Duration(seconds: 10));
    expect(reconnectRetryDelay(13), const Duration(seconds: 15));
    expect(
      reconnectRetryDelay(1) * 6,
      const Duration(seconds: 30),
      reason: 'полминуты после потери покрыты частыми попытками',
    );
  });
}
