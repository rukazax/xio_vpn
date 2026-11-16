import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

class _Store extends AppStore {
  _Store() : super(nativeTunnelOverride: true) {
    profiles.addAll(const [
      Profile(
        id: 'awg1',
        name: 'old',
        protocol: 'awg',
        endpoint: 'old.invalid:1',
      ),
      Profile(
        id: 'awg2',
        name: 'new',
        protocol: 'awg',
        endpoint: 'new.invalid:2',
      ),
    ]);
    selectedId = 'awg1';
  }

  int notifications = 0;
  bool disposed = false;

  @override
  void notifyListeners() {
    notifications++;
    super.notifyListeners();
  }

  @override
  Future<void> save() async {}

  @override
  Future<void> syncSplitDomains({bool force = false}) async {}

  @override
  Future<bool> verifyTunnel({
    Duration timeout = const Duration(seconds: 15),
  }) async => true;

  @override
  void dispose() {
    if (disposed) return;
    disposed = true;
    super.dispose();
  }
}

Map<String, Object> _up([String id = 'awg1']) => {
  'active': true,
  'id': id,
  'protocol': 'awg',
  'rx': 100,
  'tx': 200,
  'handshake': DateTime.now().millisecondsSinceEpoch,
};

class _Native {
  final replies = <Future<Map<String, Object>>>[];
  final calls = <String>[];
  Completer<void>? disconnectGate;
  bool disconnectFails = false;
  int reads = 0;

  Future<Object?> handle(MethodCall call) async {
    calls.add(call.method);
    switch (call.method) {
      case 'status':
        reads++;
        return replies.isEmpty ? _up() : await replies.removeAt(0);
      case 'connect':
        return {'connectMillis': 0};
      case 'connectionBusy':
        return false;
      case 'disconnect':
        await disconnectGate?.future;
        if (disconnectFails) throw PlatformException(code: 'DISCONNECT_FAILED');
        return null;
      default:
        throw StateError('Unexpected native call: ${call.method}');
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Native engine;

  setUp(() {
    engine = _Native();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, engine.handle);
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
  });

  for (final fails in [false, true]) {
    testWidgets(
      'late status ${fails ? 'failure' : 'success'} cannot overwrite completed disconnect',
      (tester) async {
        final store = _Store();
        addTearDown(store.dispose);
        await store.refresh();
        expect(store.activeProfile?.id, 'awg1');
        final old = Completer<Map<String, Object>>();
        engine.replies.add(old.future);
        final pending = store.refresh();
        await tester.pump();
        expect(engine.reads, 2);
        await store.disconnect();
        final notifications = store.notifications;
        final disconnected = store.status;
        if (fails) {
          old.completeError(PlatformException(code: 'OLD_STATUS'));
        } else {
          old.complete(_up());
        }
        await pending;
        expect(store.status, disconnected);
        expect(store.activeProfile, isNull);
        expect(store.status.active, isFalse);
        expect(store.notifications, notifications);
      },
    );

    testWidgets(
      'status started during teardown ${fails ? 'failure' : 'success'} cannot survive its completion',
      (tester) async {
        final store = _Store();
        addTearDown(store.dispose);
        await store.refresh();
        engine.disconnectGate = Completer<void>();
        final disconnect = store.disconnect();
        await tester.pump();
        final old = Completer<Map<String, Object>>();
        engine.replies.add(old.future);
        final pending = store.refresh();
        await tester.pump();
        engine.disconnectGate!.complete();
        await disconnect;
        final notifications = store.notifications;
        final disconnected = store.status;
        if (fails) {
          old.completeError(PlatformException(code: 'TEARDOWN_STATUS'));
        } else {
          old.complete(_up());
        }
        await pending;
        expect(store.status, disconnected);
        expect(store.activeProfile, isNull);
        expect(store.notifications, notifications);
      },
    );

    testWidgets(
      'dispose fences in-flight status ${fails ? 'failure' : 'success'} and queued fresh reads',
      (tester) async {
        final store = _Store();
        final old = Completer<Map<String, Object>>();
        engine.replies.add(old.future);
        final pending = store.refresh().then<Object?>(
          (_) => null,
          onError: (Object e) => e,
        );
        await tester.pump();
        final fresh = store
            .refresh(fresh: true)
            .then<Object?>((_) => null, onError: (Object e) => e);
        final before = store.status;
        store.dispose();
        final notifications = store.notifications;
        if (fails) {
          old.completeError(PlatformException(code: 'DISPOSED_STATUS'));
        } else {
          old.complete(_up());
        }
        expect(await pending, isNull);
        expect(await fresh, isNull);
        expect(store.status, before);
        expect(store.notifications, notifications);
        expect(engine.reads, 1);
        await store.refresh();
        expect(engine.reads, 1);
        final calls = engine.calls.length;
        await store.connect();
        await store.disconnect();
        expect(engine.calls.length, calls);
      },
    );
  }

  testWidgets(
    'connect invalidates old snapshot while new fresh verification still advances',
    (tester) async {
      final store = _Store();
      addTearDown(store.dispose);
      final old = Completer<Map<String, Object>>();
      final fresh = Completer<Map<String, Object>>();
      engine.replies.addAll([old.future, fresh.future]);
      final pending = store.refresh();
      await tester.pump();
      store.selectedId = 'awg2';
      final connect = store.connect();
      await tester.pump();
      expect(engine.calls, contains('connect'));
      final notifications = store.notifications;
      old.complete(_up('awg1'));
      await pending;
      await tester.pump();
      expect(store.activeProfile?.id, 'awg2');
      expect(store.status.active, isFalse);
      expect(store.notifications, notifications);
      expect(engine.reads, 2);
      fresh.complete(_up('awg2'));
      await connect;
      expect(store.status.active, isTrue);
      expect(store.activeProfile?.id, 'awg2');
      expect(store.error, isNull);
      expect(store.busy, isFalse);
      expect(engine.calls.where((method) => method == 'connect'), hasLength(1));
      store.dispose(); // Widget-test invariants run before addTearDown callbacks.
    },
  );

  testWidgets(
    'disposed live controller cannot re-arm watchdog from a late identical snapshot',
    (tester) async {
      final store = _Store();
      final live = _up();
      engine.replies.add(Future.value(live));
      await store.connect();
      expect(store.status.active, isTrue);
      final old = Completer<Map<String, Object>>();
      engine.replies.add(old.future);
      final pending = store.refresh().then<Object?>(
        (_) => null,
        onError: (Object e) => e,
      );
      await tester.pump();
      store.dispose();
      final reads = engine.reads;
      final calls = engine.calls.length;
      old.complete(live); // Equal status: even notification dedup alone cannot stop timer resurrection.
      final result = await pending;
      await tester.pump(const Duration(seconds: 20));
      final afterReads = engine.reads;
      final afterCalls = engine.calls.length;
      // Also clean the defective baseline's timer during the negative control.
      store.autoReconnect = false;
      await store.refresh().then<void>((_) {}, onError: (Object _) {});
      expect(result, isNull);
      expect(afterReads, reads);
      expect(afterCalls, calls);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'disconnect owns watchdog cancellation even when the last poll is discarded',
    (tester) async {
      final store = _Store();
      addTearDown(store.dispose);
      await store.connect();
      final old = Completer<Map<String, Object>>();
      engine.replies.add(old.future);
      final pending = store.refresh();
      await tester.pump();
      await store.disconnect();
      old.complete(_up());
      await pending;
      final reads = engine.reads;
      await tester.pump(const Duration(seconds: 30));
      expect(store.status.active, isFalse);
      expect(engine.reads, reads);
      // Intentionally no explicit dispose here: widget-test invariants must prove
      // teardown itself canceled the periodic timer, before addTearDown runs.
    },
  );

  testWidgets('failed native teardown still invalidates older status errors', (
    tester,
  ) async {
    final store = _Store();
    addTearDown(store.dispose);
    await store.refresh();
    final live = store.status;
    final old = Completer<Map<String, Object>>();
    engine.replies.add(old.future);
    final pending = store.refresh();
    await tester.pump();
    engine.disconnectFails = true;
    await store.disconnect();
    final notifications = store.notifications;
    expect(store.error, contains('Не удалось отключить'));
    old.completeError(PlatformException(code: 'STALE_AFTER_FAILED_TEARDOWN'));
    await pending;
    expect(store.status, live);
    expect(store.activeProfile?.id, 'awg1');
    expect(store.error, contains('Не удалось отключить'));
    expect(store.notifications, notifications);
  });

  testWidgets(
    'current status changes and current errors are still published, identical reads coalesce',
    (tester) async {
      final store = _Store();
      addTearDown(store.dispose);
      final live = _up();
      engine.replies.addAll([Future.value(live), Future.value(live)]);
      await store.refresh();
      final notifications = store.notifications;
      await store.refresh();
      expect(store.notifications, notifications);
      final error = Completer<Map<String, Object>>();
      engine.replies.add(error.future);
      final pending = store.refresh();
      await tester.pump();
      error.completeError(PlatformException(code: 'CURRENT_STATUS'));
      await pending;
      expect(store.status.state, contains('Состояние неизвестно'));
      expect(store.activeProfile?.id, 'awg1');
      expect(store.notifications, notifications + 1);
      engine.replies.add(Future.value({'active': false}));
      await store.refresh(fresh: true);
      expect(store.status.active, isFalse);
      expect(store.activeProfile, isNull);
    },
  );
}
