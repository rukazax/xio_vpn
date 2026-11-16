import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

class BudgetStore extends AppStore {
  BudgetStore({this.monotonic}) : super(nativeTunnelOverride: true) {
    autoReconnect = false;
    protocolTimeoutSeconds = 15;
    profiles.addAll(
      List.generate(
        3,
        (i) => Profile(
          id: 'awg${i + 1}',
          name: 'fixture',
          protocol: 'awg',
          endpoint: 'fixture.invalid:${i + 1}',
        ),
      ),
    );
    selectedId = 'awg1';
  }
  final Duration Function()? monotonic;
  int notifications = 0;
  @override
  void notifyListeners() {
    notifications++;
    super.notifyListeners();
  }

  @override
  ConnectionRound createConnectionRound({
    Duration maximum = const Duration(seconds: 30),
    void Function()? onExpire,
  }) {
    final start = monotonic?.call() ?? Duration.zero;
    return ConnectionRound(
      maximum: maximum,
      onExpire: onExpire,
      elapsed: monotonic == null ? null : () => monotonic!() - start,
    );
  }

  @override
  Future<void> save() async {}
  @override
  Future<void> syncSplitDomains({bool force = false}) async {}
}

class ProbeFreeBudgetStore extends BudgetStore {
  ProbeFreeBudgetStore({super.monotonic});
  @override
  Future<bool> verifyTunnel({
    Duration timeout = const Duration(seconds: 15),
  }) async => true;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  tearDown(
    () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null),
  );

  test(
    'automatic default retains selected first, selectedOnly is explicit',
    () {
      final store = BudgetStore();
      expect(store.connectionPolicy, ConnectionPolicy.automatic);
      store.priorityProtocol = 'rivet-h3';
      expect(store.connectionCandidates(store.selected).map((p) => p.id), [
        'awg1',
        'awg2',
        'awg3',
      ]);
      store.connectionPolicyForTesting = ConnectionPolicy.selectedOnly;
      expect(store.connectionCandidates(store.selected).map((p) => p.id), [
        'awg1',
      ]);
      store.dispose();
    },
  );

  for (final fails in [false, true]) {
    testWidgets(
      'disposed disconnect ${fails ? 'error' : 'success'} cannot publish or rearm',
      (tester) async {
        final gate = Completer<void>();
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, (call) async {
              if (call.method == 'disconnect') {
                await gate.future;
                if (fails) throw PlatformException(code: 'FIXTURE_DOWN_FAILED');
              }
              return null;
            });
        final store = BudgetStore();
        final down = store.disconnect();
        await tester.pump();
        store.dispose();
        final before = (
          status: store.status,
          error: store.error,
          busy: store.busy,
          notifications: store.notifications,
        );
        gate.complete();
        await down;
        await tester.pump(const Duration(seconds: 31));
        expect(store.status, before.status);
        expect(store.error, before.error);
        expect(store.busy, before.busy);
        expect(store.notifications, before.notifications);
        expect(tester.takeException(), isNull);
      },
    );

    testWidgets(
      'disposed activation ${fails ? 'error' : 'success'} cannot publish or rearm',
      (tester) async {
        final gate = Completer<Map<String, Object>>();
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, (call) async {
              if (call.method == 'connectionBusy') return false;
              if (call.method == 'connect') return gate.future;
              return null;
            });
        final store = BudgetStore();
        final up = store.connect();
        await tester.pump();
        store.dispose();
        final before = (
          status: store.status,
          error: store.error,
          busy: store.busy,
          notifications: store.notifications,
        );
        if (fails) {
          gate.completeError(PlatformException(code: 'FIXTURE_LATE_FAILED'));
        } else {
          gate.complete({'policyMode': 'automatic'});
        }
        await up;
        await tester.pump(const Duration(seconds: 31));
        expect(store.status, before.status);
        expect(store.error, before.error);
        expect(store.busy, before.busy);
        expect(store.notifications, before.notifications);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('unjoined cleanup reserves activation after round expiry', (
    tester,
  ) async {
    final cleanup = Completer<void>();
    var dials = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          if (call.method == 'connectionBusy') return false;
          if (call.method == 'connect') {
            dials++;
            throw PlatformException(code: 'FIXTURE_FAILED');
          }
          if (call.method == 'disconnect') await cleanup.future;
          return null;
        });
    final start = tester.binding.clock.now();
    final store = BudgetStore(
      monotonic: () => tester.binding.clock.now().difference(start),
    );
    final operation = store.connect();
    await tester.pump();
    await tester.pump(const Duration(seconds: 30));
    await operation;
    expect(store.busy, isFalse);
    expect(store.cleanupIncomplete, isTrue);
    await store.connect();
    expect(dials, 1);
    cleanup.complete();
    await tester.pump();
    expect(store.cleanupIncomplete, isFalse);
    store.dispose();
  });

  testWidgets('repeated native recovery polls cannot renew the same lease', (
    tester,
  ) async {
    var recovering = false;
    var dials = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          if (call.method == 'connectionBusy') return false;
          if (call.method == 'connect') {
            dials++;
            if (dials > 1) recovering = false;
            return {'policyMode': 'automatic'};
          }
          if (call.method == 'status') {
            return {
              'active': !recovering,
              'id': 'awg1',
              'protocol': 'awg',
              'handshake': DateTime.now().millisecondsSinceEpoch,
              'phase': recovering ? 'reconnecting' : 'connected',
              'recoveryPending': recovering,
              'recoveryId': 'fixed',
              'recoveryRemainingMillis': 30000,
            };
          }
          return null;
        });
    final start = tester.binding.clock.now();
    final store = ProbeFreeBudgetStore(
      monotonic: () => tester.binding.clock.now().difference(start),
    )..autoReconnect = true;
    await store.connect();
    recovering = true;
    await tester.pump(const Duration(seconds: 15));
    await tester.pump(const Duration(seconds: 15));
    expect(dials, 1);
    await tester.pump(const Duration(seconds: 15));
    expect(
      dials,
      2,
      reason: 'the original native recovery lease expired despite repeated remaining=30000 polls',
    );
    store.dispose();
  });

  testWidgets(
    'selectedOnly rejects missing native policy acknowledgement without fallback',
    (tester) async {
      var dials = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (call) async {
            if (call.method == 'connectionBusy') return false;
            if (call.method == 'connect') {
              dials++;
              return <String, Object>{};
            }
            return null;
          });
      final store = BudgetStore()
        ..connectionPolicyForTesting = ConnectionPolicy.selectedOnly;
      await store.connect();
      expect(dials, 1);
      expect(store.status.active, isFalse);
      expect(store.error, isNotNull);
      store.dispose();
    },
  );

  testWidgets(
    'one foreground round ends at 30 seconds, not 15 seconds per candidate',
    (tester) async {
      final calls = <String>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (call) async {
            if (call.method == 'connectionBusy') return false;
            if (call.method == 'connect') {
              calls.add((call.arguments as Map)['id'] as String);
              await Future<void>.delayed(const Duration(seconds: 15));
              throw PlatformException(code: 'FIXTURE_FAILED');
            }
            return null;
          });
      final start = tester.binding.clock.now();
      final store = BudgetStore(
        monotonic: () => tester.binding.clock.now().difference(start),
      );
      var completed = false;
      final operation = store.connect().then((_) => completed = true);
      await tester.pump();
      await tester.pump(const Duration(seconds: 30));
      final before = (
        completed: completed,
        busy: store.busy,
        calls: calls.length,
      );
      // Drain the defective baseline too; do not leave its third candidate pending.
      await tester.pump(const Duration(seconds: 16));
      await operation;
      store.dispose();
      expect(before.completed, isTrue);
      expect(before.busy, isFalse);
      expect(before.calls, lessThanOrEqualTo(2));
      expect(store.status.active, isFalse);
    },
  );
}
