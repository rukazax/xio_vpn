import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'fallback_budget_test.dart' show ProbeFreeBudgetStore;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  tearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(native, null));

  test('automatic fallback displays the attempted profile and only the accepted '
      'attempt becomes the durable selection', () async {
    final store = ProbeFreeBudgetStore();
    final attempts = <String>[];
    final notifiedSelections = <String?>[];
    final notifiedAttempts = <String?>[];
    store.addListener(() {
      notifiedSelections.add(store.selectedId);
      notifiedAttempts.add(store.attemptedProfile?.id);
    });
    var active = false;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(native, (call) async {
        if (call.method == 'connectionBusy') return false;
        if (call.method == 'connect') {
          final id = (call.arguments as Map)['id'] as String;
          attempts.add(id);
          if (id == 'awg1') throw PlatformException(code: 'FIXTURE_FIRST_FAIL');
          active = true;
          return {'policyMode': 'automatic'};
        }
        if (call.method == 'disconnect') {
          active = false;
          return null;
        }
        if (call.method == 'status') {
          return {
            'active': active,
            'phase': active ? 'connected' : 'disconnected',
            'id': active ? 'awg2' : null,
            'protocol': 'awg',
            'handshake': DateTime.now().millisecondsSinceEpoch,
            'rx': 100,
            'tx': 100,
          };
        }
        return null;
      });
    await store.connect();
    expect(attempts, ['awg1', 'awg2']);
    // The failed first attempt never overwrites the user's selection; the
    // accepted attempt is committed by the round's own owned save.
    expect(store.selectedId, 'awg2');
    expect(notifiedAttempts, contains('awg2'));
    expect(store.activeProfile?.id, 'awg2');
    expect(store.attemptedProfile, isNull);
    store.dispose();
  });
}
