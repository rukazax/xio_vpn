import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/policy_channel.dart';

/// Cross-language oracle: the actual serialized values from Go helper commit
/// 75ca97b (artifact SHA 92aa4f6c…, probe df939713…). The Dart typed parser and
/// the Store state/confirmation path must accept these exact maps and treat
/// only the nested READY receipt as admission authority.
Map<String, dynamic> golden() => Map<String, dynamic>.from(
  jsonDecode(File('test/fixtures/go75-policy-state-snapshots.json').readAsStringSync())
      as Map,
);

Map<String, dynamic> stateCase(String name) =>
    Map<String, dynamic>.from(
      ((golden()['cases'] as Map)[name] as Map)['state'] as Map,
    );
Map<String, dynamic> capsCase(String name) =>
    Map<String, dynamic>.from(
      ((golden()['cases'] as Map)[name] as Map)['capabilities'] as Map,
    );

final _identities = {
  'storeIdentity': 'a' * 64,
  'controllerNonce': 'b' * 32,
  'instanceNonce': 'c' * 32,
  'transactionId': 'd' * 32,
  'planGeneration': 'e' * 32,
};

PolicyChannel channelFor({
  required Map<String, dynamic> caps,
  Map<String, dynamic>? state,
  Object? Function(String method, Object? arguments)? override,
}) => PolicyChannel(
  invoke: (method, arguments) async {
    if (override != null) {
      final value = override(method, arguments);
      if (value != null) return value;
    }
    return switch (method) {
      'policyCapabilities' => caps,
      'policyState' => state,
      _ => null,
    };
  },
  storeIdentity: _identities['storeIdentity']!,
  controllerNonce: _identities['controllerNonce']!,
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('actual Go capabilities parse for every case', () async {
    for (final name in [
      'fresh_blocked',
      'ready',
      'pending',
      'blocked_after_commit',
    ]) {
      final subject = channelFor(caps: capsCase(name));
      await subject.discover();
      expect(subject.instanceNonce, _identities['instanceNonce'], reason: name);
      expect(subject.validationSupported, isTrue, reason: name);
      // Capabilities alone never carry admission authority.
      expect(subject.ready, isFalse, reason: name);
    }
    final busy = channelFor(caps: capsCase('busy_capability'));
    await busy.discover();
    expect(busy.state, 'pending');
    expect(busy.ready, isFalse);
    expect(busy.validationSupported, isTrue);
  });

  test('actual READY state admits only its nested bound receipt', () async {
    final subject = channelFor(
      caps: capsCase('ready'),
      state: stateCase('ready'),
    );
    await subject.discover();
    final state = await subject.queryState();
    expect(state.readyForAdmission, isTrue);
    expect(state.casGeneration, _identities['planGeneration']);
    expect(subject.ready, isTrue);
    expect(subject.committed?.transactionId, _identities['transactionId']);
    expect(subject.committed?.storeIdentity, _identities['storeIdentity']);
    expect(subject.committed?.controllerNonce, _identities['controllerNonce']);
  });

  test('unknown resource state is never admissible even with a receipt', () async {
    final state = stateCase('ready')..['resourceState'] = 'unknown';
    final subject = channelFor(caps: capsCase('ready'), state: state);
    await subject.discover();
    final parsed = await subject.queryState();
    expect(parsed.readyForAdmission, isFalse);
    expect(subject.ready, isFalse);
    expect(subject.receipt, isNull);
  });

  test('fresh/pending/blocked actual states are typed and non-admissible',
      () async {
    final fresh = channelFor(
      caps: capsCase('fresh_blocked'),
      state: stateCase('fresh_blocked'),
    );
    await fresh.discover();
    final freshState = await fresh.queryState();
    expect(freshState.state, 'blocked');
    expect(freshState.resourceState, 'unknown');
    expect(freshState.receipt, isNull);
    expect(freshState.casGeneration, isNull);
    expect(freshState.readyForAdmission, isFalse);
    expect(fresh.ready, isFalse);

    final pending = channelFor(
      caps: capsCase('pending'),
      state: stateCase('pending'),
    );
    await pending.discover();
    final pendingState = await pending.queryState();
    expect(pendingState.pendingLane, isTrue);
    expect(pendingState.receipt, isNull);
    expect(pendingState.pendingTransaction, '1' * 32);
    expect(pendingState.casGeneration, _identities['planGeneration']);
    expect(pending.ready, isFalse);

    final blocked = channelFor(
      caps: capsCase('blocked_after_commit'),
      state: stateCase('blocked_after_commit'),
    );
    await blocked.discover();
    final blockedState = await blocked.queryState();
    expect(blockedState.state, 'blocked');
    expect(blockedState.resourceState, 'owned');
    expect(blockedState.pendingLane, isFalse);
    expect(blockedState.receipt, isNull);
    expect(blockedState.error, 'resource_owned');
    expect(blocked.ready, isFalse);
  });

  test('a READY receipt bound to another controller is observed, never admitted',
      () async {
    // A previous process committed this READY envelope under another controller
    // nonce. Refusing to look at it left the lane permanently STALE (the user had
    // to wipe app data), so the contract is now: OBSERVE the envelope, keep its
    // committed generation for CAS, and strip the receipt so nothing can admit a
    // foreign envelope by accident.
    final foreign = Map<String, dynamic>.from(stateCase('ready'));
    (foreign['receipt'] as Map)['controllerNonce'] = 'f' * 32;
    final rebound = PolicyChannel(
      invoke: (method, arguments) async =>
          method == 'policyCapabilities' ? capsCase('ready') : foreign,
      storeIdentity: _identities['storeIdentity']!,
      controllerNonce: _identities['controllerNonce']!,
    );
    await rebound.discover();
    final observed = await rebound.queryState();
    expect(observed.state, 'ready');
    expect(observed.receipt, isNull, reason: 'a foreign receipt is stripped');
    expect(
      rebound.generation,
      _identities['planGeneration'],
      reason: 'the committed generation stays observable for CAS',
    );
    expect(rebound.ready, isFalse, reason: 'observation is not admission');
    expect(rebound.committed, isNull);
  });

  test('unknown state keys are still rejected', () async {
    final state = stateCase('ready')..['futureKey'] = true;
    final subject = channelFor(caps: capsCase('ready'), state: state);
    await subject.discover();
    await expectLater(
      subject.queryState(),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_UNKNOWN'),
      ),
    );
  });

  test('Store confirmation follows the actual blocked state', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    final directory = await Directory.systemTemp.createTemp('go75-store-');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    var state = stateCase('ready');
    var policyCommitFails = false;
    var stateQueries = 0;
    String? boundStore;
    String? boundController;
    messenger.setMockMethodCallHandler(native, (call) async {
      final arguments = call.arguments is Map
          ? Map<String, dynamic>.from(call.arguments as Map)
          : <String, dynamic>{};
      switch (call.method) {
        case 'policyCapabilities':
          return capsCase('ready');
        case 'policyState':
          if (stateQueries++ == 0) {
            // First inspection during load: no live receipt yet.
            return stateCase('blocked_after_commit');
          }
          final value = Map<String, dynamic>.from(state);
          final receipt = value['receipt'];
          if (receipt is Map && boundStore != null && boundController != null) {
            (value['receipt'] as Map)
              ..['storeIdentity'] = boundStore
              ..['controllerNonce'] = boundController;
          }
          return value;
        case 'policyBegin':
          boundStore ??= arguments['storeIdentity'] as String?;
          boundController ??= arguments['controllerNonce'] as String?;
          return _ack(arguments, 'pending');
        case 'policyCommit':
        case 'policyReconcile':
          if (policyCommitFails) {
            throw PlatformException(code: 'POLICY_PERSISTENCE');
          }
          return _ack(arguments, 'ready');
        case 'policyValidate':
          final validation =
              Map<String, dynamic>.from(arguments['validation'] as Map);
          return {
            'version': 1,
            'instanceNonce': arguments['instanceNonce'],
            'controllerNonce': arguments['controllerNonce'],
            'transactionId': arguments['transactionId'],
            'documentDigest': validation['documentDigest'],
          };
        case 'readConfig':
          return '[Interface]\nPrivateKey = k\n[Peer]\n'
              'Endpoint = 203.0.113.9:51820\n';
        case 'routingGet':
          return {
            'mode': 'all',
            'packages': <String>[],
            'networks': <String>[],
            'domains': <String>[],
          };
        case 'supportedProtocols':
          return ['awg'];
        case 'status':
          return {'active': false, 'phase': 'disconnected'};
      }
      return null;
    });
    addTearDown(() async {
      messenger.setMockMethodCallHandler(native, null);
      debugDefaultTargetPlatformOverride = null;
      await directory.delete(recursive: true);
    });
    await File('${directory.path}/profiles.json').writeAsString(jsonEncode({
      'schema': 2,
      'profiles': <Object?>[],
      'priorityProtocol': 'awg',
      'checkSite': 'https://example.invalid/',
      'siteCheckEnabled': false,
      'protocolTimeoutSeconds': 15,
    }));
    final store = AppStore()..directory = directory;
    await store.load();
    // Pristine document: no versioned receipt yet, so no native confirmation.\n    expect(store.connectionModeConfirmed, isFalse);\n    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);\n    expect(store.connectionModeConfirmed, isTrue);
    // A helper that later reports the actual blocked/owned evidence must not
    // keep the old confirmation after a failed recovery.
    state = stateCase('blocked_after_commit');
    policyCommitFails = true;
    await expectLater(
      store.retryPolicyReconciliation(),
      throwsA(isA<Object>()),
    );
    expect(store.committedReceipt, isNull);
    expect(store.connectionModeConfirmed, isFalse);
    store.dispose();
  });
  test('ready with owned or missing resource is never admission', () async {
    for (final resource in <String?>['owned', null]) {
      final state = Map<String, dynamic>.from(stateCase('ready'));
      if (resource == null) {
        state.remove('resourceState');
      } else {
        state['resourceState'] = resource;
      }
      final subject = channelFor(caps: capsCase('ready'), state: state);
      await subject.discover();
      if (resource == null) {
        await expectLater(
          subject.queryState(),
          throwsA(isA<PolicyFailure>()),
        );
      } else {
        final parsed = await subject.queryState();
        expect(parsed.readyForAdmission, isFalse, reason: resource);
        expect(parsed.resourceState, 'owned');
      }
      expect(subject.ready, isFalse, reason: '$resource');
      expect(subject.receipt, isNull, reason: '$resource');
    }
  });
}

Map<String, dynamic> _ack(Map<String, dynamic> request, String state) => {
  'version': 1,
  'instanceNonce': request['instanceNonce'],
  'controllerNonce': request['controllerNonce'],
  'transactionId': request['transactionId'],
  'planGeneration': request['planGeneration'],
  'state': state,
};
