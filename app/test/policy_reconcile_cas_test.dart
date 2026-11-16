import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/policy_channel.dart';
import 'package:xio/policy_publication.dart';

/// Desktop reconcile CAS oracle: after a successful settlement/query the Store
/// must send the OBSERVED native casGeneration as expectedGeneration in both the
/// validation and reconcile envelopes. A fresh helper without one stays null;
/// the durable/desired new generation is never substituted. Android keeps the
/// default null.
class _CasRig {
  Directory? dir;
  Map<String, dynamic>? validateArgs;
  Map<String, dynamic>? reconcileArgs;
  Map<String, dynamic>? beginArgs;
  Map<String, dynamic>? abortArgs;
  Map<String, dynamic>? lastAckRequest;
  String? observedCas = 'e' * 32;
  bool failReconcile = false;
  bool failBegin = false;
  bool nativeReady = false;
  bool owned = false;
  bool hugeConfig = false;
  bool includePolicy = true;
  bool hugeDocument = false;
  Completer<void>? beginGate;
  Completer<void>? beginEntered;
  final calls = <String>[];

  Map<String, dynamic> _ack(Map<String, dynamic> a, String state) => {
    'version': 1,
    'instanceNonce': a['instanceNonce'],
    'controllerNonce': a['controllerNonce'],
    'transactionId': a['transactionId'],
    'planGeneration': a['planGeneration'],
    'state': state,
  };

  Future<Object?> handle(MethodCall call) async {
    calls.add(call.method);
    final a = call.arguments is Map
        ? Map<String, dynamic>.from(call.arguments as Map)
        : <String, dynamic>{};
    switch (call.method) {
      case 'policyCapabilities':
        return {
          'version': 1,
          'instanceNonce': 'c' * 32,
          'state': 'blocked',
          'resourceState': 'unknown',
          'planSchema': 2,
          'validation': 1,
          'launchBound': true,
          'resourceClaimed': true,
        };
      case 'policyState':
        return {
          'version': 1,
          'instanceNonce': 'c' * 32,
          'state': nativeReady && !owned ? 'ready' : 'blocked',
          'resourceState': owned ? 'owned' : (nativeReady ? 'clean' : 'unknown'),
          'planSchema': 2,
          'validation': 1,
          'launchBound': true,
          'resourceClaimed': true,
          'clientOnly': false,
          'error': '',
          'pendingTransaction': null,
          if (observedCas != null) 'casGeneration': observedCas,
          if (nativeReady && !owned && lastAckRequest != null)
            'receipt': {
              'version': 1,
              'storeIdentity': lastAckRequest!['storeIdentity'],
              'instanceNonce': lastAckRequest!['instanceNonce'],
              'controllerNonce': lastAckRequest!['controllerNonce'],
              'transactionId': lastAckRequest!['transactionId'],
              'planGeneration': lastAckRequest!['planGeneration'],
            },
        };
      case 'policyCommit':
        lastAckRequest = a;
        observedCas = a['planGeneration'] as String?;
        nativeReady = true;
        return _ack(a, 'ready');
      case 'policyValidate':
        validateArgs = a;
        final validation = Map<String, dynamic>.from(a['validation'] as Map);
        return {
          'version': 1,
          'instanceNonce': a['instanceNonce'],
          'controllerNonce': a['controllerNonce'],
          'transactionId': a['transactionId'],
          'documentDigest': validation['documentDigest'],
        };
      case 'policyBegin':
        beginArgs = a;
        if (failBegin) {
          throw PlatformException(code: 'POLICY_STALE');
        }
        if (beginGate != null) {
          if (beginEntered != null && !beginEntered!.isCompleted) {
            beginEntered!.complete();
          }
          await beginGate!.future;
        }
        return _ack(a, 'pending');
      case 'policyAbort':
        abortArgs = a;
        return {
          'version': 1,
          'state': 'blocked',
          'transactionId': a['transactionId'],
        };
      case 'policyReconcile':
        reconcileArgs = a;
        if (failReconcile) {
          throw PlatformException(code: 'POLICY_STALE');
        }
        lastAckRequest = a;
        observedCas = a['planGeneration'] as String?;
        nativeReady = true;
        return _ack(a, 'ready');
      case 'supportedProtocols':
        return ['awg'];
      case 'status':
        return {'active': false, 'phase': 'disconnected'};
      case 'connectionBusy':
        return false;
      case 'readConfig':
        if (hugeConfig) return 'A' * 250000;
        return '[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n'
            'Address = 10.77.0.2/32\nDNS = 1.1.1.1\n[Peer]\n'
            'PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n'
            'Endpoint = 203.0.113.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n';
      case 'routingGet':
        return {
          'mode': 'all',
          'packages': <String>[],
          'networks': <String>[],
          'domains': <String>[],
        };
    }
    return null;
  }

  Future<AppStore> store() async {
    dir = await Directory.systemTemp.createTemp('reconcile-cas-');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, handle);
    await File('${dir!.path}/profiles.json').writeAsString(jsonEncode({
      'schema': 2,
      'profiles': [
        {'id': 'p1', 'name': 'one', 'protocol': 'awg', 'endpoint': '203.0.113.4:51820'},
      ],
      'selected': 'p1',
      'priorityProtocol': 'awg',
      'checkSite': 'https://example.invalid/',
      'siteCheckEnabled': false,
      'protocolTimeoutSeconds': 15,
      if (hugeDocument) 'padding': 'A' * 600000,
      if (includePolicy)
        'connectionPolicy': {'mode': 'selectedOnly', 'roundMillis': 30000},
    }));
    final s = AppStore()..directory = dir!;
    await s.load();
    return s;
  }

  Future<void> close(AppStore s) async {
    s.dispose();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
    debugDefaultTargetPlatformOverride = null;
    if (dir != null && dir!.existsSync()) await dir!.delete(recursive: true);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _CasRig rig;

  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    rig = _CasRig();
  });

  test('desktop reconcile sends the freshly observed casGeneration', () async {
    rig.includePolicy = false;
    final s = await rig.store();
    try {
      await s.retryPolicyReconciliation();
      expect(rig.validateArgs!['expectedGeneration'], 'e' * 32);
      expect(rig.reconcileArgs!['expectedGeneration'], 'e' * 32);
      expect(s.connectionModeConfirmed, isTrue);
    } finally {
      await rig.close(s);
    }
  });

  test('a fresh helper without a generation keeps expectedGeneration null',
      () async {
    rig.observedCas = null;
    rig.includePolicy = false;
    final s = await rig.store();
    try {
      await s.retryPolicyReconciliation();
      expect(rig.reconcileArgs!.containsKey('expectedGeneration'), isTrue);
      expect(rig.reconcileArgs!['expectedGeneration'], isNull);
      expect(rig.validateArgs!['expectedGeneration'], isNull);
    } finally {
      await rig.close(s);
    }
  });

  test('a newer native generation race fails closed after rename', () async {
    rig.failReconcile = true;
    final s = await rig.store();
    try {
      await expectLater(
        s.retryPolicyReconciliation(),
        throwsA(
          isA<PublicationFailure>().having(
            (e) => e.phase,
            'phase',
            PublicationPhase.renamedNativeUnconfirmed,
          ),
        ),
      );
      expect(s.connectionModeConfirmed, isFalse);
      expect(s.committedReceipt, isNull);
      // The document rename is authoritative; CAS metadata never confirms.
      final doc = jsonDecode(
        await File('${rig.dir!.path}/profiles.json').readAsString(),
      ) as Map;
      expect(doc['connectionPlanReceipt'], isNotNull);
    } finally {
      await rig.close(s);
    }
  });

  test('channel reconciliation default stays null; explicit value is passed',
      () async {
    Map<String, dynamic>? request;
    final channel = PolicyChannel(
      invoke: (method, arguments) async {
        if (method == 'policyCapabilities') {
          return {
            'version': 1,
            'instanceNonce': 'c' * 32,
            'state': 'blocked',
            'resourceState': 'unknown',
            'validation': 1,
          };
        }
        request = Map<String, dynamic>.from(arguments as Map);
        return {
          'version': 1,
          'instanceNonce': request!['instanceNonce'],
          'controllerNonce': request!['controllerNonce'],
          'transactionId': request!['transactionId'],
          'planGeneration': request!['planGeneration'],
          'state': 'ready',
        };
      },
      storeIdentity: 'a' * 64,
      controllerNonce: 'b' * 32,
    );
    await channel.discover();
    final snapshot = PublicationSnapshot(
      transactionId: 'd' * 32,
      generation: '1' * 32,
      document: const {'schema': 2},
      plan: const {'schema': 2},
    );
    await channel.reconciliation(snapshot).commit();
    expect(request!['expectedGeneration'], isNull);
    await channel
        .reconciliation(snapshot, expectedGeneration: 'e' * 32)
        .commit();
    expect(request!['expectedGeneration'], 'e' * 32);
  });

  test('already READY recovery uses begin/validate/commit, not reconcile', () async {
    final s = await rig.store();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.automatic);
      expect(s.connectionModeConfirmed, isTrue);
      final oldGeneration = s.committedReceipt!.planGeneration;
      rig.calls.clear();
      await s.retryPolicyReconciliation();
      expect(rig.calls, contains('policyBegin'));
      expect(rig.calls, contains('policyValidate'));
      expect(rig.calls, contains('policyCommit'));
      expect(rig.calls, isNot(contains('policyReconcile')));
      expect(rig.beginArgs!['expectedGeneration'], oldGeneration);
      expect(s.connectionModeConfirmed, isTrue);
    } finally {
      await rig.close(s);
    }
  });

  test('a BEGIN STALE race fails before the rename and keeps the document',
      () async {
    final s = await rig.store();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.automatic);
      final file = File('${rig.dir!.path}/profiles.json');
      final before = await file.readAsString();
      rig.failBegin = true;
      rig.calls.clear();
      await expectLater(
        s.retryPolicyReconciliation(),
        throwsA(
          isA<PublicationFailure>().having(
            (e) => e.phase,
            'phase',
            PublicationPhase.beforeRename,
          ),
        ),
      );
      expect(await file.readAsString(), before);
      expect(rig.calls, isNot(contains('policyReconcile')));
    } finally {
      await rig.close(s);
    }
  });

  test('a held begin does not rename; dispose settles safely', () async {
    final s = await rig.store();
    await s.setConnectionPolicy(ConnectionPolicy.automatic);
    final file = File('${rig.dir!.path}/profiles.json');
    final before = await file.readAsString();
    rig.beginGate = Completer<void>();
    rig.beginEntered = Completer<void>();
    final retry = s.retryPolicyReconciliation();
    await rig.beginEntered!.future;
    expect(await file.readAsString(), before);
    expect(s.connectionModeConfirmed, isFalse);
    s.dispose();
    rig.beginGate!.complete();
    Object? error;
    await retry.catchError((Object e) {
      error = e;
      return null;
    });
    expect(error, isA<PublicationFailure>());
    expect(s.connectionModeConfirmed, isFalse);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
    debugDefaultTargetPlatformOverride = null;
    await rig.dir!.delete(recursive: true);
  });

  test('OWNED/UNKNOWN ready state never takes the begin route', () async {
    final s = await rig.store();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.automatic);
      rig.owned = true;
      rig.failReconcile = true;
      rig.calls.clear();
      await expectLater(
        s.retryPolicyReconciliation(),
        throwsA(
          isA<PublicationFailure>().having(
            (e) => e.phase,
            'phase',
            PublicationPhase.renamedNativeUnconfirmed,
          ),
        ),
      );
      expect(rig.calls, isNot(contains('policyBegin')));
      expect(s.connectionModeConfirmed, isFalse);
    } finally {
      await rig.close(s);
    }
  });

  test('oversized preflight fails before begin and before any rename', () async {
    rig.hugeDocument = true;
    rig.includePolicy = false;
    final s = await rig.store();
    try {
      final file = File('${rig.dir!.path}/profiles.json');
      final before = await file.readAsString();
      rig.calls.clear();
      await expectLater(
        s.retryPolicyReconciliation(),
        throwsA(
          isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_OVERSIZE'),
        ),
      );
      expect(rig.calls, isNot(contains('policyBegin')));
      expect(await file.readAsString(), before);
    } finally {
      await rig.close(s);
    }
  });
  test('a held BEGIN superseded by a newer document aborts the same reserve',
      () async {
    final s = await rig.store();
    try {
      await s.setConnectionPolicy(ConnectionPolicy.automatic);
      expect(s.connectionModeConfirmed, isTrue);
      final file = File('${rig.dir!.path}/profiles.json');
      rig.beginGate = Completer<void>();
      rig.beginEntered = Completer<void>();
      rig.calls.clear();
      final retry = s.retryPolicyReconciliation();
      await rig.beginEntered!.future;
      final oldBegin = rig.beginArgs!;
      // A genuine newer winner lands while the old BEGIN is in flight.
      final winner = Map<String, dynamic>.from(
        jsonDecode(await file.readAsString()) as Map,
      );
      winner['connectionPolicy'] = {'mode': 'selectedOnly', 'roundMillis': 30000};
      winner['connectionPlanReceipt'] = {
        'schema': 1,
        'transactionId': 'f' * 32,
        'planGeneration': 'a' * 32,
        'plan': <String, dynamic>{},
      };
      final winnerBytes = jsonEncode(winner);
      await file.writeAsString(winnerBytes);
      rig.beginGate!.complete();
      await expectLater(
        retry,
        throwsA(
          isA<PublicationFailure>().having(
            (e) => e.phase,
            'phase',
            PublicationPhase.beforeRename,
          ),
        ),
      );
      expect(await file.readAsString(), winnerBytes);
      expect(rig.calls, contains('policyAbort'));
      expect(rig.calls, isNot(contains('policyCommit')));
      expect(rig.abortArgs!['transactionId'], oldBegin['transactionId']);
      final abortCall = rig.calls.indexOf('policyAbort');
      expect(abortCall, greaterThanOrEqualTo(0));
      expect(rig.beginArgs!['transactionId'], oldBegin['transactionId']);
      expect(s.connectionModeConfirmed, isFalse);
      expect(s.committedReceipt, isNull);
    } finally {
      await rig.close(s);
    }
  });}
