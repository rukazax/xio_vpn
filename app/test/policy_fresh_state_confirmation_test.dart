import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/policy_publication.dart';

/// Real Store/Channel oracle for DT3: the six-field ACK alone is not resource
/// proof. Initial discovery reports UNKNOWN; after a SUCCESS commit the Store
/// must obtain a FRESH policyState and require CLEAN+READY with the exact same
/// six-field identity before it adopts native confirmation.
class _FreshStateRig {
  final directory = Directory.systemTemp;
  Directory? dir;
  Map<String, dynamic>? lastRequest;
  String freshResource = 'clean';
  bool omitReceipt = false;
  String? foreignTransaction;
  Completer<void>? stateGate;
  Completer<void>? stateEntered;
  int stateQueries = 0;

  Map<String, dynamic> _ack(Map<String, dynamic> a, String state) => {
    'version': 1,
    'instanceNonce': a['instanceNonce'],
    'controllerNonce': a['controllerNonce'],
    'transactionId': a['transactionId'],
    'planGeneration': a['planGeneration'],
    'state': state,
  };

  Future<Object?> handle(MethodCall call) async {
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
        stateQueries++;
        if (stateGate != null && stateEntered != null && !stateEntered!.isCompleted) {
          stateEntered!.complete();
          await stateGate!.future;
        }
        final request = lastRequest!;
        final tx = foreignTransaction ?? request['transactionId'];
        return {
          'version': 1,
          'instanceNonce': request['instanceNonce'],
          'state': freshResource == 'clean' ? 'ready' : 'blocked',
          'resourceState': freshResource,
          'planSchema': 2,
          'validation': 1,
          'launchBound': true,
          'resourceClaimed': true,
          'clientOnly': false,
          'error': '',
          'pendingTransaction': null,
          'casGeneration': request['planGeneration'],
          if (!omitReceipt && freshResource == 'clean')
            'receipt': {
              'version': 1,
              'storeIdentity': request['storeIdentity'],
              'instanceNonce': request['instanceNonce'],
              'controllerNonce': request['controllerNonce'],
              'transactionId': tx,
              'planGeneration': request['planGeneration'],
            },
        };
      case 'policyBegin':
        lastRequest = a;
        return _ack(a, 'pending');
      case 'policyValidate':
        final validation = Map<String, dynamic>.from(a['validation'] as Map);
        return {
          'version': 1,
          'instanceNonce': a['instanceNonce'],
          'controllerNonce': a['controllerNonce'],
          'transactionId': a['transactionId'],
          'documentDigest': validation['documentDigest'],
        };
      case 'policyCommit':
        return _ack(a, 'ready');
      case 'policyReconcile':
        return _ack(a, 'ready');
      case 'supportedProtocols':
        return ['awg'];
      case 'status':
        return {'active': false, 'phase': 'disconnected'};
      case 'connectionBusy':
        return false;
      case 'readConfig':
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
      case 'secureScreen':
        return null;
    }
    return null;
  }

  Future<AppStore> store() async {
    dir = await Directory.systemTemp.createTemp('fresh-native-ready-');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, handle);
    await File('${dir!.path}/profiles.json').writeAsString(jsonEncode({
      'schema': 2,
      'profiles': <Object?>[],
      'priorityProtocol': 'awg',
      'checkSite': 'https://example.invalid/',
      'siteCheckEnabled': false,
      'protocolTimeoutSeconds': 15,
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
  late _FreshStateRig rig;

  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    rig = _FreshStateRig();
  });

  test('initial UNKNOWN -> ACK READY -> fresh CLEAN READY confirms', () async {
    final s = await rig.store();
    try {
      expect(s.connectionModeConfirmed, isFalse);
      await s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      expect(s.connectionModeConfirmed, isTrue);
      expect(s.committedReceipt?.transactionId, rig.lastRequest!['transactionId']);
      expect(rig.stateQueries, greaterThanOrEqualTo(1));
    } finally {
      await rig.close(s);
    }
  });

  test('fresh UNKNOWN is fail-closed after rename, no compensation', () async {
    rig.freshResource = 'unknown';
    final s = await rig.store();
    try {
      await expectLater(
        s.setConnectionPolicy(ConnectionPolicy.selectedOnly),
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
      final doc = jsonDecode(
        await File('${rig.dir!.path}/profiles.json').readAsString(),
      ) as Map;
      // The durable rename is authoritative: no rollback to the old mode.
      expect((doc['connectionPolicy'] as Map)['mode'], 'selectedOnly');
    } finally {
      await rig.close(s);
    }
  });

  test('fresh receipt for a foreign transaction is rejected', () async {
    rig.foreignTransaction = 'f' * 32;
    final s = await rig.store();
    try {
      await expectLater(
        s.setConnectionPolicy(ConnectionPolicy.selectedOnly),
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
    } finally {
      await rig.close(s);
    }
  });

  test('fresh CLEAN READY without the nested receipt is rejected', () async {
    rig.omitReceipt = true;
    final s = await rig.store();
    try {
      await expectLater(
        s.setConnectionPolicy(ConnectionPolicy.selectedOnly),
        throwsA(
          isA<PublicationFailure>().having(
            (e) => e.phase,
            'phase',
            PublicationPhase.renamedNativeUnconfirmed,
          ),
        ),
      );
      expect(s.connectionModeConfirmed, isFalse);
    } finally {
      await rig.close(s);
    }
  });

  test('a held post-ACK fresh query keeps confirmation false until CLEAN READY',
      () async {
    rig.stateGate = Completer<void>();
    rig.stateEntered = Completer<void>();
    final s = await rig.store();
    try {
      final change = s.setConnectionPolicy(ConnectionPolicy.selectedOnly);
      await rig.stateEntered!.future;
      expect(s.connectionModeConfirmed, isFalse);
      rig.stateGate!.complete();
      await change;
      expect(s.connectionModeConfirmed, isTrue);
    } finally {
      await rig.close(s);
    }
  });

  test('dispose while the fresh query is held stays unconfirmed and quiet',
      () async {
    rig.stateGate = Completer<void>();
    rig.stateEntered = Completer<void>();
    final s = await rig.store();
    Object? error;
    final change = s
        .setConnectionPolicy(ConnectionPolicy.selectedOnly)
        .catchError((Object e) {
          error = e;
        });
    await rig.stateEntered!.future;
    s.dispose();
    rig.stateGate!.complete();
    await change;
    expect(error, isNotNull);
    expect(s.connectionModeConfirmed, isFalse);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
    debugDefaultTargetPlatformOverride = null;
    await rig.dir!.delete(recursive: true);
  });
}
