import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/desktop_engine.dart';

const _config = '[Interface]\nAddress = 10.7.0.2/32\nPrivateKey = priv\n'
    '[Peer]\nPublicKey = pub\nEndpoint = 203.0.113.9:51820\n';
const _instance = 'cccccccccccccccccccccccccccccccc';

Map<String, dynamic> profile(String id, {String protocol = 'awg'}) => {
  'id': id,
  'name': id,
  'protocol': protocol,
  'endpoint': 'fixture.invalid:51821',
};

Map<String, dynamic> document({
  Object? policy = const {'mode': 'automatic', 'roundMillis': 30000},
  String? selected = 'p1',
  List<Map<String, dynamic>>? profiles,
  bool includePolicy = true,
}) => {
  'schema': 2,
  if (includePolicy) 'connectionPolicy': policy,
  'selected': selected,
  'priorityProtocol': 'xray',
  'profiles': profiles ?? [profile('p1'), profile('p2', protocol: 'xray')],
  'users': <Object?>[],
  'allowScreenshots': false,
};

Map<String, dynamic> ack(Map request, String state) => {
  'version': 1,
  'instanceNonce': request['instanceNonce'],
  'controllerNonce': request['controllerNonce'],
  'transactionId': request['transactionId'],
  'planGeneration': request['planGeneration'],
  'state': state,
};

/// Real Android-style channel behaviour for one store instance.
class Channel {
  Channel({this.policyCapable = false, this.failCommit = false});
  final bool policyCapable, failCommit;
  final List<MethodCall> calls = [];
  final installs = <Map>[];
  bool active = false;
  Completer<void>? gate;
  Map<String, dynamic>? committedReceipt;

  Future<Object?> handle(MethodCall call) async {
    calls.add(call);
    final arguments = call.arguments is Map
        ? Map<String, dynamic>.from(call.arguments as Map)
        : <String, dynamic>{};
    switch (call.method) {
      case 'policyCapabilities':
        if (!policyCapable) throw MissingPluginException('policyCapabilities');
        return {
          'version': 1,
          'instanceNonce': _instance,
          'state': 'blocked',
          'resourceState': 'clean',
          'validation': 1,
        };
      case 'policyBegin':
        return ack(arguments, 'pending');
      case 'policyValidate':
        return {
          'version': 1,
          'instanceNonce': arguments['instanceNonce'],
          'controllerNonce': arguments['controllerNonce'],
          'transactionId': arguments['transactionId'],
          'documentDigest':
              (arguments['validation'] as Map)['documentDigest'],
        };
      case 'policyReconcile':
      case 'policyCommit':
        if (failCommit) {
          throw PlatformException(code: 'POLICY_PERSISTENCE', message: 'no');
        }
        committedReceipt = {
          'version': 1,
          'storeIdentity': arguments['storeIdentity'],
          'instanceNonce': arguments['instanceNonce'],
          'controllerNonce': arguments['controllerNonce'],
          'transactionId': arguments['transactionId'],
          'planGeneration': arguments['planGeneration'],
        };
        return ack(arguments, 'ready');
      case 'policyState':
        return {
          'version': 1,
          'instanceNonce': _instance,
          'state': 'ready',
          'phase': 'absent',
          'resourceState': 'clean',
          if (committedReceipt != null) 'receipt': committedReceipt,
        };
      case 'policyAbort':
        return ack(arguments, 'blocked');
      case 'readConfig':
        return _config;
      case 'routingGet':
        return {
          'mode': 'all',
          'packages': <String>[],
          'networks': <String>[],
          'domains': <String>[],
        };
      case 'routingBegin':
        return {
          'revision': 'r1',
          'resolutionId': 'n1',
          'reuseAllowed': false,
          'lease': arguments['lease'],
          'domains': <String>[],
          'networks': <String>[],
        };
      case 'routingResolved':
        return null;
      case 'connect':
        installs.add(arguments);
        throw PlatformException(code: 'FIXTURE_ATTEMPT');
      case 'disconnect':
        return null;
      case 'status':
        return {
          'active': active,
          'phase': active ? 'connected' : 'disconnected',
          'id': null,
        };
      case 'supportedProtocols':
        return ['awg', 'xray'];
      case 'activeId':
        return null;
      case 'secureScreen':
        return null;
      case 'connectionBusy':
        return false;
    }
    return null;
  }
}

class GatedStore extends AppStore {
  final entered = Completer<void>();
  final gate = Completer<void>();
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    if (!entered.isCompleted) entered.complete();
    await gate.future;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-policy-store-');
  });
  tearDown(() async {
    messenger.setMockMethodCallHandler(native, null);
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  Future<void> writeDocument(Map<String, dynamic> value) =>
      File('${directory.path}/profiles.json').writeAsString(jsonEncode(value));

  Future<Map<String, dynamic>> readDocument() async =>
      Map<String, dynamic>.from(
        jsonDecode(await File('${directory.path}/profiles.json').readAsString())
            as Map,
      );

  AppStore newStore(Channel channel) {
    messenger.setMockMethodCallHandler(native, channel.handle);
    return AppStore(nativeTunnelOverride: true)..directory = directory;
  }

  test('manual mode persists, reloads and keeps the selected identity', () async {
    final channel = Channel();
    final store = newStore(channel);
    store.profiles.add(
      const Profile(
        id: 'p1',
        name: 'p1',
        protocol: 'awg',
        endpoint: 'fixture.invalid:51821',
      ),
    );
    store.selectedId = 'p1';
    await store.load();
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    expect(store.policyInvalid, isFalse);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    expect(store.connectionPolicy, ConnectionPolicy.selectedOnly);
    expect((await readDocument())['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    store.dispose();

    final reloaded = newStore(Channel());
    await reloaded.load();
    expect(reloaded.connectionPolicy, ConnectionPolicy.selectedOnly);
    expect(reloaded.selectedId, 'p1');
    expect(reloaded.policyInvalid, isFalse);
    reloaded.dispose();
  });

  test('absent property is legacy automatic, never a blocked state', () async {
    await writeDocument(document(includePolicy: false));
    final store = newStore(Channel());
    await store.load();
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    expect(store.policyInvalid, isFalse);
    // The first write normalizes the legacy document to the explicit shape.
    await store.save();
    expect((await readDocument())['connectionPolicy'], {
      'mode': 'automatic',
      'roundMillis': 30000,
    });
    store.dispose();
  });

  for (final invalid in <Object?>[
    null,
    'selectedOnly',
    {'mode': 'future', 'roundMillis': 30000},
    {'mode': 'selectedOnly'},
    {'mode': 'selectedOnly', 'roundMillis': 30001},
    {'mode': 'selectedOnly', 'roundMillis': 30000.0},
    {'mode': 'automatic', 'roundMillis': 30000, 'future': true},
    <String, Object?>{},
  ]) {
    test('present-but-invalid $invalid blocks admission and keeps its bytes', () async {
      await writeDocument(document(policy: invalid));
      final channel = Channel();
      final store = newStore(channel);
      await store.load();
      expect(store.policyInvalid, isTrue);
      expect(store.policyError, isNotNull);
      channel.calls.clear();
      await store.connect();
      expect(
        channel.calls.where((call) => call.method == 'connect'),
        isEmpty,
        reason: 'invalid durable policy must block every UP source',
      );
      expect(store.error, isNotNull);
      // An unrelated save must not normalize or erase the invalid value.
      await store.setLanguage('en');
      expect((await readDocument())['connectionPolicy'], invalid);
      expect(
        () => store.setConnectionPolicy(ConnectionPolicy.automatic),
        throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_INVALID')),
      );
      store.dispose();
    });
  }

  test('a corrupted durable receipt blocks admission too', () async {
    await writeDocument({
      ...document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
      'connectionPlanReceipt': {'schema': 1, 'transactionId': 'short'},
    });
    final store = newStore(Channel());
    await store.load();
    expect(store.policyInvalid, isTrue);
    store.dispose();
  });

  test('manual keeps a missing selection and refuses to repair it', () async {
    await writeDocument(
      document(
        policy: {'mode': 'selectedOnly', 'roundMillis': 30000},
        selected: 'gone',
      ),
    );
    final channel = Channel();
    final store = newStore(channel);
    await store.load();
    expect(store.selectedId, 'gone');
    expect(store.selected, isNull);
    channel.calls.clear();
    await store.connect();
    expect(channel.calls.where((call) => call.method == 'connect'), isEmpty);
    expect(store.error, contains('Manual mode'));
    store.dispose();
  });

  test('automatic still repairs a missing selection', () async {
    await writeDocument(document(selected: 'gone'));
    final store = newStore(Channel());
    await store.load();
    expect(store.selectedId, 'p1');
    store.dispose();
  });

  test('removing the manual selection does not pick another profile', () async {
    await writeDocument(
      document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
    );
    final store = newStore(Channel());
    await store.load();
    await store.remove('p1');
    expect(store.selectedId, 'p1');
    expect((await readDocument())['selected'], 'p1');
    store.dispose();
  });

  test('automatic removal still falls back to the first remaining profile', () async {
    await writeDocument(document());
    final store = newStore(Channel());
    await store.load();
    await store.remove('p1');
    expect(store.selectedId, 'p2');
    store.dispose();
  });

  test('mode change is idle-only and never disconnects implicitly', () async {
    await writeDocument(document());
    final channel = Channel()..active = true;
    final store = newStore(channel);
    await store.load();
    expect(store.status.active, isTrue);
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_BUSY')),
    );
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    expect(
      channel.calls.where((call) => call.method == 'disconnect'),
      isEmpty,
      reason: 'a refused mode change must not tear the tunnel down',
    );
    channel.active = false;
    store.busy = true;
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_BUSY')),
    );
    store.busy = false;
    store.dispose();
  });

  test('ordinary and exclusive owners cannot interleave, in either order', () async {
    await writeDocument(document());
    final channel = Channel();
    final store = newStore(channel);
    await store.load();

    final ticket = store.beginOwnedDocumentMutation();
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_BUSY')),
    );
    store.releaseOwnedDocumentMutation(ticket);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);

    // The reverse direction: an exclusive mode save in flight blocks a new
    // ordinary mutation before it can change any field.
    await writeDocument(
      document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
    );
    final gated = GatedStore()..directory = directory;
    await gated.load();
    final change = gated.setConnectionPolicy(ConnectionPolicy.automatic);
    await gated.entered.future;
    expect(
      () => gated.setLanguage('en'),
      throwsA(isA<StateError>()),
      reason: 'exclusive mode owner must fence ordinary mutations',
    );
    gated.gate.complete();
    await change;
    expect(gated.connectionPolicy, ConnectionPolicy.automatic);
    gated.dispose();
    store.dispose();
  });

  test('commitOwnedDocument refuses a revoked ticket', () async {
    await writeDocument(document());
    final store = newStore(Channel());
    await store.load();
    final ticket = store.beginOwnedDocumentMutation();
    store.dispose();
    await expectLater(
      store.commitOwnedDocument(ticket),
      throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_STALE')),
    );
  });

  test('manual activation uses only the selected profile and carries storeIdentity', () async {
    await writeDocument(
      document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
    );
    final channel = Channel(policyCapable: true);
    final store = newStore(channel)..androidActivationForTesting = true;
    await store.load();
    // Reconciliation produced a live receipt for this exact generation.
    expect(store.policyCapable, isTrue);
    expect(store.committedReceipt, isNotNull);
    expect(store.committedReceipt!.storeIdentity, store.storeIdentity);
    await store.connect();
    expect(
      channel.installs.map((install) => install['id']),
      ['p1'],
      reason: 'manual mode must never attempt another profile',
    );
    final receipt = channel.installs.single['policyReceipt'] as Map;
    expect(receipt['storeIdentity'], store.storeIdentity);
    expect(receipt['version'], 1);
    expect(receipt['planGeneration'], store.committedReceipt!.planGeneration);
    store.dispose();
  });

  test('automatic activation still falls back after a failed first attempt', () async {
    await writeDocument(document());
    final channel = Channel(policyCapable: true);
    final store = newStore(channel)..androidActivationForTesting = true;
    await store.load();
    await store.connect();
    expect(
      channel.installs.map((install) => install['id']),
      ['p1', 'p2'],
      reason: 'automatic fallback is unchanged',
    );
    for (final install in channel.installs) {
      expect(install['policyReceipt'], isNotNull);
    }
    store.dispose();
  });

  test('manual without a reconciled receipt fails closed before any effect', () async {
    // Capability exists, but the durable envelope refuses the commit: no live
    // receipt may authorize manual activation.
    await writeDocument(
      document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
    );
    final channel = Channel(policyCapable: true, failCommit: true);
    final store = newStore(channel);
    await store.load();
    expect(store.committedReceipt, isNull);
    expect(store.policyError, isNotNull);
    channel.calls.clear();
    await store.connect();
    expect(channel.calls.where((call) => call.method == 'connect'), isEmpty);
    expect(store.error, contains('could not be reconciled'));
    store.dispose();
  });

  test('desktop encodes the same receipt as one JSON string', () async {
    await writeDocument(
      document(policy: {'mode': 'selectedOnly', 'roundMillis': 30000}),
    );
    final channel = Channel(policyCapable: true);
    final store = newStore(channel)..androidActivationForTesting = false;
    await store.load();
    await store.connect();
    final install = channel.installs.single;
    expect(install.containsKey('policyReceipt'), isFalse);
    final decoded =
        jsonDecode(install['PolicyReceiptJSON'] as String) as Map;
    expect(decoded.keys, [
      'version',
      'storeIdentity',
      'instanceNonce',
      'controllerNonce',
      'transactionId',
      'planGeneration',
    ]);
    expect(decoded['storeIdentity'], store.storeIdentity);
    store.dispose();
  });

  test('desktop policy RPC without a helper is an explicit failure', () async {
    // No live helper in this test: changing settings must never launch/elevate,
    // and an absent helper is not a versioned ACK.
    await expectLater(
      DesktopEngine.invoke('policyCapabilities', const <String, Object?>{}),
      throwsA(
        isA<PlatformException>().having((e) => e.code, 'code', 'POLICY_UNSUPPORTED'),
      ),
    );
  });

  test('automatic stays on the legacy path when no policy capability exists', () async {
    await writeDocument(document());
    final channel = Channel();
    final store = newStore(channel);
    await store.load();
    await store.connect();
    expect(
      channel.installs.map((install) => install['id']),
      ['p1', 'p2'],
    );
    for (final install in channel.installs) {
      expect(install.containsKey('policyReceipt'), isFalse);
    }
    store.dispose();
  });
}
