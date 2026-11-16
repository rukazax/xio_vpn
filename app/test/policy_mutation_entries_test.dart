import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

/// Every admission-relevant writer owns the Store document admission before its
/// first await/IO. These use the actual Store/channel, not a parallel model.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-mutation-');
  });
  tearDown(() async {
    messenger.setMockMethodCallHandler(native, null);
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  final calls = <MethodCall>[];
  void serve() {
    calls.clear();
    messenger.setMockMethodCallHandler(native, (call) async {
      calls.add(call);
      switch (call.method) {
        case 'supportedProtocols':
          return ['awg', 'xray'];
        case 'readConfig':
          return '[Interface]\nPrivateKey = priv\n[Peer]\nEndpoint = 203.0.113.9:51820\n';
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
            'lease': (call.arguments as Map)['lease'],
            'domains': <String>[],
            'networks': <String>[],
          };
      }
      return null;
    });
  }

  Future<void> writeDocument(Map<String, dynamic> value) =>
      File('${directory.path}/profiles.json').writeAsString(jsonEncode(value));

  Future<Map<String, dynamic>> readDocument() async =>
      Map<String, dynamic>.from(
        jsonDecode(await File('${directory.path}/profiles.json').readAsString())
            as Map,
      );

  Map<String, dynamic> document({String mode = 'automatic'}) => {
    'schema': 2,
    'connectionPolicy': {'mode': mode, 'roundMillis': 30000},
    'selected': 'p1',
    'priorityProtocol': 'xray',
    'profiles': [
      {
        'id': 'p1',
        'name': 'p1',
        'protocol': 'awg',
        'endpoint': 'fixture.invalid:51821',
      },
      {
        'id': 'p2',
        'name': 'p2',
        'protocol': 'xray',
        'endpoint': 'other.invalid:443',
      },
    ],
    'users': <Object?>[],
  };

  test('import is fenced by an exclusive mode owner before any native write', () async {
    await writeDocument(document());
    serve();
    final store = AppStore(nativeTunnelOverride: true)..directory = directory;
    await store.load();
    calls.clear();

    // Hold the exclusive owner through a gated plan save.
    final entered = Completer<void>();
    final gate = Completer<void>();
    final gated = _GatedStore(entered, gate)..directory = directory;
    serve();
    await gated.load();
    final modeChange = gated.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    await entered.future;

    await expectLater(
      gated.importConnection(
        '[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 203.0.113.9:51820\n',
        name: 'fenced',
      ),
      throwsA(isA<StateError>()),
      reason: 'an ordinary graph writer must not enter behind the mode owner',
    );
    expect(
      calls.where((call) => call.method == 'saveConfig'),
      isEmpty,
      reason: 'no native config write may start before ownership',
    );
    gate.complete();
    await modeChange;
    expect(gated.connectionPolicy, ConnectionPolicy.selectedOnly);
    gated.dispose();
    store.dispose();
  });

  test('removal is fenced by an exclusive mode owner before deleteConfig', () async {
    await writeDocument(document());
    serve();
    final entered = Completer<void>();
    final gate = Completer<void>();
    final store = _GatedStore(entered, gate)..directory = directory;
    await store.load();
    final modeChange = store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    await entered.future;
    // A second store is the only way to hold a mode owner; removing the selected
    // profile must be refused instead of deleting the native config.
    calls.clear();
    await expectLater(store.remove('p2'), throwsA(isA<StateError>()));
    expect(calls.where((call) => call.method == 'deleteConfig'), isEmpty);
    gate.complete();
    await modeChange;
    store.dispose();
  });

  test('routing result and settings writers are ordinary owned mutations', () async {
    await writeDocument(document());
    serve();
    final store = AppStore(nativeTunnelOverride: true)..directory = directory;
    await store.load();
    await store.setSplitDomains(['b.example.com', 'A.example.com']);
    expect(store.splitDomains, ['b.example.com', 'a.example.com']);
    expect((await readDocument())['splitDomains'], [
      'b.example.com',
      'a.example.com',
    ]);
    await store.setDnsServers(['9.9.9.9']);
    await store.setAutostart(true);
    await store.setAutoConnectOnStart(false);
    await store.saveConnectionSettings(
      'https://probe.invalid/ok',
      'awg',
      timeoutSeconds: 20,
    );
    final saved = await readDocument();
    expect(saved['dnsServers'], ['9.9.9.9']);
    expect(saved['autostart'], isTrue);
    expect(saved['priorityProtocol'], 'awg');
    expect(saved['protocolTimeoutSeconds'], 20);
    store.dispose();
  });

  test('a mode change is refused while an ordinary mutation is outstanding', () async {
    await writeDocument(document());
    serve();
    final entered = Completer<void>();
    final gate = Completer<void>();
    final store = _GatedStore(entered, gate)..directory = directory;
    await store.load();
    final pending = store.setAutostart(true);
    await entered.future;
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_BUSY'),
      ),
    );
    gate.complete();
    await pending;
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    store.dispose();
  });
}

class _GatedStore extends AppStore {
  _GatedStore(this.entered, this.gate);
  final Completer<void> entered;
  final Completer<void> gate;
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    if (!entered.isCompleted) entered.complete();
    await gate.future;
  }
}
