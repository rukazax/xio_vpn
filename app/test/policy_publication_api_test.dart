import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/desktop_engine.dart';
import 'package:xio/policy_channel.dart';
import 'package:xio/policy_publication.dart';
import 'package:xio/store_writer_owner.dart';

const _instance = 'cccccccccccccccccccccccccccccccc';
const _config = '[Interface]\nPrivateKey = priv\n[Peer]\n'
    'Endpoint = 203.0.113.9:51820\n';

Map<String, dynamic> ack(Map request, String state) => {
  'version': 1,
  'instanceNonce': request['instanceNonce'],
  'controllerNonce': request['controllerNonce'],
  'transactionId': request['transactionId'],
  'planGeneration': request['planGeneration'],
  'state': state,
};

class Channel {
  Channel({this.policyCapable = false, this.failCommit = false});
  final bool policyCapable, failCommit;
  final List<MethodCall> calls = [];
  final List<Map<String, dynamic>> installs = [];
  int published = 0;
  String phase = 'absent';
  Map<String, dynamic>? committedReceipt;
  String? pendingTransaction;
  Completer<void>? commitGate;
  final commitEntered = Completer<void>();
  Completer<void>? stateGate;
  final stateEntered = Completer<void>();
  Completer<void>? beginGate;
  final beginEntered = Completer<void>();

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
        if (beginGate != null) {
          if (!beginEntered.isCompleted) beginEntered.complete();
          await beginGate!.future;
        }
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
        if (commitGate != null) {
          if (!commitEntered.isCompleted) commitEntered.complete();
          await commitGate!.future;
        }
        phase = 'ready';
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
        if (stateGate != null) {
          if (!stateEntered.isCompleted) stateEntered.complete();
          await stateGate!.future;
        }
        return {
          'version': 1,
          'instanceNonce': _instance,
          'state': phase == 'ready'
              ? 'ready'
              : phase == 'blocked'
              ? 'blocked'
              : 'pending',
          'phase': phase,
          'resourceState': phase == 'pending' ? 'owned' : 'clean',
          if (phase == 'ready' && committedReceipt != null)
            'receipt': committedReceipt,
          if (phase == 'ready' && committedReceipt != null)
            'casGeneration': committedReceipt!['planGeneration'],
          if (pendingTransaction != null)
            'pendingTransaction': pendingTransaction,
        };
      case 'policyAbort':
        if (arguments['transactionId'] == pendingTransaction) {
          phase = 'blocked';
          committedReceipt = null;
          pendingTransaction = null;
        }
        return {
          'version': 1,
          'state': 'blocked',
          'transactionId': arguments['transactionId'],
        };
      case 'saveConnectionPlan':
        published++;
        return null;
      case 'connect':
        installs.add(arguments);
        throw PlatformException(code: 'FIXTURE_ATTEMPT');
      case 'disconnect':
        return null;
      case 'status':
        return {'active': false, 'phase': 'disconnected'};
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
      case 'supportedProtocols':
        return ['awg', 'xray'];
      case 'secureScreen':
        return null;
    }
    return null;
  }
}

class GatedStore extends AppStore {
  GatedStore(this.entered, this.gate, {super.nativeTunnelOverride = true});
  final Completer<void> entered;
  final Completer<void> gate;
  bool failAfterRename = false;
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    if (!entered.isCompleted) entered.complete();
    await gate.future;
    if (failAfterRename) {
      throw StateError('native plan failed after rename');
    }
  }
}


class _GateWriter implements ProductStoreWriterOwner {
  _GateWriter(this.real);
  final ProductStoreWriterOwner real;
  final entered = Completer<void>();
  final gate = Completer<void>();
  bool armed = true;
  @override
  String get storeIdentity => real.storeIdentity;
  @override
  String get controllerNonce => real.controllerNonce;
  @override
  bool get acceptsWrites => real.acceptsWrites;
  @override
  int get pendingWrites => real.pendingWrites;
  @override
  Future<void> closeWhenSettled() => real.closeWhenSettled();
  @override
  Future<T> io<T>(Future<T> Function() action) => real.io(() async {
    if (armed) {
      armed = false;
      entered.complete();
      await gate.future;
    }
    return action();
  });
  @override
  Future<T> native<T>(Future<T> Function() action) => real.native(action);
}
class _PostRenameFailStore extends AppStore {
  _PostRenameFailStore() : super(nativeTunnelOverride: true);
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    throw StateError('post-rename publication failure');
  }
}

class _CountingStore extends AppStore {
  _CountingStore() : super(nativeTunnelOverride: true);
  int publications = 0;
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    publications++;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() async {
    // This suite models the desktop controller: no Android screen-security
    // queue writer may interleave with the publication it is measuring.
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    directory = await Directory.systemTemp.createTemp('xio-policy-api-');
  });
  tearDown(() async {
    debugDefaultTargetPlatformOverride = null;
    messenger.setMockMethodCallHandler(native, null);
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  Map<String, dynamic> document({String mode = 'automatic'}) => {
    'schema': 2,
    'connectionPolicy': {'mode': mode, 'roundMillis': 30000},
    'selected': 'p1',
    'priorityProtocol': 'xray',
    'checkSite': 'https://youtube.com',
    'protocolTimeoutSeconds': 15,
    'siteCheckEnabled': false,
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

  Future<void> writeDocument(Directory dir, Map<String, dynamic> value) =>
      File('${dir.path}/profiles.json').writeAsString(jsonEncode(value));

  Future<Map<String, dynamic>> readDocument(Directory dir) async =>
      Map<String, dynamic>.from(
        jsonDecode(await File('${dir.path}/profiles.json').readAsString())
            as Map,
      );

  Future<AppStore> loaded(Channel channel, {Directory? dir}) async {
    messenger.setMockMethodCallHandler(native, channel.handle);
    final store = AppStore(nativeTunnelOverride: true)
      ..directory = dir ?? directory;
    await store.load();
    return store;
  }

  test('a foreign Store ticket cannot commit another store document', () async {
    final other = await Directory.systemTemp.createTemp('xio-policy-foreign-');
    addTearDown(() => other.delete(recursive: true));
    await writeDocument(directory, document());
    await writeDocument(other, document());
    final first = await loaded(Channel());
    final second = await loaded(Channel(), dir: other);
    final beforeFirst = await readDocument(directory);
    final beforeSecond = await readDocument(other);
    final ticket = first.beginOwnedDocumentMutation();
    first.checkSite = 'https://probe.invalid/first';
    second.checkSite = 'https://probe.invalid/second';
    await expectLater(
      second.commitOwnedDocument(ticket),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_STALE'),
      ),
    );
    expect(await readDocument(other), beforeSecond);
    expect(await readDocument(directory), beforeFirst);
    first.releaseOwnedDocumentMutation(ticket);
    first.dispose();
    second.dispose();
  });

  test('a revoked ticket cannot rename after the save queue drains', () async {
    await writeDocument(directory, document());
    final entered = Completer<void>();
    final gate = Completer<void>();
    final store = GatedStore(entered, gate)..directory = directory;
    messenger.setMockMethodCallHandler(native, Channel().handle);
    await store.load();
    // Hold one physical write after its rename.
    final first = store.save();
    await entered.future;
    final ticket = store.beginOwnedDocumentMutation();
    store.checkSite = 'https://probe.invalid/second';
    final second = store.commitOwnedDocument(ticket);
    ticket.revoke();
    gate.complete();
    await first;
    await expectLater(
      second,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.beforeRename,
        ),
      ),
    );
    // The second payload never reached the disk.
    expect((await readDocument(directory))['checkSite'], 'https://youtube.com');
    store.releaseOwnedDocumentMutation(ticket);
    store.dispose();
  });

  test('mode and settings are published as one frozen snapshot', () async {
    await writeDocument(directory, document());
    final channel = Channel();
    final store = await loaded(channel);
    final publishing = _CountingStore()..directory = directory;
    messenger.setMockMethodCallHandler(native, channel.handle);
    await publishing.load();
    final pendingStates = <bool>[];
    publishing.addListener(() {
      pendingStates.add(publishing.connectionModePending);
    });
    await publishing.saveConnectionSettings(
      'https://probe.invalid/one',
      'awg',
      timeoutSeconds: 25,
      siteCheck: true,
      reconnect: false,
      policy: ConnectionPolicy.selectedOnly,
    );
    final saved = await readDocument(directory);
    expect(saved['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    expect(saved['checkSite'], 'https://probe.invalid/one');
    expect(saved['priorityProtocol'], 'awg');
    expect(saved['protocolTimeoutSeconds'], 25);
    expect(saved['siteCheckEnabled'], isTrue);
    expect(saved['autoReconnect'], isFalse);
    expect(publishing.connectionPolicy, ConnectionPolicy.selectedOnly);
    expect(publishing.canChangeConnectionMode, isTrue);
    expect(publishing.connectionPolicyError, isNull);
    expect(pendingStates, contains(true));
    expect(pendingStates.last, isFalse);
    expect(publishing.publications, 1, reason: 'one snapshot, one publication');
    publishing.dispose();
    store.dispose();
  });

  test('a rejected mode change leaves every field unmodified', () async {
    await writeDocument(directory, document());
    final store = await loaded(Channel());
    final before = await readDocument(directory);
    await expectLater(
      store.saveConnectionSettings(
        'http://insecure.example',
        'awg',
        timeoutSeconds: 10,
        policy: ConnectionPolicy.selectedOnly,
        siteCheck: true,
      ),
      throwsA(isA<FormatException>()),
    );
    expect(await readDocument(directory), before);
    expect(store.checkSite, 'https://youtube.com');
    expect(store.protocolTimeoutSeconds, 15);
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    store.status = const TunnelStatus(active: true);
    await expectLater(
      store.saveConnectionSettings(
        'https://probe.invalid/ok',
        'awg',
        timeoutSeconds: 10,
        policy: ConnectionPolicy.selectedOnly,
        siteCheck: true,
      ),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_BUSY'),
      ),
    );
    expect(await readDocument(directory), before);
    expect(store.checkSite, 'https://youtube.com');
    expect(store.protocolTimeoutSeconds, 15);
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    store.dispose();
  });

  test('begin fences native READY even when the write fails before rename',
      () async {
    await writeDocument(directory, document());
    final store = await loaded(Channel(policyCapable: true));
    // A completed reconcile is the only thing that grants native confirmation.
    expect(
      store.connectionModeConfirmation,
      ConnectionModeConfirmation.native,
    );
    expect(store.canChangeConnectionMode, isTrue);
    // Force a pre-rename failure: the temp path is occupied by a directory.
    final blocker = Directory('${directory.path}/profiles.json.tmp');
    await blocker.create();
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.beforeRename,
        ),
      ),
    );
    // The document is unchanged, but the native READY it used to have was
    // fenced by begin: nothing may claim the old mode as confirmed.
    final onDisk = await readDocument(directory);
    expect(onDisk['connectionPolicy'], {
      'mode': 'automatic',
      'roundMillis': 30000,
    });
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    expect(
      store.connectionModeConfirmation,
      ConnectionModeConfirmation.none,
    );
    expect(store.connectionModeConfirmed, isFalse);
    expect(store.connectionPolicyError, 'reconcileRequired');
    expect(store.canChangeConnectionMode, isFalse);
    await blocker.delete();
    // Only an exact ACK for the durable snapshot restores confirmation.
    await store.retryPolicyReconciliation();
    expect(
      store.connectionModeConfirmation,
      ConnectionModeConfirmation.native,
    );
    expect(store.connectionPolicyError, isNull);
    expect(store.canChangeConnectionMode, isTrue);
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'automatic',
      'roundMillis': 30000,
    });
    store.dispose();
  });

  test('post-rename failure never claims a committed mode and can reconcile',
      () async {
    await writeDocument(directory, document());
    final entered = Completer<void>();
    final gate = Completer<void>();
    final store = GatedStore(entered, gate)..directory = directory;
    messenger.setMockMethodCallHandler(native, Channel().handle);
    await store.load();
    final change = store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    await entered.future;
    store.failAfterRename = true;
    gate.complete();
    await expectLater(
      change,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.renamedNativeUnconfirmed,
        ),
      ),
    );
    expect(store.connectionModePending, isTrue);
    expect(store.connectionPolicyError, 'publishPending');
    expect(store.canChangeConnectionMode, isFalse);
    // The bytes are durable even though the reply was lost/unknown: the failure
    // must never be presented as "not applied".
    expect(
      store.connectionModeConfirmation,
      ConnectionModeConfirmation.none,
    );
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    // The bounded recovery re-reads the durable document and clears the blocker.
    await store.retryPolicyReconciliation();
    expect(store.connectionModePending, isFalse);
    expect(store.canChangeConnectionMode, isTrue);
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    store.dispose();
  });

  test('a pristine legacy document is migrated, not stranded', () async {
    await writeDocument(directory, document()..remove('connectionPolicy'));
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    // Versioned ownership has not begun: no receipt is required, so automatic
    // installs are not blocked by the missing-receipt rule.
    expect(store.policyReceiptRequired, isFalse);
    expect(store.connectionPolicyError, isNull);
    expect(store.canChangeConnectionMode, isTrue);
    await store.save();
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'automatic',
      'roundMillis': 30000,
    });
    store.dispose();
    // Reloading the migrated document reconciles it with the native envelope.
    final reloaded = await loaded(Channel(policyCapable: true));
    expect(reloaded.policyReceiptRequired, isTrue);
    expect(reloaded.committedReceipt, isNotNull);
    expect(reloaded.canChangeConnectionMode, isTrue);
    reloaded.dispose();
  });

  test('native unknown blocks edits and only an exact reconcile clears it',
      () async {
    await writeDocument(directory, document());
    final failing = Channel(policyCapable: true, failCommit: true);
    final store = await loaded(failing);
    expect(store.connectionPolicyError, 'reconcileRequired');
    expect(store.canChangeConnectionMode, isFalse);
    expect(store.connectionModePending, isTrue);
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.automatic),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_UNKNOWN'),
      ),
    );
    // Recovery needs a working native ACK, not merely "no error".
    await expectLater(
      store.retryPolicyReconciliation(),
      throwsA(isA<Object>()),
    );
    expect(store.canChangeConnectionMode, isFalse);
    messenger.setMockMethodCallHandler(native, Channel(policyCapable: true).handle);
    await store.retryPolicyReconciliation();
    expect(store.canChangeConnectionMode, isTrue);
    expect(store.connectionPolicyError, isNull);
    expect(store.committedReceipt, isNotNull);
    store.dispose();
  });

  test('corrupt durable policy is preserved until an explicit repair', () async {
    await writeDocument(directory, {
      ...document(),
      'connectionPolicy': {'mode': 'future', 'roundMillis': 30000},
    });
    final store = await loaded(Channel());
    expect(store.policyInvalid, isTrue);
    expect(store.connectionPolicyError, 'corrupt');
    expect(store.canChangeConnectionMode, isFalse);
    await store.save();
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'future',
      'roundMillis': 30000,
    });
    await store.repairConnectionPolicy(ConnectionPolicy.selectedOnly);
    expect(store.policyInvalid, isFalse);
    expect(store.canChangeConnectionMode, isTrue);
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    store.dispose();
  });

  test('product writer ownership blocks a second controller and defers dispose',
      () async {
    final owner = await ProductStoreWriterOwner.acquire(directory);
    await expectLater(
      ProductStoreWriterOwner.acquire(directory),
      throwsA(isA<StateError>()),
    );
    await writeDocument(directory, document());
    final channel = Channel();
    final store = (await loaded(channel))..attachProductWriter(owner);
    expect(store.storeIdentity, owner.storeIdentity);
    await store.setLanguage('en');
    expect((await readDocument(directory))['language'], isNotNull);
    store.dispose();
    await owner.closeWhenSettled();
    // Only after every admitted IO settled may a successor claim the lock.
    final successor = await ProductStoreWriterOwner.acquire(directory);
    await successor.closeWhenSettled();
  });

  test('the elevated helper is bound to the product store identity', () async {
    final owner = await ProductStoreWriterOwner.acquire(directory);
    addTearDown(() async {
      await owner.closeWhenSettled();
      DesktopEngine.storeIdentity = null;
    });
    DesktopEngine.storeIdentity = null;
    expect(
      () => DesktopEngine.helperArguments(port: '1', tokenFile: 't'),
      throwsA(isA<FormatException>()),
    );
    DesktopEngine.storeIdentity = 'not-a-hash';
    expect(
      () => DesktopEngine.helperArguments(port: '1', tokenFile: 't'),
      throwsA(isA<FormatException>()),
    );
    DesktopEngine.storeIdentity = owner.storeIdentity;
    expect(
      () => DesktopEngine.helperArguments(port: '1', tokenFile: 't'),
      throwsA(isA<FormatException>()),
    );
    DesktopEngine.clientOnly = false;
    addTearDown(() => DesktopEngine.clientOnly = null);
    final arguments = DesktopEngine.helperArguments(port: '1', tokenFile: 't');
    expect(arguments, contains('--store-identity=${owner.storeIdentity}'));
    expect(arguments, contains('--client-only=false'));
    await writeDocument(directory, document());
    final store = (await loaded(Channel()))..attachProductWriter(owner);
    expect(DesktopEngine.storeIdentity, owner.storeIdentity);
    store.dispose();
  });

  test('a restart reconciles inside the connection round before activation',
      () async {
    await writeDocument(directory, document(mode: 'selectedOnly'));
    final channel = Channel(policyCapable: true);
    final store = (await loaded(channel))..androidActivationForTesting = true;
    expect(store.committedReceipt, isNotNull);
    // Simulate a helper restart: the live receipt is gone, the durable one stays.
    store.invalidateCommittedPolicy();
    expect(store.committedReceipt, isNull);
    channel.calls.clear();
    await store.connect();
    expect(channel.installs, hasLength(1));
    expect(store.committedReceipt, isNotNull);
    expect(
      (channel.installs.single['policyReceipt'] as Map)['storeIdentity'],
      store.storeIdentity,
    );
    store.dispose();
  });

  test('automatic failover dials the next candidate and publishes the winner',
      () async {
    await writeDocument(directory, document());
    final base = Channel(policyCapable: true);
    var dials = 0;
    final attempts = <Map<String, dynamic>>[];
    messenger.setMockMethodCallHandler(native, (call) async {
      if (call.method == 'connect') {
        dials++;
        attempts.add(Map<String, dynamic>.from(call.arguments as Map));
        if (dials == 1) throw PlatformException(code: 'FIXTURE_ATTEMPT');
        return {'policyMode': 'automatic'};
      }
      if (call.method == 'status') {
        final up = dials >= 2;
        return {
          'active': up,
          'phase': up ? 'connected' : 'disconnected',
          'handshake': up ? DateTime.now().millisecondsSinceEpoch : 0,
          'tx': up ? 32 : 0,
          'rx': up ? 32 : 0,
          'id': up ? 'p2' : null,
          'protocol': 'xray',
        };
      }
      return base.handle(call);
    });
    final store = AppStore(nativeTunnelOverride: true)
      ..directory = directory
      ..androidActivationForTesting = true;
    await store.load();
    expect(store.committedReceipt, isNotNull);
    base.installs.clear();
    attempts.clear();
    await store.connect();
    // The failed candidate is not the end of the round: the next one is dialed
    // with the SAME committed receipt, and the winner becomes the durable
    // selection (the publication after a settled activation is what used to be
    // refused natively with POLICY_BUSY).
    expect(attempts.map((a) => a['id']), ['p1', 'p2']);
    expect(attempts[1]['policyReceipt'], attempts[0]['policyReceipt']);
    expect(store.status.active, isTrue);
    expect(store.selectedId, 'p2');
    expect((await readDocument(directory))['selected'], 'p2');
    expect(store.committedReceipt, isNotNull);
    expect(store.error, isNull);
    store.dispose();
  });

  test('a persisted pending lane is settled by aborting the SAME dead transaction',
      () async {
    await writeDocument(directory, document());
    const dead = '11111111111111111111111111111111';
    final channel = Channel(policyCapable: true)
      ..phase = 'pending'
      ..pendingTransaction = dead;
    final store = await loaded(channel);
    final aborts =
        channel.calls.where((call) => call.method == 'policyAbort').toList();
    expect(aborts, hasLength(1));
    expect(aborts.single.arguments, {
      'version': 1,
      'instanceNonce': _instance,
      'transactionId': dead,
    });
    // Only after the blocked settlement does a fresh reconcile run.
    expect(
      channel.calls.where((call) => call.method == 'policyReconcile'),
      hasLength(1),
    );
    expect(store.committedReceipt, isNotNull);
    expect(store.connectionModeConfirmed, isTrue);
    store.dispose();
  });

  test('desktop publication sends the exact readback validation bundle', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    // The load reconcile validates its own snapshot first; the publication's
    // validation is the last one and must describe the committed snapshot.
    final validate = channel.calls.lastWhere(
      (call) => call.method == 'policyValidate',
    );
    final arguments = validate.arguments as Map;
    expect(arguments.keys.toSet(), {
      'version',
      'storeIdentity',
      'controllerNonce',
      'instanceNonce',
      'transactionId',
      'expectedGeneration',
      'planGeneration',
      'plan',
      'validation',
    });
    final validation = arguments['validation'] as Map;
    final payload = utf8.decode(
      base64Decode(validation['documentBytesBase64'] as String),
    );
    expect(validation['schema'], 1);
    expect(
      validation['documentDigest'],
      crypto.sha256.convert(utf8.encode(payload)).toString(),
    );
    // The validated bytes are the exact frozen snapshot this publication
    // commits: same transaction, generation, policy and plan.
    final committed = store.committedReceipt!;
    expect(payload, contains(committed.transactionId));
    expect(payload, contains(committed.planGeneration));
    expect(payload, contains('"connectionPlanReceipt"'));
    expect(payload, contains('"connectionPolicy":{"mode":"selectedOnly"'));
    expect(store.connectionPolicy, ConnectionPolicy.selectedOnly);
    expect(store.connectionModeConfirmed, isTrue);
    final configs = (validation['configs'] as List).cast<Map>();
    expect(configs.map((entry) => entry['id']), ['p1']);
    expect(
      utf8.decode(base64Decode(configs.single['bytesBase64'] as String)),
      _config,
    );
    final commit = channel.calls.firstWhere(
      (call) => call.method == 'policyCommit',
    );
    expect((commit.arguments as Map).containsKey('validation'), isFalse);
    store.dispose();
  });

  test('an unavailable product writer refuses writes without touching disk',
      () async {
    await writeDocument(directory, document());
    final store = await loaded(Channel());
    final before = await readDocument(directory);
    store.markProductWriterUnavailable(StateError('second controller'));
    await expectLater(
      store.save(),
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.beforeRename,
        ),
      ),
    );
    expect(await readDocument(directory), before);
    expect(store.connectionPolicyError, 'persistence');
    expect(store.canChangeConnectionMode, isFalse);
    store.dispose();
  });

  test('oversized document is rejected before begin or rename', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    final before = await readDocument(directory);
    for (var i = 0; i < 12000; i++) {
      store.profiles.add(
        Profile(
          id: 'huge$i',
          name: 'n$i',
          protocol: 'awg',
          endpoint: '198.51.100.$i:51820',
        ),
      );
    }
    channel.calls.clear();
    await expectLater(
      store.setConnectionPolicy(ConnectionPolicy.selectedOnly),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_OVERSIZE'),
      ),
    );
    // No native READY fencing and no rename: old data + native authority stay.
    expect(
      channel.calls.where((call) => call.method == 'policyBegin'),
      isEmpty,
    );
    expect(
      channel.calls.where((call) => call.method == 'policyValidate'),
      isEmpty,
    );
    expect(await readDocument(directory), before);
    expect(store.connectionPolicy, ConnectionPolicy.automatic);
    expect(store.connectionPolicyFailureCode, 'POLICY_OVERSIZE');
    expect(store.connectionPolicyFailureMessage, isNotNull);
    // Removing the oversized input lets the same edit succeed and clears the
    // explicit failure reason.
    store.profiles.removeRange(2, store.profiles.length);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    expect((await readDocument(directory))['connectionPolicy'], {
      'mode': 'selectedOnly',
      'roundMillis': 30000,
    });
    expect(store.connectionPolicyFailureCode, isNull);
    store.dispose();
  });
  test('ordinary save queued at dispose cannot rename', () async {
    await writeDocument(directory, document());
    final entered = Completer<void>();
    final gate = Completer<void>();
    final store = GatedStore(entered, gate)..directory = directory;
    messenger.setMockMethodCallHandler(native, Channel().handle);
    await store.load();
    final first = store.save();
    await entered.future;
    store.checkSite = 'https://probe.invalid/late';
    final second = store.save();
    store.dispose();
    gate.complete();
    // The first write already renamed; its revoked ticket may not claim success.
    await expectLater(
      first,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.renamedNativeUnconfirmed,
        ),
      ),
    );
    await expectLater(
      second,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.beforeRename,
        ),
      ),
    );
    expect(
      (await readDocument(directory))['checkSite'],
      'https://youtube.com',
      reason: 'the revoked late save must not replace the first payload',
    );
  });

  test('plan-sensitive settings publish a new receipt and confirmation', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    final oldTransaction = store.committedReceipt!.transactionId;
    await store.saveConnectionSettings(
      'https://probe.invalid/new',
      'awg',
      timeoutSeconds: 20,
    );
    expect(store.committedReceipt!.transactionId, isNot(oldTransaction));
    expect(store.connectionModeConfirmed, isTrue);
    expect(store.checkSite, 'https://probe.invalid/new');
    final saved = await readDocument(directory);
    expect(saved['checkSite'], 'https://probe.invalid/new');
    expect(
      saved['connectionPlanReceipt']['transactionId'],
      store.committedReceipt!.transactionId,
    );
    store.dispose();
  });

  test('dispose does not release the product writer before native commit settles',
      () async {
    await writeDocument(directory, document());
    final owner = await ProductStoreWriterOwner.acquire(directory);
    addTearDown(() async {
      await owner.closeWhenSettled();
    });
    final channel = Channel(policyCapable: true);
    final store = (await loaded(channel))..attachProductWriter(owner);
    final gate = Completer<void>();
    channel.commitGate = gate;
    final change = store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    await channel.commitEntered.future;
    store.dispose();
    await expectLater(
      ProductStoreWriterOwner.acquire(directory),
      throwsA(isA<StateError>()),
    );
    gate.complete();
    await change.catchError((Object _) {});
    await owner.closeWhenSettled();
    final successor = await ProductStoreWriterOwner.acquire(directory);
    await successor.closeWhenSettled();
  });

  test('remove keeps the durable outcome after a post-rename failure', () async {
    final store = _PostRenameFailStore()..directory = directory;
    messenger.setMockMethodCallHandler(native, Channel().handle);
    await writeDocument(directory, {
      ...document(),
      'profiles': [
        {
          'id': 'solo',
          'name': 'solo',
          'protocol': 'awg',
          'endpoint': '203.0.113.9:51820',
        },
      ],
      'selected': 'solo',
      'users': <Object?>[],
    });
    await store.load();
    await expectLater(
      store.remove('solo'),
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.renamedNativeUnconfirmed,
        ),
      ),
    );
    expect(store.profiles, isEmpty, reason: 'no old whole-document rollback');
    expect(store.selectedId, isNull);
    expect((await readDocument(directory))['profiles'], isEmpty);
    expect(store.policyUnconfirmed, isTrue);
    store.dispose();
  });
  test('observed BLOCKED clears confirmation synchronously', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true, failCommit: true);
    final store = await loaded(channel);
    // Load reconciliation failed, so no live confirmation exists.
    expect(store.connectionModeConfirmed, isFalse);
    expect(store.committedReceipt, isNull);
    store.dispose();
  });

  test('a recovery cannot overwrite a newer durable publication', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    expect(store.connectionModeConfirmed, isTrue);
    final gate = Completer<void>();
    channel.stateGate = gate;
    final retry = store.retryPolicyReconciliation();
    await channel.stateEntered.future;
    // A newer publication commits a different durable snapshot meanwhile.
    final newerReceipt = {
      'schema': 1,
      'transactionId': '7' * 32,
      'planGeneration': '8' * 32,
      'plan': <String, dynamic>{},
    };
    final newer = {
      ...document(),
      'connectionPolicy': {'mode': 'automatic', 'roundMillis': 30000},
      'connectionPlanReceipt': newerReceipt,
    };
    await writeDocument(directory, newer);
    final newerBytes = await File(
      '${directory.path}/profiles.json',
    ).readAsString();
    gate.complete();
    await expectLater(
      retry,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.cause,
          'cause',
          isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_STALE'),
        ),
      ),
    );
    // The older recovery snapshot must not have replaced the newer bytes.
    expect(
      await File('${directory.path}/profiles.json').readAsString(),
      newerBytes,
    );
    store.dispose();
  });
  test('post-rename add failure keeps the durable profile', () async {
    await writeDocument(directory, document());
    final store = _PostRenameFailStore()..directory = directory;
    messenger.setMockMethodCallHandler(native, Channel().handle);
    await store.load();
    const raw = '[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n'
        'Address = 10.77.0.9/32\nDNS = 1.1.1.1\n[Peer]\n'
        'PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n'
        'Endpoint = 203.0.113.44:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n';
    store.endpointCountries['203.0.113.44:51820'] = 'RU';
    await expectLater(
      store.addWireGuard('late', raw),
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.renamedNativeUnconfirmed,
        ),
      ),
    );
    expect(store.profiles.map((p) => p.name), contains('late'));
    final saved = await readDocument(directory);
    expect(
      (saved['profiles'] as List).map((p) => (p as Map)['name']),
      contains('late'),
    );
    store.dispose();
  });

  test('an externally changed durable receipt aborts before the rename', () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    final owner = await ProductStoreWriterOwner.acquire(directory);
    addTearDown(() async {
      await owner.closeWhenSettled();
    });
    final writer = _GateWriter(owner);
    store.attachProductWriter(writer);
    store.allowScreenshots = true; // plan-insensitive ordinary write
    final pending = store.save();
    await writer.entered.future;
    final external = {
      ...document(),
      'connectionPlanReceipt': {
        'schema': 1,
        'transactionId': '9' * 32,
        'planGeneration': 'a' * 32,
        'plan': <String, dynamic>{},
      },
    };
    await writeDocument(directory, external);
    final externalBytes = await File(
      '${directory.path}/profiles.json',
    ).readAsString();
    writer.gate.complete();
    await expectLater(
      pending,
      throwsA(
        isA<PublicationFailure>().having(
          (e) => e.phase,
          'phase',
          PublicationPhase.beforeRename,
        ),
      ),
    );
    expect(
      await File('${directory.path}/profiles.json').readAsString(),
      externalBytes,
    );
    store.dispose();
  });
  test('confirmation is false from publication admission through exact READY',
      () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    expect(store.connectionModeConfirmed, isTrue);
    channel.beginGate = Completer<void>();
    channel.commitGate = Completer<void>();
    final change = store.setConnectionPolicy(ConnectionPolicy.automatic);
    // Synchronous admission: old confirmation is already gone.
    expect(store.connectionModeConfirmed, isFalse);
    await channel.beginEntered.future;
    expect(store.connectionModeConfirmed, isFalse);
    channel.beginGate!.complete();
    await channel.commitEntered.future;
    expect(store.connectionModeConfirmed, isFalse);
    channel.commitGate!.complete();
    await change;
    expect(store.connectionModeConfirmed, isTrue);
    store.dispose();
  });

  test('dispose during a held commit settles without an unguarded notify',
      () async {
    await writeDocument(directory, document());
    final channel = Channel(policyCapable: true);
    final store = await loaded(channel);
    await store.setConnectionPolicy(ConnectionPolicy.selectedOnly);
    channel.commitGate = Completer<void>();
    final change = store.setConnectionPolicy(ConnectionPolicy.automatic);
    await channel.commitEntered.future;
    store.dispose();
    channel.commitGate!.complete();
    await change.catchError((Object _) {});
    expect(store.connectionModeConfirmed, isFalse);
  });

  test('android READY reconcile binds the committed generation', () {
    // Android has no desktop CAS field. Its journal still requires the exact
    // READY generation, so a null expectedGeneration would wedge every restart.
    const instance = 'cccccccccccccccccccccccccccccccc';
    final state = PolicyNativeState.parse({
      'version': 1,
      'instanceNonce': instance,
      'state': 'ready',
      'phase': 'ready',
      'resourceState': 'clean',
      'planGeneration': 'd' * 32,
    }, instance: instance);
    expect(policyReconcileGeneration(state, desktop: false), 'd' * 32);
    expect(policyReconcileGeneration(state, desktop: true), isNull);
  });}
