import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' show PrivateKey;
import 'package:xio/issuance_canonical.dart';
import 'package:xio/issuance_capsule.dart';
import 'package:xio/issuance_journal.dart';
import 'package:xio/issuance_material_scope.dart';
import 'package:xio/issuance_vault.dart';

final Uint8List testPrivateKey =
    Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
final Uint8List testPublicKey =
    Uint8List.fromList(PrivateKey(testPrivateKey).publicKey);

final String testStoreIdentity = 'a' * 64;
final String testUid = 'b' * 32;

Map<String, String> validTestMaterial({bool extra = false}) => {
  'capsuleRecipientPrivateKey': base64Encode(testPrivateKey),
  if (extra) 'wireguardPrivate': base64Encode(List<int>.filled(32, 1)),
  if (extra) 'wireguardPublic': base64Encode(List<int>.filled(32, 2)),
  if (extra) 'deviceSecret': base64Encode(List<int>.filled(32, 3)),
  if (extra) 'entryToken': base64Encode(List<int>.filled(32, 4)),
  if (extra) 'xrayUuid': '11111111-1111-4111-8111-111111111111',
  if (extra) 'shadowsocksKey': base64Encode(List<int>.filled(32, 5)),
};

Map<String, Object?> testRequest(List<String> protocols) => {
  'protocols': protocols,
};

final class FakeBinding implements ExpectedDeliveryBinding {
  FakeBinding({this.fail = false});
  bool fail;
  String deployment = 'deploy-test';
  String? digestOverride;
  int calls = 0;
  List<String>? lastProtocols;

  @override
  Future<ExpectedBinding> resolve({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required String requestDigest,
    required List<String> protocols,
  }) async {
    calls++;
    lastProtocols = List<String>.of(protocols);
    if (fail) throw StateError('binding failed');
    final ids = {for (final protocol in protocols) protocol: '$protocol-1'};
    return ExpectedBinding(
      deployment: deployment,
      profileSetDigest:
          digestOverride ?? issuanceProfileSetDigest(protocols, ids),
    );
  }
}

final class FakeAuthority implements MaterialAuthority {
  int acquired = 0;
  int closed = 0;
  bool cancelled = false;
  bool failAcquire = false;
  bool failClose = false;
  void Function()? onAcquire;
  bool currentValid = true;
  bool throwCheck = false;
  int checkCalls = 0;

  @override
  Future<void> acquire({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required MaterialPurpose purpose,
    required int revision,
  }) async {
    acquired++;
    if (failAcquire) throw StateError('authority rejected');
    onAcquire?.call();
  }

  @override
  bool get cancelRequested => cancelled;

  @override
  bool checkCurrent({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required MaterialPurpose purpose,
    required int revision,
  }) {
    checkCalls++;
    if (throwCheck) throw StateError('authority epoch changed');
    return currentValid;
  }

  @override
  Future<void> close() async {
    closed++;
    if (failClose) throw StateError('authority close failed');
  }
}

final class FakeVaultBackend implements IssuanceVaultBackend {
  final Map<String, Uint8List> sealed = {};
  bool isOpen = false;
  void Function()? onRead;

  @override
  @override
  Future<void> open() async => isOpen = true;

  @override
  Future<Uint8List?> readSealed(String id) async {
    onRead?.call();
    return sealed[id];
  }

  @override
  Future<void> writeSealed(String id, Uint8List bytes) async =>
      sealed[id] = Uint8List.fromList(bytes);

  @override
  Future<Uint8List> sealSealed(
    IssuanceVaultContext context,
    Uint8List plaintext,
  ) async => Uint8List.fromList(plaintext);

  @override
  Future<Uint8List> openSealed(
    IssuanceVaultContext context,
    Uint8List sealed,
  ) async => Uint8List.fromList(sealed);

  @override
  @override
  Future<void> close() async => isOpen = false;
}

final class FakeLease implements IssuanceJournalLease {
  int pending = 0;
  bool closing = false;
  bool _held = true;
  Completer<void>? _drained;

  @override
  bool get held => _held;

  @override
  bool get ownedByCurrentIsolate => true;

  @override
  Future<T> admit<T>(Future<T> Function() io) async {
    if (closing || !_held) throw StateError('lease closed');
    pending++;
    try {
      return await io();
    } finally {
      pending--;
      if (closing && pending == 0) _drained?.complete();
    }
  }

  @override
  Future<void> closeWhenSettled() async {
    closing = true;
    if (pending > 0) {
      _drained = Completer<void>();
      await _drained!.future;
    }
    _held = false;
  }
}

Future<(IssuanceJournalStore, FakeVaultBackend, FakeLease)> boundTestStore() async {
  final backend = FakeVaultBackend();
  final lease = FakeLease();
  final vault = IssuanceJournalVault(
    storeIdentity: testStoreIdentity,
    backend: backend,
    lease: lease,
  );
  await vault.open();
  return (IssuanceJournalStore.bound(vault), backend, lease);
}

CapsuleContext testContext({
  required String operation,
  required String deployment,
  required String profileSetDigest,
  String server = 'srv-test',
  String actor = 'owner',
  String? requestDigest,
}) => CapsuleContext(
  operation: operation,
  uid: testUid,
  server: server,
  deployment: deployment,
  actor: actor,
  requestDigest: requestDigest ?? 'c' * 64,
  profileSetDigest: profileSetDigest,
);

String canonicalTestPartial({
  required String operationId,
  required String deployment,
  required Set<String> backends,
  required String capsuleId,
  required String ciphertextDigest,
  required String envelopeSha256,
  required int envelopeSize,
  String phase = 'remotePending',
  bool csrPresent = false,
  String csrSha = '',
  String csrSpki = '',
  String csrCn = '',
  Map<String, String> backendStates = const {},
  bool materialRequested = false,
  String purpose = 'none',
  List<String> kinds = const [],
}) {
  final map = <String, Object?>{
    'schema': 1,
    'operationId': operationId,
    'uid': testUid,
    'deploymentId': deployment,
    'phase': phase,
    'replay': false,
    'capsuleRef': {
      'capsuleId': capsuleId,
      'ciphertextDigest': ciphertextDigest,
      'envelopeSha256': envelopeSha256,
      'size': envelopeSize,
    },
    'csr': {
      'present': csrPresent,
      'sha256': csrSha,
      'spkiSha256': csrSpki,
      'cn': csrCn,
    },
    'backends': {
      for (final backend in backends)
        backend: backendStates[backend] ?? 'pending',
    },
    'materialRequest': {
      'requested': materialRequested,
      'purpose': purpose,
      'kinds': kinds,
    },
    'fence': 'none',
    'updatedAt': 1,
  };
  return canonicalJsonV1(map);
}
