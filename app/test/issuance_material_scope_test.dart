import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_canonical.dart';
import 'package:xio/issuance_capsule.dart';
import 'package:xio/issuance_journal.dart';
import 'package:xio/issuance_material_scope.dart';

import 'issuance_a2_test_support.dart';

Future<IssuanceRecord> pinnedRecord(
  IssuanceJournalStore store, {
  required List<String> protocols,
  Map<String, String> artifacts = const {
    'ikev2.password': 'p',
    'cloak.uid': 'AAAAAAAAAAAAAAAAAAAAAA==',
  },
  MaterialAuthority? authority,
}) async {
  final record = await store.prepareV2(
    storeIdentity: testStoreIdentity,
    uid: testUid,
    serverId: 'srv',
    sshFingerprint: 'cc' * 32,
    actor: 'owner',
    request: {'protocols': protocols},
    material: validTestMaterial(extra: true),
    capsuleRecipientPublicKey: testPublicKey,
    binding: FakeBinding(),
  );
  final dispatched = await store.markDispatchIntent(record);
  final context = testContext(
    operation: dispatched.operationId,
    deployment: dispatched.deployment,
    profileSetDigest: dispatched.profileSetDigest,
    requestDigest: dispatched.requestDigest,
    server: dispatched.serverId,
    actor: dispatched.actor,
  );
  final envelope = CapsuleCodec.seal(
    context: context,
    artifacts: artifacts,
    recipientPublicKey: testPublicKey,
  );
  final opened = CapsuleCodec.open(
    envelope: envelope,
    recipientPrivateKey: testPrivateKey,
    expectedRecipientPublicKey: testPublicKey,
    expected: context,
  ) as CapsuleOpened;
  final raw = utf8.encode(jsonEncode(envelope.toJson()));
  final kinds = opened.artifacts.keys.toList()..sort();
  return store.pinFirstCapsule(
    storeIdentity: testStoreIdentity,
    operationId: dispatched.operationId,
    uid: testUid,
    expectedRevision: dispatched.revision,
    expectedIdentityDigest: dispatched.preparedIdentityDigest,
    envelopeBytesB64: base64Encode(raw),
    envelopeSha256: sha256Hex(raw),
    capsuleId: envelope.capsuleId,
    ciphertextDigest: sha256Hex(envelope.ciphertext),
    contextSha256: sha256Hex(utf8.encode(context.canonical)),
    plaintextSha256: opened.plaintextSha256,
    artifactKinds: kinds,
    authority: authority ?? FakeAuthority(),
  );
}

void main() {
  test('scoped remoteResume returns only requested A kinds', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    Map<String, String>? seen;
    var bodyCalls = 0;
    await store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        bodyCalls++;
        seen = artifacts;
        ticket.settled();
      },
    );
    expect(bodyCalls, 1);
    expect(seen!.keys, {'rivetDeviceSecret'});
    expect(seen!.containsKey('capsuleRecipientPrivateKey'), isFalse);
  });

  test('certificate-dependent local commit is denied before callback', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['openvpn']);
    final completed = await store.remoteResult(
      record,
      receipt: {'status': 'ok'},
      capsuleDigest: record.capsuleCiphertextDigest,
    );
    var called = false;
    await expectLater(
      store.withMaterial(
        storeIdentity: testStoreIdentity,
        operationId: record.operationId,
        uid: testUid,
        expectedRevision: completed.revision,
        expectedIdentityDigest: completed.postPinIdentityDigest,
        purpose: MaterialPurpose.localCommit,
        requestedKinds: {'wireguardPrivate'},
        authority: FakeAuthority(),
        body: (artifacts, ticket) async {
          called = true;
          ticket.settled();
        },
      ),
      throwsA(anything),
    );
    expect(called, isFalse);
  });

  test('rejected authority unwinds the shared guard for a later retry', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final bad = FakeAuthority()..failAcquire = true;
    await expectLater(
      store.withMaterial(
        storeIdentity: testStoreIdentity,
        operationId: record.operationId,
        uid: testUid,
        expectedRevision: record.revision,
        expectedIdentityDigest: record.postPinIdentityDigest,
        purpose: MaterialPurpose.remoteResume,
        requestedKinds: {'rivetDeviceSecret'},
        authority: bad,
        body: (artifacts, ticket) async => ticket.settled(),
      ),
      throwsA(anything),
    );
    var called = false;
    await store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        called = true;
        ticket.settled();
      },
    );
    expect(called, isTrue);
  });

  test('a legacy/unbound store cannot acquire scoped material authority', () async {
    final store = IssuanceJournalStore(
      read: (id) async => null,
      write: (id, data) async {},
    );
    await expectLater(
      store.withMaterial(
        storeIdentity: testStoreIdentity,
        operationId: 'a' * 32,
        uid: testUid,
        expectedRevision: 0,
        expectedIdentityDigest: 'b' * 64,
        purpose: MaterialPurpose.remoteResume,
        requestedKinds: {'rivetDeviceSecret'},
        authority: FakeAuthority(),
        body: (artifacts, ticket) async => ticket.settled(),
      ),
      throwsA(anything),
    );
  });

  test('active material blocks queued same-store legacy mutation', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final entered = Completer<void>();
    final gate = Completer<void>();
    final run = store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        entered.complete();
        await gate.future;
        ticket.settled();
      },
    );
    await entered.future;
    await expectLater(
      store.markCommitted(record),
      throwsA(isA<IssuanceJournalBusy>()),
    );
    gate.complete();
    await run;
  });
  test('settled close error is finite and clears the shared guard', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final bad = FakeAuthority()..failClose = true;
    final error = await store
        .withMaterial(
          storeIdentity: testStoreIdentity,
          operationId: record.operationId,
          uid: testUid,
          expectedRevision: record.revision,
          expectedIdentityDigest: record.postPinIdentityDigest,
          purpose: MaterialPurpose.remoteResume,
          requestedKinds: {'rivetDeviceSecret'},
          authority: bad,
          body: (artifacts, ticket) async => ticket.settled(),
        )
        .then<Object?>((_) => null)
        .catchError((Object e) => e);
    expect(error, isNotNull);
    expect(bad.closed, 1);
    var called = false;
    await store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        called = true;
        ticket.settled();
      },
    );
    expect(called, isTrue);
  });

  test('acquire failure plus settled close error still unwinds finitely', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final bad = FakeAuthority()
      ..failAcquire = true
      ..failClose = true;
    final error = await store
        .withMaterial(
          storeIdentity: testStoreIdentity,
          operationId: record.operationId,
          uid: testUid,
          expectedRevision: record.revision,
          expectedIdentityDigest: record.postPinIdentityDigest,
          purpose: MaterialPurpose.remoteResume,
          requestedKinds: {'rivetDeviceSecret'},
          authority: bad,
          body: (artifacts, ticket) async => ticket.settled(),
        )
        .then<Object?>((_) => null)
        .catchError((Object e) => e);
    expect(error, isNotNull);
    var called = false;
    await store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        called = true;
        ticket.settled();
      },
    );
    expect(called, isTrue);
  });
  test('partial acquisition failure with settled close error unwinds', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final size = base64Decode(record.capsuleEnvelopeB64).length;
    final partial = canonicalTestPartial(
      operationId: record.operationId,
      deployment: record.deployment,
      backends: {'awg', 'rivet'},
      capsuleId: record.capsuleId,
      ciphertextDigest: record.capsuleCiphertextDigest,
      envelopeSha256: record.capsuleEnvelopeSha256,
      envelopeSize: size,
      phase: record.phase.name,
    );
    final bad = FakeAuthority()
      ..failAcquire = true
      ..failClose = true;
    final error = await store
        .recordPartialReceipt(
          storeIdentity: testStoreIdentity,
          operationId: record.operationId,
          uid: testUid,
          expectedRevision: record.revision,
          expectedIdentityDigest: record.postPinIdentityDigest,
          partialReceiptJson: partial,
          authority: bad,
        )
        .then<Object?>((_) => null)
        .catchError((Object e) => e);
    expect(error, isNotNull);
    final updated = await store.recordPartialReceipt(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      partialReceiptJson: partial,
      authority: FakeAuthority(),
    );
    expect(updated.partialReceiptJson, partial);
  });
  test('false final current check denies handoff and unwinds', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final bad = FakeAuthority()..currentValid = false;
    var called = false;
    final error = await store
        .withMaterial(
          storeIdentity: testStoreIdentity,
          operationId: record.operationId,
          uid: testUid,
          expectedRevision: record.revision,
          expectedIdentityDigest: record.postPinIdentityDigest,
          purpose: MaterialPurpose.remoteResume,
          requestedKinds: {'rivetDeviceSecret'},
          authority: bad,
          body: (artifacts, ticket) async {
            called = true;
            ticket.settled();
          },
        )
        .then<Object?>((_) => null)
        .catchError((Object e) => e);
    expect(error, isNotNull);
    expect(called, isFalse);
    expect(bad.checkCalls, 1);
    var retried = false;
    await store.withMaterial(
      storeIdentity: testStoreIdentity,
      operationId: record.operationId,
      uid: testUid,
      expectedRevision: record.revision,
      expectedIdentityDigest: record.postPinIdentityDigest,
      purpose: MaterialPurpose.remoteResume,
      requestedKinds: {'rivetDeviceSecret'},
      authority: FakeAuthority(),
      body: (artifacts, ticket) async {
        retried = true;
        ticket.settled();
      },
    );
    expect(retried, isTrue);
  });

  test('throwing final current check is a finite denial', () async {
    final (store, _, _) = await boundTestStore();
    final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
    final bad = FakeAuthority()..throwCheck = true;
    var called = false;
    final error = await store
        .withMaterial(
          storeIdentity: testStoreIdentity,
          operationId: record.operationId,
          uid: testUid,
          expectedRevision: record.revision,
          expectedIdentityDigest: record.postPinIdentityDigest,
          purpose: MaterialPurpose.remoteResume,
          requestedKinds: {'rivetDeviceSecret'},
          authority: bad,
          body: (artifacts, ticket) async {
            called = true;
            ticket.settled();
          },
        )
        .then<Object?>((_) => null)
        .catchError((Object e) => e);
    expect(error, isNotNull);
    expect(called, isFalse);
  });
  test('a fresh-view change during the final read denies handoff', () async {
    for (final change in ['revision', 'cancel', 'phase']) {
      final (store, backend, _) = await boundTestStore();
      final record = await pinnedRecord(store, protocols: ['awg', 'rivet-h3']);
      final authority = FakeAuthority();
      authority.onAcquire = () {
        backend.onRead = () {
          final id = IssuanceJournalStore.vaultId(testStoreIdentity);
          final frame = Map<String, Object?>.from(
            jsonDecode(utf8.decode(backend.sealed[id]!)) as Map,
          );
          final data = Map<String, Object?>.from(frame['data'] as Map);
          if (change == 'revision') {
            data['revision'] = '${int.parse(data['revision']! as String) + 1}';
          } else if (change == 'cancel') {
            data['flags'] = 'cancelRequested';
          } else {
            data['phase'] = 'remoteComplete';
            data['revision'] = '${int.parse(data['revision']! as String) + 1}';
          }
          frame['data'] = data;
          backend.sealed[id] = utf8.encode(jsonEncode(frame));
          backend.onRead = null;
        };
      };
      var called = false;
      final error = await store
          .withMaterial(
            storeIdentity: testStoreIdentity,
            operationId: record.operationId,
            uid: testUid,
            expectedRevision: record.revision,
            expectedIdentityDigest: record.postPinIdentityDigest,
            purpose: MaterialPurpose.remoteResume,
            requestedKinds: {'rivetDeviceSecret'},
            authority: authority,
            body: (artifacts, ticket) async {
              called = true;
              ticket.settled();
            },
          )
          .then<Object?>((_) => null)
          .catchError((Object e) => e);
      expect(error, isNotNull, reason: change);
      expect(called, isFalse, reason: change);
    }
  });}
