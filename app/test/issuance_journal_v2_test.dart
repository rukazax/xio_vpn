import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_canonical.dart';
import 'package:xio/issuance_capsule.dart';
import 'package:xio/issuance_journal.dart';

import 'issuance_a2_test_support.dart';

void main() {
  test('prepareV2 binds protocols/deployment before pin and survives reload', () async {
    final (store, backend, _) = await boundTestStore();
    final binding = FakeBinding();
    final request = <String, Object?>{
      'protocols': ['awg', 'rivet-h3'],
    };
    final record = await store.prepareV2(
      storeIdentity: testStoreIdentity,
      uid: testUid,
      serverId: 'srv',
      sshFingerprint: 'cc' * 32,
      actor: 'owner',
      request: request,
      material: validTestMaterial(extra: true),
      capsuleRecipientPublicKey: testPublicKey,
      binding: binding,
    );
    expect(record.deployment, 'deploy-test');
    expect(record.profileSetDigest, isNotEmpty);
    expect(record.preparedIdentityDigest, isNotEmpty);
    expect(binding.lastProtocols, ['awg', 'rivet-h3']);
    final frame = jsonDecode(utf8.decode(
      backend.sealed[IssuanceJournalStore.vaultId(testStoreIdentity)]!,
    )) as Map;
    expect(frame['v'], 1);
    expect(frame['store'], testStoreIdentity);
    expect(frame['id'], IssuanceJournalStore.vaultId(testStoreIdentity));
    expect((frame['data'] as Map)['journalSchema'], '2');
    (request['protocols'] as List).add('xray');
    final loaded = await store.load(testStoreIdentity);
    expect(loaded!.request['protocols'], ['awg', 'rivet-h3']);
    for (final bad in [
      <String>[],
      ['rivet'],
      ['mesh'],
      ['awg', 'awg'],
      ['awg', 'management'],
    ]) {
      await expectLater(
        store.prepareV2(
          storeIdentity: testStoreIdentity,
          uid: testUid,
          serverId: 'srv',
          sshFingerprint: 'cc' * 32,
          actor: 'owner',
          request: {'protocols': bad},
          material: validTestMaterial(extra: true),
          capsuleRecipientPublicKey: testPublicKey,
          binding: FakeBinding(),
        ),
        throwsA(isA<FormatException>()),
      );
    }
  });
  test('pin/partial use exact identity, phase and first-pin atomicity', () async {
    final (store, _, _) = await boundTestStore();
    final record = await store.prepareV2(
      storeIdentity: testStoreIdentity,
      uid: testUid,
      serverId: 'srv',
      sshFingerprint: 'cc' * 32,
      actor: 'owner',
      request: {'protocols': ['awg', 'rivet-h3']},
      material: validTestMaterial(extra: true),
      capsuleRecipientPublicKey: testPublicKey,
      binding: FakeBinding(),
    );
    await expectLater(
      store.pinFirstCapsule(
        storeIdentity: testStoreIdentity,
        operationId: record.operationId,
        uid: testUid,
        expectedRevision: record.revision,
        expectedIdentityDigest: record.preparedIdentityDigest,
        envelopeBytesB64: '',
        envelopeSha256: '',
        capsuleId: '',
        ciphertextDigest: '',
        contextSha256: '',
        plaintextSha256: '',
        artifactKinds: const [],
        authority: FakeAuthority(),
      ),
      throwsA(anything),
    ); // phase is prepared, not pending
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
      artifacts: {
        'ikev2.password': 'p',
        'cloak.uid': base64Encode(List<int>.filled(16, 1)),
      },
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
    final partial = canonicalTestPartial(
      operationId: dispatched.operationId,
      deployment: dispatched.deployment,
      backends: {'awg', 'rivet'},
      capsuleId: envelope.capsuleId,
      ciphertextDigest: sha256Hex(envelope.ciphertext),
      envelopeSha256: sha256Hex(raw),
      envelopeSize: raw.length,
      phase: IssuancePhase.dispatchIntent.name,
    );
    final pinned = await store.pinFirstCapsule(
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
      partialReceiptJson: partial,
      authority: FakeAuthority(),
    );
    expect(pinned.hasPin, isTrue);
    expect(pinned.partialReceiptJson, partial);
    expect(pinned.revision, dispatched.revision + 1);
    // Identical replay at the current revision is a no-op.
    final replay = await store.pinFirstCapsule(
      storeIdentity: testStoreIdentity,
      operationId: pinned.operationId,
      uid: testUid,
      expectedRevision: pinned.revision,
      expectedIdentityDigest: pinned.preparedIdentityDigest,
      envelopeBytesB64: base64Encode(raw),
      envelopeSha256: sha256Hex(raw),
      capsuleId: envelope.capsuleId,
      ciphertextDigest: sha256Hex(envelope.ciphertext),
      contextSha256: sha256Hex(utf8.encode(context.canonical)),
      plaintextSha256: opened.plaintextSha256,
      artifactKinds: kinds,
      partialReceiptJson: partial,
      authority: FakeAuthority(),
    );
    expect(replay.revision, pinned.revision);
    // A different optional partial is a conflict, not silently ignored.
    final other = canonicalTestPartial(
      operationId: pinned.operationId,
      deployment: pinned.deployment,
      backends: {'awg', 'rivet'},
      capsuleId: envelope.capsuleId,
      ciphertextDigest: sha256Hex(envelope.ciphertext),
      envelopeSha256: sha256Hex(raw),
      envelopeSize: raw.length,
      phase: IssuancePhase.dispatchIntent.name,
      backendStates: {'awg': 'appliedVerified'},
    );
    final updated = await store.recordPartialReceipt(
      storeIdentity: testStoreIdentity,
      operationId: pinned.operationId,
      uid: testUid,
      expectedRevision: pinned.revision,
      expectedIdentityDigest: pinned.postPinIdentityDigest,
      partialReceiptJson: other,
      authority: FakeAuthority(),
    );
    expect(updated.partialReceiptJson, other);
  });
}
