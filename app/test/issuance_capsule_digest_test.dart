import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pinenacl/x25519.dart' show PrivateKey;
import 'package:xio/issuance_capsule.dart';

void main() {
  final private = Uint8List.fromList(List<int>.generate(32, (i) => i + 7));
  final public = Uint8List.fromList(PrivateKey(private).publicKey);
  final context = CapsuleContext(
    operation: 'a' * 32,
    uid: 'b' * 32,
    server: 'srv',
    deployment: 'deploy',
    actor: 'owner',
    requestDigest: 'c' * 64,
    profileSetDigest: 'd' * 64,
  );
  final artifacts = {
    'ikev2.password': 'password',
    'cloak.uid': base64Encode(List<int>.filled(16, 4)),
  };

  test('plaintext digest is over actual authenticated plaintext', () {
    final envelope = CapsuleCodec.seal(
      context: context,
      artifacts: artifacts,
      recipientPublicKey: public,
    );
    final opened = CapsuleCodec.open(
      envelope: envelope,
      recipientPrivateKey: private,
      expectedRecipientPublicKey: public,
      expected: context,
    );
    expect(opened, isA<CapsuleOpened>());
    final value = opened as CapsuleOpened;
    expect(value.plaintextSha256, hasLength(64));
    expect(value.artifacts, artifacts);
  });

  test('wrong context rejects before exposing a digest', () {
    final envelope = CapsuleCodec.seal(
      context: context,
      artifacts: artifacts,
      recipientPublicKey: public,
    );
    final wrong = CapsuleContext(
      operation: 'a' * 32,
      uid: 'b' * 32,
      server: 'srv',
      deployment: 'other',
      actor: 'owner',
      requestDigest: 'c' * 64,
      profileSetDigest: 'd' * 64,
    );
    final opened = CapsuleCodec.open(
      envelope: envelope,
      recipientPrivateKey: private,
      expectedRecipientPublicKey: public,
      expected: wrong,
    );
    expect(opened, isA<CapsuleRejected>());
  });

  test('short ciphertext MAC guard is retained', () {
    final envelope = CapsuleCodec.seal(
      context: context,
      artifacts: artifacts,
      recipientPublicKey: public,
    );
    final short = CapsuleEnvelope(
      v: envelope.v,
      alg: envelope.alg,
      capsuleId: envelope.capsuleId,
      recipientPublicKey: public,
      ciphertext: Uint8List(capsuleAnonymousOverhead),
    );
    final opened = CapsuleCodec.open(
      envelope: short,
      recipientPrivateKey: private,
      expectedRecipientPublicKey: public,
      expected: context,
    );
    expect(opened, isA<CapsuleRejected>());
    expect((opened as CapsuleRejected).reason, CapsuleRejectReason.short);
  });
}
