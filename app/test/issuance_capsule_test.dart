import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pinenacl/x25519.dart' show PrivateKey, PublicKey, SealedBox;
import 'package:xio/issuance_canonical.dart';
import 'package:xio/issuance_capsule.dart';

const String _scalarA =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const String _scalarB =
    '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';
const String _uid32 = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const String _requestDigest =
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const String _profileSetDigest =
    'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';
const String _capsuleId = '00112233445566778899aabbccddeeff';

// Frozen Go v0.58.0 packet from work/agent-review-capsule-interop-pin058-
// 20261106/fixtures/go_op0001.bin (489 bytes), copied read-only as a constant.
const String _frozenPacketB64 =
    'NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlRMBaROyy/EfhGEEi7GZeE7/n2x/'
    'aS1XkzvaKYHrGRGIRK79UwyvzbozzreCFx5rvBf1vFWs2XyAXuoJ+oFqtxrMqMPaNzVOv4T'
    'nrZgNCvs1/9p8zBgHPkc3IDWcLhTLUMZ0mBnbXYvKTOl4FzJbMEV4J+y2gVA+EmnWdzfD5T'
    'yIDp47SuvGZse5yce7CJsuTy43s/xafzJoFoGwa+1UDwkciXJI75sAHjJZiPyt0vxtyAgzY'
    'NNjJ+2ah0i+CcQ9Mk2kcjyQDTZ2SL3vadOKfMqXlnQbXYfnvThq4t7fHLwUocCsd+zMLj+'
    'yaCataEprYb59GAtlAHUGhWqaWsu8us5GYWbxb9KmY23hA1V2EwI+KGfj8YIsN8jLcF5xxL'
    'tJj/T8RcdOLRQvZ+CkHFrD5FAPkEqYCuonbDRGnTK7O8yCg8Bzw3efcTTsfJG4Q8KnK8ZrH'
    'RoHdRJTwSWvd61bVccG9uzIMVARV0H/Qa+f31CZaBdRSUSp2Occsa972CuvSNTif9R2GOtS'
    'LvskDMivVw2d516Rj+3ClIuw0BNu0DlWjdx/xmL8y6jUs1MarC3ItVU8YPpnl7LGptavHfc'
    'qyhyzAZCQwK2g6UT';

final Uint8List _privateA = decodeCanonicalHex(_scalarA, length: 32);
final Uint8List _privateB = decodeCanonicalHex(_scalarB, length: 32);
final PrivateKey _keyA = PrivateKey(_privateA);
final PrivateKey _keyB = PrivateKey(_privateB);
final Uint8List _publicA = Uint8List.fromList(_keyA.publicKey);
final Uint8List _publicB = Uint8List.fromList(_keyB.publicKey);

final Map<String, String> _artifacts = {
  'cloak.uid': base64Encode(List<int>.generate(16, (i) => 0xc0 + i)),
};

CapsuleContext _context(String operation) => CapsuleContext(
  operation: operation,
  uid: _uid32,
  server: 'srv-test-1',
  deployment: 'dep-test-1',
  actor: 'owner',
  requestDigest: _requestDigest,
  profileSetDigest: _profileSetDigest,
);

CapsuleEnvelope _rawSeal(
  Map<String, Object?> payload, {
  Uint8List? recipient,
  String capsuleId = _capsuleId,
}) {
  final plaintext = Uint8List.fromList(utf8.encode(canonicalJsonV1(payload)));
  final ciphertext = SealedBox(
    PublicKey(Uint8List.fromList(recipient ?? _publicA)),
  ).encrypt(plaintext);
  return CapsuleEnvelope(
    v: capsuleVersion,
    alg: capsuleAlg,
    capsuleId: capsuleId,
    recipientPublicKey: recipient ?? _publicA,
    ciphertext: ciphertext,
  );
}

Map<String, Object?> _payload(
  CapsuleContext context, {
  Map<String, String>? artifacts,
  Map<String, Object?> overrides = const {},
}) => {
  ...context.toJson(),
  'artifacts': artifacts ?? _artifacts,
  ...overrides,
};

CapsuleRejectReason _reason(CapsuleOpen result) {
  expect(result, isA<CapsuleRejected>());
  return (result as CapsuleRejected).reason;
}

void main() {
  test('seal/open round trip binds context and copies bytes', () {
    final context = _context('op-0001');
    final envelope = CapsuleCodec.seal(
      context: context,
      artifacts: _artifacts,
      recipientPublicKey: _publicA,
    );
    expect(envelope.v, capsuleVersion);
    expect(envelope.alg, capsuleAlg);
    expect(envelope.capsuleId.length, 32);
    expect(envelope.ciphertext.length, greaterThan(48));
    expect(envelope.digest, sha256Hex(envelope.ciphertext));
    expect(
      CapsuleEnvelope.parseStrict(envelope.toJson()).digest,
      envelope.digest,
    );

    final opened = CapsuleCodec.open(
      envelope: envelope,
      recipientPrivateKey: _privateA,
      expectedRecipientPublicKey: _publicA,
      expected: context,
    );
    expect(opened, isA<CapsuleOpened>());
    final value = opened as CapsuleOpened;
    expect(value.context.canonical, context.canonical);
    expect(value.artifacts, _artifacts);
    expect(value.artifacts, isNot(same(_artifacts)));

    final artifacts = Map<String, String>.of(_artifacts);
    final second = CapsuleCodec.seal(
      context: context,
      artifacts: artifacts,
      recipientPublicKey: _publicA,
    );
    artifacts['cloak.uid'] = 'tampered-after-seal';
    final secondOpened = CapsuleCodec.open(
      envelope: second,
      recipientPrivateKey: _privateA,
      expectedRecipientPublicKey: _publicA,
      expected: context,
    ) as CapsuleOpened;
    expect(secondOpened.artifacts['cloak.uid'], _artifacts['cloak.uid']);

    final copy = envelope.ciphertext;
    copy[0] ^= 0xff;
    expect(envelope.digest, sha256Hex(envelope.ciphertext));
  });

  test('48-byte ciphertext is rejected before decryption and never opens', () {
    final trap = SealedBox(_keyA).decrypt(Uint8List(48));
    expect(trap, isEmpty);

    final envelope = CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _capsuleId,
      recipientPublicKey: _publicA,
      ciphertext: Uint8List(48),
    );
    expect(
      _reason(
        CapsuleCodec.open(
          envelope: envelope,
          recipientPrivateKey: _privateA,
          expectedRecipientPublicKey: _publicA,
          expected: _context('op-0001'),
        ),
      ),
      CapsuleRejectReason.short,
    );
  });

  test('49-byte garbage throws a raw String upstream and is caught bare', () {
    Object? thrown;
    try {
      SealedBox(_keyA).decrypt(Uint8List(49)..fillRange(0, 49, 0x42));
    } catch (error) {
      thrown = error;
    }
    expect(thrown, isA<String>());

    final envelope = CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _capsuleId,
      recipientPublicKey: _publicA,
      ciphertext: Uint8List(49),
    );
    expect(
      _reason(
        CapsuleCodec.open(
          envelope: envelope,
          recipientPrivateKey: _privateA,
          expectedRecipientPublicKey: _publicA,
          expected: _context('op-0001'),
        ),
      ),
      CapsuleRejectReason.badBox,
    );
  });

  test('tamper, wrong recipient and truncation are rejected', () {
    final context = _context('op-0001');
    final envelope = _rawSeal(_payload(context));
    final valid = envelope.ciphertext;
    for (final index in [0, 32, 40, valid.length - 1]) {
      final tampered = Uint8List.fromList(valid);
      tampered[index] ^= 0x01;
      final candidate = CapsuleEnvelope(
        v: capsuleVersion,
        alg: capsuleAlg,
        capsuleId: _capsuleId,
        recipientPublicKey: _publicA,
        ciphertext: tampered,
      );
      expect(
        _reason(
          CapsuleCodec.open(
            envelope: candidate,
            recipientPrivateKey: _privateA,
            expectedRecipientPublicKey: _publicA,
            expected: context,
          ),
        ),
        CapsuleRejectReason.badBox,
        reason: 'index $index',
      );
    }

    final forB = _rawSeal(_payload(context), recipient: _publicB);
    expect(
      _reason(
        CapsuleCodec.open(
          envelope: forB,
          recipientPrivateKey: _privateA,
          expectedRecipientPublicKey: _publicA,
          expected: context,
        ),
      ),
      CapsuleRejectReason.recipientKey,
    );
    expect(
      _reason(
        CapsuleCodec.open(
          envelope: envelope,
          recipientPrivateKey: _privateB,
          expectedRecipientPublicKey: _publicB,
          expected: context,
        ),
      ),
      CapsuleRejectReason.recipientKey,
    );

    for (final length in [0, 1, 32, 47, 48]) {
      final candidate = CapsuleEnvelope(
        v: capsuleVersion,
        alg: capsuleAlg,
        capsuleId: _capsuleId,
        recipientPublicKey: _publicA,
        ciphertext: valid.sublist(0, length),
      );
      expect(
        _reason(
          CapsuleCodec.open(
            envelope: candidate,
            recipientPrivateKey: _privateA,
            expectedRecipientPublicKey: _publicA,
            expected: context,
          ),
        ),
        CapsuleRejectReason.short,
        reason: 'length $length',
      );
    }
    for (final length in [49, 50, valid.length - 1]) {
      final candidate = CapsuleEnvelope(
        v: capsuleVersion,
        alg: capsuleAlg,
        capsuleId: _capsuleId,
        recipientPublicKey: _publicA,
        ciphertext: valid.sublist(0, length),
      );
      expect(
        _reason(
          CapsuleCodec.open(
            envelope: candidate,
            recipientPrivateKey: _privateA,
            expectedRecipientPublicKey: _publicA,
            expected: context,
          ),
        ),
        CapsuleRejectReason.badBox,
        reason: 'length $length',
      );
    }
  });

  test('empty, non-JSON, missing and unexpected fields are rejected', () {
    final context = _context('op-0001');
    final empty = CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _capsuleId,
      recipientPublicKey: _publicA,
      ciphertext: SealedBox(PublicKey(_publicA)).encrypt(Uint8List(0)),
    );
    expect(
      _reason(
        CapsuleCodec.open(
          envelope: empty,
          recipientPrivateKey: _privateA,
          expectedRecipientPublicKey: _publicA,
          expected: context,
        ),
      ),
      CapsuleRejectReason.short,
    );

    CapsuleEnvelope raw(List<int> bytes) => CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _capsuleId,
      recipientPublicKey: _publicA,
      ciphertext: SealedBox(PublicKey(_publicA)).encrypt(
        Uint8List.fromList(bytes),
      ),
    );
    CapsuleRejectReason reasonFor(CapsuleEnvelope envelope) => _reason(
      CapsuleCodec.open(
        envelope: envelope,
        recipientPrivateKey: _privateA,
        expectedRecipientPublicKey: _publicA,
        expected: context,
      ),
    );

    expect(
      reasonFor(raw(utf8.encode('hello-not-json'))),
      CapsuleRejectReason.notJson,
    );
    final missing = _payload(context)..remove('uid');
    expect(reasonFor(raw(utf8.encode(canonicalJsonV1(missing)))),
        CapsuleRejectReason.missingField);
    final extra = _payload(context, overrides: {'extra': 1});
    expect(reasonFor(raw(utf8.encode(canonicalJsonV1(extra)))),
        CapsuleRejectReason.unexpectedField);
  });

  test('schema, purpose, version and context are bound exactly', () {
    final context = _context('op-0001');
    CapsuleRejectReason reasonFor(Map<String, Object?> payload) => _reason(
      CapsuleCodec.open(
        envelope: _rawSeal(payload),
        recipientPrivateKey: _privateA,
        expectedRecipientPublicKey: _publicA,
        expected: context,
      ),
    );

    expect(
      reasonFor(_payload(context, overrides: {'schema': 2})),
      CapsuleRejectReason.schema,
    );
    expect(
      reasonFor(_payload(context, overrides: {'purpose': 'other/purpose'})),
      CapsuleRejectReason.purpose,
    );
    expect(
      reasonFor(_payload(context, overrides: {'version': 2})),
      CapsuleRejectReason.version,
    );
    expect(
      reasonFor(_payload(_context('op-0002'))),
      CapsuleRejectReason.context,
    );
    final swapped = _payload(context, overrides: {'uid': 'f'.padRight(32, 'f')});
    expect(reasonFor(swapped), CapsuleRejectReason.context);
  });

  test('artifact kinds and sizes are closed', () {
    final context = _context('op-0001');
    CapsuleRejectReason reasonFor(Map<String, String> artifacts) => _reason(
      CapsuleCodec.open(
        envelope: _rawSeal(_payload(context, artifacts: artifacts)),
        recipientPrivateKey: _privateA,
        expectedRecipientPublicKey: _publicA,
        expected: context,
      ),
    );
    expect(
      reasonFor({'evil.kind': 'x'}),
      CapsuleRejectReason.artifactKind,
    );
    expect(
      reasonFor({'cloak.uid': 'a'.padRight(capsuleMaxArtifactBytes + 1, 'a')}),
      CapsuleRejectReason.artifactSize,
    );
    expect(
      () => CapsuleCodec.seal(
        context: context,
        artifacts: {'evil.kind': 'x'},
        recipientPublicKey: _publicA,
      ),
      throwsFormatException,
    );
    expect(
      () => CapsuleCodec.seal(
        context: context,
        artifacts: {'cloak.uid': 'a'.padRight(capsuleMaxArtifactBytes + 1, 'a')},
        recipientPublicKey: _publicA,
      ),
      throwsFormatException,
    );
    expect(
      () => CapsuleCodec.seal(
        context: context,
        artifacts: _artifacts,
        recipientPublicKey: Uint8List(31),
      ),
      throwsFormatException,
    );
  });

  test('envelope parsing rejects shape, algorithm and non-canonical base64', () {
    final context = _context('op-0001');
    final envelope = _rawSeal(_payload(context));
    expect(
      () => CapsuleEnvelope.parseStrict({...envelope.toJson(), 'extra': 1}),
      throwsFormatException,
    );
    expect(
      () => CapsuleEnvelope.parseStrict({...envelope.toJson(), 'alg': 'x'}),
      throwsFormatException,
    );
    expect(
      () => CapsuleEnvelope.parseStrict({...envelope.toJson(), 'v': 2}),
      throwsFormatException,
    );
    expect(
      () => CapsuleEnvelope.parseStrict(
        {...envelope.toJson(), 'capsuleId': 'XYZ'},
      ),
      throwsFormatException,
    );
    final nonCanonical = base64Encode(envelope.ciphertext);
    final padded = '${nonCanonical.substring(0, nonCanonical.length - 1)}B';
    expect(
      () => CapsuleEnvelope.parseStrict(
        {...envelope.toJson(), 'ciphertext': padded},
      ),
      throwsFormatException,
    );
  });

  test('capsule payload permits LF in PEM artifacts; requests stay strict', () {
    final context = _context('op-0001');
    const pem = 'SYNTHETIC\nKEY\n';
    final envelope = CapsuleCodec.seal(
      context: context,
      artifacts: const {'openvpn.client-key': pem},
      recipientPublicKey: _publicA,
    );
    final opened = CapsuleCodec.open(
      envelope: envelope,
      recipientPrivateKey: _privateA,
      expectedRecipientPublicKey: _publicA,
      expected: context,
    );
    expect(opened, isA<CapsuleOpened>());
    expect(
      (opened as CapsuleOpened).artifacts['openvpn.client-key'],
      pem,
    );
    // The strict request canonicalizer is unchanged: LF is still rejected
    // outside the bounded artifact payload.
    expect(() => canonicalJsonV1({'name': pem}), throwsFormatException);
  });

  test('frozen Go v0.58.0 vector opens with the same context and key', () {
    final context = CapsuleContext(
      operation: 'op-0001',
      uid: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
          'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
      server: 'srv-test-1',
      deployment: 'dep-test-1',
      actor: 'owner',
      requestDigest: _requestDigest,
      profileSetDigest: _profileSetDigest,
    );
    final envelope = CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _capsuleId,
      recipientPublicKey: _publicA,
      ciphertext: base64Decode(_frozenPacketB64),
    );
    final opened = CapsuleCodec.open(
      envelope: envelope,
      recipientPrivateKey: _privateA,
      expectedRecipientPublicKey: _publicA,
      expected: context,
    );
    expect(opened, isA<CapsuleOpened>());
    expect(
      (opened as CapsuleOpened).artifacts,
      _artifacts,
    );
  });
}
