import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_partial_receipt.dart';

import 'issuance_a2_test_support.dart';

void main() {
  final valid = canonicalTestPartial(
    operationId: 'a' * 32,
    deployment: 'deploy',
    backends: {'awg', 'rivet'},
    capsuleId: 'b' * 32,
    ciphertextDigest: 'c' * 64,
    envelopeSha256: 'd' * 64,
    envelopeSize: 128,
    csrPresent: false,
  );

  test('parses the exact closed canonical document', () {
    final parsed = IssuancePartialReceipt.parse(valid);
    expect(parsed.backends, {'awg': 'pending', 'rivet': 'pending'});
    expect(parsed.csrPresent, isFalse);
  });

  test('rejects duplicate raw keys before a Map can lose them', () {
    final duplicate = valid.replaceFirst('{"backends"', '{"schema":1,"backends"');
    expect(
      () => IssuancePartialReceipt.parse(duplicate),
      throwsA(isA<FormatException>()),
    );
  });

  test('rejects trailing data and non-canonical spelling', () {
    expect(
      () => IssuancePartialReceipt.parse('$valid '),
      throwsA(isA<FormatException>()),
    );
    expect(
      () => IssuancePartialReceipt.parse(
        valid.replaceFirst('"replay":false', '"replay": false'),
      ),
      throwsA(isA<FormatException>()),
    );
  });

  test('rejects absent CSR with nonempty fields and requested=false leaks', () {
    final absentWithHash = valid.replaceFirst(
      '"cn":"","present":false,"sha256":"","spkiSha256":""',
      '"cn":"","present":false,"sha256":"${'e' * 64}","spkiSha256":""',
    );
    expect(
      () => IssuancePartialReceipt.parse(absentWithHash),
      throwsA(isA<FormatException>()),
    );
    final requestedLeak = valid.replaceFirst(
      '"kinds":[],"purpose":"none","requested":false',
      '"kinds":[],"purpose":"localStage","requested":false',
    );
    expect(
      () => IssuancePartialReceipt.parse(requestedLeak),
      throwsA(isA<FormatException>()),
    );
  });

  test('rejects unknown backend keys and states', () {
    final unknown = valid.replaceFirst('"awg":"pending"', '"nope":"pending"');
    expect(
      () => IssuancePartialReceipt.parse(unknown),
      throwsA(isA<FormatException>()),
    );
    final badState = valid.replaceFirst('"awg":"pending"', '"awg":"done"');
    expect(
      () => IssuancePartialReceipt.parse(badState),
      throwsA(isA<FormatException>()),
    );
  });
}
