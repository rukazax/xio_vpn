import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_canonical.dart';

void main() {
  test('canonical JSON sorts keys and keeps integers untouched', () {
    expect(
      canonicalJsonV1({
        'b': 'x',
        'a': 1,
        'c': [true, 2],
      }),
      '{"a":1,"b":"x","c":[true,2]}',
    );
  });

  test('canonical JSON rejects null, floats, non-ASCII and foreign keys', () {
    expect(() => canonicalJsonV1({'a': null}), throwsFormatException);
    expect(() => canonicalJsonV1({'a': 1.5}), throwsFormatException);
    expect(() => canonicalJsonV1({'a': 'привет'}), throwsFormatException);
    expect(() => canonicalJsonV1({'a': 'line\nbreak'}), throwsFormatException);
    expect(() => canonicalJsonV1({1: 'a'}), throwsFormatException);
    expect(() => canonicalJsonV1(Object()), throwsFormatException);
  });

  test('request digest matches the documented domain-separated vector', () {
    expect(
      issuanceRequestDigest({'b': 'x', 'a': 1}),
      '39198ac5f0cb75da570fd1d0598180c3b2e5d9bc834d79f4757bc848e9fb4b29',
    );
  });

  test('profile-set digest is stable and rejects duplicate protocols', () {
    expect(
      issuanceProfileSetDigest(['awg'], {'awg': 'awg1'}),
      'e739268ee494bec3eda2909f72cfcb4b723d4d3a2ebc98c389f4f22b1720bbf5',
    );
    expect(
      () => issuanceProfileSetDigest(['awg', 'awg'], {'awg': 'awg1'}),
      throwsFormatException,
    );
  });

  test('name digest is the raw UTF-8 SHA-256', () {
    expect(
      issuanceNameSha256('alice'),
      '2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90',
    );
  });

  test('base64 must be canonical and of the expected length', () {
    expect(decodeCanonicalBase64('AA==', length: 1), Uint8List.fromList([0]));
    expect(() => decodeCanonicalBase64('AB==', length: 1), throwsFormatException);
    expect(() => decodeCanonicalBase64('AA==', length: 2), throwsFormatException);
    expect(() => decodeCanonicalBase64('!!!', length: 1), throwsFormatException);
  });

  test('hex helpers reject uppercase, odd length and wrong size', () {
    expect(isLowerHex('00ff', length: 4), isTrue);
    expect(isLowerHex('00FF', length: 4), isFalse);
    expect(decodeCanonicalHex('00ff'), Uint8List.fromList([0, 255]));
    expect(() => decodeCanonicalHex('abc'), throwsFormatException);
    expect(() => decodeCanonicalHex('00ff', length: 1), throwsFormatException);
    expect(canonicalHex([0, 255]), '00ff');
  });

  test('constant-time byte equality works for equal and different lengths', () {
    expect(constantTimeBytesEqual([1, 2, 3], [1, 2, 3]), isTrue);
    expect(constantTimeBytesEqual([1, 2, 3], [1, 2, 4]), isFalse);
    expect(constantTimeBytesEqual([1, 2], [1, 2, 3]), isFalse);
  });
}
