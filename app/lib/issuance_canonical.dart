// Canonical request bytes for the owner-issuance journal.
//
// This file is deliberately dumb and deterministic: the same rules are
// reimplemented on the server side later, so the contract is spelled out in
// code rather than hidden in a JSON encoder. It performs no key handling and
// never sees private material.
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashing;

/// Domain separation for the canonical issuance request digest.
const String issuanceRequestDomain = 'xio/issuance/v1/request\n';

/// Domain separation for the canonical profile-set digest.
const String issuanceProfileSetDomain = 'xio/issuance/v1/profile-set\n';

final RegExp _lowerHex = RegExp(r'^[a-f0-9]*$');

String sha256Hex(List<int> bytes) => hashing.sha256.convert(bytes).toString();

/// Rejects anything outside printable ASCII. Canonical bytes are ASCII-only so
/// that no Dart/Python/Go Unicode normalization difference can change a digest.
String requirePrintableAscii(String value) {
  for (var index = 0; index < value.length; index++) {
    final unit = value.codeUnitAt(index);
    if (unit < 0x20 || unit > 0x7e) {
      throw const FormatException('Canonical strings must be printable ASCII');
    }
  }
  return value;
}

/// Canonical JSON v1: sorted keys, no whitespace, integers/bools/strings/
/// lists/maps only. `null` and floating point are rejected rather than
/// serialized, because the two runtimes disagree about their spelling.
String canonicalJsonV1(Object? value) {
  final output = StringBuffer();
  _writeCanonical(value, output);
  return output.toString();
}

void _writeCanonical(Object? value, StringBuffer output) {
  if (value == null) {
    throw const FormatException('Canonical JSON rejects null');
  }
  if (value is bool) {
    output.write(value ? 'true' : 'false');
    return;
  }
  if (value is int) {
    output.write(value);
    return;
  }
  if (value is double) {
    throw const FormatException('Canonical JSON rejects floating point');
  }
  if (value is String) {
    output.write(jsonEncode(requirePrintableAscii(value)));
    return;
  }
  if (value is List) {
    output.write('[');
    for (var index = 0; index < value.length; index++) {
      if (index > 0) output.write(',');
      _writeCanonical(value[index], output);
    }
    output.write(']');
    return;
  }
  if (value is Map) {
    final keys = <String>[];
    for (final key in value.keys) {
      if (key is! String) {
        throw const FormatException('Canonical JSON requires string keys');
      }
      requirePrintableAscii(key);
      keys.add(key);
    }
    keys.sort();
    output.write('{');
    for (var index = 0; index < keys.length; index++) {
      if (index > 0) output.write(',');
      output.write(jsonEncode(keys[index]));
      output.write(':');
      _writeCanonical(value[keys[index]], output);
    }
    output.write('}');
    return;
  }
  throw FormatException('Canonical JSON rejects ${value.runtimeType}');
}

String issuanceRequestDigest(Map<String, Object?> request) =>
    sha256Hex(utf8.encode('$issuanceRequestDomain${canonicalJsonV1(request)}'));

String issuanceProfileSetDigest(
  List<String> protocols,
  Map<String, String> profileIds,
) {
  final sorted = List<String>.of(protocols)..sort();
  if (sorted.toSet().length != sorted.length) {
    throw const FormatException('Duplicate protocol in profile set');
  }
  return sha256Hex(
    utf8.encode(
      '$issuanceProfileSetDomain'
      '${canonicalJsonV1({'protocols': sorted, 'profiles': profileIds})}',
    ),
  );
}

/// Digest of the free-form display name. The name itself is never part of the
/// canonical request bytes, only this digest plus the original string.
String issuanceNameSha256(String name) => sha256Hex(utf8.encode(name));

String canonicalBase64(List<int> bytes) => base64Encode(bytes);

Uint8List decodeCanonicalBase64(String value, {required int length}) {
  final Uint8List decoded;
  try {
    decoded = base64Decode(value);
  } on FormatException {
    throw const FormatException('Invalid base64');
  }
  if (base64Encode(decoded) != value) {
    throw const FormatException('Non-canonical base64 spelling');
  }
  if (decoded.length != length) {
    throw const FormatException('Unexpected base64 length');
  }
  return Uint8List.fromList(decoded);
}

String canonicalHex(List<int> bytes) {
  final output = StringBuffer();
  for (final byte in bytes) {
    output.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return output.toString();
}

Uint8List decodeCanonicalHex(String value, {int? length}) {
  if (value.length.isOdd || !_lowerHex.hasMatch(value)) {
    throw const FormatException('Invalid lower-case hex');
  }
  final output = Uint8List(value.length ~/ 2);
  for (var index = 0; index < output.length; index++) {
    output[index] = int.parse(value.substring(index * 2, index * 2 + 2), radix: 16);
  }
  // `length` is the decoded byte count, mirroring decodeCanonicalBase64.
  if (length != null && output.length != length) {
    throw const FormatException('Unexpected hex length');
  }
  return output;
}

bool isLowerHex(String value, {required int length}) =>
    value.length == length && _lowerHex.hasMatch(value);

/// Constant-time byte comparison for key material and context fields.
bool constantTimeBytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var index = 0; index < a.length; index++) {
    difference |= a[index] ^ b[index];
  }
  return difference == 0;
}
