// Recipient-encrypted replay capsule codec (XIO-CAPSULE-1, synthetic subset).
//
// The capsule gives confidentiality and context binding only. It is NOT server
// proof, NOT key validity, NOT CA state and NOT sender authentication: a sealed
// box is anonymous, so anyone holding the recipient public key can produce one.
// The transport that delivers it is the external trust boundary.
//
// Guards are mandatory in this order because pinenacl 0.6.0 returns an empty
// plaintext for any 48-byte ciphertext WITHOUT verifying the tag, and throws a
// raw String (not an Exception) on MAC failure.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' show PrivateKey, PublicKey, SealedBox;

import 'issuance_canonical.dart';

const String capsuleAlg = 'nacl-box-sealed-x25519-xsalsa20-poly1305-b2b24';
const int capsuleVersion = 1;
const int capsuleSchema = 1;
const String capsulePurpose = 'owner-issuance/delivery';

/// 32-byte ephemeral public key + 16-byte Poly1305 tag.
const int capsuleAnonymousOverhead = 48;
const int capsuleMaxPlaintext = 32768;
const int capsuleMaxCiphertext = 32816;
const int capsuleMaxEnvelopeBytes = 45056;
const int capsuleMaxArtifactBytes = 8192;
const int capsuleMaxArtifacts = 8;

/// Closed v1 artifact set. An unknown kind is a rejection, never ignored.
const Set<String> capsuleArtifactKinds = {
  'openvpn.client-key',
  'openvpn.tls-crypt-v2-client',
  'openvpn.client-cert',
  'ikev2.password',
  'tailscale.authKey',
  'cloak.uid',
};

const Set<String> _envelopeFields = {
  'v',
  'alg',
  'capsuleId',
  'recipientPublicKey',
  'ciphertext',
};

const Set<String> _contextFields = {
  'schema',
  'purpose',
  'version',
  'operation',
  'uid',
  'server',
  'deployment',
  'actor',
  'requestDigest',
  'profileSetDigest',
};

const Set<String> _payloadFields = {
  ..._contextFields,
  'artifacts',
};

final RegExp _operation = RegExp(r'^[A-Za-z0-9._:-]{1,64}$');
final RegExp _uid = RegExp(r'^[a-f0-9]{32}([a-f0-9]{32})?$');
final RegExp _digest = RegExp(r'^[a-f0-9]{64}$');

enum CapsuleRejectReason {
  envelopeShape,
  unexpectedField,
  capsuleTooLarge,
  short,
  badBox,
  empty,
  blank,
  notJson,
  notObject,
  missingField,
  schema,
  purpose,
  version,
  context,
  recipientKey,
  artifactKind,
  artifactSize,
}

final class CapsuleEnvelope {
  CapsuleEnvelope({
    required this.v,
    required this.alg,
    required this.capsuleId,
    required List<int> recipientPublicKey,
    required List<int> ciphertext,
  }) : _recipientPublicKey = Uint8List.fromList(recipientPublicKey),
       _ciphertext = Uint8List.fromList(ciphertext) {
    if (v != capsuleVersion) {
      throw const FormatException('Unsupported capsule version');
    }
    if (alg != capsuleAlg) {
      throw const FormatException('Unsupported capsule algorithm');
    }
    if (!isLowerHex(capsuleId, length: 32)) {
      throw const FormatException('Invalid capsule id');
    }
    if (_recipientPublicKey.length != 32) {
      throw const FormatException('Invalid capsule recipient key');
    }
    if (_ciphertext.length > capsuleMaxCiphertext) {
      throw const FormatException('Capsule ciphertext too large');
    }
  }

  final int v;
  final String alg;
  final String capsuleId;
  final Uint8List _recipientPublicKey;
  final Uint8List _ciphertext;

  /// Copies so callers cannot mutate the sealed bytes through the getter.
  Uint8List get recipientPublicKey => Uint8List.fromList(_recipientPublicKey);
  Uint8List get ciphertext => Uint8List.fromList(_ciphertext);

  String get digest => sha256Hex(_ciphertext);

  Map<String, Object?> toJson() => {
    'v': v,
    'alg': alg,
    'capsuleId': capsuleId,
    'recipientPublicKey': base64Encode(_recipientPublicKey),
    'ciphertext': base64Encode(_ciphertext),
  };

  static CapsuleEnvelope parseStrict(Map<String, Object?> json) {
    if (json.length != _envelopeFields.length ||
        !json.keys.every(_envelopeFields.contains)) {
      throw const FormatException('Invalid capsule envelope fields');
    }
    final v = json['v'];
    final alg = json['alg'];
    final capsuleId = json['capsuleId'];
    final recipient = json['recipientPublicKey'];
    final ciphertext = json['ciphertext'];
    if (v is! int || alg is! String || capsuleId is! String) {
      throw const FormatException('Invalid capsule envelope types');
    }
    if (recipient is! String || ciphertext is! String) {
      throw const FormatException('Invalid capsule envelope types');
    }
    final envelope = CapsuleEnvelope(
      v: v,
      alg: alg,
      capsuleId: capsuleId,
      recipientPublicKey: decodeCanonicalBase64(recipient, length: 32),
      ciphertext: decodeCanonicalBase64Any(
        ciphertext,
        maxLength: capsuleMaxCiphertext,
      ),
    );
    if (utf8.encode(jsonEncode(envelope.toJson())).length >
        capsuleMaxEnvelopeBytes) {
      throw const FormatException('Capsule envelope too large');
    }
    return envelope;
  }
}

Uint8List decodeCanonicalBase64Any(String value, {required int maxLength}) {
  final Uint8List decoded;
  try {
    decoded = base64Decode(value);
  } on FormatException {
    throw const FormatException('Invalid base64');
  }
  if (base64Encode(decoded) != value) {
    throw const FormatException('Non-canonical base64 spelling');
  }
  if (decoded.length > maxLength) {
    throw const FormatException('Base64 payload too large');
  }
  return Uint8List.fromList(decoded);
}

final class CapsuleContext {
  CapsuleContext({
    required this.operation,
    required this.uid,
    required this.server,
    required this.deployment,
    required this.actor,
    required this.requestDigest,
    required this.profileSetDigest,
    this.schema = capsuleSchema,
    this.version = capsuleVersion,
    this.purpose = capsulePurpose,
  }) {
    if (schema != capsuleSchema) {
      throw const FormatException('Unsupported capsule schema');
    }
    if (version != capsuleVersion) {
      throw const FormatException('Unsupported capsule context version');
    }
    if (purpose != capsulePurpose) {
      throw const FormatException('Unsupported capsule purpose');
    }
    if (!_operation.hasMatch(operation)) {
      throw const FormatException('Invalid capsule operation');
    }
    if (!_uid.hasMatch(uid)) {
      throw const FormatException('Invalid capsule uid');
    }
    if (!_digest.hasMatch(requestDigest) ||
        !_digest.hasMatch(profileSetDigest)) {
      throw const FormatException('Invalid capsule digest');
    }
    for (final value in [server, deployment, actor]) {
      requirePrintableAscii(value);
      if (value.isEmpty || value.length > 128) {
        throw const FormatException('Invalid capsule context field');
      }
    }
  }

  final int schema;
  final int version;
  final String purpose;
  final String operation;
  final String uid;
  final String server;
  final String deployment;
  final String actor;
  final String requestDigest;
  final String profileSetDigest;

  Map<String, Object?> toJson() => {
    'schema': schema,
    'purpose': purpose,
    'version': version,
    'operation': operation,
    'uid': uid,
    'server': server,
    'deployment': deployment,
    'actor': actor,
    'requestDigest': requestDigest,
    'profileSetDigest': profileSetDigest,
  };

  String get canonical => canonicalJsonV1(toJson());

  static CapsuleContext parseStrict(Map<String, Object?> json) {
    if (json.length != _contextFields.length ||
        !json.keys.every(_contextFields.contains)) {
      throw const FormatException('Invalid capsule context fields');
    }
    Object? required(String key) {
      final value = json[key];
      if (value == null) throw const FormatException('Missing capsule field');
      return value;
    }

    final schema = required('schema');
    final purpose = required('purpose');
    final version = required('version');
    final operation = required('operation');
    final uid = required('uid');
    final server = required('server');
    final deployment = required('deployment');
    final actor = required('actor');
    final requestDigest = required('requestDigest');
    final profileSetDigest = required('profileSetDigest');
    if (schema is! int ||
        purpose is! String ||
        version is! int ||
        operation is! String ||
        uid is! String ||
        server is! String ||
        deployment is! String ||
        actor is! String ||
        requestDigest is! String ||
        profileSetDigest is! String) {
      throw const FormatException('Invalid capsule context types');
    }
    return CapsuleContext(
      schema: schema,
      purpose: purpose,
      version: version,
      operation: operation,
      uid: uid,
      server: server,
      deployment: deployment,
      actor: actor,
      requestDigest: requestDigest,
      profileSetDigest: profileSetDigest,
    );
  }
}

sealed class CapsuleOpen {
  const CapsuleOpen();
}

final class CapsuleRejected extends CapsuleOpen {
  const CapsuleRejected(this.reason);
  final CapsuleRejectReason reason;
}

/// Successfully opened and context-bound. [artifacts] are UNVALIDATED material:
/// no key/cert consistency, host identity, CA state or sender authenticity is
/// established here. Callers must validate and treat the transport as trusted.
final class CapsuleOpened extends CapsuleOpen {
  CapsuleOpened._(
    this.context,
    this.plaintextSha256,
    Map<String, String> artifacts,
  ) : artifacts = Map<String, String>.unmodifiable(
        Map<String, String>.of(artifacts),
      );

  final CapsuleContext context;
  final String plaintextSha256;
  final Map<String, String> artifacts;
}

final class CapsuleCodec {
  const CapsuleCodec._();

  static CapsuleEnvelope seal({
    required CapsuleContext context,
    required Map<String, String> artifacts,
    required Uint8List recipientPublicKey,
  }) {
    if (recipientPublicKey.length != 32) {
      throw const FormatException('Invalid recipient public key');
    }
    final validatedArtifacts = _validateArtifacts(artifacts);
    final plaintext = Uint8List.fromList(
      utf8.encode(_encodePayload(context, validatedArtifacts)),
    );
    if (plaintext.isEmpty || plaintext.length > capsuleMaxPlaintext) {
      throw const FormatException('Capsule plaintext size out of bounds');
    }
    final sealed = SealedBox(
      PublicKey(Uint8List.fromList(recipientPublicKey)),
    ).encrypt(plaintext);
    return CapsuleEnvelope(
      v: capsuleVersion,
      alg: capsuleAlg,
      capsuleId: _randomHex(16),
      recipientPublicKey: recipientPublicKey,
      ciphertext: sealed,
    );
  }

  static CapsuleOpen open({
    required CapsuleEnvelope envelope,
    required Uint8List recipientPrivateKey,
    required Uint8List expectedRecipientPublicKey,
    required CapsuleContext expected,
  }) {
    if (recipientPrivateKey.length != 32 ||
        expectedRecipientPublicKey.length != 32) {
      return const CapsuleRejected(CapsuleRejectReason.recipientKey);
    }
    final privateKey = PrivateKey(Uint8List.fromList(recipientPrivateKey));
    final derivedPublic = Uint8List.fromList(privateKey.publicKey);
    if (!constantTimeBytesEqual(derivedPublic, envelope._recipientPublicKey) ||
        !constantTimeBytesEqual(derivedPublic, expectedRecipientPublicKey)) {
      return const CapsuleRejected(CapsuleRejectReason.recipientKey);
    }
    // The 48-byte path must never reach the library: pinenacl treats it as an
    // empty message and skips MAC verification entirely.
    if (envelope._ciphertext.length <= capsuleAnonymousOverhead) {
      return const CapsuleRejected(CapsuleRejectReason.short);
    }
    Uint8List plaintext;
    try {
      plaintext = SealedBox(privateKey).decrypt(envelope._ciphertext);
    } catch (_) {
      // Bare catch: MAC failure is thrown as a raw String by pinenacl.
      return const CapsuleRejected(CapsuleRejectReason.badBox);
    }
    if (plaintext.isEmpty) {
      return const CapsuleRejected(CapsuleRejectReason.empty);
    }
    final String text;
    try {
      text = utf8.decode(plaintext, allowMalformed: false);
    } on FormatException {
      return const CapsuleRejected(CapsuleRejectReason.notJson);
    }
    if (text.trim().isEmpty) {
      return const CapsuleRejected(CapsuleRejectReason.blank);
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException {
      return const CapsuleRejected(CapsuleRejectReason.notJson);
    }
    if (decoded is! Map<String, Object?>) {
      return const CapsuleRejected(CapsuleRejectReason.notObject);
    }
    if (!decoded.keys.every(_payloadFields.contains) ||
        decoded.length < _payloadFields.length) {
      return CapsuleRejected(
        decoded.keys.every(_payloadFields.contains)
            ? CapsuleRejectReason.missingField
            : CapsuleRejectReason.unexpectedField,
      );
    }
    if (decoded['schema'] != expected.schema) {
      return const CapsuleRejected(CapsuleRejectReason.schema);
    }
    if (decoded['purpose'] != expected.purpose) {
      return const CapsuleRejected(CapsuleRejectReason.purpose);
    }
    if (decoded['version'] != expected.version) {
      return const CapsuleRejected(CapsuleRejectReason.version);
    }
    final CapsuleContext context;
    try {
      context = CapsuleContext.parseStrict(
        Map<String, Object?>.from(decoded)..remove('artifacts'),
      );
    } on FormatException {
      return const CapsuleRejected(CapsuleRejectReason.envelopeShape);
    }
    if (context.canonical != expected.canonical) {
      return const CapsuleRejected(CapsuleRejectReason.context);
    }
    final artifactsJson = decoded['artifacts'];
    if (artifactsJson is! Map) {
      return const CapsuleRejected(CapsuleRejectReason.envelopeShape);
    }
    final artifacts = <String, String>{};
    for (final entry in artifactsJson.entries) {
      final key = entry.key;
      final value = entry.value;
      if (key is! String || value is! String) {
        return const CapsuleRejected(CapsuleRejectReason.envelopeShape);
      }
      if (!capsuleArtifactKinds.contains(key)) {
        return const CapsuleRejected(CapsuleRejectReason.artifactKind);
      }
      if (!_printableArtifact(value)) {
        return const CapsuleRejected(CapsuleRejectReason.artifactSize);
      }
      if (value.isEmpty || value.length > capsuleMaxArtifactBytes) {
        return const CapsuleRejected(CapsuleRejectReason.artifactSize);
      }
      artifacts[key] = value;
    }
    if (artifacts.length > capsuleMaxArtifacts) {
      return const CapsuleRejected(CapsuleRejectReason.artifactSize);
    }
    return CapsuleOpened._(context, sha256Hex(plaintext), artifacts);
  }

  /// Capsule plaintext serialization.
  ///
  /// Deliberately NOT the request canonicalizer: artifact values are opaque,
  /// validated strings that may contain LF (PEM material), so the global
  /// printable-ASCII rule cannot apply to them. Context fields stay strictly
  /// validated by [CapsuleContext], and artifact values are bounded and
  /// restricted to printable ASCII + LF by [_validateArtifacts]. Keys are
  /// sorted so the encoding is deterministic.
  static String _encodePayload(
    CapsuleContext context,
    Map<String, String> artifacts,
  ) {
    final artifactKeys = artifacts.keys.toList()..sort();
    final artifactsJson = StringBuffer('{');
    for (var index = 0; index < artifactKeys.length; index++) {
      if (index > 0) artifactsJson.write(',');
      artifactsJson.write(jsonEncode(artifactKeys[index]));
      artifactsJson.write(':');
      artifactsJson.write(jsonEncode(artifacts[artifactKeys[index]]!));
    }
    artifactsJson.write('}');
    final encoded = <String, String>{
      'schema': '${context.schema}',
      'purpose': jsonEncode(context.purpose),
      'version': '${context.version}',
      'operation': jsonEncode(context.operation),
      'uid': jsonEncode(context.uid),
      'server': jsonEncode(context.server),
      'deployment': jsonEncode(context.deployment),
      'actor': jsonEncode(context.actor),
      'requestDigest': jsonEncode(context.requestDigest),
      'profileSetDigest': jsonEncode(context.profileSetDigest),
      'artifacts': artifactsJson.toString(),
    };
    final keys = encoded.keys.toList()..sort();
    final output = StringBuffer('{');
    for (var index = 0; index < keys.length; index++) {
      if (index > 0) output.write(',');
      output.write(jsonEncode(keys[index]));
      output.write(':');
      output.write(encoded[keys[index]]!);
    }
    output.write('}');
    return output.toString();
  }

  static Map<String, String> _validateArtifacts(Map<String, String> artifacts) {
    if (artifacts.length > capsuleMaxArtifacts) {
      throw const FormatException('Too many capsule artifacts');
    }
    final copy = <String, String>{};
    for (final entry in artifacts.entries) {
      if (!capsuleArtifactKinds.contains(entry.key)) {
        throw const FormatException('Unknown capsule artifact kind');
      }
      if (!_printableArtifact(entry.value) ||
          entry.value.isEmpty ||
          entry.value.length > capsuleMaxArtifactBytes) {
        throw const FormatException('Invalid capsule artifact value');
      }
      copy[entry.key] = entry.value;
    }
    return copy;
  }

  static bool _printableArtifact(String value) {
    for (var index = 0; index < value.length; index++) {
      final unit = value.codeUnitAt(index);
      if (unit != 0x0a && (unit < 0x20 || unit > 0x7e)) return false;
    }
    return true;
  }

  static String _randomHex(int bytes) {
    final random = Random.secure();
    final output = StringBuffer();
    for (var index = 0; index < bytes; index++) {
      output.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return output.toString();
  }
}
