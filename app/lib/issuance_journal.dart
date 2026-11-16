// Encrypted PREPARED local issuance journal (Slice A).
//
// Storage contract:
// * The injected `write` MUST persist an ENCRYPTED vault record (CredentialVault
//   on desktop, ConfigVault on Android). This class never opens a file, never
//   writes plaintext and has no "default encrypted" fallback: every callback is
//   a required constructor argument.
// * The injected `write` MUST be durable on success (file and directory flushed,
//   or an equivalent durable commit). A write that throws may leave new bytes
//   visible while the durable record is still the previous one, so read-back is
//   never accepted as proof of durability: uncertain resolution recommits the
//   matched snapshot through `write` again and clears the latch only if that
//   recommit succeeds. The journal holds its writer exclusion across it.
// * Serialization is per identity and in-process. Revision checks defend against
//   stale in-process callers only; they are NOT a cross-process CAS. A second OS
//   process, or a provider without an exclusive writer, must be excluded by the
//   platform vault/lock (Slice B). Until then the guarantee is bounded to one
//   process and must not be described as cross-process safe.
// * Recovery resolves through the SAME per-identity serialization domain as
//   mutations. It reserves its slot before any await; a resolver that runs
//   later observes the cleared latch and reads the CURRENT record instead of
//   rewriting a stale snapshot. Ownership tokens keep one completion from
//   deleting another operation's active claim.
// * A write is acknowledged only after read-back equality AND the durability
//   barrier. While a physical write is outstanding every mutation of that
//   identity fails fast; after a failed or unconfirmed write the identity is
//   latched until resolveUncertain() re-commits the matched snapshot through the
//   barrier and only then clears the latch.
//
// A record is one unresolved owner issuance per product Store. It never mutates
// the Store graph, never publishes a native plan and never performs network IO.
import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'issuance_canonical.dart';
import 'issuance_capsule.dart';
import 'issuance_material_scope.dart';
import 'issuance_partial_receipt.dart';
import 'issuance_vault.dart';

part 'issuance_journal_v2_part.dart';

const String issuanceJournalSchema = '1';
const Set<String> issuanceV2FlatFields = {
  'deployment',
  'profileSetDigest',
  'capsuleEnvelopeB64',
  'capsuleEnvelopeSha256',
  'capsuleId',
  'capsuleCiphertextDigest',
  'capsuleContextSha256',
  'capsulePlaintextSha256',
  'capsuleArtifactKinds',
  'partialReceiptJson',
};
const int issuanceJournalMaxBytes = 512 * 1024;
const int issuanceReceiptMaxBytes = 64 * 1024;
const int issuanceRequestMaxBytes = 16 * 1024;

/// Closed set of private-material keys. An unknown key is a rejection.
const Set<String> issuanceMaterialKinds = {
  'wireguardPrivate',
  'wireguardPublic',
  'awgPrivate',
  'awgPublic',
  'deviceSecret',
  'entryToken',
  'managementPrivate',
  'managementPublic',
  'capsuleRecipientPrivateKey',
};

const Set<String> _base64MaterialKinds = {
  'wireguardPrivate',
  'wireguardPublic',
  'awgPrivate',
  'awgPublic',
  'deviceSecret',
  'entryToken',
  'capsuleRecipientPrivateKey',
};

const Set<String> issuanceJournalFlags = {
  'definiteRejected',
  'identityConflict',
  'cancelRequested',
  'cancelledConfirmed',
  'repairRequired',
};

const Set<String> issuanceJournalErrorCodes = {
  'OWNER_REQUIRED',
  'SERVER_IDENTITY',
  'INVALID_REQUEST',
  'SEND_FAILED',
  'TIMEOUT',
  'IO_FAILURE',
  'INVALID_RESULT',
  'SERVER_REJECTED',
  'JOURNAL_FAILURE',
  'CANCELLED',
  'UNKNOWN',
};

enum IssuancePhase {
  prepared,
  dispatchIntent,
  remotePending,
  remoteComplete,
  localStaged,
  localDurableNativeUnconfirmed,
  committed,
}

sealed class IssuanceJournalException implements Exception {
  const IssuanceJournalException(this.message);
  final String message;
  @override
  String toString() => '$runtimeType: $message';
}

final class IssuanceJournalBusy extends IssuanceJournalException {
  const IssuanceJournalBusy(super.message);
}

final class IssuanceJournalUnknown extends IssuanceJournalException {
  const IssuanceJournalUnknown(super.message);
}

final class IssuanceJournalConflict extends IssuanceJournalException {
  const IssuanceJournalConflict(super.message);
}

/// The callback used to read one encrypted vault record.
typedef IssuanceJournalRead =
    Future<Map<String, String>?> Function(String id);

/// The callback used to persist one encrypted vault record.
///
/// Contract: a SUCCESSFUL write is durable (it acts as the commit/barrier for
/// that record: file and directory flushed, or an equivalent durable commit).
/// A write that throws may have left new bytes VISIBLE while the durable view
/// is still the previous record, so read-back alone is never treated as proof
/// of durability. Implementations MUST encrypt before writing; see the
/// library-level contract above.
typedef IssuanceJournalWrite =
    Future<void> Function(String id, Map<String, String> data);

final class IssuanceRecord {
  IssuanceRecord._({
    required this.revision,
    required this.operationId,
    required this.uid,
    required this.storeIdentity,
    required this.serverId,
    required this.sshFingerprint,
    required this.actor,
    required this.requestDigest,
    required this.requestJson,
    required this.phase,
    required this.dispatchIntent,
    required Set<String> flags,
    required Map<String, String> material,
    required List<int> capsuleRecipientPublicKey,
    required this.capsuleDigest,
    required this.errorCode,
    required this.localSnapshotDigest,
    required this.receiptJson,
    Map<String, String> v2 = const {},
  }) : flags = Set<String>.unmodifiable(Set<String>.of(flags)),
       _material = Map<String, String>.unmodifiable(
         Map<String, String>.of(material),
       ),
       _capsuleRecipientPublicKey = Uint8List.fromList(
         capsuleRecipientPublicKey,
       ),
       _v2 = Map<String, String>.unmodifiable(Map<String, String>.of(v2));

  final int revision;
  final String operationId;
  final String uid;
  final String storeIdentity;
  final String serverId;
  final String sshFingerprint;
  final String actor;
  final String requestDigest;
  final String requestJson;
  final IssuancePhase phase;
  final bool dispatchIntent;
  final Set<String> flags;

  /// Private material. Never exposed through JSON, diagnostics or `toString`.
  final Map<String, String> _material;
  final Uint8List _capsuleRecipientPublicKey;
  final String capsuleDigest;
  final String errorCode;
  final String localSnapshotDigest;
  final String receiptJson;

  /// Schema-2 flat fields. Empty for schema 1; never secret.
  final Map<String, String> _v2;

  /// The kinds present, never the values. Callers that need the bytes must go
  /// through a later, explicitly-scoped commit path; there is no public getter
  /// for the capsule private scalar or any other secret.
  Set<String> get materialKinds => Set<String>.unmodifiable(_material.keys);

  /// Integrity fingerprint of one material value (for tests and diagnostics).
  String? materialSha256(String key) {
    final value = _material[key];
    return value == null ? null : sha256Hex(utf8.encode(value));
  }

  Uint8List get capsuleRecipientPublicKey =>
      Uint8List.fromList(_capsuleRecipientPublicKey);

  Map<String, Object?> get request =>
      Map<String, Object?>.from(jsonDecode(requestJson) as Map);

  Map<String, Object?>? get receipt => receiptJson.isEmpty
      ? null
      : Map<String, Object?>.from(jsonDecode(receiptJson) as Map);

  bool get isUnresolved =>
      phase != IssuancePhase.committed &&
      !flags.contains('cancelledConfirmed');

  /// No `toJson` by design: ordinary state and exports must never contain this
  /// record or its encrypted payload.
  @override
  String toString() => 'IssuanceRecord([redacted])';

  Map<String, String> _toVault() => {
    'journalSchema': _v2.isEmpty ? issuanceJournalSchema : issuanceJournalSchemaV2,
    'revision': '$revision',
    'operationId': operationId,
    'uid': uid,
    'storeIdentity': storeIdentity,
    'serverId': serverId,
    'sshFingerprint': sshFingerprint,
    'actor': actor,
    'requestDigest': requestDigest,
    'request': requestJson,
    'phase': phase.name,
    'dispatchIntent': dispatchIntent ? '1' : '0',
    'flags': (flags.toList()..sort()).join(','),
    'material': jsonEncode(_sortedMaterial()),
    'capsuleRecipientPublicKey': base64Encode(_capsuleRecipientPublicKey),
    'capsuleDigest': capsuleDigest,
    'errorCode': errorCode,
    'localSnapshotDigest': localSnapshotDigest,
    'receipt': receiptJson,
    ..._v2,
  };

  Map<String, String> _sortedMaterial() {
    final keys = _material.keys.toList()..sort();
    return {for (final key in keys) key: _material[key]!};
  }

  IssuanceRecord _copyWith({
    int? revision,
    IssuancePhase? phase,
    bool? dispatchIntent,
    Set<String>? flags,
    String? capsuleDigest,
    String? errorCode,
    String? localSnapshotDigest,
    String? receiptJson,
    Map<String, String>? v2,
  }) => IssuanceRecord._(
    revision: revision ?? this.revision,
    operationId: operationId,
    uid: uid,
    storeIdentity: storeIdentity,
    serverId: serverId,
    sshFingerprint: sshFingerprint,
    actor: actor,
    requestDigest: requestDigest,
    requestJson: requestJson,
    phase: phase ?? this.phase,
    dispatchIntent: dispatchIntent ?? this.dispatchIntent,
    flags: flags ?? this.flags,
    material: _material,
    capsuleRecipientPublicKey: _capsuleRecipientPublicKey,
    capsuleDigest: capsuleDigest ?? this.capsuleDigest,
    errorCode: errorCode ?? this.errorCode,
    localSnapshotDigest: localSnapshotDigest ?? this.localSnapshotDigest,
    receiptJson: receiptJson ?? this.receiptJson,
    v2: v2 ?? _v2,
  );

  static IssuanceRecord _parse(Map<String, String> raw) {
    const baseFields = {
      'journalSchema',
      'revision',
      'operationId',
      'uid',
      'storeIdentity',
      'serverId',
      'sshFingerprint',
      'actor',
      'requestDigest',
      'request',
      'phase',
      'dispatchIntent',
      'flags',
      'material',
      'capsuleRecipientPublicKey',
      'capsuleDigest',
      'errorCode',
      'localSnapshotDigest',
      'receipt',
    };
    final schema = raw['journalSchema'];
    if (schema != issuanceJournalSchema && schema != issuanceJournalSchemaV2) {
      throw const FormatException('Unsupported issuance journal schema');
    }
    final fields = schema == issuanceJournalSchema
        ? baseFields
        : {...baseFields, ...issuanceV2FlatFields};
    if (raw.length != fields.length || !raw.keys.every(fields.contains)) {
      throw const FormatException('Invalid issuance journal fields');
    }
    if (schema == issuanceJournalSchemaV2) {
      _validateV2FlatFields(raw);
    }
    final revision = int.tryParse(raw['revision']!);
    if (revision == null ||
        revision < 0 ||
        revision > issuanceRevisionMax ||
        '$revision' != raw['revision']) {
      throw const FormatException('Invalid issuance journal revision');
    }
    final operationId = raw['operationId']!;
    final uid = raw['uid']!;
    final storeIdentity = raw['storeIdentity']!;
    if (!isLowerHex(operationId, length: 32) ||
        !isLowerHex(uid, length: 32) ||
        !isLowerHex(storeIdentity, length: 64)) {
      throw const FormatException('Invalid issuance journal identity');
    }
    for (final key in ['serverId', 'sshFingerprint', 'actor']) {
      requirePrintableAscii(raw[key]!);
      if (raw[key]!.isEmpty || raw[key]!.length > 256) {
        throw const FormatException('Invalid issuance journal field');
      }
    }
    final requestDigest = raw['requestDigest']!;
    if (!isLowerHex(requestDigest, length: 64)) {
      throw const FormatException('Invalid issuance request digest');
    }
    final requestJson = raw['request']!;
    if (requestJson.isEmpty ||
        utf8.encode(requestJson).length > issuanceRequestMaxBytes) {
      throw const FormatException('Invalid issuance request payload');
    }
    final Object? requestValue = jsonDecode(requestJson);
    if (requestValue is! Map<String, Object?> ||
        canonicalJsonV1(requestValue) != requestJson ||
        issuanceRequestDigest(requestValue) != requestDigest) {
      throw const FormatException('Issuance request is not canonical');
    }
    IssuancePhase? phase;
    for (final candidate in IssuancePhase.values) {
      if (candidate.name == raw['phase']) {
        phase = candidate;
        break;
      }
    }
    if (phase == null) {
      throw const FormatException('Invalid issuance journal phase');
    }
    final dispatchRaw = raw['dispatchIntent']!;
    if (dispatchRaw != '0' && dispatchRaw != '1') {
      throw const FormatException('Invalid dispatch intent');
    }
    final dispatchIntent = dispatchRaw == '1';
    if (phase == IssuancePhase.prepared && dispatchIntent) {
      throw const FormatException('Prepared record cannot carry a dispatch intent');
    }
    if (phase != IssuancePhase.prepared && !dispatchIntent) {
      throw const FormatException('Committed dispatch state missing');
    }
    final flagsRaw = raw['flags']!;
    final flags = flagsRaw.isEmpty ? <String>{} : flagsRaw.split(',').toSet();
    if (!flags.every(issuanceJournalFlags.contains)) {
      throw const FormatException('Invalid issuance journal flag');
    }
    if ((flagsRaw.split(',').length) != flags.length && flagsRaw.isNotEmpty) {
      throw const FormatException('Duplicate issuance journal flag');
    }
    final materialValue = jsonDecode(raw['material']!);
    if (materialValue is! Map) {
      throw const FormatException('Invalid issuance material');
    }
    final material = <String, String>{};
    for (final entry in materialValue.entries) {
      final key = entry.key;
      final value = entry.value;
      if (key is! String || value is! String) {
        throw const FormatException('Invalid issuance material entry');
      }
      material[key] = value;
    }
    final isV2 = raw['journalSchema'] == issuanceJournalSchemaV2;
    _validateMaterial(material, v2: isV2);
    if (!isV2) {
      final sortedKeys = material.keys.toList()..sort();
      final canonicalMaterial = jsonEncode({
        for (final key in sortedKeys) key: material[key],
      });
      if (raw['material'] != canonicalMaterial) {
        throw const FormatException('Unsupported legacy material spelling');
      }
    }
    final capsuleRecipientPublicKey = decodeCanonicalBase64(
      raw['capsuleRecipientPublicKey']!,
      length: 32,
    );
    final capsuleDigest = raw['capsuleDigest']!;
    if (capsuleDigest.isNotEmpty &&
        !isLowerHex(capsuleDigest, length: 64)) {
      throw const FormatException('Invalid capsule digest');
    }
    final errorCode = raw['errorCode']!;
    if (errorCode.isNotEmpty &&
        !issuanceJournalErrorCodes.contains(errorCode)) {
      throw const FormatException('Invalid issuance error code');
    }
    final localSnapshotDigest = raw['localSnapshotDigest']!;
    if (localSnapshotDigest.isNotEmpty &&
        !isLowerHex(localSnapshotDigest, length: 64)) {
      throw const FormatException('Invalid local snapshot digest');
    }
    final receiptJson = raw['receipt']!;
    if (receiptJson.isNotEmpty) {
      if (utf8.encode(receiptJson).length > issuanceReceiptMaxBytes) {
        throw const FormatException('Issuance receipt too large');
      }
      if (jsonDecode(receiptJson) is! Map) {
        throw const FormatException('Invalid issuance receipt');
      }
    }
    final v2 = <String, String>{};
    if (raw['journalSchema'] == issuanceJournalSchemaV2) {
      for (final key in issuanceV2FlatFields) {
        v2[key] = raw[key] ?? '';
      }
    }
    return IssuanceRecord._(
      revision: revision,
      operationId: operationId,
      uid: uid,
      storeIdentity: storeIdentity,
      serverId: raw['serverId']!,
      sshFingerprint: raw['sshFingerprint']!,
      actor: raw['actor']!,
      requestDigest: requestDigest,
      requestJson: requestJson,
      phase: phase,
      dispatchIntent: dispatchIntent,
      flags: flags,
      material: material,
      capsuleRecipientPublicKey: capsuleRecipientPublicKey,
      capsuleDigest: capsuleDigest,
      errorCode: errorCode,
      localSnapshotDigest: localSnapshotDigest,
      receiptJson: receiptJson,
      v2: v2,
    );
  }
}

/// A single authorized transition table keeps phases monotonic.
const Map<IssuancePhase, Set<IssuancePhase>> issuancePhaseTransitions = {
  IssuancePhase.prepared: {IssuancePhase.dispatchIntent},
  IssuancePhase.dispatchIntent: {IssuancePhase.remotePending, IssuancePhase.remoteComplete},
  IssuancePhase.remotePending: {IssuancePhase.remoteComplete},
  IssuancePhase.remoteComplete: {IssuancePhase.localStaged},
  IssuancePhase.localStaged: {
    IssuancePhase.localDurableNativeUnconfirmed,
    IssuancePhase.committed,
  },
  IssuancePhase.localDurableNativeUnconfirmed: {IssuancePhase.committed},
  IssuancePhase.committed: {},
};

final class IssuanceJournalStore {
  IssuanceJournalStore({required this.read, required this.write}) : _vault = null;

  IssuanceJournalStore._bound({
    required this.read,
    required this.write,
    required IssuanceJournalVault vault,
  }) : _vault = vault;

  factory IssuanceJournalStore.bound(IssuanceJournalVault vault) =>
      IssuanceJournalStore._bound(
        read: vault.read,
        write: vault.write,
        vault: vault,
      );

  final IssuanceJournalRead read;
  final IssuanceJournalWrite write;
  final IssuanceJournalVault? _vault;

  static final Map<String, Future<void>> _tails = {};
  static final Map<String, Object> _activeWrites = {};
  static final Set<String> _uncertain = {};
  static final Map<String, Map<String, String>> _intended = {};
  static final Map<String, Map<String, String>?> _previous = {};
  static final Map<String, Object> _materialActive = {};

  static String vaultId(String storeIdentity) {
    if (!isLowerHex(storeIdentity, length: 64)) {
      throw const FormatException('Invalid product store identity');
    }
    return 'state${sha256Hex(utf8.encode('xio-issuance/v1/$storeIdentity'))}';
  }

  Future<IssuanceRecord?> load(String storeIdentity) async {
    final raw = await read(vaultId(storeIdentity));
    if (raw == null) return null;
    final record = IssuanceRecord._parse(raw);
    if (record.storeIdentity != storeIdentity) {
      throw const FormatException('Issuance journal identity mismatch');
    }
    return record;
  }

  Future<IssuanceRecord> prepare({
    required String storeIdentity,
    required String uid,
    required String serverId,
    required String sshFingerprint,
    required String actor,
    required Map<String, Object?> request,
    required Map<String, String> material,
    required Uint8List capsuleRecipientPublicKey,
    String? operationId,
  }) async {
    if (!isLowerHex(uid, length: 32)) {
      throw const FormatException('Invalid issuance uid');
    }
    if (capsuleRecipientPublicKey.length != 32) {
      throw const FormatException('Invalid capsule recipient key');
    }
    final canonicalRequest = canonicalJsonV1(request);
    if (canonicalRequest.isEmpty ||
        utf8.encode(canonicalRequest).length > issuanceRequestMaxBytes) {
      throw const FormatException('Issuance request size out of bounds');
    }
    final requestDigest = issuanceRequestDigest(request);
    final normalizedMaterial = Map<String, String>.of(material);
    _validateMaterial(normalizedMaterial);
    final id = operationId ?? _randomHex(16);
    if (!isLowerHex(id, length: 32)) {
      throw const FormatException('Invalid issuance operation id');
    }
    for (final value in [serverId, sshFingerprint, actor]) {
      requirePrintableAscii(value);
      if (value.isEmpty || value.length > 256) {
        throw const FormatException('Invalid issuance journal field');
      }
    }
    return _mutate(storeIdentity, () async {
      final existingRaw = await read(vaultId(storeIdentity));
      if (existingRaw != null) {
        final existing = IssuanceRecord._parse(existingRaw);
        if (existing.storeIdentity != storeIdentity) {
          throw const FormatException('Issuance journal identity mismatch');
        }
        if (existing.isUnresolved) {
          throw const IssuanceJournalConflict(
            'A prepared issuance already exists for this store',
          );
        }
      }
      final record = IssuanceRecord._(
        revision: 0,
        operationId: id,
        uid: uid,
        storeIdentity: storeIdentity,
        serverId: serverId,
        sshFingerprint: sshFingerprint,
        actor: actor,
        requestDigest: requestDigest,
        requestJson: canonicalRequest,
        phase: IssuancePhase.prepared,
        dispatchIntent: false,
        flags: const {},
        material: normalizedMaterial,
        capsuleRecipientPublicKey: capsuleRecipientPublicKey,
        capsuleDigest: '',
        errorCode: '',
        localSnapshotDigest: '',
        receiptJson: '',
      );
      await _writeVerified(storeIdentity, record._toVault());
      return record;
    });
  }

  Future<IssuanceRecord> markDispatchIntent(IssuanceRecord record) =>
      _mutate(record.storeIdentity, () async {
        final current = await _require(record);
        if (current.phase != IssuancePhase.prepared) {
          throw const IssuanceJournalConflict(
            'Dispatch intent is only valid for a prepared record',
          );
        }
        final next = current._copyWith(
          revision: current.revision + 1,
          phase: IssuancePhase.dispatchIntent,
          dispatchIntent: true,
        );
        _checkTransition(current.phase, next.phase);
        await _writeVerified(record.storeIdentity, next._toVault());
        return next;
      });

  Future<IssuanceRecord> remoteResult(
    IssuanceRecord record, {
    required Map<String, Object?> receipt,
    String? capsuleDigest,
  }) async {
    if (capsuleDigest != null && !isLowerHex(capsuleDigest, length: 64)) {
      throw const FormatException('Invalid capsule digest');
    }
    final encoded = _encodeReceipt(receipt);
    return _mutate(record.storeIdentity, () async {
      final current = await _require(record);
      if (current.phase == IssuancePhase.remoteComplete) {
        if (current.receiptJson != encoded) {
          throw const IssuanceJournalConflict(
            'The operation already has a different receipt',
          );
        }
        if (capsuleDigest != null &&
            current.capsuleDigest.isNotEmpty &&
            current.capsuleDigest != capsuleDigest) {
          throw const IssuanceJournalConflict(
            'The first capsule digest cannot rotate',
          );
        }
        return current;
      }
      if (current.phase != IssuancePhase.dispatchIntent &&
          current.phase != IssuancePhase.remotePending) {
        throw const IssuanceJournalConflict(
          'No dispatched operation is awaiting a result',
        );
      }
      if (capsuleDigest != null &&
          current.capsuleDigest.isNotEmpty &&
          current.capsuleDigest != capsuleDigest) {
        throw const IssuanceJournalConflict(
          'The first capsule digest cannot rotate',
        );
      }
      final next = current._copyWith(
        revision: current.revision + 1,
        phase: IssuancePhase.remoteComplete,
        capsuleDigest: capsuleDigest ?? current.capsuleDigest,
        receiptJson: encoded,
      );
      _checkTransition(current.phase, next.phase);
      await _writeVerified(record.storeIdentity, next._toVault());
      return next;
    });
  }

  Future<IssuanceRecord> fail(IssuanceRecord record, String errorCode) async {
    if (!issuanceJournalErrorCodes.contains(errorCode)) {
      throw const FormatException('Unknown issuance error code');
    }
    return _mutate(record.storeIdentity, () async {
      final current = await _require(record);
      if (current.phase != IssuancePhase.dispatchIntent &&
          current.phase != IssuancePhase.remotePending) {
        throw const IssuanceJournalConflict(
          'Only a dispatched operation can retain a failure code',
        );
      }
      if (current.errorCode == errorCode) return current;
      final next = current._copyWith(
        revision: current.revision + 1,
        errorCode: errorCode,
      );
      await _writeVerified(record.storeIdentity, next._toVault());
      return next;
    });
  }

  Future<IssuanceRecord> commitLocal(
    IssuanceRecord record,
    String localSnapshotDigest,
  ) async {
    if (!isLowerHex(localSnapshotDigest, length: 64)) {
      throw const FormatException('Invalid local snapshot digest');
    }
    return _mutate(record.storeIdentity, () async {
      final current = await _require(record);
      _checkTransition(current.phase, IssuancePhase.localStaged);
      final next = current._copyWith(
        revision: current.revision + 1,
        phase: IssuancePhase.localStaged,
        localSnapshotDigest: localSnapshotDigest,
      );
      await _writeVerified(record.storeIdentity, next._toVault());
      return next;
    });
  }

  Future<IssuanceRecord> markLocalUnconfirmed(IssuanceRecord record) =>
      _mutate(record.storeIdentity, () async {
        final current = await _require(record);
        _checkTransition(
          current.phase,
          IssuancePhase.localDurableNativeUnconfirmed,
        );
        final next = current._copyWith(
          revision: current.revision + 1,
          phase: IssuancePhase.localDurableNativeUnconfirmed,
        );
        await _writeVerified(record.storeIdentity, next._toVault());
        return next;
      });

  Future<IssuanceRecord> markCommitted(IssuanceRecord record) =>
      _mutate(record.storeIdentity, () async {
        final current = await _require(record);
        _checkTransition(current.phase, IssuancePhase.committed);
        final next = current._copyWith(
          revision: current.revision + 1,
          phase: IssuancePhase.committed,
        );
        await _writeVerified(record.storeIdentity, next._toVault());
        return next;
      });

  /// Abandons a prepared record that never reached a dispatch intent. The
  /// record is retained (encrypted, redacted, one unresolved per Store is
  /// released by the `cancelledConfirmed` flag), because dropping the bytes
  /// could not be proven safe.
  Future<IssuanceRecord> abandonPrepared(IssuanceRecord record) =>
      _mutate(record.storeIdentity, () async {
        final current = await _require(record);
        if (current.phase != IssuancePhase.prepared ||
            current.dispatchIntent) {
          throw const IssuanceJournalConflict(
            'A dispatched issuance cannot be abandoned locally',
          );
        }
        final next = current._copyWith(
          revision: current.revision + 1,
          flags: {...current.flags, 'cancelledConfirmed'},
        );
        await _writeVerified(record.storeIdentity, next._toVault());
        return next;
      });

  /// Classifies the durable state after a failed or unconfirmed write.
  ///
  /// The read-back only selects WHICH snapshot is plausible (intended or
  /// previous). It is never treated as proof of durability: the selected
  /// snapshot is recommitted through the provider's durable `write` while this
  /// identity stays excluded, and only that successful recommit clears the
  /// latch. Any failure keeps the identity unknown.
  Future<IssuanceRecord?> resolveUncertain(String storeIdentity) {
    if (!isLowerHex(storeIdentity, length: 64)) {
      return Future<IssuanceRecord?>.error(
        const FormatException('Invalid product store identity'),
      );
    }
    if (_materialActive.containsKey(storeIdentity)) {
      return Future<IssuanceRecord?>.error(
        const IssuanceJournalBusy('A material operation owns this store'),
      );
    }
    // Recovery shares the identity's single serialization domain and reserves
    // its slot synchronously. No read happens before the reservation, so two
    // resolvers cannot both decide they own the barrier.
    return _serialize(storeIdentity, () async {
      if (_materialActive.containsKey(storeIdentity)) {
        throw const IssuanceJournalBusy('A material operation owns this store');
      }
      if (!_uncertain.contains(storeIdentity)) {
        // A concurrent resolver already settled this identity. Read the CURRENT
        // record; never rewrite a snapshot selected before the latch cleared.
        return load(storeIdentity);
      }
      if (_activeWrites.containsKey(storeIdentity)) {
        throw const IssuanceJournalBusy(
          'A journal write is still pending for this store',
        );
      }
      final id = vaultId(storeIdentity);
      final actual = await read(id);
      final intended = _intended[storeIdentity];
      final previous = _previous[storeIdentity];
      Map<String, String>? matched;
      var absent = false;
      if (intended != null && _sameMap(actual, intended)) {
        matched = intended;
      } else if (_sameMap(actual, previous)) {
        if (previous == null) {
          absent = true;
        } else {
          matched = previous;
        }
      } else {
        throw const IssuanceJournalUnknown(
          'Journal state differs from both the intended and the previous write',
        );
      }

      if (absent) {
        // Nothing existed before this operation. The caller sees an absent
        // record, which is the conservative reading of "no record was left".
        _clearLatch(storeIdentity);
        return null;
      }

      // Recommit the SAME matched snapshot through the durable write. A write
      // that throws may leave it visible but not durable, so a failed recommit
      // never clears the latch. The ownership token ensures this completion
      // cannot delete a claim belonging to another operation.
      final token = Object();
      _activeWrites[storeIdentity] = token;
      try {
        try {
          await write(id, Map<String, String>.of(matched!));
        } catch (_) {
          throw const IssuanceJournalUnknown(
            'Journal re-commit failed; outcome stays unknown',
          );
        }
        final rewritten = await read(id);
        if (!_sameMap(rewritten, matched)) {
          throw const IssuanceJournalUnknown(
            'Journal re-commit did not reproduce the matched snapshot',
          );
        }
        // The latch can only change inside this serialized domain; verify it is
        // still the same uncertainty before clearing.
        if (!_uncertain.contains(storeIdentity)) {
          throw const IssuanceJournalUnknown(
            'Journal uncertainty changed during recovery',
          );
        }
        _clearLatch(storeIdentity);
        return IssuanceRecord._parse(matched);
      } finally {
        if (identical(_activeWrites[storeIdentity], token)) {
          _activeWrites.remove(storeIdentity);
        }
      }
    });
  }

  Future<IssuanceRecord> _require(IssuanceRecord expected) async {
    final raw = await read(vaultId(expected.storeIdentity));
    if (raw == null) {
      throw const IssuanceJournalConflict('Issuance journal record disappeared');
    }
    final current = IssuanceRecord._parse(raw);
    if (current.storeIdentity != expected.storeIdentity ||
        current.operationId != expected.operationId ||
        current.revision != expected.revision) {
      throw const IssuanceJournalConflict(
        'Issuance journal changed; reload before retrying',
      );
    }
    return current;
  }

  /// The ONE physical serialization domain for an identity. The queue slot is
  /// reserved synchronously, before any await, so two callers cannot both pass
  /// an admission check and then interleave their awaited reads/writes. Every
  /// mutator and every resolver uses this domain; there is no recovery-only
  /// writer.
  Future<T> _serialize<T>(
    String storeIdentity,
    Future<T> Function() body,
  ) {
    final previous = _tails[storeIdentity] ?? Future<void>.value();
    final done = Completer<void>();
    final tail = done.future;
    _tails[storeIdentity] = tail;
    return () async {
      try {
        await previous;
        return await body();
      } finally {
        done.complete();
        if (identical(_tails[storeIdentity], tail)) {
          _tails.remove(storeIdentity);
        }
      }
    }();
  }

  Future<T> _mutate<T>(
    String storeIdentity,
    Future<T> Function() body,
  ) {
    if (!isLowerHex(storeIdentity, length: 64)) {
      return Future<T>.error(
        const FormatException('Invalid product store identity'),
      );
    }
    if (_activeWrites.containsKey(storeIdentity)) {
      return Future<T>.error(
        const IssuanceJournalBusy(
          'A journal write is still pending for this store',
        ),
      );
    }
    if (_uncertain.contains(storeIdentity)) {
      return Future<T>.error(
        const IssuanceJournalUnknown(
          'The previous journal write outcome is unknown; resolve it first',
        ),
      );
    }
    if (_materialActive.containsKey(storeIdentity)) {
      return Future<T>.error(
        const IssuanceJournalBusy('A material operation owns this store'),
      );
    }
    return _serialize(storeIdentity, () async {
      // The enqueue-time checks above are only a fast path. A mutation that was
      // queued BEFORE an earlier write became unknown must not cross the
      // uncertain boundary: re-check the latches inside the serialized
      // execution, after the tail has been awaited.
      if (_activeWrites.containsKey(storeIdentity)) {
        throw const IssuanceJournalBusy(
          'A journal write is still pending for this store',
        );
      }
      if (_uncertain.contains(storeIdentity)) {
        throw const IssuanceJournalUnknown(
          'The previous journal write outcome is unknown; resolve it first',
        );
      }
      if (_materialActive.containsKey(storeIdentity)) {
        throw const IssuanceJournalBusy('A material operation owns this store');
      }
      return await body();
    });
  }

  Future<void> _writeVerified(
    String storeIdentity,
    Map<String, String> expected,
  ) async {
    _validateVaultSize(expected);
    final revisionValue = int.parse(expected['revision']!);
    if (revisionValue < 0 || revisionValue > issuanceRevisionMax) {
      throw const FormatException('Issuance revision out of bounds');
    }
    final frame = jsonEncode({
      'v': 1,
      'id': vaultId(storeIdentity),
      'store': storeIdentity,
      'rev': int.parse(expected['revision']!),
      'data': expected,
    });
    if (utf8.encode(frame).length > issuanceJournalMaxBytes) {
      throw const FormatException('Issuance B frame too large');
    }
    final previous = await read(vaultId(storeIdentity));
    final token = Object();
    _activeWrites[storeIdentity] = token;
    _intended[storeIdentity] = Map<String, String>.of(expected);
    _previous[storeIdentity] = previous == null
        ? null
        : Map<String, String>.of(previous);
    var confirmed = false;
    try {
      await write(vaultId(storeIdentity), Map<String, String>.of(expected));
      final actual = await read(vaultId(storeIdentity));
      if (!_sameMap(actual, expected)) {
        throw const IssuanceJournalUnknown(
          'Journal read-back did not confirm the write',
        );
      }
      // `write` is contractually durable on success, so a matching read-back
      // after a successful write is the acknowledged record. A write that threw
      // is caught by the latch below, never classified by read-back alone.
      confirmed = true;
    } finally {
      // Ownership token: this completion must not delete a claim belonging to
      // another operation.
      if (identical(_activeWrites[storeIdentity], token)) {
        _activeWrites.remove(storeIdentity);
      }
      if (confirmed) {
        _clearLatch(storeIdentity);
      } else {
        _uncertain.add(storeIdentity);
      }
    }
  }

  void _clearLatch(String storeIdentity) {
    _uncertain.remove(storeIdentity);
    _intended.remove(storeIdentity);
    _previous.remove(storeIdentity);
  }

  static void _checkTransition(IssuancePhase from, IssuancePhase to) {
    final allowed = issuancePhaseTransitions[from];
    if (allowed == null || !allowed.contains(to)) {
      throw IssuanceJournalConflict('Invalid phase transition $from -> $to');
    }
  }

  static String _encodeReceipt(Map<String, Object?> receipt) {
    final encoded = jsonEncode(receipt);
    if (utf8.encode(encoded).length > issuanceReceiptMaxBytes) {
      throw const FormatException('Issuance receipt too large');
    }
    return encoded;
  }

  static void _validateVaultSize(Map<String, String> value) {
    var total = 0;
    for (final entry in value.entries) {
      total += utf8.encode(entry.key).length + utf8.encode(entry.value).length;
    }
    if (total > issuanceJournalMaxBytes) {
      throw const FormatException('Issuance journal record too large');
    }
  }

  static bool _sameMap(
    Map<String, String>? left,
    Map<String, String>? right,
  ) {
    if (left == null || right == null) return left == null && right == null;
    if (left.length != right.length) return false;
    for (final entry in left.entries) {
      if (right[entry.key] != entry.value) return false;
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

void _validateMaterial(Map<String, String> material, {bool v2 = false}) {
  if (!material.containsKey('capsuleRecipientPrivateKey')) {
    throw const FormatException('Missing capsule recipient private key');
  }
  final allowed = v2
      ? {...issuanceMaterialKinds, 'xrayUuid', 'shadowsocksKey'}
      : issuanceMaterialKinds;
  if (material.length > allowed.length) {
    throw const FormatException('Unknown issuance material entry');
  }
  for (final entry in material.entries) {
    if (!allowed.contains(entry.key)) {
      throw const FormatException('Unknown issuance material entry');
    }
    if (v2 && entry.key == 'xrayUuid') {
      if (!RegExp(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$').hasMatch(entry.value)) {
        throw const FormatException('Invalid xray uuid');
      }
      continue;
    }
    if (v2 && entry.key == 'shadowsocksKey') {
      decodeCanonicalBase64(entry.value, length: 32);
      continue;
    }
    if (_base64MaterialKinds.contains(entry.key)) {
      decodeCanonicalBase64(entry.value, length: 32);
      continue;
    }
    if (entry.key == 'managementPrivate') {
      if (entry.value.isEmpty ||
          entry.value.length > 4096 ||
          !_printableMultiline(entry.value)) {
        throw const FormatException('Invalid management private key');
      }
      continue;
    }
    if (entry.key == 'managementPublic') {
      requirePrintableAscii(entry.value);
      if (entry.value.isEmpty || entry.value.length > 256) {
        throw const FormatException('Invalid management public key');
      }
    }
  }
}

bool _printableMultiline(String value) {
  for (var index = 0; index < value.length; index++) {
    final unit = value.codeUnitAt(index);
    if (unit != 0x0a && (unit < 0x20 || unit > 0x7e)) return false;
  }
  return true;
}
