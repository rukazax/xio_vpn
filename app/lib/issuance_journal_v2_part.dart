part of 'issuance_journal.dart';

// A2 passive journal-v2/scoped-material implementation. No production callers.
// This part is deliberately internal to the journal library so it can reuse the
// existing serialization/uncertainty domain without widening A's public surface.

String _preparedIdentityDigest(IssuanceRecord record) => sha256Hex(utf8.encode(
  canonicalJsonV1({
    'schema': 1,
    'storeIdentity': record.storeIdentity,
    'operationId': record.operationId,
    'uid': record.uid,
    'requestDigest': record.requestDigest,
    'recipientPublicKey': base64Encode(record._capsuleRecipientPublicKey),
    'deployment': record._v2['deployment']!,
    'profileSetDigest': record._v2['profileSetDigest']!,
  }),
));

String _postPinIdentityDigest(IssuanceRecord record) => sha256Hex(utf8.encode(
  canonicalJsonV1({
    'schema': 1,
    'storeIdentity': record.storeIdentity,
    'operationId': record.operationId,
    'uid': record.uid,
    'requestDigest': record.requestDigest,
    'recipientPublicKey': base64Encode(record._capsuleRecipientPublicKey),
    'deployment': record._v2['deployment']!,
    'profileSetDigest': record._v2['profileSetDigest']!,
    'capsuleContextSha256': record._v2['capsuleContextSha256']!,
  }),
));

List<String> _requestProtocols(IssuanceRecord record) {
  final request = record.request;
  final value = request['protocols'];
  if (value is! List ||
      value.isEmpty ||
      value.any((entry) => entry is! String) ||
      value.toSet().length != value.length ||
      value.any((entry) => !issuanceV2Protocols.contains(entry))) {
    throw const FormatException('Invalid v2 request protocols');
  }
  return value.cast<String>();
}

Set<String> _selectedBackends(IssuanceRecord record) {
  const map = {
    'wireguard': 'wireguard',
    'awg': 'awg',
    'rivet-h3': 'rivet',
    'rivet-s1': 'rivet',
    'xray': 'xray',
    'shadowsocks': 'shadowsocks',
    'openvpn': 'openvpn',
    'cloak': 'cloak',
    'ikev2': 'ikev2',
  };
  return {for (final protocol in _requestProtocols(record)) map[protocol]!};
}

bool _certificateDependent(IssuanceRecord record) {
  final protocols = _requestProtocols(record).toSet();
  return protocols.contains('openvpn') || protocols.contains('ikev2');
}

void _validateV2FlatFields(Map<String, String> raw) {
  final deployment = raw['deployment']!;
  if (deployment.isEmpty ||
      deployment.length > 128 ||
      !RegExp(r'^[\x20-\x7e]+$').hasMatch(deployment)) {
    throw const FormatException('Invalid deployment');
  }
  if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(raw['profileSetDigest']!)) {
    throw const FormatException('Invalid profile set digest');
  }
  const pinKeys = [
    'capsuleEnvelopeB64',
    'capsuleEnvelopeSha256',
    'capsuleId',
    'capsuleCiphertextDigest',
    'capsuleContextSha256',
    'capsulePlaintextSha256',
    'capsuleArtifactKinds',
  ];
  final present = raw['capsuleEnvelopeB64']!.isNotEmpty;
  if (!present && pinKeys.any((key) => raw[key]!.isNotEmpty)) {
    throw const FormatException('Partial pin representation');
  }
  if (present && pinKeys.any((key) => raw[key]!.isEmpty)) {
    throw const FormatException('Incomplete pin representation');
  }
  if (!present && raw['partialReceiptJson']!.isNotEmpty) {
    throw const FormatException('Partial without pin');
  }
  if (present) {
    if (raw['capsuleEnvelopeB64']!.length > issuanceEnvelopeB64MaxChars) {
      throw const FormatException('Envelope encoding too large');
    }
    final envelope = decodeCanonicalBase64Any(
      raw['capsuleEnvelopeB64']!,
      maxLength: issuanceEnvelopeMaxBytes,
    );
    if (base64Encode(envelope) != raw['capsuleEnvelopeB64']) {
      throw const FormatException('Invalid envelope encoding');
    }
    for (final key in [
      'capsuleEnvelopeSha256',
      'capsuleCiphertextDigest',
      'capsuleContextSha256',
      'capsulePlaintextSha256',
    ]) {
      if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(raw[key]!)) {
        throw const FormatException('Invalid pin digest');
      }
    }
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(raw['capsuleId']!)) {
      throw const FormatException('Invalid capsule id');
    }
    final kinds = jsonDecode(raw['capsuleArtifactKinds']!);
    if (kinds is! List ||
        kinds.isEmpty ||
        kinds.length > 4 ||
        kinds.any((kind) => kind is! String || !issuanceCapsuleArtifactsA2.contains(kind)) ||
        kinds.toSet().length != kinds.length ||
        canonicalJsonV1(kinds) != raw['capsuleArtifactKinds']) {
      throw const FormatException('Invalid capsule artifact kinds');
    }
  }
  if (raw['partialReceiptJson']!.isNotEmpty) {
    IssuancePartialReceipt.parse(raw['partialReceiptJson']!);
  }
}

extension IssuanceRecordV2 on IssuanceRecord {
  String get deployment => _v2['deployment']!;
  String get profileSetDigest => _v2['profileSetDigest']!;
  String get capsuleEnvelopeB64 => _v2['capsuleEnvelopeB64']!;
  String get capsuleEnvelopeSha256 => _v2['capsuleEnvelopeSha256']!;
  String get capsuleId => _v2['capsuleId']!;
  String get capsuleCiphertextDigest => _v2['capsuleCiphertextDigest']!;
  String get capsuleContextSha256 => _v2['capsuleContextSha256']!;
  String get capsulePlaintextSha256 => _v2['capsulePlaintextSha256']!;
  String get capsuleArtifactKindsJson => _v2['capsuleArtifactKinds']!;
  String get partialReceiptJson => _v2['partialReceiptJson']!;
  bool get hasPin => _v2['capsuleEnvelopeB64']!.isNotEmpty;
  String get preparedIdentityDigest => _preparedIdentityDigest(this);
  String get postPinIdentityDigest => _postPinIdentityDigest(this);
}

extension IssuanceJournalV2 on IssuanceJournalStore {

Future<IssuanceRecord> prepareV2({
  required String storeIdentity,
  required String uid,
  required String serverId,
  required String sshFingerprint,
  required String actor,
  required Map<String, Object?> request,
  required Map<String, String> material,
  required Uint8List capsuleRecipientPublicKey,
  required ExpectedDeliveryBinding binding,
  String? operationId,
}) async {
  if (!isLowerHex(uid, length: 32) ||
      !isLowerHex(storeIdentity, length: 64)) {
    throw const FormatException('Invalid issuance identity');
  }
  if (capsuleRecipientPublicKey.length != 32) {
    throw const FormatException('Invalid capsule recipient key');
  }
  final requestJson = canonicalJsonV1(request);
  if (requestJson.isEmpty ||
      utf8.encode(requestJson).length > issuanceRequestMaxBytes) {
    throw const FormatException('Issuance request size out of bounds');
  }
  final requestValue =
      Map<String, Object?>.from(jsonDecode(requestJson) as Map);
  final protocols = requestValue['protocols'];
  if (protocols is! List ||
      protocols.isEmpty ||
      protocols.any((entry) => entry is! String) ||
      protocols.toSet().length != protocols.length ||
      protocols.any((entry) => !issuanceV2Protocols.contains(entry)) ||
      protocols.contains('rivet') ||
      protocols.contains('management') ||
      protocols.contains('mesh')) {
    throw const FormatException('Invalid v2 request protocols');
  }
  final materialSnapshot = Map<String, String>.of(material);
  final recipientSnapshot = Uint8List.fromList(capsuleRecipientPublicKey);
  _validateMaterial(materialSnapshot, v2: true);
  final requestDigest = issuanceRequestDigest(requestValue);
  final id = operationId ?? IssuanceJournalStore._randomHex(16);
  if (!isLowerHex(id, length: 32)) {
    throw const FormatException('Invalid issuance operation id');
  }
  for (final value in [serverId, sshFingerprint, actor]) {
    requirePrintableAscii(value);
    if (value.isEmpty || value.length > 256) {
      throw const FormatException('Invalid issuance journal field');
    }
  }
  final expected = await binding.resolve(
    storeIdentity: storeIdentity,
    operationId: id,
    uid: uid,
    requestDigest: requestDigest,
    protocols: List<String>.unmodifiable(protocols.cast<String>()),
  );
  return this._mutate(storeIdentity, () async {
    final existingRaw = await read(IssuanceJournalStore.vaultId(storeIdentity));
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
      requestJson: requestJson,
      phase: IssuancePhase.prepared,
      dispatchIntent: false,
      flags: const {},
      material: materialSnapshot,
      capsuleRecipientPublicKey: recipientSnapshot,
      capsuleDigest: '',
      errorCode: '',
      localSnapshotDigest: '',
      receiptJson: '',
      v2: {
        for (final key in issuanceV2FlatFields) key: '',
        'deployment': expected.deployment,
        'profileSetDigest': expected.profileSetDigest,
      },
    );
    await _writeVerified(storeIdentity, record._toVault());
    return record;
  });
}

Future<IssuanceRecord> pinFirstCapsule({
  required String storeIdentity,
  required String operationId,
  required String uid,
  required int expectedRevision,
  required String expectedIdentityDigest,
  required String envelopeBytesB64,
  required String envelopeSha256,
  required String capsuleId,
  required String ciphertextDigest,
  required String contextSha256,
  required String plaintextSha256,
  required List<String> artifactKinds,
  String? partialReceiptJson,
  required MaterialAuthority authority,
}) async {
  return this._mutate(storeIdentity, () async {
    var current = await _loadFresh(storeIdentity);
    _requireIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
    _requireRecordUsable(current);
    if (current.phase != IssuancePhase.dispatchIntent &&
        current.phase != IssuancePhase.remotePending) {
      throw const IssuanceJournalConflict('First pin phase is not pending');
    }
    try {
      await authority.acquire(
      storeIdentity: storeIdentity,
      operationId: operationId,
      uid: uid,
      purpose: MaterialPurpose.remoteResume,
        revision: expectedRevision,
      );
    } catch (error) {
      try {
        await authority.close();
      } catch (_) {}
      rethrow;
    }
    try {
      current = await _loadFresh(storeIdentity);
      _requireIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
      _requireRecordUsable(current);
      if (authority.cancelRequested) {
        throw const IssuanceJournalConflict('Capsule pin cancelled');
      }
      if (current._v2['capsuleEnvelopeB64']!.isNotEmpty) {
        final same = current._v2['capsuleEnvelopeB64'] == envelopeBytesB64 &&
            current._v2['capsuleEnvelopeSha256'] == envelopeSha256 &&
            current._v2['capsuleId'] == capsuleId &&
            current._v2['capsuleCiphertextDigest'] == ciphertextDigest &&
            current._v2['capsuleContextSha256'] == contextSha256 &&
            current._v2['capsulePlaintextSha256'] == plaintextSha256 &&
            current._v2['capsuleArtifactKinds'] == canonicalJsonV1(artifactKinds) &&
            (partialReceiptJson == null ||
                current._v2['partialReceiptJson'] == partialReceiptJson);
        if (!same) {
          throw const IssuanceJournalConflict('Capsule pin conflict');
        }
        return current;
      }
      if (envelopeBytesB64.length > issuanceEnvelopeB64MaxChars) {
        throw const FormatException('Envelope encoding too large');
      }
      final envelopeBytes = decodeCanonicalBase64Any(
        envelopeBytesB64,
        maxLength: issuanceEnvelopeMaxBytes,
      );
      if (base64Encode(envelopeBytes) != envelopeBytesB64) {
        throw const FormatException('Invalid envelope base64');
      }
      final envelopeJson = jsonDecode(utf8.decode(envelopeBytes));
      if (envelopeJson is! Map) {
        throw const FormatException('Invalid envelope bytes');
      }
      final envelope = CapsuleEnvelope.parseStrict(
        Map<String, Object?>.from(envelopeJson),
      );
      final expectedContext = _expectedContext(current);
      final privateRaw = current._material['capsuleRecipientPrivateKey']!;
      final privateKey = decodeCanonicalBase64(privateRaw, length: 32);
      final opened = CapsuleCodec.open(
        envelope: envelope,
        recipientPrivateKey: privateKey,
        expectedRecipientPublicKey: current._capsuleRecipientPublicKey,
        expected: expectedContext,
      );
      if (opened is! CapsuleOpened) {
        throw const IssuanceJournalConflict('Capsule open rejected');
      }
      final actualEnvelopeSha = sha256Hex(envelopeBytes);
      final actualCipher = sha256Hex(envelope.ciphertext);
      final actualContextSha = sha256Hex(utf8.encode(expectedContext.canonical));
      final actualKinds = opened.artifacts.keys.toList()..sort();
      if (actualEnvelopeSha != envelopeSha256 ||
          envelope.capsuleId != capsuleId ||
          actualCipher != ciphertextDigest ||
          actualContextSha != contextSha256 ||
          opened.plaintextSha256 != plaintextSha256) {
        throw const IssuanceJournalConflict('Capsule assertion mismatch');
      }
      for (final entry in opened.artifacts.entries) {
        _validateCapsuleArtifactValue(entry.key, entry.value);
      }
      if (!actualKinds.every(issuanceCapsuleArtifactsA2.contains) ||
          actualKinds.length != actualKinds.toSet().length ||
          actualKinds.isEmpty ||
          canonicalJsonV1(artifactKinds) != canonicalJsonV1(actualKinds)) {
        throw const IssuanceJournalConflict('Unsupported capsule artifacts');
      }
      IssuancePartialReceipt? partial;
      final pinV2 = <String, String>{
        ...current._v2,
        'capsuleEnvelopeB64': envelopeBytesB64,
        'capsuleEnvelopeSha256': envelopeSha256,
        'capsuleId': capsuleId,
        'capsuleCiphertextDigest': ciphertextDigest,
        'capsuleContextSha256': contextSha256,
        'capsulePlaintextSha256': plaintextSha256,
        'capsuleArtifactKinds': canonicalJsonV1(actualKinds),
      };
      if (partialReceiptJson != null && partialReceiptJson.isNotEmpty) {
        partial = IssuancePartialReceipt.parse(partialReceiptJson);
        _validatePartial(
          current._copyWith(v2: pinV2),
          partial,
          firstPin: true,
        );
      }
      final next = current._copyWith(
        revision: current.revision + 1,
        v2: {
          ...current._v2,
          'capsuleEnvelopeB64': envelopeBytesB64,
          'capsuleEnvelopeSha256': envelopeSha256,
          'capsuleId': capsuleId,
          'capsuleCiphertextDigest': ciphertextDigest,
          'capsuleContextSha256': contextSha256,
          'capsulePlaintextSha256': plaintextSha256,
          'capsuleArtifactKinds': canonicalJsonV1(actualKinds),
          'partialReceiptJson': partialReceiptJson ?? '',
        },
      );
      await _writeVerified(storeIdentity, next._toVault());
      return next;
    } finally {
      await authority.close();
    }
  });
}

Future<IssuanceRecord> recordPartialReceipt({
  required String storeIdentity,
  required String operationId,
  required String uid,
  required int expectedRevision,
  required String expectedIdentityDigest,
  required String partialReceiptJson,
  required MaterialAuthority authority,
}) async {
  return this._mutate(storeIdentity, () async {
    var current = await _loadFresh(storeIdentity);
    _requirePostPinIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
    _requireRecordUsable(current);
    try {
      await authority.acquire(
        storeIdentity: storeIdentity,
        operationId: operationId,
        uid: uid,
        purpose: MaterialPurpose.localStage,
        revision: expectedRevision,
      );
    } catch (error) {
      try {
        await authority.close();
      } catch (_) {}
      rethrow;
    }
    try {
      current = await _loadFresh(storeIdentity);
      _requirePostPinIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
      _requireRecordUsable(current);
      if (authority.cancelRequested) {
        throw const IssuanceJournalConflict('Partial receipt cancelled');
      }
      final partial = IssuancePartialReceipt.parse(partialReceiptJson);
      _validatePartial(current, partial);
      if (current._v2['partialReceiptJson'] == partialReceiptJson) {
        return current;
      }
      final next = current._copyWith(
        revision: current.revision + 1,
        v2: {...current._v2, 'partialReceiptJson': partialReceiptJson},
      );
      await _writeVerified(storeIdentity, next._toVault());
      return next;
    } finally {
      await authority.close();
    }
  });
}

Future<void> withMaterial({
  required String storeIdentity,
  required String operationId,
  required String uid,
  required int expectedRevision,
  required String expectedIdentityDigest,
  required MaterialPurpose purpose,
  required Set<String> requestedKinds,
  required MaterialAuthority authority,
  MaterialObserver? observer,
  required Future<void> Function(Map<String, String>, MaterialSettlementTicket) body,
}) async {
  final vault = _vault;
  final lease = vault?.lease;
  if (vault == null || lease == null || vault.storeIdentity != storeIdentity) {
    throw const IssuanceJournalConflict('Wrong provider or unbound store');
  }
  final token = Object();
  final requested = Set<String>.unmodifiable(Set<String>.of(requestedKinds));
  // Join A's existing serialized domain so an already-admitted preceding
  // mutation cannot advance the journal while this material scope runs.
  await this._serialize(storeIdentity, () async {
    if (IssuanceJournalStore._activeWrites.containsKey(storeIdentity)) {
      throw const IssuanceJournalBusy(
        'A journal write is still pending for this store',
      );
    }
    if (IssuanceJournalStore._uncertain.contains(storeIdentity)) {
      throw const IssuanceJournalUnknown(
        'The previous journal write outcome is unknown; resolve it first',
      );
    }
    if (IssuanceJournalStore._materialActive.containsKey(storeIdentity)) {
      throw const IssuanceJournalBusy('A material operation is active');
    }
    IssuanceJournalStore._materialActive[storeIdentity] = token;
  });
  var entered = false;
  var handedOff = false;
  var authorityAcquired = false;
  var closed = false;
  Object? bodyError;
  _MaterialTicket? ticket;
  try {
    await lease.admit(() async {
      entered = true;
      var current = await _loadFresh(storeIdentity);
      _requirePostPinIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
      _requireRecordUsable(current);
      _checkMaterialPurpose(current, purpose, requested);
      try {
        await authority.acquire(
          storeIdentity: storeIdentity,
          operationId: operationId,
          uid: uid,
          purpose: purpose,
          revision: expectedRevision,
        );
        authorityAcquired = true;
      } catch (error) {
        if (!closed) {
          try {
            await authority.close();
          } finally {
            closed = true;
          }
        }
        rethrow;
      }
      try {
        // FINAL authenticated journal view after the awaited authority step.
        current = await _loadFresh(storeIdentity);
        _requirePostPinIdentity(current, operationId, uid, expectedRevision, expectedIdentityDigest);
        _requireRecordUsable(current);
        _checkMaterialPurpose(current, purpose, requested);
        if (IssuanceJournalStore._uncertain.contains(storeIdentity) ||
            !identical(IssuanceJournalStore._materialActive[storeIdentity], token)) {
          throw const IssuanceJournalConflict('Material scope fence changed');
        }
        if (authority.cancelRequested) {
          throw const IssuanceJournalConflict('Material use cancelled');
        }
        // Pure synchronous derivation from the FINAL record; no stale artifact
        // reuse and no await before handoff.
        final artifacts = _materialArtifactsSync(current, purpose, requested);
        final bool currentAuthority;
        try {
          currentAuthority = authority.checkCurrent(
            storeIdentity: storeIdentity,
            operationId: operationId,
            uid: uid,
            purpose: purpose,
            revision: current.revision,
          );
        } catch (_) {
          throw const IssuanceJournalConflict(
            'Current authority check failed',
          );
        }
        if (!currentAuthority) {
          throw const IssuanceJournalConflict(
            'Current authority check failed',
          );
        }
        ticket = _MaterialTicket();
        handedOff = true;
        try {
          await body(
            Map<String, String>.unmodifiable(artifacts),
            ticket!,
          );
        } catch (error) {
          bodyError = error;
        }
        if (!ticket!.isSettled) {
          try {
            observer?.onDiagnostic('SETTLEMENT_UNKNOWN');
          } catch (_) {}
          await ticket!.settledSignal;
        }
        try {
          await authority.close();
        } finally {
          closed = true;
        }
        if (bodyError != null) throw bodyError!;
      } catch (error) {
        if (!handedOff && authorityAcquired && !closed) {
          try {
            await authority.close();
          } finally {
            closed = true;
          }
        }
        rethrow;
      }
    });
  } catch (error) {
    if (!entered || !handedOff) {
      if (identical(IssuanceJournalStore._materialActive[storeIdentity], token)) {
        IssuanceJournalStore._materialActive.remove(storeIdentity);
      }
      rethrow;
    }
    rethrow;
  } finally {
    if (entered && handedOff && ticket != null &&
        ticket!.isSettled && closed) {
      if (identical(IssuanceJournalStore._materialActive[storeIdentity], token)) {
        IssuanceJournalStore._materialActive.remove(storeIdentity);
      }
    }
  }
}
Future<IssuanceRecord> _loadFresh(String storeIdentity) async {
  final raw = await _vaultRead(storeIdentity);
  if (raw == null) {
    throw const IssuanceJournalConflict('Issuance journal record disappeared');
  }
  final record = IssuanceRecord._parse(raw);
  if (record.storeIdentity != storeIdentity) {
    throw const FormatException('Issuance journal identity mismatch');
  }
  return record;
}

Future<Map<String, String>?> _vaultRead(String storeIdentity) {
  // The bound store and legacy callbacks are the same read path.
  return read(IssuanceJournalStore.vaultId(storeIdentity));
}

void _requireIdentity(
  IssuanceRecord record,
  String operationId,
  String uid,
  int expectedRevision,
  String expectedIdentity,
) {
  if (record.operationId != operationId ||
      record.uid != uid ||
      record.revision != expectedRevision ||
      _preparedIdentityDigest(record) != expectedIdentity) {
    throw const IssuanceJournalConflict('Prepared identity/revision mismatch');
  }
}

void _requirePostPinIdentity(
  IssuanceRecord record,
  String operationId,
  String uid,
  int expectedRevision,
  String expectedIdentity,
) {
  if (record._v2['capsuleEnvelopeB64']!.isEmpty) {
    throw const IssuanceJournalConflict('Pin required');
  }
  if (record.operationId != operationId ||
      record.uid != uid ||
      record.revision != expectedRevision ||
      _postPinIdentityDigest(record) != expectedIdentity) {
    throw const IssuanceJournalConflict('Post-pin identity/revision mismatch');
  }
}

CapsuleContext _expectedContext(IssuanceRecord record) {
  if (record.serverId.length > 128 || record.actor.length > 128) {
    throw const FormatException('Capsule context field too long');
  }
  return CapsuleContext(
    operation: record.operationId,
    uid: record.uid,
    server: record.serverId,
    deployment: record._v2['deployment']!,
    actor: record.actor,
    requestDigest: record.requestDigest,
    profileSetDigest: record._v2['profileSetDigest']!,
  );
}

Map<String, String> _materialArtifactsSync(
  IssuanceRecord record,
  MaterialPurpose purpose,
  Set<String> requested,
) {
  if (requested.isEmpty) {
    throw const FormatException('Empty material request');
  }
  final out = <String, String>{};
  for (final logical in requested) {
    if (logicalCapsuleKindMap.containsKey(logical)) {
      if (purpose != MaterialPurpose.remoteResume ||
          !const {'ikePassword', 'cloakUid'}.contains(logical)) {
        throw const IssuanceJournalConflict(
          'CERTIFICATE_DEPENDENT_ASSEMBLY_UNAVAILABLE',
        );
      }
      continue;
    }
    final key = logicalAKindMap[logical];
    if (key == null || !record._material.containsKey(key)) {
      throw const IssuanceJournalConflict('Requested material absent');
    }
    out[logical] = record._material[key]!;
  }
  final capsuleKinds = requested
      .where(logicalCapsuleKindMap.containsKey)
      .map((logical) => logicalCapsuleKindMap[logical]!)
      .toSet();
  if (capsuleKinds.isEmpty) return out;
  final envelopeBytes = decodeCanonicalBase64Any(
    record._v2['capsuleEnvelopeB64']!,
    maxLength: issuanceEnvelopeMaxBytes,
  );
  final envelopeJson = jsonDecode(utf8.decode(envelopeBytes));
  final envelope = CapsuleEnvelope.parseStrict(
    Map<String, Object?>.from(envelopeJson as Map),
  );
  final expected = _expectedContext(record);
  final privateKey = decodeCanonicalBase64(
    record._material['capsuleRecipientPrivateKey']!,
    length: 32,
  );
  final opened = CapsuleCodec.open(
    envelope: envelope,
    recipientPrivateKey: privateKey,
    expectedRecipientPublicKey: record._capsuleRecipientPublicKey,
    expected: expected,
  );
  if (opened is! CapsuleOpened ||
      opened.plaintextSha256 != record._v2['capsulePlaintextSha256'] ||
      sha256Hex(envelope.ciphertext) != record._v2['capsuleCiphertextDigest'] ||
      sha256Hex(envelopeBytes) != record._v2['capsuleEnvelopeSha256'] ||
      envelope.capsuleId != record._v2['capsuleId'] ||
      sha256Hex(utf8.encode(expected.canonical)) !=
          record._v2['capsuleContextSha256']) {
    throw const IssuanceJournalConflict('Pinned capsule verification failed');
  }
  final actualKinds = opened.artifacts.keys.toList()..sort();
  final pinnedKinds =
      (jsonDecode(record._v2['capsuleArtifactKinds']!) as List)
          .cast<String>()
          .toSet();
  if (canonicalJsonV1(actualKinds) != record._v2['capsuleArtifactKinds']) {
    throw const IssuanceJournalConflict('Pinned artifact set changed');
  }
  for (final entry in opened.artifacts.entries) {
    _validateCapsuleArtifactValue(entry.key, entry.value);
  }
  if (!capsuleKinds.every(pinnedKinds.contains)) {
    throw const IssuanceJournalConflict('Artifact not pinned');
  }
  for (final logical in requested) {
    final artifactKey = logicalCapsuleKindMap[logical];
    if (artifactKey == null) continue;
    final value = opened.artifacts[artifactKey];
    if (value == null) {
      throw const IssuanceJournalConflict('Requested artifact absent');
    }
    out[logical] = value;
  }
  return out;
}

void _requireRecordUsable(IssuanceRecord record) {
  const blocked = {
    'cancelRequested',
    'cancelledConfirmed',
    'repairRequired',
    'identityConflict',
  };
  if (record.flags.any((flag) => blocked.contains(flag))) {
    throw const IssuanceJournalConflict('Record flags forbid material use');
  }
}

Set<String> _selectedLogicalKinds(IssuanceRecord record) {
  final protocols = _requestProtocols(record).toSet();
  final selected = <String>{};
  if (protocols.contains('ikev2')) selected.add('ikePassword');
  if (protocols.contains('cloak')) selected.add('cloakUid');
  if (protocols.contains('rivet-h3') || protocols.contains('rivet-s1')) {
    selected.addAll({'rivetDeviceSecret', 'rivetEntryToken'});
  }
  if (protocols.contains('xray')) selected.add('xrayUuid');
  if (protocols.contains('shadowsocks')) selected.add('shadowsocksKey');
  if (protocols.contains('wireguard')) {
    selected.addAll({'wireguardPrivate', 'wireguardPublic'});
  }
  if (protocols.contains('awg')) selected.addAll({'awgPrivate', 'awgPublic'});
  selected.addAll({'managementPrivate', 'managementPublic'});
  return selected;
}

void _validateCapsuleArtifactValue(String key, String value) {
  switch (key) {
    case 'ikev2.password':
      if (value.isEmpty || utf8.encode(value).length > 128) {
        throw const FormatException('IKE password out of bounds');
      }
      return;
    case 'cloak.uid':
      decodeCanonicalBase64(value, length: 16);
      return;
    case 'openvpn.client-key':
    case 'openvpn.tls-crypt-v2-client':
      if (value.isEmpty ||
          value.length > 4096 ||
          !_printableCapsuleArtifact(value)) {
        throw const FormatException('OpenVPN artifact out of bounds');
      }
      return;
    default:
      throw const FormatException('Unsupported capsule artifact');
  }
}

bool _printableCapsuleArtifact(String value) {
  for (var index = 0; index < value.length; index++) {
    final unit = value.codeUnitAt(index);
    if (unit != 0x0a && (unit < 0x20 || unit > 0x7e)) return false;
  }
  return true;
}
void _checkMaterialPurpose(
  IssuanceRecord record,
  MaterialPurpose purpose,
  Set<String> requested,
) {
  final allowed = switch (purpose) {
    MaterialPurpose.remoteResume => remoteResumeKinds,
    _ => localMaterialKinds,
  };
  if (requested.isEmpty || !requested.every(allowed.contains)) {
    throw const IssuanceJournalConflict('Requested kind not allowed');
  }
  final selected = _selectedLogicalKinds(record);
  if (!requested.every(selected.contains)) {
    throw const IssuanceJournalConflict('Requested kind not selected');
  }
  final now = record.phase.name;
  if (!materialPurposePhases[purpose]!.any((phase) => phase.name == now)) {
    throw const IssuanceJournalConflict('Purpose phase mismatch');
  }
  if (purpose == MaterialPurpose.localCommit ||
      purpose == MaterialPurpose.localRestart) {
    if (_certificateDependent(record)) {
      throw const IssuanceJournalConflict(
        'CERTIFICATE_DEPENDENT_ASSEMBLY_UNAVAILABLE',
      );
    }
  }
  if (purpose != MaterialPurpose.remoteResume &&
      requested.any(logicalCapsuleKindMap.containsKey)) {
    throw const IssuanceJournalConflict(
      'CERTIFICATE_DEPENDENT_ASSEMBLY_UNAVAILABLE',
    );
  }
}

void _validatePartial(
  IssuanceRecord record,
  IssuancePartialReceipt partial, {
  bool firstPin = false,
}) {
  if (partial.operationId != record.operationId ||
      partial.uid != record.uid ||
      partial.deploymentId != record._v2['deployment'] ||
      partial.phase != record.phase.name ||
      partial.capsuleId != record._v2['capsuleId'] ||
      partial.ciphertextDigest != record._v2['capsuleCiphertextDigest'] ||
      partial.envelopeSha256 != record._v2['capsuleEnvelopeSha256'] ||
      partial.envelopeSize !=
          decodeCanonicalBase64Any(
            record._v2['capsuleEnvelopeB64']!,
            maxLength: issuanceEnvelopeMaxBytes,
          ).length) {
    throw const IssuanceJournalConflict('Partial identity mismatch');
  }
  final selected = _selectedBackends(record);
  if (partial.backends.keys.toSet().length != partial.backends.length ||
      !partial.backends.keys.toSet().containsAll(selected) ||
      partial.backends.length != selected.length) {
    throw const IssuanceJournalConflict('Partial backend set mismatch');
  }
  if (partial.materialRequested) {
    final purpose = MaterialPurpose.values.firstWhere(
      (value) => value.name == partial.materialPurpose,
      orElse: () => throw const IssuanceJournalConflict('Invalid purpose'),
    );
    _checkMaterialPurpose(record, purpose, partial.materialKinds.toSet());
    if (partial.materialKinds.isEmpty ||
        partial.materialKinds.toSet().length != partial.materialKinds.length) {
      throw const IssuanceJournalConflict('Invalid partial kinds');
    }
  }
  if (partial.csrPresent && partial.csrCn != record.uid) {
    throw const IssuanceJournalConflict('CSR CN mismatch');
  }
  if (!firstPin) {
    final rawOld = record._v2['partialReceiptJson']!;
    if (rawOld.isNotEmpty) {
      final old = IssuancePartialReceipt.parse(rawOld);
      for (final entry in old.backends.entries) {
        final next = partial.backends[entry.key];
        if (next == null) {
          throw const IssuanceJournalConflict('Backend removed');
        }
        if (entry.value != 'pending' && entry.value != next) {
          throw const IssuanceJournalConflict('Terminal backend changed');
        }
      }
      if (old.csrPresent) {
        if (!partial.csrPresent ||
            old.csrSha256 != partial.csrSha256 ||
            old.csrSpkiSha256 != partial.csrSpkiSha256 ||
            old.csrCn != partial.csrCn) {
          throw const IssuanceJournalConflict('CSR changed after present');
        }
      } else if (partial.csrPresent) {
        // absent -> present is the one explicit exception.
      }
      if (old.capsuleId != partial.capsuleId ||
          old.ciphertextDigest != partial.ciphertextDigest ||
          old.envelopeSha256 != partial.envelopeSha256) {
        throw const IssuanceJournalConflict('Capsule evidence changed');
      }
    }
  }
}

}

final class _MaterialTicket implements MaterialSettlementTicket {
  bool _settled = false;
  String? _diagnostic;
  final _signal = Completer<void>();
  Future<void> get settledSignal => _signal.future;
  @override
  void settled() {
    _settled = true;
    if (!_signal.isCompleted) _signal.complete();
  }
  @override
  void uncertain(String code) => _diagnostic = code;
  @override
  bool get isSettled => _settled;
  @override
  String? get diagnosticCode => _diagnostic;
}
