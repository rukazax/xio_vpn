import 'dart:async';

/// A2 model only. These interfaces are fake-test seams; no production caller.
const String issuanceJournalSchemaV2 = '2';
const int issuanceRevisionMax = 9007199254740991;
const int issuanceEnvelopeMaxBytes = 45056;
const int issuanceEnvelopeB64MaxChars = 60076;
const int issuancePartialMaxBytes = 16384;
const int issuancePartialMaxDepth = 8;
const int issuancePartialMaxNodes = 256;

const List<String> issuanceV2Protocols = [
  'wireguard',
  'awg',
  'rivet-h3',
  'rivet-s1',
  'xray',
  'shadowsocks',
  'openvpn',
  'cloak',
  'ikev2',
];

const Set<String> issuanceCapsuleArtifactsA2 = {
  'ikev2.password',
  'cloak.uid',
  'openvpn.client-key',
  'openvpn.tls-crypt-v2-client',
};

const Set<String> issuancePartialBackends = {
  'wireguard',
  'awg',
  'rivet',
  'xray',
  'shadowsocks',
  'openvpn',
  'cloak',
  'ikev2',
};

enum MaterialPurpose { remoteResume, localStage, localCommit, localRestart }

const Map<MaterialPurpose, Set<IssuancePhaseName>> materialPurposePhases = {
  MaterialPurpose.remoteResume: {
    IssuancePhaseName.dispatchIntent,
    IssuancePhaseName.remotePending,
  },
  MaterialPurpose.localStage: {
    IssuancePhaseName.remoteComplete,
    IssuancePhaseName.localStaged,
    IssuancePhaseName.localDurableNativeUnconfirmed,
  },
  MaterialPurpose.localCommit: {
    IssuancePhaseName.remoteComplete,
    IssuancePhaseName.localStaged,
    IssuancePhaseName.localDurableNativeUnconfirmed,
  },
  MaterialPurpose.localRestart: {
    IssuancePhaseName.remoteComplete,
    IssuancePhaseName.localStaged,
    IssuancePhaseName.localDurableNativeUnconfirmed,
  },
};

/// A duplicated phase-name enum keeps this helper free of a journal import.
enum IssuancePhaseName {
  prepared,
  dispatchIntent,
  remotePending,
  remoteComplete,
  localStaged,
  localDurableNativeUnconfirmed,
  committed,
}

/// Logical kind -> actual A material key (A-sourced kinds only).
const Map<String, String> logicalAKindMap = {
  'wireguardPrivate': 'wireguardPrivate',
  'wireguardPublic': 'wireguardPublic',
  'awgPrivate': 'awgPrivate',
  'awgPublic': 'awgPublic',
  'rivetDeviceSecret': 'deviceSecret',
  'rivetEntryToken': 'entryToken',
  'xrayUuid': 'xrayUuid',
  'shadowsocksKey': 'shadowsocksKey',
  'managementPrivate': 'managementPrivate',
  'managementPublic': 'managementPublic',
};

/// Logical kind -> actual capsule artifact key (capsule-sourced kinds only).
const Map<String, String> logicalCapsuleKindMap = {
  'ikePassword': 'ikev2.password',
  'cloakUid': 'cloak.uid',
  'openvpnClientKey': 'openvpn.client-key',
  'openvpnTlsCryptV2': 'openvpn.tls-crypt-v2-client',
};

const Set<String> remoteResumeKinds = {
  'ikePassword',
  'cloakUid',
  'rivetDeviceSecret',
  'rivetEntryToken',
  'xrayUuid',
  'shadowsocksKey',
};

const Set<String> localMaterialKinds = {
  'wireguardPrivate',
  'wireguardPublic',
  'awgPrivate',
  'awgPublic',
  'rivetDeviceSecret',
  'rivetEntryToken',
  'xrayUuid',
  'shadowsocksKey',
  'managementPrivate',
  'managementPublic',
};

abstract interface class ExpectedDeliveryBinding {
  Future<ExpectedBinding> resolve({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required String requestDigest,
    required List<String> protocols,
  });
}

final class ExpectedBinding {
  ExpectedBinding({
    required this.deployment,
    required this.profileSetDigest,
  }) {
    if (deployment.isEmpty ||
        deployment.length > 128 ||
        !RegExp(r'^[\x20-\x7e]+$').hasMatch(deployment)) {
      throw const FormatException('Invalid expected deployment');
    }
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(profileSetDigest)) {
      throw const FormatException('Invalid expected profile set digest');
    }
  }

  final String deployment;
  final String profileSetDigest;
}

abstract interface class MaterialAuthority {
  /// Fresh owner/transport verification. Must be called before handoff.
  Future<void> acquire({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required MaterialPurpose purpose,
    required int revision,
  });

  /// Cooperative cancellation; never awaits the held material tail.
  bool get cancelRequested;

  /// Synchronous final current-authority check for the context bound by the
  /// successful acquisition. Must not perform IO/await/application mutation.
  /// Returns false (or throws) on observed owner/transport revocation,
  /// context/epoch change, completed close or a different active binding.
  /// One adapter instance is dedicated to one active scope; repeated
  /// acquisition must revalidate, never silently rebind or resurrect.
  bool checkCurrent({
    required String storeIdentity,
    required String operationId,
    required String uid,
    required MaterialPurpose purpose,
    required int revision,
  });

  /// Adapter-owned cleanup. The returned future completes — with success OR
  /// error — ONLY after every adapter-owned piece of work/resource is
  /// physically settled. An error completion is a settled failed cleanup, not
  /// an unknown/live state. If settlement is unknown, the future must remain
  /// pending. The operation awaits this inside its B admission.
  Future<void> close();
}

abstract interface class MaterialSettlementTicket {
  void settled();
  void uncertain(String code);
  bool get isSettled;
  String? get diagnosticCode;
}

abstract interface class MaterialObserver {
  void onDiagnostic(String code);
  void onCancelRequested();
}

/// Closed redacted diagnostic codes for A2 scaffolding.
const Set<String> issuanceMaterialDiagnostics = {
  'SETTLEMENT_UNKNOWN',
  'CALLBACK_REENTRANT',
  'WRONG_PROVIDER',
  'MATERIAL_BUSY',
  'CERTIFICATE_DEPENDENT_ASSEMBLY_UNAVAILABLE',
  'IDENTITY_MISMATCH',
  'PIN_REQUIRED',
  'ARTIFACT_UNSUPPORTED',
  'PARTIAL_CONFLICT',
  'PARTIAL_INVALID',
};
