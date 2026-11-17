import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'connection_attempt.dart';
import 'connection_plan.dart';
import 'policy_publication.dart';

typedef PolicyInvoke =
    Future<Object?> Function(String method, Object? arguments);

/// Strict v1 receipt handling. A successful transport with null/legacy response
/// is not evidence of durable policy publication.
class PolicyChannel {
  PolicyChannel({
    required this.invoke,
    required this.storeIdentity,
    required this.controllerNonce,
  }) {
    if (!_store.hasMatch(storeIdentity) || !_nonce.hasMatch(controllerNonce)) {
      throw const FormatException('Invalid controller identity');
    }
  }
  static final _nonce = RegExp(r'^[a-f0-9]{32}$');
  static final _store = RegExp(r'^[a-f0-9]{64}$');
  static const Object _useCurrentGeneration = Object();
  final PolicyInvoke invoke;
  final String storeIdentity, controllerNonce;
  String? _instanceNonce;
  String? _generation;
  String? _state;
  String? _resourceState;
  bool _validationSupported = false;
  Map<String, dynamic>? _receipt;
  String? get instanceNonce => _instanceNonce;
  String? get generation => _generation;
  String? get state => _state;
  String? get resourceState => _resourceState;

  /// Desktop validation extension (WIRE-V2 §8): the helper declares it can
  /// validate the exact document/config bytes before READY. Absent means a
  /// desktop publication must fail closed instead of claiming READY.
  bool get validationSupported => _validationSupported;

  /// Native readiness is admission evidence only for this exact instance, and
  /// an unknown resource state is never admissible.
  bool get ready =>
      _state == 'ready' &&
      _resourceState == 'clean' &&
      _receipt != null;
  Map<String, dynamic>? get receipt =>
      _receipt == null ? null : Map.of(_receipt!);

  /// Typed committed identity; null until an exact ready ACK was received.
  PolicyReceipt? get committed {
    final value = _receipt;
    if (value == null || !ready) return null;
    try {
      return PolicyReceipt.parse(value);
    } catch (_) {
      return null;
    }
  }

  /// Exact documented capability fields. Go adds planSchema/validation/
  /// launchBound/resourceClaimed (and `busy` for a contention reply); legacy
  /// Android capability replies use the same core four. Unknown keys are still
  /// rejected — coordinated typed fields, not a drop-the-guard parser.
  static const _capabilityKeys = {
    'version',
    'instanceNonce',
    'state',
    'resourceState',
    'planSchema',
    'validation',
    'launchBound',
    'resourceClaimed',
    'busy',
  };

  Future<void> discover() async {
    final response = await invoke('policyCapabilities', null);
    if (response is! Map ||
        response.keys.any((key) => !_capabilityKeys.contains(key)) ||
        response['version'] != 1 ||
        response['version'] is! int ||
        response['instanceNonce'] is! String ||
        !_nonce.hasMatch(response['instanceNonce'] as String) ||
        !const ['blocked', 'ready', 'pending', 'absent'].contains(response['state']) ||
        !const ['clean', 'owned', 'unknown'].contains(response['resourceState']) ||
        (response['planSchema'] != null &&
            (response['planSchema'] is! int || response['planSchema'] != 2)) ||
        (response['validation'] != null && response['validation'] is! int) ||
        (response['launchBound'] != null && response['launchBound'] is! bool) ||
        (response['resourceClaimed'] != null &&
            response['resourceClaimed'] is! bool) ||
        (response['busy'] != null && response['busy'] is! bool)) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'The local engine has no versioned policy capability',
      );
    }
    final instance = response['instanceNonce'] as String;
    if (_instanceNonce != instance) {
      // A helper/engine restart invalidates every old receipt and generation.
      _receipt = null;
      _generation = null;
    }
    _instanceNonce = instance;
    _state = response['state'] as String;
    _resourceState = response['resourceState'] as String;
    _validationSupported = response['validation'] == 1;
    if (response['busy'] == true || _state == 'pending') {
      _state = 'pending';
    }
  }

  Map<String, dynamic> request(
    PublicationSnapshot snapshot, {
    Object? expectedGeneration = _useCurrentGeneration,
  }) {
    if (_instanceNonce == null) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'Policy capability was not discovered',
      );
    }
    return {
      'version': 1,
      'storeIdentity': storeIdentity,
      'controllerNonce': controllerNonce,
      'instanceNonce': _instanceNonce,
      'transactionId': snapshot.transactionId,
      'expectedGeneration': identical(expectedGeneration, _useCurrentGeneration)
          ? _generation
          : expectedGeneration,
      'planGeneration': snapshot.generation,
      'plan': snapshot.plan,
    };
  }

  void _ack(Object? response, Map<String, dynamic> request, String state) {
    if (response is! Map ||
        response.length != 6 ||
        response['version'] is! int ||
        response['version'] != 1 ||
        response['instanceNonce'] != request['instanceNonce'] ||
        response['controllerNonce'] != request['controllerNonce'] ||
        response['transactionId'] != request['transactionId'] ||
        response['planGeneration'] != request['planGeneration'] ||
        response['state'] != state) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'The local engine reply is not a versioned policy receipt',
      );
    }
  }

  /// Reads the native lane state (never a launch trigger). Used to settle a
  /// dead pending transaction before starting a fresh publication.
  Future<PolicyNativeState> queryState() async {
    final instance = _instanceNonce;
    if (instance == null) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'Policy capability was not discovered',
      );
    }
    final response = await invoke('policyState', {
      'version': 1,
      'instanceNonce': instance,
    });
    var state = PolicyNativeState.parse(response, instance: instance);
    // READY authority is the NESTED receipt only, bound to this exact store,
    // controller and instance; top-level diagnostics are never an attachment.
    // An UNBOUND READY envelope (a previous process committed it under another
    // controller nonce) is still OBSERVED: recovery has to CAS against the
    // generation the native journal holds, and refusing to look at it made the
    // lane unrecoverable without wiping app data. The receipt itself is
    // stripped from the observation so nothing can admit it by accident.
    final receipt = state.receipt;
    final bound = receipt != null &&
        receipt.storeIdentity == storeIdentity &&
        receipt.controllerNonce == controllerNonce &&
        receipt.instanceNonce == instance;
    if (receipt != null && !bound) {
      state = state._withoutReceipt();
    }
    final admissible = state.state == 'ready' &&
        bound &&
        state.resourceState == 'clean';
    if (admissible) {
      _receipt = receipt.toJson();
      _generation = receipt.planGeneration;
      _state = 'ready';
    } else {
      _receipt = null;
      // Keep the observed committed generation as the CAS value; it is what a
      // reconcile/publication must name to replace a READY envelope.
      _generation = state.state == 'ready'
          ? (state.planGeneration ?? receipt?.planGeneration)
          : null;
      _state = state.state == 'absent' ? 'blocked' : state.state;
    }
    _resourceState = state.resourceState;
    return state;
  }

  /// Exactly `{version, instanceNonce, transactionId}` (WIRE-V2 §9); used to
  /// settle a dead pending transaction. A no-op response for an unknown
  /// transaction is still a settled reply.
  Future<void> abort({required String transactionId}) async {
    final instance = _instanceNonce;
    if (instance == null) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'Policy capability was not discovered',
      );
    }
    final abort = {
      'version': 1,
      'instanceNonce': instance,
      'transactionId': transactionId,
    };
    final response = await invoke('policyAbort', abort);
    _ackAbort(response, abort);
  }

  /// Desktop validation ACK (WIRE-V2 §8): exactly
  /// `{version, instanceNonce, controllerNonce, transactionId, documentDigest}`.
  /// `documentDigest` is the helper's independent re-hash of the received exact
  /// bytes and must equal the bundle digest. A helper may not claim READY here.
  void _ackValidation(
    Object? response,
    Map<String, dynamic> request, {
    required String expectedDocumentDigest,
  }) {
    if (response is! Map ||
        response.length != 5 ||
        response['version'] != 1 ||
        response['version'] is! int ||
        response['instanceNonce'] != request['instanceNonce'] ||
        response['controllerNonce'] != request['controllerNonce'] ||
        response['transactionId'] != request['transactionId'] ||
        response['documentDigest'] != expectedDocumentDigest) {
      throw const PolicyFailure(
        'POLICY_UNVERIFIED',
        'The local helper did not return an exact validation receipt',
      );
    }
    _state = 'pending';
  }
  /// Android's abort reply may be the documented three-field shape

  /// `{version, state, transactionId}`; a six-field ACK is also accepted. Any
  /// other shape/unknown key is not a settled blocked receipt.
  void _ackAbort(Object? response, Map<String, dynamic> abort) {
    final valid = response is Map &&
        response['version'] == 1 &&
        response['version'] is int &&
        response['transactionId'] == abort['transactionId'] &&
        response['state'] == 'blocked' &&
        (response.length == 3 ||
            (response.length == 6 &&
                response['instanceNonce'] == abort['instanceNonce']));
    if (!valid) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'The local engine did not ACK a settled blocked receipt',
      );
    }
  }

  /// The request is captured once at begin, including expected generation.
  /// Commit/abort must not sample a replacement controller/helper identity.
  PolicyChannelTransaction transaction(
    PublicationSnapshot snapshot, {
    Object? expectedGeneration = _useCurrentGeneration,
  }) =>
      PolicyChannelTransaction._(
        this,
        identical(expectedGeneration, _useCurrentGeneration)
            ? request(snapshot)
            : request(snapshot, expectedGeneration: expectedGeneration),
        beginMode: true,
      );

  /// Pending-recovery reconciliation: a fresh transaction/generation.
  /// `expectedGeneration` is the platform CAS value (desktop: freshly observed
  /// native casGeneration, null only when the fresh helper has none; Android
  /// keeps null). Native validates the durable document receipt written by the
  /// app before this call.
  PolicyChannelTransaction reconciliation(
    PublicationSnapshot snapshot, {
    String? expectedGeneration,
  }) =>
      PolicyChannelTransaction._(
        this,
        request(snapshot, expectedGeneration: expectedGeneration),
        beginMode: false,
      );
}

class PolicyChannelTransaction {
  PolicyChannelTransaction._(this.channel, this._request, {required this.beginMode});
  final PolicyChannel channel;
  final Map<String, dynamic> _request;
  final bool beginMode;

  Future<void> begin() async {
    if (!beginMode) {
      throw StateError('A reconciliation transaction has no begin step');
    }
    final response = await channel.invoke('policyBegin', Map.of(_request));
    channel._ack(response, _request, 'pending');
    channel._state = 'pending';
  }

  Future<void> commit() async {
    final response = await channel.invoke(
      beginMode ? 'policyCommit' : 'policyReconcile',
      Map.of(_request),
    );
    channel._ack(response, _request, 'ready');
    _adoptAck();
  }

  /// Desktop-only validation step (WIRE-V2 §8): the same eight request fields
  /// plus `validation`. The ACK is the six-field pending validation receipt; a
  /// READY state is still only produced by [commit].
  Future<void> validate(Map<String, Object?> validation) async {
    final response = await channel.invoke('policyValidate', {
      ...Map<String, dynamic>.of(_request),
      'validation': validation,
    });
    channel._ackValidation(
      response,
      _request,
      expectedDocumentDigest: validation['documentDigest'] as String,
    );
    channel._state = 'pending';
  }

  void _adoptAck() {
    if (channel._instanceNonce != _request['instanceNonce']) {
      throw const PolicyFailure(
        'POLICY_STALE',
        'The engine instance changed while the transaction was in flight',
      );
    }
    channel._generation = _request['planGeneration'] as String;
    channel._state = 'ready';
    channel._receipt = {
      'version': 1,
      'storeIdentity': _request['storeIdentity'],
      'instanceNonce': _request['instanceNonce'],
      'controllerNonce': _request['controllerNonce'],
      'transactionId': _request['transactionId'],
      'planGeneration': _request['planGeneration'],
    };
  }

  Future<void> block() async {
    // Android accepts exactly {version, instanceNonce, transactionId}; the
    // reply may be the three-field abort shape or the six-field ACK.
    final abort = {
      'version': 1,
      'instanceNonce': _request['instanceNonce'],
      'transactionId': _request['transactionId'],
    };
    final response = await channel.invoke('policyAbort', abort);
    channel._ackAbort(response, abort);
    channel._state = 'blocked';
    if (channel._receipt?['transactionId'] == _request['transactionId']) {
      channel._receipt = null;
    }
  }
}
/// Desktop publication-validation bundle (WIRE-V2 §8). The helper re-hashes the
/// supplied exact bytes independently; echoing a caller digest is not evidence.
/// No secrets are logged or persisted by this class.
class PolicyValidation {
  static const schema = 1;
  static const maxDocumentBytes = 512 * 1024;
  static const maxConfigBytes = 200000;
  static const maxTotalConfigBytes = 1024 * 1024;
  static const maxCombinedBytes = 1536 * 1024;
  static const maxConfigs = 16;

  static Map<String, Object?> build({
    required String documentBytes,
    required Map<String, String?> configs,
  }) {
    final document = utf8.encode(documentBytes);
    if (document.isEmpty || document.length > maxDocumentBytes) {
      throw const PolicyFailure(
        'POLICY_OVERSIZE',
        'Document bytes are empty or exceed the validation bound',
      );
    }
    if (configs.length > maxConfigs) {
      throw const PolicyFailure(
        'POLICY_OVERSIZE',
        'More configurations than the validation bundle allows',
      );
    }
    var total = 0;
    final entries = <Map<String, Object?>>[];
    for (final entry in configs.entries) {
      final bytes = entry.value;
      if (bytes == null || bytes.trim().isEmpty) {
        throw const PolicyFailure(
          'POLICY_INVALID',
          'A configuration is missing or empty',
        );
      }
      final raw = utf8.encode(bytes);
      if (raw.length > maxConfigBytes) {
        throw const PolicyFailure(
          'POLICY_OVERSIZE',
          'A configuration exceeds the validation bound',
        );
      }
      total += raw.length;
      entries.add({'id': entry.key, 'bytesBase64': base64Encode(raw)});
    }
    if (total > maxTotalConfigBytes || document.length + total > maxCombinedBytes) {
      throw const PolicyFailure(
        'POLICY_OVERSIZE',
        'Configurations exceed the total validation bound',
      );
    }
    return {
      'schema': schema,
      'documentDigest': crypto.sha256.convert(document).toString(),
      'documentBytesBase64': base64Encode(document),
      'configs': entries,
    };
  }
}

/// Typed `policyState` reply (WIRE-V2 §9). Optional diagnostic fields are
/// validated when present; arbitrary unknown keys are not accepted.
/// Typed native lane state (WIRE-V2 §9 / Go policyState).
///
/// Actual Go replies carry documented diagnostic fields beyond the legacy
/// Android shape (planSchema, validation, launchBound, resourceClaimed,
/// clientOnly, busy, error, pendingTransaction, casGeneration). They are parsed
/// with strict types; unknown keys are still rejected. READY admission comes
/// ONLY from the nested six-field `receipt`, never from diagnostic booleans.
class PolicyNativeState {
  PolicyNativeState._({
    required this.state,
    required this.phase,
    required this.resourceState,
    required this.receipt,
    required this.pendingTransaction,
    required this.casGeneration,
    required this.planSchema,
    required this.validation,
    required this.launchBound,
    required this.resourceClaimed,
    required this.clientOnly,
    required this.busy,
    required this.error,
    required this.transactionId,
    required this.planGeneration,
  });

  static const _allowed = {
    'version',
    'instanceNonce',
    'state',
    'phase',
    'resourceState',
    'planSchema',
    'validation',
    'launchBound',
    'resourceClaimed',
    'busy',
    'storeIdentity',
    'controllerNonce',
    'clientOnly',
    'error',
    'pendingTransaction',
    'casGeneration',
    'receipt',
    'transactionId',
    'planGeneration',
  };
  static const _states = {'ready', 'pending', 'blocked', 'absent'};
  static const _resources = {'clean', 'owned', 'unknown'};
  static const _phases = {'absent', 'pending', 'pendingUnknown', 'ready', 'blocked'};
  static final _hex32 = RegExp(r'^[a-f0-9]{32}$');

  /// Observation copy without the nested receipt: used when a READY envelope
  /// belongs to another controller/instance and must be readable for recovery
  /// but never admissible.
  PolicyNativeState _withoutReceipt() => PolicyNativeState._(
        state: state,
        phase: phase,
        resourceState: resourceState,
        receipt: null,
        pendingTransaction: pendingTransaction,
        casGeneration: casGeneration,
        planSchema: planSchema,
        validation: validation,
        launchBound: launchBound,
        resourceClaimed: resourceClaimed,
        clientOnly: clientOnly,
        busy: busy,
        error: error,
        transactionId: transactionId,
        planGeneration: planGeneration,
      );

  final String state;
  final String? phase;
  final String? resourceState;
  final PolicyReceipt? receipt;
  final String? pendingTransaction;
  final String? casGeneration;
  final int? planSchema;
  final int? validation;
  final bool? launchBound;
  final bool? resourceClaimed;
  final bool? clientOnly;
  final bool? busy;
  final String? error;
  final String? transactionId;
  final String? planGeneration;

  /// The lane still holds an unfinished publication.
  bool get pendingLane =>
      state == 'pending' || phase == 'pending' || phase == 'pendingUnknown';

  /// Only an exact nested receipt with a non-unknown resource state admits.
  bool get readyForAdmission =>
      state == 'ready' && receipt != null && resourceState == 'clean';

  static PolicyNativeState parse(Object? value, {required String instance}) {
    PolicyFailure reject() => const PolicyFailure(
          'POLICY_UNKNOWN',
          'The local engine state is not a typed policy state',
        );
    if (value is! Map ||
        value.keys.any((key) => !_allowed.contains(key)) ||
        value['version'] != 1 ||
        value['version'] is! int ||
        value['instanceNonce'] != instance ||
        !_states.contains(value['state']) ||
        value['resourceState'] is! String ||
        !_resources.contains(value['resourceState']) ||
        (value['phase'] != null && !_phases.contains(value['phase'])) ||
        (value['planSchema'] != null &&
            (value['planSchema'] is! int || value['planSchema'] != 2)) ||
        (value['validation'] != null && value['validation'] is! int) ||
        (value['launchBound'] != null && value['launchBound'] is! bool) ||
        (value['resourceClaimed'] != null && value['resourceClaimed'] is! bool) ||
        (value['clientOnly'] != null && value['clientOnly'] is! bool) ||
        (value['busy'] != null && value['busy'] is! bool) ||
        (value['error'] != null && value['error'] is! String) ||
        (value['pendingTransaction'] != null &&
            (value['pendingTransaction'] is! String ||
                !_hex32.hasMatch(value['pendingTransaction'] as String))) ||
        (value['casGeneration'] != null &&
            (value['casGeneration'] is! String ||
                !_hex32.hasMatch(value['casGeneration'] as String))) ||
        (value['transactionId'] != null &&
            (value['transactionId'] is! String ||
                !_hex32.hasMatch(value['transactionId'] as String))) ||
        (value['planGeneration'] != null &&
            (value['planGeneration'] is! String ||
                !_hex32.hasMatch(value['planGeneration'] as String))) ||
        (value['storeIdentity'] != null &&
            (value['storeIdentity'] is! String ||
                ((value['storeIdentity'] as String).isNotEmpty &&
                    !RegExp(r'^[a-f0-9]{64}$')
                        .hasMatch(value['storeIdentity'] as String)))) ||
        (value['controllerNonce'] != null &&
            (value['controllerNonce'] is! String ||
                !_hex32.hasMatch(value['controllerNonce'] as String))) ||
        (value['receipt'] != null && value['receipt'] is! Map)) {
      throw reject();
    }
    PolicyReceipt? receipt;
    if (value['receipt'] != null) {
      receipt = PolicyReceipt.parse(value['receipt']);
    }
    return PolicyNativeState._(
      state: value['state'] as String,
      phase: value['phase'] as String?,
      resourceState: value['resourceState'] as String,
      receipt: receipt,
      pendingTransaction: value['pendingTransaction'] as String?,
      casGeneration: value['casGeneration'] as String?,
      planSchema: value['planSchema'] as int?,
      validation: value['validation'] as int?,
      launchBound: value['launchBound'] as bool?,
      resourceClaimed: value['resourceClaimed'] as bool?,
      clientOnly: value['clientOnly'] as bool?,
      busy: value['busy'] as bool?,
      error: value['error'] as String?,
      transactionId: value['transactionId'] as String?,
      planGeneration: value['planGeneration'] as String?,
    );
  }
}
/// Native generation a reconciliation must target.
///
/// Desktop CAS uses the helper's observed `casGeneration`. Android has no CAS
/// field, but its journal rejects replacing READY with any generation other
/// than the committed one, so a READY state must bind its own plan generation.
String? policyReconcileGeneration(
  PolicyNativeState? state, {
  required bool desktop,
}) {
  if (desktop) return state?.casGeneration;
  if (state == null || state.state != 'ready') return null;
  return state.planGeneration ?? state.receipt?.planGeneration;
}

/// Builds the activation attachment and enforces the plan identity it binds.
///
/// A missing receipt is `POLICY_UNSUPPORTED` only when the durable document
/// already carries versioned policy state (WIRE-V2 §2.1). A pristine legacy
/// document keeps the existing automatic activation path unchanged, and that
/// path must never be presented as a manual mode having taken effect.
class PolicyActivation {
  static const _versionedKeys = {'connectionPolicy', 'connectionPlanReceipt'};

  static bool receiptRequired(Map<String, dynamic> document) =>
      _versionedKeys.any(document.containsKey);

  /// Plan-visible part of the boundary; pending/unknown publication state is
  /// owned by the caller because it is not a document property.
  static bool receiptRequiredFor(
    Map<String, dynamic> document, {
    required bool publicationPendingOrUnknown,
  }) => receiptRequired(document) || publicationPendingOrUnknown;

  static Map<String, Object?> arguments({
    required PublicationSnapshot snapshot,
    required String candidateId,
    required PolicyReceipt? receipt,
    required bool receiptRequired,
    PolicyPlatform platform = PolicyPlatform.android,
  }) {
    if (receipt == null) {
      if (receiptRequired) {
        throw const PolicyFailure(
          'POLICY_UNSUPPORTED',
          'This document already uses versioned policy; a committed receipt is required',
        );
      }
      return const {};
    }
    if (receipt.planGeneration != snapshot.generation) {
      throw const PolicyFailure(
        'POLICY_STALE',
        'The receipt does not describe this plan generation',
      );
    }
    final plan = snapshot.plan;
    final ids = plan['ids'];
    final policy = ConnectionPolicy.parse(plan['policy']);
    if (ids is! List || ids.any((id) => id is! String)) {
      throw const PolicyFailure('POLICY_INVALID', 'The plan has no candidate list');
    }
    if (!ids.contains(candidateId)) {
      throw const PolicyFailure(
        'POLICY_STALE',
        'The candidate is not part of the committed plan',
      );
    }
    if (policy == ConnectionPolicy.selectedOnly) {
      if (ids.length != 1 ||
          ids.single != candidateId ||
          plan['selectedId'] != candidateId) {
        throw const PolicyFailure(
          'POLICY_STALE',
          'Manual activation must be exactly the committed selected profile',
        );
      }
    }
    return switch (platform) {
      // Android passes the typed map; desktop keeps its capitalized transport
      // request and adds one JSON string member (WIRE-V2 §2).
      PolicyPlatform.android => {'policyReceipt': receipt.toJson()},
      PolicyPlatform.desktop => {
        'PolicyReceiptJSON': jsonEncode(receipt.toJson()),
      },
    };
  }
}
