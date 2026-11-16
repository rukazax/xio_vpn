import 'dart:async';

/// Runtime intent, independent of the legacy preferred-protocol ordering.
/// Persistence/UI owners must explicitly opt into selectedOnly.
enum ConnectionPolicy {
  automatic,
  selectedOnly;

  Map<String, Object> toJson() => {'mode': name, 'roundMillis': 30000};

  /// Absence is handled by the document caller. Present null is NOT legacy.
  static ConnectionPolicy parse(Object? value) {
    if (value is! Map || value.length != 2 ||
        !value.containsKey('mode') || !value.containsKey('roundMillis') ||
        value['roundMillis'] is! int || value['roundMillis'] != 30000) {
      throw const FormatException('Invalid connection policy');
    }
    return switch (value['mode']) {
      'automatic' => automatic,
      'selectedOnly' => selectedOnly,
      _ => throw const FormatException('Unknown connection policy'),
    };
  }

  static ConnectionPolicy fromDocument(Map<String, dynamic> document) =>
      document.containsKey('connectionPolicy')
          ? parse(document['connectionPolicy']) : automatic;
}

/// Why an activation or publication request was refused. Codes are the exact
/// wire codes of WIRE-V1/V2; callers must not translate them into a mode claim.
class PolicyFailure implements Exception {
  const PolicyFailure(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => 'PolicyFailure($code): $message';
}

/// Durable document receipt of the last acknowledged publication
/// (`connectionPlanReceipt` in the app document): schema 1 plus the exact
/// transaction/generation and the plan those describe. This is NOT the
/// six-field activation attachment.
class DocumentPlanReceipt {
  DocumentPlanReceipt._(this.transactionId, this.planGeneration, this.plan);
  static const schema = 1;
  static final _identity = RegExp(r'^[a-f0-9]{32}$');
  final String transactionId, planGeneration;
  final Map<String, dynamic> plan;

  factory DocumentPlanReceipt.parse(Object? value) {
    if (value is! Map ||
        value.length != 4 ||
        value['schema'] != schema ||
        value['schema'] is! int ||
        value['transactionId'] is! String ||
        !_identity.hasMatch(value['transactionId'] as String) ||
        value['planGeneration'] is! String ||
        !_identity.hasMatch(value['planGeneration'] as String) ||
        value['plan'] is! Map) {
      throw const FormatException('Invalid document plan receipt');
    }
    return DocumentPlanReceipt._(
      value['transactionId'] as String,
      value['planGeneration'] as String,
      Map<String, dynamic>.from(value['plan'] as Map),
    );
  }
}

/// Committed admission identity of exactly one plan generation. A missing
/// receipt is only legacy on a pristine document (WIRE-V2 §2.1).
class PolicyReceipt {
  PolicyReceipt._({
    required this.storeIdentity,
    required this.instanceNonce,
    required this.controllerNonce,
    required this.transactionId,
    required this.planGeneration,
  }) {
    if (!_store.hasMatch(storeIdentity) ||
        !_nonce.hasMatch(instanceNonce) ||
        !_nonce.hasMatch(controllerNonce) ||
        !_nonce.hasMatch(transactionId) ||
        !_nonce.hasMatch(planGeneration)) {
      throw const FormatException('Invalid policy receipt');
    }
  }
  static final _nonce = RegExp(r'^[a-f0-9]{32}$');
  static final _store = RegExp(r'^[a-f0-9]{64}$');
  static const version = 1;
  final String storeIdentity, instanceNonce, controllerNonce, transactionId,
      planGeneration;

  factory PolicyReceipt.parse(Object? value) {
    if (value is! Map ||
        value.length != 6 ||
        value['version'] != version ||
        value['version'] is! int ||
        value['storeIdentity'] is! String ||
        value['instanceNonce'] is! String ||
        value['controllerNonce'] is! String ||
        value['transactionId'] is! String ||
        value['planGeneration'] is! String) {
      throw const FormatException('Invalid policy receipt');
    }
    return PolicyReceipt._(
      storeIdentity: value['storeIdentity'] as String,
      instanceNonce: value['instanceNonce'] as String,
      controllerNonce: value['controllerNonce'] as String,
      transactionId: value['transactionId'] as String,
      planGeneration: value['planGeneration'] as String,
    );
  }

  /// Exact wire shape; `version` is first so an encoded receipt is also a valid
  /// parsed receipt without reordering.
  Map<String, Object> toJson() => {
    'version': version,
    'storeIdentity': storeIdentity,
    'instanceNonce': instanceNonce,
    'controllerNonce': controllerNonce,
    'transactionId': transactionId,
    'planGeneration': planGeneration,
  };

  @override
  bool operator ==(Object other) =>
      other is PolicyReceipt &&
      other.storeIdentity == storeIdentity &&
      other.instanceNonce == instanceNonce &&
      other.controllerNonce == controllerNonce &&
      other.transactionId == transactionId &&
      other.planGeneration == planGeneration;

  @override
  int get hashCode => Object.hash(
    storeIdentity,
    instanceNonce,
    controllerNonce,
    transactionId,
    planGeneration,
  );
}

/// Which evidence backs the currently displayed connection mode. The durable
/// document selection is NOT a confirmation: `beforeRename` only proves the
/// document unchanged, `pendingUnknown` may still rename, and
/// `renamedNativeUnconfirmed` may have lost a native ACK.
enum ConnectionModeConfirmation {
  /// No confirmation this session: pending/unknown publication, unresolved
  /// reconciliation or a preserved malformed document.
  none,

  /// Pristine legacy document: absence of the property means automatic.
  legacyAutomatic,

  /// The durable document was read back (or renamed) and no versioned native
  /// envelope exists; the selection is the confirmed intent.
  document,

  /// An exact native ACK describes this exact generation (committed/reconciled).
  native,
}

/// One monotonic deadline; phase/candidate limits can only shorten it.
/// The timer is also authoritative, so expiry never depends on another poll.
class ConnectionRound {
  ConnectionRound({
    this.maximum = const Duration(seconds: 30),
    Duration Function()? elapsed,
    this.onExpire,
  }) {
    if (maximum <= Duration.zero || maximum > const Duration(seconds: 30)) {
      throw ArgumentError.value(maximum, 'maximum');
    }
    final clock = Stopwatch()..start();
    _elapsed = elapsed ?? (() => clock.elapsed);
    _timer = Timer(maximum, () {
      _expired = true;
      try {
        onExpire?.call();
      } finally {
        _end();
      }
    });
  }

  final Duration maximum;
  final void Function()? onExpire;
  late final Duration Function() _elapsed;
  late final Timer _timer;
  final _ended = Completer<void>();
  bool _expired = false, _cancelled = false, _closed = false;
  Duration get elapsed => _elapsed();
  bool get current =>
      !_expired && !_cancelled && !_closed && remaining > Duration.zero;
  Duration get remaining {
    if (_expired || _closed) return Duration.zero;
    final left = maximum - elapsed;
    return left > Duration.zero ? left : Duration.zero;
  }

  /// Leave bounded time for joined native teardown before admitting more work.
  Duration get workRemaining {
    final reserve = Duration(
      microseconds: (maximum.inMicroseconds ~/ 5).clamp(0, 5000000),
    );
    final left = remaining - reserve;
    return left > Duration.zero ? left : Duration.zero;
  }

  Duration limit(Duration ceiling) => remaining < ceiling ? remaining : ceiling;

  Future<T> run<T>(Future<T> Function() action, {Duration? ceiling}) {
    final left = ceiling == null ? remaining : limit(ceiling);
    if (!current || left <= Duration.zero) {
      return Future.error(TimeoutException('Connection round ended'));
    }
    return Future.any([
      Future<T>.sync(action).timeout(left),
      _ended.future.then<T>(
        (_) => throw TimeoutException('Connection round ended'),
      ),
    ]);
  }

  void _end() {
    if (!_ended.isCompleted) _ended.complete();
  }

  /// Revoke work immediately; cleanup may still use the original remaining time.
  void cancel() {
    _cancelled = true;
    _end();
  }

  void close() {
    _closed = true;
    _timer.cancel();
    _end();
  }
}
