import 'dart:async';
import 'dart:convert';

/// The outcome belongs to the physical document write, not to the UI future.
enum PublicationPhase {
  beforeRename,
  pendingUnknown,
  renamedNativeUnconfirmed,
  committed,
}

class PublicationFailure implements Exception {
  const PublicationFailure(this.phase, this.cause);
  final PublicationPhase phase;
  final Object cause;
  @override
  String toString() => 'PublicationFailure($phase)';
}

/// Serialization is the deep-copy boundary, including nested profile/user maps.
/// Callers cannot change a queued document or native plan through an alias.
class PublicationSnapshot {
  PublicationSnapshot({
    required this.transactionId,
    required this.generation,
    required Map<String, dynamic> document,
    required Map<String, dynamic> plan,
  }) : documentBytes = jsonEncode(document), planBytes = jsonEncode(plan) {
    if (!_identity.hasMatch(transactionId) || !_identity.hasMatch(generation)) {
      throw const FormatException('Invalid publication identity');
    }
  }
  static final _identity = RegExp(r'^[a-f0-9]{32}$');
  final String transactionId, generation, documentBytes, planBytes;
  Map<String, dynamic> get document =>
      Map<String, dynamic>.from(jsonDecode(documentBytes) as Map);
  Map<String, dynamic> get plan =>
      Map<String, dynamic>.from(jsonDecode(planBytes) as Map);
}

/// Platform adapter. begin/commit/block ALL use one native physical writer.
/// A failed commit may have changed cached or durable state. block is an
/// acknowledged blocked reconciliation, NOT an attempted cancellation of IO.
abstract interface class PublicationIO {
  Future<void> begin(PublicationSnapshot snapshot);
  Future<void> writeDocument(
    PublicationSnapshot snapshot,
    void Function() renamed,
  );
  Future<void> commit(PublicationSnapshot snapshot);
  Future<void> block(PublicationSnapshot snapshot);
}

/// Serial ownership for policy publication. This is not a VPN coordinator.
///
/// Logical revocation never releases physical IO ownership. Even a timed-out
/// caller cannot admit a successor before the old IO and blocked reconciliation
/// settle. No IO runs under an OS/native monitor here.
class PolicyPublicationWriter {
  PolicyPublicationWriter(this.io);
  final PublicationIO io;
  Future<void>? _flight;
  int _epoch = 0;
  bool _disposed = false;
  bool _blocked = false;
  PublicationSnapshot? _committed;
  final Map<String, String> _transactions = {};
  bool get writing => _flight != null;
  bool get blocked => _blocked;
  PublicationSnapshot? get committed => _committed;
  Future<void> get settled => _flight ?? Future<void>.value();

  /// UP must separately require its Store/native owner and known idle state.
  bool get publicationReady => !_disposed && !writing && !_blocked;

  void revoke() {
    _epoch++;
    if (writing) _blocked = true;
  }

  void dispose() {
    _disposed = true;
    revoke();
  }

  Future<PublicationSnapshot> publish(
    PublicationSnapshot snapshot, {
    Duration wait = const Duration(seconds: 10),
    bool reconcile = false,
  }) {
    if (_disposed || writing || (_blocked && !reconcile)) {
      return Future.error(
        const PublicationFailure(PublicationPhase.beforeRename, 'writer busy'),
      );
    }
    final fingerprint = '${snapshot.generation}\n${snapshot.documentBytes}\n${snapshot.planBytes}';
    final previous = _transactions[snapshot.transactionId];
    if (previous != null) {
      if (previous == fingerprint &&
          _committed?.transactionId == snapshot.transactionId && !_blocked) {
        return Future.value(_committed!);
      }
      return Future.error(const PublicationFailure(
        PublicationPhase.beforeRename, 'replayed transaction',
      ));
    }
    if (wait <= Duration.zero) {
      return Future.error(ArgumentError.value(wait, 'wait'));
    }
    _transactions[snapshot.transactionId] = fingerprint;
    final owner = ++_epoch;
    // Install physical ownership BEFORE the async body can begin or notify.
    final physicallySettled = Completer<void>();
    _flight = physicallySettled.future;
    final caller = Completer<PublicationSnapshot>();
    var phase = PublicationPhase.beforeRename;
    bool current() => !_disposed && _epoch == owner;
    final timer = Timer(wait, () {
      if (caller.isCompleted) return;
      if (current()) revoke();
      // An in-flight write may rename AFTER this timeout. Never report a
      // proven pre-rename outcome while physical ownership is outstanding.
      caller.completeError(PublicationFailure(
        phase == PublicationPhase.beforeRename
            ? PublicationPhase.pendingUnknown : phase,
        TimeoutException('Policy publication pending'),
      ));
    });
    unawaited(() async {
      Object? failure;
      try {
        await io.begin(snapshot);
        if (!current()) throw StateError('Publication revoked');
        await io.writeDocument(snapshot, () {
          phase = PublicationPhase.renamedNativeUnconfirmed;
        });
        if (phase != PublicationPhase.renamedNativeUnconfirmed) {
          throw StateError('Document writer did not confirm rename');
        }
        if (!current()) throw StateError('Publication revoked');
        await io.commit(snapshot);
        if (!current()) throw StateError('Publication revoked');
        phase = PublicationPhase.committed;
        _committed = snapshot;
        _blocked = false;
      } catch (error) {
        failure = error;
        _blocked = true;
        // Even if begin threw, its native outcome may be unknown. This lane
        // remains owned until a blocked receipt settles, or fails visibly.
        try {
          await io.block(snapshot);
        } catch (reconcileError) {
          failure = (original: error, reconciliation: reconcileError);
        }
      } finally {
        timer.cancel();
        _flight = null;
        physicallySettled.complete();
        if (!caller.isCompleted) {
          if (failure == null && current()) {
            caller.complete(snapshot);
          } else {
            caller.completeError(PublicationFailure(
              phase, failure ?? StateError('Publication revoked'),
            ));
          }
        }
      }
    }());
    return caller.future;
  }
}

/// Count admission at enqueue time. In particular two screenshot setters may
/// queue legitimately, but neither leaves an uncounted gap for mode begin.
class StoreMutationAdmission {
  final Set<StoreMutationIntent> _ordinary = {};
  StoreMutationIntent? _policy;
  bool _disposed = false;
  bool get busy => _ordinary.isNotEmpty || _policy != null;

  StoreMutationIntent ordinary() {
    if (_disposed || _policy != null) throw StateError('Store mutation busy');
    final intent = StoreMutationIntent._(this, false);
    _ordinary.add(intent);
    return intent;
  }

  StoreMutationIntent policy() {
    if (_disposed || busy) throw StateError('Store mutation busy');
    return _policy = StoreMutationIntent._(this, true);
  }

  void dispose() {
    _disposed = true;
    // No release: physical writers/queued bodies retain their own intents.
    for (final intent in _ordinary) { intent._revoked = true; }
    _policy?._revoked = true;
  }
}

class StoreMutationIntent {
  StoreMutationIntent._(this._gate, this.policy);
  final StoreMutationAdmission _gate;
  final bool policy;
  bool _released = false, _revoked = false;
  bool get current => !_released && !_revoked && !_gate._disposed;

  /// A ticket is only usable by the admission gate that issued it; a foreign
  /// ticket must be rejected before it can authorize IO in another store.
  bool ownedBy(Object admission) => identical(_gate, admission);
  void revoke() => _revoked = true;
  void release() {
    if (_released) return;
    _released = true;
    if (policy) {
      if (identical(_gate._policy, this)) _gate._policy = null;
    } else {
      _gate._ordinary.remove(this);
    }
  }
}
