import 'package:flutter/foundation.dart';

import 'connection_attempt.dart';
import 'connection_mode_ui.dart';
import 'core.dart';

/// Production adapter: forwards the frozen Store mode API (WIRE-V2 §7) to the
/// two settings surfaces.
///
/// It adds no policy of its own: every value comes from [AppStore], including
/// the positive `connectionModeConfirmed` receipt, the pending flag, the
/// authoritative blocker code and the combined atomic save. It never infers
/// confirmation from "no error" and never synthesises an ACK.
class StoreConnectionModeSource extends ChangeNotifier
    implements ConnectionModeSource {
  StoreConnectionModeSource(this.store) {
    store.addListener(_forward);
  }

  final AppStore store;
  bool _disposed = false;

  void _forward() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    store.removeListener(_forward);
    super.dispose();
  }

  @override
  ConnectionPolicy get connectionPolicy => store.connectionPolicy;

  @override
  ConnectionModeConfirmation get connectionModeConfirmation =>
      store.connectionModeConfirmation;

  @override
  bool get connectionModeConfirmed => store.connectionModeConfirmed;

  @override
  bool get connectionModePending => store.connectionModePending;

  @override
  bool get canChangeConnectionMode => store.canChangeConnectionMode;

  @override
  String? get connectionPolicyError => store.connectionPolicyError;

  @override
  bool get selectedProfileUsable {
    final selected = store.selected;
    if (selected == null) return false;
    // Same candidate rules the Store uses for admission: a manual selection that
    // yields no candidate is not usable, and the UI must ask for one.
    return store.connectionCandidates(selected).any((p) => p.id == selected.id);
  }

  @override
  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    required ConnectionPolicy policy,
  }) => store.saveConnectionSettings(
    site,
    priority,
    timeoutSeconds: timeoutSeconds,
    siteCheck: siteCheck,
    reconnect: reconnect,
    policy: policy,
  );

  @override
  Future<void> repairConnectionPolicy(ConnectionPolicy policy) =>
      store.repairConnectionPolicy(policy);

  @override
  Future<void> retryPolicyReconciliation() => store.retryPolicyReconciliation();
}
