/// Per-native inner-family readiness, independent of the connector endpoint.
/// Presence is authoritative: malformed/stale/down metadata never falls back to
/// the legacy host-default flag. Intent is not evidence of readiness.
class NativeProfileReadiness {
  final bool explicit;
  final bool ipv4;
  final bool ipv6;
  const NativeProfileReadiness._(this.explicit, this.ipv4, this.ipv6);
  bool get selected => ipv4 || ipv6;
  // Capture is deliberately broader than verified egress. For opted-in native
  // cascades the other family is blocked at the bridge, never sent DIRECT.
  bool get captureIpv4 => explicit ? selected : ipv4;
  bool get captureIpv6 => explicit ? selected : ipv6;

  static NativeProfileReadiness forProtocol(
    Map<dynamic, dynamic> server,
    String protocol, {
    DateTime? now,
  }) {
    if (!{'awg', 'rivet'}.contains(protocol)) {
      throw ArgumentError.value(protocol, 'protocol');
    }
    if (!server.containsKey('nativeProfileReadiness')) {
      final rivet = server['rivet'];
      return NativeProfileReadiness._(
        false,
        true,
        protocol == 'awg' || rivet is Map && rivet['ipv6'] == true,
      );
    }
    final value = server['nativeProfileReadiness'];
    if (value is! Map || value['schema'] != 1 || value['enabled'] != true) {
      throw const FormatException('Invalid native cascade readiness');
    }
    final identity = value['connectorId'];
    final revision = value['revision'];
    if (identity is! String ||
        identity.trim().isEmpty ||
        identity != identity.trim() ||
        !(revision is int && revision >= 0 ||
            revision is String && revision.trim().isNotEmpty)) {
      throw const FormatException('Invalid native cascade readiness identity');
    }
    final current = (now ?? DateTime.now()).toUtc();
    DateTime timestamp(dynamic raw) {
      if (raw is! String ||
          !RegExp(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)$')
              .hasMatch(raw)) {
        throw const FormatException('Invalid native cascade readiness time');
      }
      final parsed = DateTime.tryParse(raw);
      if (parsed == null ||
          parsed.toUtc().toIso8601String().substring(0, 19) !=
              raw.substring(0, 19)) {
        throw const FormatException('Invalid native cascade readiness time');
      }
      return parsed.toUtc();
    }

    final observed = timestamp(value['observedAt']);
    final expires = timestamp(value['expiresAt']);
    if (observed.isAfter(current.add(const Duration(seconds: 5))) ||
        !expires.isAfter(current) ||
        !expires.isAfter(observed) ||
        expires.difference(observed) > const Duration(seconds: 60) ||
        current.difference(observed) > const Duration(seconds: 60)) {
      throw StateError(
        'Native cascade readiness expired; verify the route again',
      );
    }
    final entry = value[protocol];
    final required = value['requiredFamilies'];
    final desired = required is Map ? required[protocol] : null;
    if (entry is! Map || desired is! Map) {
      throw const FormatException('Missing native cascade family readiness');
    }
    for (final family in ['ipv4', 'ipv6']) {
      if (entry[family] is! bool || desired[family] is! bool) {
        throw const FormatException('Invalid native cascade family readiness');
      }
      if (desired[family] == true && entry[family] != true) {
        throw StateError('Native cascade $protocol $family is not ready');
      }
    }
    return NativeProfileReadiness._(
      true,
      desired['ipv4'] == true,
      desired['ipv6'] == true,
    );
  }
}
