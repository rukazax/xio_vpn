import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'connection_attempt.dart';
import 'legal_record.dart';
import 'rivet_profile.dart';
import 'routing_domains.dart';

/// Which platform identity the plan is published for. Desktop publishes no
/// routing snapshot: its helper must reject a non-null one as POLICY_INVALID.
enum PolicyPlatform { android, desktop }

/// Derives the admission payload from the same immutable document that will be
/// renamed. Never consult mutable AppStore after awaiting persistence.
///
/// Wire contract: WIRE-V2.md section 1. Anything outside the exact shape below
/// is a [FormatException]; the caller maps it to POLICY_INVALID.
class ConnectionPlan {
  ConnectionPlan._(Map<String, dynamic> value) : bytes = jsonEncode(value);
  final String bytes;
  Map<String, dynamic> get json =>
      Map<String, dynamic>.from(jsonDecode(bytes) as Map);

  static const schema = 2;
  static const maxCandidates = 16;
  static const maxRoutingEntries = 128;
  static final _digest = RegExp(r'^[a-f0-9]{64}$');
  static final _package = RegExp(r'^[A-Za-z0-9][A-Za-z0-9_.]*$');
  static const _routingModes = {
    'all',
    'include',
    'exclude',
    'ipInclude',
    'ipExclude',
  };

  /// Lowercase hex SHA-256 of the exact native-stored config bytes as UTF-8.
  /// No trimming, newline, JSON or DNS transformations are applied here.
  static String configDigest(String exactStoredBytes) =>
      sha256.convert(utf8.encode(exactStoredBytes)).toString();

  static ConnectionPlan fromDocument(
    Map<String, dynamic> document, {
    required Set<String> supportedProtocols,
    required bool clientOnly,
    PolicyPlatform platform = PolicyPlatform.android,
    Object? routing,
    required String? Function(String id) config,
  }) {
    final policy = ConnectionPolicy.fromDocument(document);
    final rawProfiles = document['profiles'];
    if (rawProfiles is! List) {
      throw const FormatException('Invalid profile graph');
    }
    final profiles = <Map<String, dynamic>>[];
    final seen = <String>{};
    for (final value in rawProfiles) {
      if (value is! Map ||
          value['id'] is! String ||
          value['protocol'] is! String ||
          value['endpoint'] is! String ||
          !seen.add(value['id'] as String)) {
        throw const FormatException('Invalid profile graph');
      }
      profiles.add(Map<String, dynamic>.from(value));
    }
    final selected = document['selected'];
    if (selected != null && selected is! String) {
      throw const FormatException('Invalid selected identity');
    }
    Map<String, dynamic>? initial;
    for (final profile in profiles) {
      if (profile['id'] == selected) initial = profile;
    }
    final users = document['users'] ?? const [];
    if (users is! List) throw const FormatException('Invalid user graph');
    Map? user;
    for (final entry in users) {
      if (entry is! Map ||
          entry['profileIds'] is! Map ||
          (entry['profileIds'] as Map).values.any((v) => v is! String)) {
        throw const FormatException('Invalid user graph');
      }
      if ((entry['profileIds'] as Map).values.contains(selected)) {
        if (user != null) {
          throw const FormatException('Ambiguous selected owner');
        }
        user = entry;
      }
    }
    final ordered = <Map<String, dynamic>>[];
    bool usable(Map<String, dynamic> p) =>
        nativeProtocols.contains(p['protocol']) &&
        supportedProtocols.contains(p['protocol']);
    if (initial != null && user?['revoked'] != true) {
      if (usable(initial)) ordered.add(initial);
      if (policy == ConnectionPolicy.automatic) {
        final allowed = user?['profileIds'] as Map?;
        final pool = profiles.where(
          (p) =>
              usable(p) &&
              (clientOnly ||
                  user == null ||
                  allowed!.values.contains(p['id'])),
        );
        final preferred = document['priorityProtocol'];
        int preference(Map<String, dynamic> p) => protocolPreference(
          p['protocol'] as String,
          preferred is String && nativeProtocols.contains(preferred)
              ? preferred
              : 'xray',
          restricted: true,
        );
        // Explicit source-order tie-break avoids native/Dart sort differences.
        int compare(Map<String, dynamic> a, Map<String, dynamic> b) {
          final priority = preference(a).compareTo(preference(b));
          return priority == 0
              ? profiles.indexOf(a).compareTo(profiles.indexOf(b))
              : priority;
        }

        final same = pool
            .where(
              (p) => p['id'] != selected && p['endpoint'] == initial!['endpoint'],
            )
            .toList()
          ..sort(compare);
        final other = pool
            .where(
              (p) => p['id'] != selected && p['endpoint'] != initial!['endpoint'],
            )
            .toList()
          ..sort(compare);
        ordered.addAll([...same, ...other]);
      }
    }
    if (ordered.length > maxCandidates) {
      throw const FormatException('Too many plan candidates');
    }
    // Exact stored bytes are the only admissible config identity. An unreadable
    // config never becomes "automatic" for another profile: a selected one is a
    // hard POLICY_INVALID, other candidates simply cannot be admitted.
    final admitted = <Map<String, dynamic>>[];
    final digests = <String, String>{};
    for (final profile in ordered) {
      final id = profile['id'] as String;
      final bytes = config(id);
      // Empty or whitespace-only stored bytes are UNREADABLE, not a legitimate
      // all-zero-input digest: no protocol can be admitted from "no config".
      if (bytes == null || bytes.trim().isEmpty) {
        if (id == selected) {
          throw const FormatException('Selected configuration unreadable');
        }
        continue;
      }
      final digest = configDigest(bytes);
      if (!_digest.hasMatch(digest)) {
        throw const FormatException('Invalid configuration digest');
      }
      digests[id] = digest;
      admitted.add(profile);
    }
    final siteCheck = document['siteCheckEnabled'] ?? false;
    if (siteCheck is! bool) {
      throw const FormatException('Invalid verification option');
    }
    final site = document['checkSite'] ?? 'https://youtube.com';
    final parsed = site is String ? Uri.tryParse(site) : null;
    if (parsed == null ||
        parsed.scheme != 'https' ||
        parsed.host.isEmpty ||
        parsed.userInfo.isNotEmpty) {
      throw const FormatException('Invalid verification site');
    }
    final timeout = document['protocolTimeoutSeconds'] ?? 15;
    if (timeout is! int || timeout < 5 || timeout > 60) {
      throw const FormatException('Invalid candidate timeout');
    }
    final disclosure = document['vpnDisclosure'];
    if (disclosure != null && disclosure is! String) {
      throw const FormatException('Invalid VPN disclosure');
    }
    final priority = document['priorityProtocol'];
    if (priority != null && priority is! String) {
      throw const FormatException('Invalid protocol priority');
    }
    return ConnectionPlan._({
      'schema': schema,
      'selectedId': selected,
      'ids': [for (final p in admitted) p['id']],
      'profiles': [
        for (final p in admitted)
          {
            'id': p['id'],
            'protocol': p['protocol'],
            'endpoint': p['endpoint'],
            'configDigest': digests[p['id']],
          },
      ],
      'routing': canonicalRouting(routing, platform: platform),
      'priorityProtocol': priority,
      'policy': policy.toJson(),
      'site': parsed.toString(),
      'siteCheckEnabled': siteCheck,
      'timeoutSeconds': timeout,
      'roundMillis': 30000,
      'clientOnly': clientOnly,
      'consentRevision':
          LegalRecord.parse(document['legalRecord'])?.revision ?? '',
      'vpnDisclosure': disclosure,
    });
  }

  /// Android publishes the native routing snapshot; desktop publishes `null`
  /// and its helper rejects a non-null snapshot. Lists are validated with the
  /// app's existing parsers and made deterministic (dedupe + byte order).
  static Map<String, dynamic>? canonicalRouting(
    Object? policy, {
    required PolicyPlatform platform,
  }) {
    if (platform == PolicyPlatform.desktop) {
      if (policy != null) {
        throw const FormatException('Desktop cannot publish routing rules');
      }
      return null;
    }
    if (policy is! Map) {
      throw const FormatException('Routing snapshot missing');
    }
    final mode = policy['mode'];
    if (mode is! String || !_routingModes.contains(mode)) {
      throw const FormatException('Invalid routing mode');
    }
    final packages = _canonical(
      policy['packages'],
      'package',
      (entry) => _package.hasMatch(entry) ? entry : null,
      max: maxRoutingEntries,
    );
    final networks = _canonical(
      policy['networks'],
      'network',
      (entry) => isIpOrCidr(entry) ? entry : null,
      max: maxRoutingEntries,
    );
    final domains = _canonical(
      policy['domains'],
      'domain',
      normalizeDomainRule,
      max: maxRoutingEntries,
    );
    return {
      'mode': mode,
      'packages': packages,
      'networks': networks,
      'domains': domains,
    };
  }

  static List<String> _canonical(
    Object? value,
    String what,
    String? Function(String entry) normalize, {
    required int max,
  }) {
    if (value == null) return const [];
    if (value is! List) {
      throw FormatException('Invalid routing $what list');
    }
    final result = <String>{};
    for (final entry in value) {
      if (entry is! String) {
        throw FormatException('Invalid routing $what entry');
      }
      final trimmed = entry.trim();
      if (trimmed.isEmpty || trimmed.length > 255) {
        throw FormatException('Invalid routing $what entry');
      }
      final normalized = normalize(trimmed);
      if (normalized == null) {
        throw FormatException('Invalid routing $what entry');
      }
      result.add(normalized);
    }
    if (result.length > max) {
      throw FormatException('Too many routing $what entries');
    }
    return result.toList()..sort();
  }
}
