import 'dart:convert';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';

import 'cascade_model.dart';

enum NativeCascadeFamily { ipv4, ipv6 }

enum NativeCascadeRole { bridge, exit }

/// A verified installation, not a guessed SSH destination or display label.
class NativeCascadeTarget {
  NativeCascadeTarget({
    required this.serverId,
    required this.hostKey,
    required String publicHost,
    required bool exit,
  }) : publicHost = _host(publicHost, exit) {
    if (serverId.isEmpty ||
        serverId.length > 256 ||
        serverId.trim() != serverId ||
        RegExp(r'[\x00-\x1f\x7f]').hasMatch(serverId)) {
      throw const FormatException('Invalid cascade server identity');
    }
    if (hostKey.length != 50 ||
        !RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(hostKey)) {
      throw const FormatException('A verified SSH SHA256 identity is required');
    }
  }

  final String serverId;
  final String hostKey;
  final String publicHost;

  static String _host(String raw, bool exit) {
    final normalized = exit
        ? validateCascadeExit(raw)
        : validateCascadeBridge(raw);
    if (normalized == null) {
      throw const FormatException('Invalid cascade address');
    }
    return normalized;
  }

  Map<String, Object> toJson() => {
    'serverId': serverId,
    'hostKey': hostKey,
    'publicHost': publicHost,
  };
}

/// Immutable intent. Endpoint address family does NOT imply egress capability.
/// Selected native transports capture both IP families; an unavailable egress
/// family is blocked, never silently routed outside the configured cascade.
class NativeCascadePlan {
  NativeCascadePlan({
    required this.bridge,
    required this.exit,
    required Set<NativeCascadeFamily> families,
    required Map<NativeCascadeFamily, String> exitInterfaces,
    this.exitPort = 9443,
  }) : families = Set.unmodifiable(families),
       exitInterfaces = Map.unmodifiable(exitInterfaces) {
    if (validateCascadeBridge(bridge.publicHost) != bridge.publicHost ||
        validateCascadeExit(exit.publicHost) != exit.publicHost) {
      throw const FormatException('Invalid bridge/exit address roles');
    }
    if (bridge.serverId == exit.serverId ||
        bridge.publicHost == exit.publicHost) {
      throw const FormatException(
        'Two different verified servers are required',
      );
    }
    if (families.isEmpty ||
        exitPort < 1 ||
        exitPort > 65535 ||
        exitInterfaces.length != families.length ||
        exitInterfaces.keys.any((f) => !families.contains(f)) ||
        families.any(
          (f) =>
              !_interface.hasMatch(exitInterfaces[f] ?? '') ||
              exitInterfaces[f]!.trim() != exitInterfaces[f],
        ) ||
        exitInterfaces.values.any(
          (name) => name == uplink || name == 'xioawg0' || name == 'xiorivet',
        )) {
      throw const FormatException(
        'Explicit egress families and interfaces required',
      );
    }
  }

  factory NativeCascadePlan.fromJson(Object? value) {
    const fields = {
      'schema',
      'bridge',
      'exit',
      'innerFamilies',
      'exitPort',
      'exitInterfaces',
      'sourceMode',
    };
    if (value is! Map ||
        value['schema'] is! int ||
        value['schema'] != 1 ||
        value['sourceMode'] != 'hop-snat' ||
        value.length != fields.length ||
        !value.keys.every(fields.contains)) {
      throw const FormatException('Invalid cascade plan');
    }
    NativeCascadeTarget target(Object? data, bool exit) {
      if (data is! Map ||
          data.length != 3 ||
          data['serverId'] is! String ||
          data['hostKey'] is! String ||
          data['publicHost'] is! String) {
        throw const FormatException('Invalid cascade target');
      }
      return NativeCascadeTarget(
        serverId: data['serverId'] as String,
        hostKey: data['hostKey'] as String,
        publicHost: data['publicHost'] as String,
        exit: exit,
      );
    }

    final rawFamilies = value['innerFamilies'];
    final rawInterfaces = value['exitInterfaces'];
    if (rawFamilies is! List ||
        rawInterfaces is! Map ||
        value['exitPort'] is! int) {
      throw const FormatException('Invalid cascade families/interfaces');
    }
    final families = <NativeCascadeFamily>{};
    for (final name in rawFamilies) {
      final found = NativeCascadeFamily.values.where((f) => f.name == name);
      if (found.isEmpty || !families.add(found.single)) {
        throw const FormatException('Invalid cascade family');
      }
    }
    final interfaces = <NativeCascadeFamily, String>{};
    for (final entry in rawInterfaces.entries) {
      final found = NativeCascadeFamily.values.where(
        (f) => f.name == entry.key,
      );
      if (found.isEmpty || entry.value is! String) {
        throw const FormatException('Invalid cascade interface');
      }
      interfaces[found.single] = entry.value as String;
    }
    return NativeCascadePlan(
      bridge: target(value['bridge'], false),
      exit: target(value['exit'], true),
      families: families,
      exitInterfaces: interfaces,
      exitPort: value['exitPort'] as int,
    );
  }

  final NativeCascadeTarget bridge;
  final NativeCascadeTarget exit;
  final Set<NativeCascadeFamily> families;
  final Map<NativeCascadeFamily, String> exitInterfaces;
  final int exitPort;
  static const uplink = 'xiocascade0';
  static final _interface = RegExp(r'^[A-Za-z0-9_.-]{1,15}$');
  static const _bridgeHops = {
    'ipv4': '10.204.241.2',
    'ipv6': 'fd42:204:241::2',
  };
  static const _exitHops = {'ipv4': '10.204.241.1', 'ipv6': 'fd42:204:241::1'};
  static const _ingresses = {
    'awg': {
      'interface': 'xioawg0',
      'ipv4': '10.78.0.0/24',
      'ipv6': 'fd78:1::/64',
    },
    'rivet': {
      'interface': 'xiorivet',
      'ipv4': '10.79.0.0/24',
      'ipv6': 'fd79:1::/64',
    },
  };

  List<String> get familyNames => [
    for (final family in NativeCascadeFamily.values)
      if (families.contains(family)) family.name,
  ];

  /// Contains no tunnel secrets. Suitable for ordinary local setup references.
  Map<String, Object> toJson() => {
    'schema': 1,
    'bridge': bridge.toJson(),
    'exit': exit.toJson(),
    'innerFamilies': familyNames,
    'exitPort': exitPort,
    'exitInterfaces': {
      for (final f in NativeCascadeFamily.values)
        if (families.contains(f)) f.name: exitInterfaces[f]!,
    },
    'sourceMode': 'hop-snat',
  };

  String get identity =>
      hashes.sha256.convert(utf8.encode(jsonEncode(toJson()))).toString();

  /// Configuration accepted by the owned server connector. Only send this over
  /// the verified SSH stdin channel; NEVER shell argv, clipboard or diagnostics.
  Map<String, Object> configuration(
    NativeCascadeRole role,
    NativeCascadeKeys keys,
  ) {
    final isBridge = role == NativeCascadeRole.bridge;
    return {
      ...publicConfiguration(role, keys),
      'privateKey': isBridge ? keys._bridgePrivate : keys._exitPrivate,
      'presharedKey': keys._preshared,
    };
  }

  /// The exact normalized non-secret Python connector configuration, allowing
  /// a timed-out call to be inspected/resumed without blind remove/reconfigure.
  Map<String, Object> publicConfiguration(
    NativeCascadeRole role,
    NativeCascadeKeys keys,
  ) {
    final isBridge = role == NativeCascadeRole.bridge;
    return {
      'schema': 1,
      'enabled': true,
      'ownerOptIn': true,
      'role': role.name,
      'backend': 'userspace',
      'interface': uplink,
      'ingresses': _ingresses,
      'innerFamilies': familyNames,
      'sourceMode': 'hop-snat',
      'localAddresses': isBridge ? _bridgeHops : _exitHops,
      'peerAddresses': isBridge ? _exitHops : _bridgeHops,
      'peer': {
        'publicKey': isBridge ? keys.exitPublic : keys.bridgePublic,
        if (isBridge) 'host': exit.publicHost,
        if (isBridge) 'port': exitPort,
      },
      'listenPort': isBridge ? 0 : exitPort,
      'exitInterfaces': {
        if (!isBridge)
          for (final f in NativeCascadeFamily.values)
            if (families.contains(f)) f.name: exitInterfaces[f]!,
      },
    };
  }

  String configurationHash(NativeCascadeRole role, NativeCascadeKeys keys) =>
      hashes.sha256
          .convert(
            utf8.encode(jsonEncode(_sorted(publicConfiguration(role, keys)))),
          )
          .toString();

  static Object? _sorted(Object? value) {
    if (value is Map) {
      final names = value.keys.cast<String>().toList()..sort();
      return {for (final name in names) name: _sorted(value[name])};
    }
    if (value is List) return value.map(_sorted).toList();
    return value;
  }

  @override
  String toString() => 'NativeCascadePlan($identity)';
}

/// Separate secret object so plan serialization cannot accidentally export keys.
/// Persist in CredentialVault BEFORE the first remote mutation. Retain until
/// both nodes are inspected/config-matched; unknown outcomes are not rollback.
class NativeCascadeKeys {
  NativeCascadeKeys._(
    this._bridgePrivate,
    this.bridgePublic,
    this._exitPrivate,
    this.exitPublic,
    this._preshared,
  );
  final String _bridgePrivate;
  final String bridgePublic;
  final String _exitPrivate;
  final String exitPublic;
  final String _preshared;

  static Future<NativeCascadeKeys> generate() async {
    Future<(String, String)> pair() async {
      final key = await X25519().newKeyPair();
      return (
        base64Encode(await key.extractPrivateKeyBytes()),
        base64Encode((await key.extractPublicKey()).bytes),
      );
    }

    final bridge = await pair(), exit = await pair();
    return NativeCascadeKeys._(
      bridge.$1,
      bridge.$2,
      exit.$1,
      exit.$2,
      base64Encode(SecretKeyData.random(length: 32).bytes),
    );
  }

  Map<String, String> toVault() => {
    'schema': '1',
    'bridgePrivate': _bridgePrivate,
    'bridgePublic': bridgePublic,
    'exitPrivate': _exitPrivate,
    'exitPublic': exitPublic,
    'preshared': _preshared,
  };

  static Future<NativeCascadeKeys> fromVault(Map<String, String> data) async {
    const fields = {
      'schema',
      'bridgePrivate',
      'bridgePublic',
      'exitPrivate',
      'exitPublic',
      'preshared',
    };
    if (data['schema'] != '1' ||
        data.length != fields.length ||
        !data.keys.every(fields.contains)) {
      throw const FormatException('Invalid encrypted cascade key record');
    }
    List<int> bytes(String name) {
      final value = data[name]!;
      try {
        final decoded = base64Decode(value);
        if (decoded.length != 32 || base64Encode(decoded) != value) {
          throw const FormatException();
        }
        return decoded;
      } on FormatException {
        throw const FormatException('Invalid encrypted cascade key record');
      }
    }

    Future<void> check(String private, String public) async {
      final pair = await X25519().newKeyPairFromSeed(bytes(private));
      final derived = base64Encode((await pair.extractPublicKey()).bytes);
      bytes(public);
      if (derived != data[public]) {
        throw const FormatException('Cascade key pair does not match');
      }
    }

    await check('bridgePrivate', 'bridgePublic');
    await check('exitPrivate', 'exitPublic');
    bytes('preshared');
    if (data['bridgePublic'] == data['exitPublic']) {
      throw const FormatException('Cascade nodes require different keys');
    }
    return NativeCascadeKeys._(
      data['bridgePrivate']!,
      data['bridgePublic']!,
      data['exitPrivate']!,
      data['exitPublic']!,
      data['preshared']!,
    );
  }

  @override
  String toString() => 'NativeCascadeKeys([redacted])';
}
