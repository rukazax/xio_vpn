import 'account_access.dart';
import 'client_policy.dart';
import 'server_address.dart';

import 'dart:convert';
import 'dart:io';

/// Схема ссылок ранних сборок (устаревшее имя проекта). Оставлена только для
/// приёма профилей, выданных старыми версиями: новые ссылки всегда `xio://`,
/// записи в старом формате не создаются.
const String legacyX1oUriScheme = 'x1o://';

/// A ready-made set of third-party DNS resolvers. The addresses are the public
/// ones published by each provider; the app never probes them.
class DnsPreset {
  final String id, name;
  final List<String> servers;
  const DnsPreset(this.id, this.name, this.servers);
}

/// Hard-coded resolver list for the settings (and the install wizard).
const List<DnsPreset> dnsPresets = [
  DnsPreset('adguard', 'AdGuard DNS (IPv6)', [
    '2a10:50c0::ad1:ff',
    '2a10:50c0::ad2:ff',
  ]),
  DnsPreset('quad9', 'Quad9', ['9.9.9.9', '2620:fe::fe']),
  DnsPreset('cloudflare', 'Cloudflare', ['1.1.1.1', '2606:4700:4700::1111']),
  DnsPreset('google', 'Google Public DNS', ['8.8.8.8', '2001:4860:4860::8888']),
];

/// Identifier of the manual ("Свои") resolver set.
const String customDnsPreset = 'custom';

/// An Android resolver and an `AmneziaWG` `DNS = a, b` line both hold two
/// addresses; more would be silently dropped by a client.
const int maxDnsServers = 2;

/// Quad9 was written into generated AWG profiles before the setting existed, so
/// it stays the default and an upgrade keeps the same DNS.
const List<String> defaultDnsServers = ['9.9.9.9', '2620:fe::fe'];

final _dnsHostname = RegExp(
  r'^([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$',
);

bool _isIpLiteral(String value) {
  if (!RegExp(r'^[0-9a-fA-F:.]+$').hasMatch(value)) return false;
  try {
    InternetAddress(value);
    return true;
  } on ArgumentError {
    return false;
  }
}

/// True for an IPv6 literal (a domain name is never one).
bool isIpv6Literal(String value) =>
    value.contains(':') && _isIpLiteral(value.trim());

/// True for an IPv4 literal (a domain name with digits is never one).
bool isIpv4Literal(String value) {
  final trimmed = value.trim();
  return !trimmed.contains(':') && _isIpLiteral(trimmed);
}

/// Validates one resolver address: IPv4, IPv6 or a domain name.
///
/// Ports, schemes, credentials and paths are rejected: a resolver address is
/// written into a profile line, not into a URL.
String validateDnsServer(String input) {
  final raw = input.trim();
  if (raw.isEmpty) {
    throw const FormatException('Укажите адрес DNS-сервера');
  }
  if (raw.length > 253) {
    throw const FormatException('Адрес DNS-сервера слишком длинный');
  }
  if (_isIpLiteral(raw)) return raw;
  if (raw.contains(':') ||
      raw.contains('/') ||
      raw.contains('@') ||
      raw.contains('?') ||
      raw.contains('#')) {
    throw const FormatException(
      'DNS: IPv4, IPv6 или домен — без порта, схемы и пути',
    );
  }
  if (!_dnsHostname.hasMatch(raw)) {
    throw const FormatException('DNS: некорректный адрес');
  }
  return raw.toLowerCase();
}

/// Validates the selected set: at most two addresses, no duplicates.
List<String> validateDnsServers(Iterable<String> input) {
  final result = <String>[];
  for (final value in input) {
    if (value.trim().isEmpty) continue;
    final normalized = validateDnsServer(value);
    if (!result.contains(normalized)) result.add(normalized);
  }
  if (result.isEmpty) {
    throw const FormatException('Укажите хотя бы один DNS-сервер');
  }
  if (result.length > maxDnsServers) {
    throw const FormatException('Не больше двух DNS-серверов');
  }
  return result;
}

/// Preset that exactly matches [servers], or [customDnsPreset].
String dnsPresetIdFor(List<String> servers) {
  final wanted = servers.map((v) => v.trim().toLowerCase()).toSet();
  for (final preset in dnsPresets) {
    if (wanted.length == preset.servers.length &&
        preset.servers.every(wanted.contains)) {
      return preset.id;
    }
  }
  return customDnsPreset;
}

/// Human-readable name of a resolver set for the settings and the wizard.
String dnsServersLabel(List<String> servers) {
  if (servers.isEmpty) return 'не заданы';
  final id = dnsPresetIdFor(servers);
  var name = 'Свои';
  for (final preset in dnsPresets) {
    if (preset.id == id) name = preset.name;
  }
  return '$name · ${servers.join(', ')}';
}

/// Writes the configured resolvers into an AWG profile.
///
/// Advertise IPv6 DNS only when the managed gateway confirms IPv6 egress: an
/// IPv6 DNS black hole otherwise stalls Android's resolver on AWG. An explicit
/// IPv6-only choice is kept as is — the owner asked for that resolver, and the
/// settings screen warns about the missing IPv6 uplink.
String managedDnsServers(
  Map<dynamic, dynamic> server, [
  Iterable<String>? selection,
]) {
  final rivet = server['rivet'];
  final ipv6 = rivet is Map && rivet['ipv6'] == true;
  final chosen = <String>[
    for (final value in selection ?? defaultDnsServers)
      if (value.trim().isNotEmpty) value.trim(),
  ];
  final usable = ipv6
      ? chosen
      : [
          for (final value in chosen)
            if (!isIpv6Literal(value)) value,
        ];
  final list = usable.isEmpty ? chosen : usable;
  return list.isEmpty ? defaultDnsServers.first : list.join(', ');
}

class ManagedServer {
  /// [host] is the SSH transport; [publicHost] is the VPN service address.
  final String id, host, publicHost, username;
  String name, country, hostKey;
  final String actorId;
  bool get delegated => actorId.isNotEmpty;
  String get flag => countryFlag(country);
  String get label => '$flag ${name.isEmpty ? host : name}';
  final int port;
  ManagedServer({
    required this.id,
    required String host,
    String? publicHost,
    this.port = 22,
    this.username = 'root',
    this.name = '',
    this.country = '',
    this.hostKey = '',
    this.actorId = '',
  }) : host = normalizeServerHost(host),
       publicHost = normalizeServerHost(
         publicHost == null || publicHost.trim().isEmpty ? host : publicHost,
       );
  factory ManagedServer.fromJson(Map<String, dynamic> j) {
    final host = j['host'], publicHost = j['publicHost'];
    if (host is! String || (publicHost != null && publicHost is! String)) {
      throw const FormatException('Некорректный адрес сервера');
    }
    return ManagedServer(
      id: j['id'],
      host: host,
      publicHost: publicHost,
      port: j['port'] ?? 22,
      username: j['username'] ?? 'root',
      name: j['name'] ?? '',
      country: j['country'] ?? '',
      hostKey: j['hostKey'] ?? '',
      actorId: j['actorId'] ?? '',
    );
  }
  Map<String, dynamic> toJson() => {
    'id': id,
    'host': host,
    'publicHost': publicHost,
    'port': port,
    'username': username,
    'name': name,
    'country': country,
    'hostKey': hostKey,
    'actorId': actorId,
  };
}

class ManagedUser {
  final String id, name, serverId;
  final Map<String, String> profileIds;
  bool revoked;
  bool admin;
  int userLimit;
  Map<String, dynamic> statistics;
  ManagedUser({
    required this.id,
    required this.name,
    required this.serverId,
    required this.profileIds,
    this.revoked = false,
    this.admin = false,
    this.userLimit = 0,
    Map<String, dynamic>? statistics,
  }) : statistics = statistics ?? {};
  factory ManagedUser.fromJson(Map<String, dynamic> j) => ManagedUser(
    id: j['id'],
    name: j['name'],
    serverId: j['serverId'],
    profileIds: Map<String, String>.from(j['profileIds']),
    revoked: j['revoked'] ?? false,
    admin: j['admin'] ?? false,
    userLimit: j['userLimit'] ?? 0,
    statistics: Map<String, dynamic>.from(j['statistics'] ?? {}),
  );
  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'serverId': serverId,
    'profileIds': profileIds,
    'revoked': revoked,
    'admin': admin,
    'userLimit': userLimit,
    'statistics': statistics,
  };
}

Uri validateCheckSite(String input) {
  final raw = input.trim();
  final uri = Uri.tryParse(raw.contains('://') ? raw : 'https://$raw');
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasFragment ||
      raw.length > 2048) {
    throw const FormatException(
      'Укажите HTTPS-адрес сайта без логина и пароля',
    );
  }
  return uri;
}

String countryFlag(String code) {
  if (!RegExp(r'^[A-Z]{2}$').hasMatch(code) || code == 'ZZ') return '🌐';
  return String.fromCharCodes(code.codeUnits.map((c) => 0x1f1e6 + c - 65));
}

class UserBundle {
  final String name, userId, serverId;
  final Map<String, String> configs;
  final Map<String, dynamic>? adminAccess;
  final Map<String, dynamic>? clientAccess;
  const UserBundle(
    this.name,
    this.userId,
    this.serverId,
    this.configs, {
    this.adminAccess,
    this.clientAccess,
  });
  String encode() =>
      'xio://${base64Url.encode(utf8.encode(jsonEncode({'schema': clientAccess != null
          ? 3
          : adminAccess == null
          ? 1
          : 2, 'name': name, 'userId': userId, 'serverId': serverId, 'configs': configs, if (adminAccess != null) 'adminAccess': adminAccess, if (clientAccess != null) 'clientAccess': clientAccess})))}';
  static UserBundle decode(String raw) {
    if (raw.length > 200000 ||
        !(raw.startsWith('xio://') || raw.startsWith(legacyX1oUriScheme))) {
      throw const FormatException('Некорректный профиль XIO');
    }
    try {
      final j = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(raw.substring(6)))),
      );
      if (j is! Map ||
          ![1, 2, 3].contains(j['schema']) ||
          j['name'] is! String ||
          j['name'].length > 80 ||
          j['userId'] is! String ||
          !RegExp(r'^[a-f0-9]{32}$').hasMatch(j['userId']) ||
          j['serverId'] is! String ||
          !RegExp(r'^[a-zA-Z0-9-]{1,80}$').hasMatch(j['serverId'])) {
        throw const FormatException('Invalid metadata');
      }
      if (clientOnlyBuild &&
          (j.containsKey('adminAccess') ||
              j.keys.toSet().difference({
                'schema',
                'name',
                'userId',
                'serverId',
                'configs',
                'clientAccess',
              }).isNotEmpty)) {
        throw const FormatException(
          'Административный доступ запрещён в клиенте',
        );
      }
      Map<String, dynamic>? clientAccess;
      if (j['schema'] == 3) {
        if (j.containsKey('adminAccess')) {
          throw const FormatException('Mixed credentials');
        }
        clientAccess = AccountAccess.parse(
          Map.from(j['clientAccess']),
          j['userId'],
          j['serverId'],
        ).toJson();
      } else if (j.containsKey('clientAccess')) {
        throw const FormatException('Invalid schema');
      }
      final configs = Map<String, String>.from(j['configs']);
      configs.removeWhere(
        (key, _) => const {
          'wireguard',
          'openvpn',
          'ikev2',
          'shadowsocks',
          'tailscale',
        }.contains(key),
      );
      if (configs.isEmpty ||
          configs.keys.any(
            (p) =>
                !['awg', 'rivet-h3', 'rivet-s1', 'xray', 'cloak'].contains(p),
          ) ||
          configs.values.any((v) => v.length > 65536)) {
        throw const FormatException('Invalid protocols');
      }
      Map<String, dynamic>? access;
      if (j['schema'] == 2) {
        access = Map<String, dynamic>.from(j['adminAccess']);
        final server = ManagedServer.fromJson(
          Map<String, dynamic>.from(access['server']),
        );
        if (server.id != j['serverId'] ||
            server.actorId != j['userId'] ||
            access['key'] is! String ||
            !(access['key'] as String).startsWith(
              '-----BEGIN OPENSSH PRIVATE KEY-----',
            ) ||
            (access['key'] as String).length > 16000 ||
            access.containsKey('password')) {
          throw const FormatException('Invalid delegation');
        }
      }
      return UserBundle(
        j['name'],
        j['userId'],
        j['serverId'],
        configs,
        adminAccess: access,
        clientAccess: clientAccess,
      );
    } catch (_) {
      throw const FormatException(
        'Повреждённый или неподдерживаемый профиль XIO',
      );
    }
  }
}
