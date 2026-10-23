import 'account_access.dart';
import 'client_policy.dart';

import 'dart:convert';

/// Advertise IPv6 DNS only when the managed gateway confirms IPv6 egress.
/// An IPv6 DNS black hole can otherwise stall Android's resolver on AWG.
String managedDnsServers(Map<dynamic, dynamic> server) {
  final rivet = server['rivet'];
  return rivet is Map && rivet['ipv6'] == true
      ? '9.9.9.9, 2620:fe::fe'
      : '9.9.9.9';
}

class ManagedServer {
  final String id, host, username;
  String name, country, hostKey;
  final String actorId;
  bool get delegated => actorId.isNotEmpty;
  String get flag => countryFlag(country);
  String get label => '$flag ${name.isEmpty ? host : name}';
  final int port;
  ManagedServer({
    required this.id,
    required this.host,
    this.port = 22,
    this.username = 'root',
    this.name = '',
    this.country = '',
    this.hostKey = '',
    this.actorId = '',
  });
  factory ManagedServer.fromJson(Map<String, dynamic> j) => ManagedServer(
    id: j['id'],
    host: j['host'],
    port: j['port'] ?? 22,
    username: j['username'] ?? 'root',
    name: j['name'] ?? '',
    country: j['country'] ?? '',
    hostKey: j['hostKey'] ?? '',
    actorId: j['actorId'] ?? '',
  );
  Map<String, dynamic> toJson() => {
    'id': id,
    'host': host,
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
        !(raw.startsWith('xio://') || raw.startsWith('x1o://'))) {
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
