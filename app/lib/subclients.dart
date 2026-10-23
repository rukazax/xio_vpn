import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';

import 'account_access.dart';
import 'core.dart';

class SubclientApi {
  final AccountAccess access;
  SubclientApi(this.access);
  Future<Map<String, dynamic>> call(Map<String, dynamic> body) async {
    // Only the explicit certificate from the owner's profile is trusted. No
    // redirects, system proxy or permissive fallback; token stays on this host.
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
      ..connectionTimeout = const Duration(seconds: 15)
      ..findProxy = (_) => 'DIRECT';
    client.badCertificateCallback = (certificate, host, port) {
      final now = DateTime.now();
      return host == access.endpoint.host &&
          port == access.endpoint.port &&
          !now.isBefore(certificate.startValidity) &&
          !now.isAfter(certificate.endValidity) &&
          hashes.sha256.convert(certificate.der).toString() ==
              access.certificateSha256;
    };
    try {
      final request = await client
          .postUrl(access.endpoint)
          .timeout(const Duration(seconds: 20));
      request.followRedirects = false;
      request.headers.set(
        HttpHeaders.authorizationHeader,
        'Bearer ${access.token}',
      );
      request.headers.contentType = ContentType.json;
      final payload = utf8.encode(
        jsonEncode({...body, 'serverId': access.serverId}),
      );
      request.contentLength = payload.length;
      request.add(payload);
      final response = await request.close().timeout(
        const Duration(seconds: 130),
      );
      if (response.isRedirect ||
          response.statusCode != 200 && response.statusCode != 403) {
        throw StateError(
          'API аккаунта недоступен. Повторное создание автоматически не выполняется.',
        );
      }
      final bytes = <int>[];
      await for (final chunk in response.timeout(const Duration(seconds: 20))) {
        bytes.addAll(chunk);
        if (bytes.length > 200000) {
          throw const FormatException('Слишком большой ответ аккаунта');
        }
      }
      final data = Map<String, dynamic>.from(jsonDecode(utf8.decode(bytes)));
      if (data['ok'] != true) {
        throw StateError(switch (data['error']) {
          'User quota exceeded' => 'Лимит субклиентов исчерпан',
          'Admin access revoked' ||
          'Access denied' => 'Доступ аккаунта отозван',
          'Cannot revoke another admin user' =>
            'Можно отзывать только своих субклиентов',
          'Operation outcome unknown; owner reconciliation required' => 'Исход создания неизвестен. Нужна сверка владельцем сервера; новая операция не начата.',
          'Client access revoked' => 'Доступ этого субклиента уже отозван',
          _ => 'Операция аккаунта отклонена сервером',
        });
      }
      return data;
    } finally {
      client.close(force: true);
    }
  }
}

class Subclients {
  final AppStore store;
  final ManagedUser user;
  final Future<Map<String, dynamic>?> Function()? readRecord;
  final Future<void> Function(Map<String, dynamic>)? writeRecord;
  final SubclientApi Function(AccountAccess)? apiFactory;
  Subclients(
    this.store,
    this.user, {
    this.readRecord,
    this.writeRecord,
    this.apiFactory,
  });
  Future<void> _save(Map<String, dynamic> value) => writeRecord != null
      ? writeRecord!(value)
      : AccountVault.write(user.serverId, user.id, value);
  Future<Map<String, dynamic>> _record() async {
    final record =
        await (readRecord?.call() ?? AccountVault.read(user.serverId, user.id));
    if (record == null) {
      throw StateError('Аккаунту не выдано право создания субклиентов');
    }
    AccountAccess.parse(Map.from(record['access']), user.id, user.serverId);
    return record;
  }

  SubclientApi _api(Map record) => (apiFactory ?? SubclientApi.new)(
    AccountAccess.parse(Map.from(record['access']), user.id, user.serverId),
  );
  Future<Map<String, dynamic>> status() async {
    final record = await _record();
    final result = await _api(record).call({'action': 'status'});
    if (result['userId'] != user.id ||
        result['serverId'] != user.serverId ||
        result['limit'] is! int ||
        result['used'] is! int ||
        result['remaining'] is! int ||
        result['children'] is! List ||
        result['limit'] < 0 ||
        result['limit'] > 250) {
      throw const FormatException('Некорректный ответ аккаунта');
    }
    return {
      ...result,
      'pending': record['pending'] != null,
      'apiEndpoint': _api(record).access.endpoint.toString(),
    };
  }

  Future<UserBundle> create(String name) async {
    if (store.busy || store.status.active) {
      throw StateError('Сначала отключите VPN');
    }
    final record = await _record();
    Map<String, dynamic> pending;
    if (record['pending'] != null) {
      pending = Map<String, dynamic>.from(record['pending']);
    } else {
      if (name.trim().isEmpty || name.trim().length > 80) {
        throw const FormatException('Имя: от 1 до 80 символов');
      }
      final random = Random.secure();
      String hex(int count) => List.generate(
        count,
        (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
      ).join();
      final public = <String, String>{}, private = <String, String>{};
      for (final protocol in ['wireguard', 'awg']) {
        final pair = await X25519().newKeyPair();
        private[protocol] = base64Encode(await pair.extractPrivateKeyBytes());
        public[protocol] = base64Encode((await pair.extractPublicKey()).bytes);
      }
      final secret = base64Encode(
        List.generate(32, (_) => random.nextInt(256)),
      );
      final entryToken = base64Encode(
        List.generate(32, (_) => random.nextInt(256)),
      );
      pending = {
        'request': {
          'action': 'add',
          'id': hex(16),
          'name': name.trim(),
          'publicKeys': public,
          'rivet': {'secret': secret, 'entryToken': entryToken},
        },
        'private': private,
      };
      record['pending'] = pending;
      // Persist before sending; retry always uses the same keys and operation ID.
      await _save(record);
    }
    final request = Map<String, dynamic>.from(pending['request']);
    final response = await _api(record).call(request);
    final bundle = provisioningBundle(
      response,
      request,
      Map<String, String>.from(pending['private']),
      user.serverId,
    );
    final existing = store.users
        .where((u) => u.id == bundle.userId && u.serverId == bundle.serverId)
        .firstOrNull;
    if (existing == null || existing.profileIds.isEmpty) {
      await store.importBundle(bundle);
    }
    // Only this new child's VPN profiles are shared; never the parent capability.
    record.remove('pending');
    await _save(record);
    return bundle;
  }

  Future<void> revoke(String id) async {
    final record = await _record();
    await _api(record).call({'action': 'revoke', 'id': id});
    final child = store.users
        .where((u) => u.serverId == user.serverId && u.id == id)
        .firstOrNull;
    if (child != null) {
      child.revoked = true;
      await store.save();
      store.changed();
    }
  }
}

UserBundle provisioningBundle(
  Map<String, dynamic> response,
  Map<String, dynamic> request,
  Map<String, String> private,
  String serverId,
) {
  final server = Map<String, dynamic>.from(response['server']);
  final remoteUser = Map<String, dynamic>.from(response['user']);
  if (server['id'] != serverId ||
      remoteUser['id'] != request['id'] ||
      remoteUser['slot'] is! int ||
      remoteUser['slot'] < 2 ||
      remoteUser['slot'] > 254 ||
      response.containsKey('adminAccess') ||
      response.containsKey('clientAccess')) {
    throw const FormatException('Неожиданные данные субклиента');
  }
  final host = server['host'] as String;
  if (!RegExp(r'^[a-zA-Z0-9.:-]+$').hasMatch(host)) {
    throw const FormatException('Некорректный endpoint');
  }
  final endpoint = host.contains(':') ? '[$host]' : host;
  final slot = remoteUser['slot'] as int;
  final configs = <String, String>{};
  final extensions = (server['awg'] as Map).entries
      .map((e) => '${e.key} = ${e.value}')
      .join('\n');
  configs['awg'] =
      '[Interface]\nPrivateKey = ${private['awg']}\nAddress = 10.78.0.$slot/32, fd78:1::${slot.toRadixString(16)}/128\nDNS = ${managedDnsServers(server)}\nMTU = 1280\n$extensions\n\n[Peer]\nPublicKey = ${server['publicKeys']['awg']}\nEndpoint = $endpoint:51821\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n';
  WireGuardProfile.parse(configs['awg']!, amnezia: true);
  if (server['rivet'] is Map) {
    final meta = Map<String, dynamic>.from(server['rivet']);
    for (final protocol in rivetProtocols) {
      final config = jsonEncode({
        'protocol': protocol,
        'endpoint': '$endpoint:8443',
        'serverName': meta['serverName'],
        'pin': meta['pin'],
        'gatewayId': meta['gatewayId'],
        'id': request['id'],
        'secret': request['rivet']['secret'],
        'entryToken': request['rivet']['entryToken'],
        'ip': '10.79.0.$slot',
        if (meta['ipv6'] == true) 'ip6': 'fd79:1::${slot.toRadixString(16)}',
        if (meta['outerCA'] != null) 'outerCA': meta['outerCA'],
      });
      RivetProfile.parse(config);
      configs[protocol] = config;
    }
  }
  for (final e in Map<String, dynamic>.from(
    response['configs'] ?? {},
  ).entries) {
    if (!{'xray', 'cloak'}.contains(e.key) || e.value is! String) {
      throw const FormatException('Неожиданный профиль');
    }
    final parsed = ExtendedProfile.parse(e.value);
    if (parsed.protocol != e.key) {
      throw const FormatException('Протокол не совпадает');
    }
    configs[e.key] = parsed.encoded;
  }
  return UserBundle(request['name'], request['id'], serverId, configs);
}
