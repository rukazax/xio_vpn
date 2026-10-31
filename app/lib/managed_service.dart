import 'account_access.dart';
import 'credentials.dart';
import 'server_address.dart';

import 'package:dartssh2/dartssh2.dart';

import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';

import 'core.dart';

/// The server bundle described by `assets/xio-server-release.json`.
/// Installation must never upload an archive that does not match this manifest.
class ServerRelease {
  final int recipeVersion;
  final String sha256;

  /// Digest of `assets/xio-bootstrap.sh`. The script runs as root over SSH, so
  /// the manifest must pin it as well as the archive.
  final String? bootstrapSha256;
  const ServerRelease(this.recipeVersion, this.sha256, {this.bootstrapSha256});
  static const manifestAsset = 'assets/xio-server-release.json';
  static Future<ServerRelease> load(AssetBundle assets) async =>
      parse(await assets.loadString(manifestAsset));
  static ServerRelease parse(String raw) {
    final data = jsonDecode(raw);
    if (data is! Map || data['schema'] != 1) {
      throw const FormatException('Некорректный манифест серверного релиза');
    }
    final recipe = data['recipeVersion'], sha = data['sha256'];
    final bootstrap = data['bootstrapSha256'];
    if (recipe is! int ||
        recipe < 1 ||
        sha is! String ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(sha) ||
        (bootstrap != null &&
            (bootstrap is! String ||
                !RegExp(r'^[a-f0-9]{64}$').hasMatch(bootstrap)))) {
      throw const FormatException('Некорректный манифест серверного релиза');
    }
    return ServerRelease(
      recipe,
      sha,
      bootstrapSha256: bootstrap as String?,
    );
  }

  void verifyBootstrap(String script) {
    final pinned = bootstrapSha256;
    if (pinned == null) return; // Older manifest: archive digest still applies.
    if (digest(utf8.encode(script)) != pinned) {
      throw StateError(
        'Установочный скрипт не совпадает с манифестом приложения',
      );
    }
  }

  String digest(List<int> bytes) => hashes.sha256.convert(bytes).toString();
  void verifyArchive(List<int> bytes) {
    if (digest(bytes) != sha256) {
      throw StateError(
        'Архив серверного релиза не совпадает с манифестом приложения',
      );
    }
  }
}

Future<(String, String)> newManagementKey() async {
  final pair = await Ed25519().newKeyPair();
  final seed = await pair.extractPrivateKeyBytes();
  final pub = (await pair.extractPublicKey()).bytes;
  List<int> uint(int n) => [
    (n >> 24) & 255,
    (n >> 16) & 255,
    (n >> 8) & 255,
    n & 255,
  ];
  List<int> block(List<int> b) => [...uint(b.length), ...b];
  final alg = utf8.encode('ssh-ed25519');
  final public = [...block(alg), ...block(pub)];
  final check = Random.secure().nextInt(0x7fffffff);
  final secret = [
    ...uint(check),
    ...uint(check),
    ...block(alg),
    ...block(pub),
    ...block([...seed, ...pub]),
    ...block([]),
  ];
  var padding = 1;
  while (secret.length % 8 != 0) {
    secret.add(padding++);
  }
  final all = [
    ...utf8.encode('openssh-key-v1\u0000'),
    ...block(utf8.encode('none')),
    ...block(utf8.encode('none')),
    ...block([]),
    ...uint(1),
    ...block(public),
    ...block(secret),
  ];
  final b64 = base64Encode(all);
  final lines = [
    for (var i = 0; i < b64.length; i += 64)
      b64.substring(i, (i + 64).clamp(0, b64.length)),
  ];
  final pem =
      '-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n';
  SSHKeyPair.fromPem(pem); // Validate the standard serialization before use.
  return (pem, 'ssh-ed25519 ${base64Encode(public)}');
}

class ManagedService {
  final VpsService ssh;
  final AssetBundle assets;
  ManagedService(this.ssh, {AssetBundle? assets})
    : assets = assets ?? rootBundle;

  /// Only an owner with a previously verified SSH identity may update an
  /// existing installation. Delegated users cannot replace server executables.
  Future<void> ensureUpdated(AppStore store, ManagedServer server) async {
    if (server.delegated) return;
    if (store.status.active || store.busy) {
      store.log('Обновление сервера отложено до отключения VPN');
      return;
    }
    if (server.hostKey.isEmpty || ssh.verifiedFingerprint != server.hostKey) {
      throw StateError(
        'Для обновления нужна сохранённая SSH-идентичность сервера',
      );
    }
    final local = await ServerRelease.load(assets);
    final remote = await command({'action': 'inspect'});
    final metadata = Map<String, dynamic>.from(remote['server']);
    if (metadata['id'] != server.id) {
      throw StateError('Идентичность сервера изменилась');
    }
    final revision = metadata['recipeVersion'] as int? ?? 13;
    if (revision > local.recipeVersion) return; // Never downgrade.
    if (revision == local.recipeVersion &&
        metadata['bundleSha256'] == local.sha256) {
      return;
    }
    final archive = await assets.load('assets/xio-server.tar.gz');
    final archiveBytes = archive.buffer.asUint8List(
      archive.offsetInBytes,
      archive.lengthInBytes,
    );
    local.verifyArchive(archiveBytes);
    final program = await assets.loadString('assets/xio-server-update.py');
    String quoted(String value) => "'${value.replaceAll("'", "'\\''")}'";
    if (store.status.active || store.busy || store.serverMaintenance) return;
    store.serverMaintenance = true;
    store.changed();
    try {
      await store.saveNativePlan();
      final bytes = await ssh.executeInput(
        'python3 -c ${quoted(program)} ${quoted(local.sha256)} ${quoted(server.id)}',
        archiveBytes,
        timeout: const Duration(minutes: 12),
      );
      final result = Map<String, dynamic>.from(jsonDecode(utf8.decode(bytes)));
      if (result['ok'] != true) {
        throw StateError(
          'Не удалось обновить сервер. Проверьте его состояние; обновление будет повторено.',
        );
      }
    } finally {
      store.serverMaintenance = false;
      await store.saveNativePlan();
      store.changed();
    }
    store.log('Сервер XIO обновлён; пользователи и ключи сохранены');
  }

  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    final bytes = await ssh.executeInput(
      'python3 /usr/local/lib/xio-managed/admin.py',
      utf8.encode(jsonEncode(request)),
      timeout: timeout,
    );
    final result = Map<String, dynamic>.from(jsonDecode(utf8.decode(bytes)));
    if (result['ok'] != true) {
      final message = switch (result['error']) {
        'User quota exceeded' => 'Лимит действующих пользователей исчерпан',
        'Only owner may create admins' =>
          'Только владелец может создавать администраторов',
        'Operation not permitted' || 'Cannot revoke another admin user' =>
          'Операция недоступна администратору',
        'Admin access revoked' => 'Доступ отозван',
        'Invalid admin limit' => 'Некорректный лимит: от 0 до 250',
        _ => result['error'] ?? 'Ошибка сервера',
      };
      throw StateError(message);
    }
    return result;
  }

  /// Returns the server record only for a complete owned installation. A
  /// missing admin.py, or an installation that is not ready, is not silently
  /// treated as a fresh server; an incomplete receipt is a hard stop.
  Future<Map<String, dynamic>?> _inspectReady() async {
    try {
      final result = await command({'action': 'inspect'});
      if (result['phase'] != 'ready') {
        throw StateError(
          'Незавершённая установка XIO. Удалите её перед повторной установкой.',
        );
      }
      final server = result['server'];
      if (server is! Map) {
        throw StateError('Сервер не подтвердил идентичность установки');
      }
      return Map<String, dynamic>.from(server);
    } on StateError catch (e) {
      if (e.message.startsWith('Незавершённая установка')) rethrow;
      // No owned admin.py yet: a fresh server belongs to the bootstrap path.
      return null;
    } on FormatException {
      return null;
    }
  }

  Future<ManagedServer> _registerInstalled(
    AppStore store,
    SshTarget target, {
    required Map<String, dynamic> remote,
    required String requestedHost,
    required bool explicitVpnHost,
    required bool existing,
    required String fingerprint,
  }) async {
    final id = remote['id'], confirmedRaw = remote['host'];
    if (id is! String || id.isEmpty) {
      throw StateError('Сервер не подтвердил идентичность установки');
    }
    if (confirmedRaw is! String || confirmedRaw.isEmpty) {
      throw StateError('Сервер не подтвердил VPN-адрес');
    }
    final confirmed = normalizeServerHost(confirmedRaw);
    // A ready installation returns its original host. Never silently build
    // client profiles for a domain the server is not actually configured for.
    if (canonicalServerHost(confirmed) != canonicalServerHost(requestedHost)) {
      if (!existing || explicitVpnHost) {
        throw StateError(
          existing
              ? 'Сервер уже настроен на другой VPN-адрес: $confirmed. '
                    'Укажите этот адрес в поле VPN-адреса или удалите установку.'
              : 'Сервер подтвердил другой VPN-адрес: $confirmed',
        );
      }
    }
    final server = ManagedServer(
      id: id,
      host: target.host,
      publicHost: confirmed,
      port: target.port,
      username: target.username,
      country: remote['country'] ?? '',
      hostKey: fingerprint,
    );
    final known = store.servers.where((s) => s.id == server.id).firstOrNull;
    if (known != null) {
      if (known.host != server.host ||
          known.port != server.port ||
          known.username != server.username ||
          known.publicHost != server.publicHost) {
        throw StateError(
          'Сервер с этим идентификатором уже добавлен с другими параметрами',
        );
      }
      if (known.hostKey.isEmpty) {
        known.hostKey = server.hostKey;
        await store.save();
      }
      return known;
    }
    store.servers.add(server);
    await store.save();
    store.changed();
    return server;
  }

  Future<ManagedServer> install(AppStore store, {String? publicHost}) async {
    final target = ssh.target;
    if (target == null) throw StateError('Сначала подключитесь по SSH');
    final fingerprint = ssh.verifiedFingerprint;
    if (!RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
      throw StateError('Нет проверенного ключа SSH сервера');
    }
    // Validate before uploading anything. A provider SSH proxy is not a VPN endpoint.
    final requested = publicHost?.trim();
    final explicitVpnHost = requested != null && requested.isNotEmpty;
    final vpnHost = normalizeServerHost(
      explicitVpnHost ? requested : target.host,
    );
    // Never overwrite a ready installation with the (possibly older) bundled
    // archive just because the user opened setup again.
    final ready = await _inspectReady();
    if (ready != null) {
      return _registerInstalled(
        store,
        target,
        remote: ready,
        requestedHost: vpnHost,
        explicitVpnHost: explicitVpnHost,
        existing: true,
        fingerprint: fingerprint,
      );
    }
    final release = await ServerRelease.load(assets);
    final archive = await assets.load('assets/xio-server.tar.gz');
    final archiveBytes = archive.buffer.asUint8List(
      archive.offsetInBytes,
      archive.lengthInBytes,
    );
    release.verifyArchive(archiveBytes);
    final bootstrap = await assets.loadString('assets/xio-bootstrap.sh');
    release.verifyBootstrap(bootstrap);
    // The script compares its stdin against this digest before unpacking.
    final script =
        "export XIO_EXPECTED_ARCHIVE_SHA256='${release.sha256}'\n$bootstrap";
    await ssh.executeInput(
      script,
      archiveBytes,
      timeout: const Duration(minutes: 30),
    );
    final result = await command({
      'action': 'init',
      'host': vpnHost,
      'restrictedNetwork': true,
    }, timeout: const Duration(minutes: 30));
    final remote = result['server'];
    if (remote is! Map) {
      throw StateError('Сервер не подтвердил установку VPN');
    }
    return _registerInstalled(
      store,
      target,
      remote: Map<String, dynamic>.from(remote),
      requestedHost: vpnHost,
      explicitVpnHost: explicitVpnHost,
      existing: result['existing'] == true,
      fingerprint: fingerprint,
    );
  }

  Future<ManagedUser> createUser(
    AppStore store,
    ManagedServer server,
    String name, {
    bool admin = false,
    int userLimit = 0,
  }) async {
    if (admin && (userLimit < 0 || userLimit > 250)) {
      throw const FormatException('Некорректный лимит: от 0 до 250');
    }
    if (!admin) userLimit = 0;
    if (name.trim().isEmpty || name.trim().length > 80) {
      throw const FormatException('Имя: от 1 до 80 символов');
    }
    final random = Random.secure();
    final uid = List.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    final private = <String, String>{}, public = <String, String>{};
    for (final p in ['wireguard', 'awg']) {
      final pair = await X25519().newKeyPair();
      private[p] = base64Encode(await pair.extractPrivateKeyBytes());
      public[p] = base64Encode((await pair.extractPublicKey()).bytes);
    }
    final managementKey = admin ? await newManagementKey() : null;
    final deviceSecret = base64Encode(
      List.generate(32, (_) => random.nextInt(256)),
    );
    final entryToken = base64Encode(
      List.generate(32, (_) => random.nextInt(256)),
    );
    final response = await command({
      'action': 'add',
      'id': uid,
      'name': name.trim(),
      'publicKeys': public,
      'rivet': {'secret': deviceSecret, 'entryToken': entryToken},
      'admin': admin,
      'userLimit': userLimit,
      if (managementKey != null) 'adminPublicKey': managementKey.$2,
      'serverId': server.id,
    });
    final remote = Map<String, dynamic>.from(response['server']);
    final slot = response['user']['slot'] as int;
    final configs = <String, String>{};
    for (final p in ['wireguard', 'awg']) {
      if (p == 'wireguard') continue;
      final subnet = p == 'awg' ? 78 : 77;
      final v6 = p == 'awg' ? 'fd78:1' : 'fd77:1';
      final extras = p == 'awg'
          ? (remote['awg'] as Map).entries
                .map((e) => '${e.key} = ${e.value}')
                .join('\n')
          : '';
      final endpoint = serverEndpoint(
        server.publicHost,
        p == 'awg' ? 51821 : 51820,
      );
      configs[p] =
          '[Interface]\nPrivateKey = ${private[p]}\nAddress = 10.$subnet.0.$slot/32, $v6::${slot.toRadixString(16)}/128\nDNS = ${managedDnsServers(remote)}\nMTU = 1280\n$extras\n\n[Peer]\nPublicKey = ${remote['publicKeys'][p]}\nEndpoint = $endpoint\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n';
    }
    if (remote['rivet'] is Map) {
      final meta = Map<String, dynamic>.from(remote['rivet']);
      for (final protocol in rivetProtocols) {
        configs[protocol] = jsonEncode({
          'protocol': protocol,
          'endpoint': serverEndpoint(server.publicHost, 8443),
          'serverName': meta['serverName'],
          'pin': meta['pin'],
          'gatewayId': meta['gatewayId'],
          'id': uid,
          'secret': deviceSecret,
          'entryToken': entryToken,
          'ip': '10.79.0.$slot',
          if (meta['ipv6'] == true) 'ip6': 'fd79:1::${slot.toRadixString(16)}',
          if (meta['outerCA'] != null) 'outerCA': meta['outerCA'],
        });
      }
    }
    for (final e in Map<String, dynamic>.from(
      response['configs'] ?? {},
    ).entries) {
      if (['xray', 'cloak'].contains(e.key)) {
        final value = e.value;
        if (value is! String) {
          throw const FormatException('Некорректный профиль сервера');
        }
        final parsed = ExtendedProfile.parse(value);
        if (parsed.protocol != e.key) {
          throw const FormatException('Протокол не совпадает с конфигурацией');
        }
        configs[e.key] = parsed.encoded;
      }
    }
    try {
      // The server response is authenticated transport input, not a trusted
      // config: validate every generated profile before storing or exporting it.
      for (final p in configs.keys) {
        if (p == 'awg') {
          WireGuardProfile.parse(configs[p]!, amnezia: true);
        } else if (rivetProtocols.contains(p)) {
          RivetProfile.parse(configs[p]!);
        } else if (extendedProtocols.contains(p)) {
          ExtendedProfile.parse(configs[p]!);
        }
      }
      final user = await store.importBundle(
        UserBundle(name.trim(), uid, server.id, configs),
      );
      user.admin = admin;
      user.userLimit = userLimit;
      if (managementKey != null) {
        await CredentialVault.write(
          CredentialVault.id(
            server.host,
            server.port,
            server.username,
            scope: uid,
          ),
          {'key': managementKey.$1, 'password': '', 'passphrase': ''},
        );
      }
      await store.save();
      return user;
    } catch (_) {
      await command({'action': 'revoke', 'id': uid, 'serverId': server.id});
      rethrow;
    }
  }

  Future<void> issueClientAccess(
    AppStore store,
    ManagedServer server,
    ManagedUser user,
  ) async {
    if (server.delegated ||
        server.hostKey.isEmpty ||
        ssh.verifiedFingerprint != server.hostKey) {
      throw StateError(
        'Ограниченный доступ выдаёт владелец сервера с проверенной SSH-идентичностью',
      );
    }
    final result = await command({
      'action': 'client-grant',
      'serverId': server.id,
      'id': user.id,
    });
    final access = AccountAccess.parse(
      Map.from(result['clientAccess']),
      user.id,
      server.id,
    );
    await AccountVault.write(server.id, user.id, {'access': access.toJson()});
  }

  Future<void> refresh(AppStore store, ManagedServer server) async {
    final result = await command({'action': 'status', 'serverId': server.id});
    for (final remote in result['users']) {
      final user = store.users
          .where((u) => u.id == remote['id'] && u.serverId == server.id)
          .firstOrNull;
      if (user != null) {
        user.revoked = remote['revoked'] == true;
        user.admin = remote['role'] == 'admin';
        user.userLimit = remote['userLimit'] ?? 0;
        user.statistics = {
          'protocols': remote['stats'] ?? {},
          'month': remote['month'],
          'monthBytes': remote['monthBytes'],
          'online': remote['online'],
          'trackingSince': remote['trackingSince'],
          'sampledAt': result['sampledAt'],
        };
      } else {
        store.users.add(
          ManagedUser(
            id: remote['id'],
            name: remote['name'],
            serverId: server.id,
            profileIds: {},
            revoked: remote['revoked'] == true,
            admin: remote['role'] == 'admin',
            userLimit: remote['userLimit'] ?? 0,
            statistics: {
              'protocols': remote['stats'] ?? {},
              'month': remote['month'],
              'monthBytes': remote['monthBytes'],
              'online': remote['online'],
              'trackingSince': remote['trackingSince'],
              'sampledAt': result['sampledAt'],
            },
          ),
        );
      }
    }
    await store.save();
    store.changed();
  }

  Future<void> revoke(AppStore store, ManagedUser user) async {
    if (store.status.active) throw StateError('Сначала отключите VPN');
    await command({
      'action': 'revoke',
      'id': user.id,
      'serverId': user.serverId,
    });
    user.revoked = true;
    // remove() prunes user.profileIds, so iterate a snapshot.
    for (final id in user.profileIds.values.toList()) {
      await store.remove(id);
    }
    await store.save();
    store.changed();
  }

  Future<Map<String, dynamic>> uninstall(
    AppStore store,
    ManagedServer server,
  ) async {
    if (store.status.active || store.busy) {
      throw StateError('Сначала отключите VPN');
    }
    // Replace only our owned script; no VPN binary is uploaded or overwritten.
    for (final entry in {
      'mesh_stack.py': 'assets/xio-mesh-stack.py',
      'mesh-pins.json': 'assets/mesh-pins.json',
    }.entries) {
      final asset = await assets.load(entry.value);
      await ssh.executeInput(
        'set -eu\numask 077\ntest "\$(cat /usr/local/lib/xio-managed/.owner)" = xio-managed-v1\ncat > /usr/local/lib/xio-managed/${entry.key}.next\nmv /usr/local/lib/xio-managed/${entry.key}.next /usr/local/lib/xio-managed/${entry.key}\n',
        asset.buffer.asUint8List(asset.offsetInBytes, asset.lengthInBytes),
      );
    }
    final networkScript = await assets.load('assets/xio-network-stack.py');
    await ssh.executeInput(
      r'''set -eu
umask 077
test "$(cat /usr/local/lib/xio-managed/.owner)" = xio-managed-v1
cat > /usr/local/lib/xio-managed/network_stack.py.next
mv /usr/local/lib/xio-managed/network_stack.py.next /usr/local/lib/xio-managed/network_stack.py
''',
      networkScript.buffer.asUint8List(
        networkScript.offsetInBytes,
        networkScript.lengthInBytes,
      ),
    );
    final stackScript = await assets.load('assets/xio-stack.py');
    await ssh.executeInput(
      r'''set -eu
umask 077
test "$(cat /usr/local/lib/xio-managed/.owner)" = xio-managed-v1
cat > /usr/local/lib/xio-managed/stack.py.next
mv /usr/local/lib/xio-managed/stack.py.next /usr/local/lib/xio-managed/stack.py
''',
      stackScript.buffer.asUint8List(
        stackScript.offsetInBytes,
        stackScript.lengthInBytes,
      ),
    );
    final script = await assets.load('assets/xio-admin.py');
    await ssh.executeInput(r'''set -eu
umask 077
test "$(cat /usr/local/lib/xio-managed/.owner)" = xio-managed-v1
cat > /usr/local/lib/xio-managed/admin.py.next
chmod 600 /usr/local/lib/xio-managed/admin.py.next
mv /usr/local/lib/xio-managed/admin.py.next /usr/local/lib/xio-managed/admin.py
''', script.buffer.asUint8List(script.offsetInBytes, script.lengthInBytes));
    final result = await command({'action': 'remove', 'serverId': server.id});
    if (result['removed'] != true) {
      throw StateError('Сервер не подтвердил удаление');
    }
    await store.forgetServer(server.id);
    return result;
  }
}
