import 'dart:convert';

import 'server_address.dart';

const extendedProtocols = ['xray', 'cloak'];
const nativePrefix = {'xray': 'xr', 'cloak': 'ck'};

/// Normalized client material. No listeners, API servers, executable commands,
/// filesystem references or direct/freedom outbounds are accepted from imports.
class ExtendedProfile {
  final String protocol, endpoint, name;
  final Map<String, dynamic> data;
  ExtendedProfile._(this.protocol, this.endpoint, this.data, [this.name = '']);
  String get encoded => jsonEncode(data);
  static String _text(dynamic value, {int max = 8192, bool empty = false}) {
    if (value is! String ||
        (!empty && value.isEmpty) ||
        value.length > max ||
        value.contains(RegExp(r'[\u0000\r\n]'))) {
      throw const FormatException('Некорректная конфигурация');
    }
    return value;
  }

  static String _host(dynamic value) {
    final s = _text(value, max: 253);
    if (s.startsWith('[') || s.contains(']')) {
      throw const FormatException('Некорректный адрес сервера');
    }
    try {
      return normalizeServerHost(s);
    } on FormatException {
      throw const FormatException('Некорректный адрес сервера');
    }
  }

  static int _port(dynamic value) {
    final n = value is int ? value : int.tryParse('$value');
    if (n == null || n < 1 || n > 65535) {
      throw const FormatException('Некорректный порт');
    }
    return n;
  }

  static String _endpoint(String host, int port) => serverEndpoint(host, port);
  static String _uuid(String raw) {
    final h = raw.replaceAll('-', '').toLowerCase();
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(h)) {
      throw const FormatException('Некорректный UUID');
    }
    return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
  }

  static void _noUnsafeFiles(dynamic node) {
    if (node is Map) {
      for (final e in node.entries) {
        final key = '${e.key}'.toLowerCase();
        if (key.endsWith('file') ||
            key == 'allowinsecure' && e.value != false ||
            const {
              'sockopt',
              'dialerproxy',
              'proxysettings',
              'downloadsettings',
              'reverse',
            }.contains(key)) {
          throw const FormatException('Небезопасная конфигурация');
        }
        _noUnsafeFiles(e.value);
      }
    } else if (node is List) {
      for (final v in node) {
        _noUnsafeFiles(v);
      }
    }
  }

  static ExtendedProfile outbound(
    Map<String, dynamic> input, {
    String name = '',
  }) {
    final o = Map<String, dynamic>.from(jsonDecode(jsonEncode(input)) as Map);
    _noUnsafeFiles(o);
    const fields = {'protocol', 'settings', 'streamSettings', 'mux', 'tag'};
    if (o.keys.any((k) => !fields.contains(k))) {
      throw const FormatException('Неподдерживаемая конфигурация Xray');
    }
    final kind = o['protocol'];
    if (!['vless', 'vmess', 'trojan'].contains(kind)) {
      throw const FormatException('Неподдерживаемый протокол');
    }
    final settings = Map<String, dynamic>.from(o['settings'] as Map);
    String host;
    int port;
    if (kind == 'vless' || kind == 'vmess') {
      final servers = settings['vnext'] as List;
      if (servers.length != 1) throw const FormatException();
      final server = Map<String, dynamic>.from(servers.single as Map);
      host = _host(server['address']);
      port = _port(server['port']);
      server['address'] = host;
      final users = server['users'] as List;
      if (users.length != 1) throw const FormatException();
      final u = Map<String, dynamic>.from(users.single as Map);
      u['id'] = _uuid(_text(u['id'], max: 64));
      if (kind == 'vless' && !_vlessEncryption(u['encryption'])) {
        throw const FormatException('Неподдерживаемое шифрование VLESS');
      }
      if (kind == 'vmess' &&
          ((u['alterId'] ?? 0) != 0 ||
              ![
                'auto',
                'aes-128-gcm',
                'chacha20-poly1305',
              ].contains(u['security'] ?? 'auto'))) {
        throw const FormatException('Устаревшая конфигурация VMess');
      }
      server['users'] = [u];
      settings['vnext'] = [server];
    } else {
      final servers = settings['servers'] as List;
      if (servers.length != 1) throw const FormatException();
      final server = Map<String, dynamic>.from(servers.single as Map);
      host = _host(server['address']);
      port = _port(server['port']);
      server['address'] = host;
      server['password'] = _text(server['password'], max: 2048);
      settings['servers'] = [server];
    }
    final stream = Map<String, dynamic>.from(
      (o['streamSettings'] ?? {}) as Map,
    );
    final security = stream['security'] ?? 'none';
    if (!const {
      'tcp',
      'raw',
      'ws',
      'grpc',
      'httpupgrade',
      'xhttp',
      'splithttp',
    }.contains(stream['network'] ?? 'tcp')) {
      throw const FormatException('Неподдерживаемый транспорт Xray');
    }
    if (const {'xhttp', 'splithttp'}.contains(stream['network'])) {
      final xhttp =
          stream['xhttpSettings'] ?? stream['splithttpSettings'] ?? {};
      if (xhttp is! Map ||
          !const {
            'auto',
            'packet-up',
            'stream-up',
            'stream-one',
          }.contains(xhttp['mode'] ?? 'auto')) {
        throw const FormatException('Некорректный режим XHTTP');
      }
    }
    if ((kind == 'vless' && !['tls', 'reality'].contains(security)) ||
        (kind == 'trojan' && security != 'tls')) {
      throw const FormatException('Требуется TLS или REALITY');
    }
    if (security == 'reality') {
      final reality = Map<String, dynamic>.from(
        stream['realitySettings'] as Map,
      );
      _host(reality['serverName']);
      final key = reality['publicKey'] ?? reality['password'];
      final decoded = base64Url.decode(
        base64Url.normalize(_text(key, max: 100)),
      );
      if (decoded.length != 32) {
        throw const FormatException('Некорректный ключ REALITY');
      }
      if (!RegExp(r'^(?:[0-9a-fA-F]{2}){0,8}$')
          .hasMatch('${reality['shortId'] ?? ''}')) {
        throw const FormatException('Некорректный shortId');
      }
    }
    if (security == 'tls') {
      final tls = Map<String, dynamic>.from(
        (stream['tlsSettings'] ?? {}) as Map,
      );
      _host(tls['serverName'] ?? host);
    }
    o['settings'] = settings;
    o['tag'] = 'proxy';
    const p = 'xray';
    return ExtendedProfile._(p, _endpoint(host, port), {
      'protocol': p,
      'outbound': o,
    }, name);
  }

  static String _decode64(String s) =>
      utf8.decode(base64Url.decode(base64Url.normalize(s)));
  // Match the pinned Xray core's supported key format; cryptography stays in
  // upstream Xray. Keep outer TLS/REALITY mandatory, including with Encryption.
  static bool _vlessEncryption(dynamic value) {
    if (value == 'none') return true;
    if (value is! String || value.length > 8192) return false;
    final fields = value.split('.');
    if (fields.length < 4 ||
        fields[0] != 'mlkem768x25519plus' ||
        !const {'native', 'xorpub', 'random'}.contains(fields[1]) ||
        !const {'0rtt', '1rtt'}.contains(fields[2])) {
      return false;
    }
    var keys = 0;
    for (final field in fields.skip(3)) {
      if (field.length < 20) {
        if (!RegExp(r'^[0-9-]*$').hasMatch(field)) return false;
        continue;
      }
      try {
        if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(field)) return false;
        final bytes = base64Url.decode(base64Url.normalize(field));
        if (bytes.length != 32 && bytes.length != 1184) return false;
        keys++;
      } catch (_) {
        return false;
      }
    }
    return keys > 0;
  }

  static ExtendedProfile parse(String input) {
    try {
      final raw = input.trim();
      if (raw.length > 65536 || raw.contains('\u0000')) {
        throw const FormatException();
      }
      if (raw.startsWith('vless://') || raw.startsWith('trojan://')) {
        final u = Uri.parse(raw);
        final host = _host(u.host), port = _port(u.port), q = u.queryParameters;
        if (q['allowInsecure'] == '1' || q['allowInsecure'] == 'true') {
          throw const FormatException('Небезопасная конфигурация');
        }
        if (u.userInfo.isEmpty || !u.hasPort) throw const FormatException();
        final type = q['type'] ?? 'tcp',
            security = q['security'] ?? (u.scheme == 'trojan' ? 'tls' : 'none');
        final stream = <String, dynamic>{'network': type, 'security': security};
        if (security == 'tls') {
          stream['tlsSettings'] = {
            'serverName': q['sni'] ?? host,
            'fingerprint': q['fp'] ?? 'chrome',
            if (q['alpn'] != null) 'alpn': q['alpn']!.split(','),
          };
        }
        if (security == 'reality') {
          stream['realitySettings'] = {
            'serverName': q['sni'] ?? '',
            'fingerprint': q['fp'] ?? 'chrome',
            'publicKey': q['pbk'] ?? '',
            'shortId': q['sid'] ?? '',
            'spiderX': q['spx'] ?? '/',
          };
        }
        if (type == 'ws') {
          stream['wsSettings'] = {
            'path': q['path'] ?? '/',
            if (q['host'] != null) 'headers': {'Host': q['host']},
          };
        }
        if (type == 'grpc') {
          stream['grpcSettings'] = {'serviceName': q['serviceName'] ?? ''};
        }
        if (type == 'httpupgrade') {
          stream['httpupgradeSettings'] = {
            'path': q['path'] ?? '/',
            'host': q['host'] ?? host,
          };
        }
        if (type == 'xhttp' || type == 'splithttp') {
          stream['xhttpSettings'] = {
            'path': q['path'] ?? '/',
            'host': q['host'] ?? host,
            'mode': q['mode'] ?? 'auto',
            if (q['extra'] != null) 'extra': jsonDecode(q['extra']!),
          };
        }
        final settings = u.scheme == 'vless'
            ? {
                'vnext': [
                  {
                    'address': host,
                    'port': port,
                    'users': [
                      {
                        'id': _uuid(Uri.decodeComponent(u.userInfo)),
                        'encryption': q['encryption'] ?? 'none',
                        'flow': q['flow'] ?? '',
                      },
                    ],
                  },
                ],
              }
            : {
                'servers': [
                  {
                    'address': host,
                    'port': port,
                    'password': Uri.decodeComponent(u.userInfo),
                  },
                ],
              };
        return outbound({
          'protocol': u.scheme,
          'settings': settings,
          'streamSettings': stream,
        }, name: Uri.decodeComponent(u.fragment));
      }
      if (raw.startsWith('vmess://')) {
        final j = Map<String, dynamic>.from(
          jsonDecode(_decode64(raw.substring(8))) as Map,
        );
        final host = _host(j['add']);
        final network = j['net'] ?? 'tcp';
        final stream = <String, dynamic>{
          'network': network,
          'security': j['tls'] == 'tls' ? 'tls' : 'none',
        };
        if (j['tls'] == 'tls') {
          stream['tlsSettings'] = {
            'serverName': j['sni'] ?? host,
            'fingerprint': j['fp'] ?? 'chrome',
          };
        }
        if (network == 'ws') {
          stream['wsSettings'] = {
            'path': j['path'] ?? '/',
            'headers': {'Host': j['host'] ?? host},
          };
        }
        if (network == 'grpc') {
          stream['grpcSettings'] = {'serviceName': j['path'] ?? ''};
        }
        return outbound({
          'protocol': 'vmess',
          'settings': {
            'vnext': [
              {
                'address': host,
                'port': _port(j['port']),
                'users': [
                  {
                    'id': _uuid(j['id']),
                    'alterId': int.tryParse('${j['aid'] ?? 0}') ?? -1,
                    'security': j['scy'] ?? 'auto',
                  },
                ],
              },
            ],
          },
          'streamSettings': stream,
        }, name: j['ps'] is String ? j['ps'] : '');
      }
      if (raw.startsWith('{')) {
        final j = Map<String, dynamic>.from(jsonDecode(raw) as Map);
        if (j['outbound'] is Map) {
          return outbound(Map<String, dynamic>.from(j['outbound']));
        }
        if (j['protocol'] == null && j['config'] is String) {
          return parse(j['config'] as String);
        }
        if (j['outbounds'] is List) {
          final a = (j['outbounds'] as List)
              .where(
                (v) =>
                    v is Map &&
                    ['vless', 'vmess', 'trojan'].contains(v['protocol']),
              )
              .toList();
          if (a.length != 1) {
            throw const FormatException('Требуется один исходящий VPN');
          }
          return outbound(Map<String, dynamic>.from(a.single as Map));
        }
        if (j['protocol'] == 'cloak') {
          final p = _cloakPayload(
            j['config'] as String,
            username: j['username'] as String? ?? '',
            password: j['password'] as String? ?? '',
          );
          final c = Map<String, dynamic>.from(j['cloak'] as Map);
          c['RemoteHost'] = _host(c['RemoteHost']);
          c['RemotePort'] = '${_port(c['RemotePort'])}';
          for (final field in ['UID', 'PublicKey']) {
            final b = base64Decode(_text(c[field]));
            if (b.length != (field == 'UID' ? 16 : 32)) {
              throw const FormatException();
            }
          }
          _host(c['ServerName']);
          return ExtendedProfile._(
            'cloak',
            _endpoint(c['RemoteHost'], _port(c['RemotePort'])),
            {
              'protocol': 'cloak',
              'config': p.data['config'],
              'username': p.data['username'],
              'password': p.data['password'],
              'cloak': c,
            },
          );
        }
      }
      throw const FormatException('Неподдерживаемая конфигурация');
    } on FormatException {
      rethrow;
    } catch (_) {
      throw const FormatException('Некорректная конфигурация');
    }
  }

  static ExtendedProfile _cloakPayload(
    String raw, {
    String username = '',
    String password = '',
  }) {
    if (raw.length > 60000 || raw.contains('\u0000')) {
      throw const FormatException();
    }
    const inline = {
      'ca',
      'cert',
      'key',
      'tls-auth',
      'tls-crypt',
      'tls-crypt-v2',
      'auth-user-pass',
    };
    const allowed = {
      'client',
      'dev',
      'dev-type',
      'proto',
      'remote',
      'remote-random',
      'remote-random-hostname',
      'resolv-retry',
      'nobind',
      'persist-key',
      'persist-tun',
      'cipher',
      'data-ciphers',
      'data-ciphers-fallback',
      'auth',
      'auth-nocache',
      'auth-user-pass',
      'remote-cert-tls',
      'verify-x509-name',
      'tls-version-min',
      'tls-version-max',
      'tls-cipher',
      'tls-ciphersuites',
      'tls-cert-profile',
      'tls-timeout',
      'tls-exit',
      'tls-client',
      'key-direction',
      'keysize',
      'reneg-sec',
      'verb',
      'mute',
      'connect-retry',
      'connect-retry-max',
      'connect-timeout',
      'server-poll-timeout',
      'ping',
      'ping-restart',
      'explicit-exit-notify',
      'redirect-gateway',
      'route',
      'route-ipv6',
      'route-metric',
      'route-delay',
      'route-nopull',
      'dhcp-option',
      'tun-mtu',
      'mssfix',
      'sndbuf',
      'rcvbuf',
      'socket-flags',
      'setenv',
      'pull',
      'pull-filter',
      'block-ipv6',
      'block-outside-dns',
      'ignore-unknown-option',
      'float',
      'allow-compression',
      'compress',
      'comp-lzo',
      'auth-retry',
      'inactive',
    };
    String? block;
    String host = '';
    int port = 1194;
    bool ca = false, verify = false;
    final lines = const LineSplitter().convert(raw);
    final clean = <String>[];
    final credentialLines = <String>[];
    for (final original in lines) {
      final line = original.trim();
      if (block != null) {
        if (line == '</$block>') {
          if (block == 'ca') ca = true;
          if (block != 'auth-user-pass') clean.add(original);
          block = null;
        } else if (block == 'auth-user-pass') {
          credentialLines.add(original);
        } else {
          clean.add(original);
        }
        continue;
      }
      if (line.startsWith('#') || line.startsWith(';') || line.isEmpty) {
        clean.add(original);
        continue;
      }
      final tag = RegExp(r'^<([a-z0-9-]+)>$').firstMatch(line);
      if (tag != null) {
        block = tag[1]!;
        if (!inline.contains(block)) {
          throw const FormatException('Внешние команды запрещены');
        }
        clean.add(block == 'auth-user-pass' ? 'auth-user-pass' : original);
        continue;
      }
      final parts = line.split(RegExp(r'\s+'));
      final key = parts.first;
      if (!allowed.contains(key)) {
        throw const FormatException('Неподдерживаемая директива OpenVPN');
      }
      if (key == 'setenv' &&
          !(parts.length >= 2 && parts[1] == 'CLIENT_CERT')) {
        throw const FormatException('Внешние команды запрещены');
      }
      if (key == 'auth-user-pass' && parts.length != 1) {
        throw const FormatException('Внешние файлы запрещены');
      }
      if (key == 'remote') {
        if (parts.length < 2) throw const FormatException();
        host = _host(parts[1]);
        if (parts.length > 2) port = _port(parts[2]);
      }
      if (key == 'remote-cert-tls' &&
          parts.length == 2 &&
          parts[1] == 'server') {
        verify = true;
      }
      if (key == 'allow-compression' && parts.length == 2 && parts[1] != 'no') {
        throw const FormatException('Сжатие не поддерживается');
      }
      if (key == 'comp-lzo' && (parts.length < 2 || parts[1] != 'no')) {
        throw const FormatException('Сжатие не поддерживается');
      }
      if (key == 'compress') {
        throw const FormatException('Сжатие не поддерживается');
      }
      clean.add(original);
    }
    if (block != null || host.isEmpty || !ca || !verify) {
      throw const FormatException(
        'Требуется remote-cert-tls server и встроенный CA',
      );
    }
    if (credentialLines.isNotEmpty) {
      if (credentialLines.length != 2) throw const FormatException();
      username = credentialLines[0];
      password = credentialLines[1];
    }
    _text(username, max: 512, empty: true);
    _text(password, max: 2048, empty: true);
    return ExtendedProfile._('openvpn', _endpoint(host, port), {
      'protocol': 'openvpn',
      'config': '${clean.join('\n')}\n',
      'username': username,
      'password': password,
    });
  }
}
