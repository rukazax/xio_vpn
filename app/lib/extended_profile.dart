import 'dart:convert';
import 'dart:io';

const extendedProtocols = [
  'xray',
  'shadowsocks',
  'openvpn',
  'cloak',
  'ikev2',
  'tailscale',
];
const nativePrefix = {
  'xray': 'xr',
  'shadowsocks': 'ss',
  'openvpn': 'ov',
  'cloak': 'ck',
  'ikev2': 'ik',
  'tailscale': 'ts',
};

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
    if (InternetAddress.tryParse(s) == null &&
        !RegExp(r'^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$').hasMatch(s)) {
      throw const FormatException('Некорректный адрес сервера');
    }
    return s;
  }

  static int _port(dynamic value) {
    final n = value is int ? value : int.tryParse('$value');
    if (n == null || n < 1 || n > 65535) {
      throw const FormatException('Некорректный порт');
    }
    return n;
  }

  static String _endpoint(String host, int port) =>
      '${host.contains(':') ? '[$host]' : host}:$port';
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
        if (key.endsWith('file') || key == 'allowinsecure' && e.value == true) {
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
    if (!['vless', 'vmess', 'trojan', 'shadowsocks'].contains(kind)) {
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
      final users = server['users'] as List;
      if (users.length != 1) throw const FormatException();
      final u = Map<String, dynamic>.from(users.single as Map);
      u['id'] = _uuid(_text(u['id'], max: 64));
      if (kind == 'vless' && u['encryption'] != 'none') {
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
      _text(server['password'], max: 2048);
      if (kind == 'shadowsocks' &&
          ![
            'aes-128-gcm',
            'aes-256-gcm',
            'chacha20-ietf-poly1305',
            '2022-blake3-aes-128-gcm',
            '2022-blake3-aes-256-gcm',
            '2022-blake3-chacha20-poly1305',
          ].contains(server['method'])) {
        throw const FormatException('Неподдерживаемое шифрование Shadowsocks');
      }
    }
    final stream = Map<String, dynamic>.from(
      (o['streamSettings'] ?? {}) as Map,
    );
    final security = stream['security'] ?? 'none';
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
    final p = kind == 'shadowsocks' ? 'shadowsocks' : 'xray';
    return ExtendedProfile._(p, _endpoint(host, port), {
      'protocol': p,
      'outbound': o,
    }, name);
  }

  static String _decode64(String s) =>
      utf8.decode(base64Url.decode(base64Url.normalize(s)));
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
      if (raw.startsWith('ss://')) {
        var payload = raw.substring(5);
        if (!payload.contains('@')) {
          payload =
              _decode64(payload.split('#').first) +
              (payload.contains('#') ? '#${payload.split('#').last}' : '');
        }
        final u = Uri.parse('ss://$payload');
        if (u.queryParameters['plugin'] != null) {
          throw const FormatException('Плагин Shadowsocks не поддерживается');
        }
        final info = u.userInfo.contains(':')
            ? Uri.decodeComponent(u.userInfo)
            : _decode64(Uri.decodeComponent(u.userInfo));
        final i = info.indexOf(':');
        if (i < 1) throw const FormatException();
        return outbound({
          'protocol': 'shadowsocks',
          'settings': {
            'servers': [
              {
                'address': _host(u.host),
                'port': _port(u.port),
                'method': info.substring(0, i),
                'password': info.substring(i + 1),
              },
            ],
          },
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
        if (j['server'] is String &&
            j['server_port'] != null &&
            j['method'] is String &&
            j['password'] is String) {
          if (j['plugin'] != null && j['plugin'] != '') {
            throw const FormatException('Плагин Shadowsocks не поддерживается');
          }
          return outbound({
            'protocol': 'shadowsocks',
            'settings': {
              'servers': [
                {
                  'address': j['server'],
                  'port': _port(j['server_port']),
                  'method': j['method'],
                  'password': j['password'],
                },
              ],
            },
          });
        }
        if (j['outbounds'] is List) {
          final a = (j['outbounds'] as List)
              .where(
                (v) =>
                    v is Map &&
                    [
                      'vless',
                      'vmess',
                      'trojan',
                      'shadowsocks',
                    ].contains(v['protocol']),
              )
              .toList();
          if (a.length != 1) {
            throw const FormatException('Требуется один исходящий VPN');
          }
          return outbound(Map<String, dynamic>.from(a.single as Map));
        }
        if (j['protocol'] == 'openvpn' || j['protocol'] == 'cloak') {
          final p = openVpn(
            j['config'] as String,
            username: j['username'] as String? ?? '',
            password: j['password'] as String? ?? '',
          );
          if (j['protocol'] == 'openvpn') return p;
          final c = Map<String, dynamic>.from(j['cloak'] as Map);
          _host(c['RemoteHost']);
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
        if (j['protocol'] == 'ikev2') {
          final server = _host(j['server']);
          _text(j['identity'], max: 253);
          _text(j['username'], max: 128);
          _text(j['password'], max: 512);
          final ca = j['ca'];
          if (ca is! String ||
              ca.length > 16384 ||
              !ca.contains('-----BEGIN CERTIFICATE-----')) {
            throw const FormatException('Требуется сертификат CA');
          }
          return ExtendedProfile._('ikev2', server, {
            'protocol': 'ikev2',
            'server': server,
            'identity': j['identity'],
            'username': j['username'],
            'password': j['password'],
            'ca': ca,
          });
        }
        if (j['protocol'] == 'tailscale') {
          final url = Uri.parse(j['controlURL'] as String);
          if (url.scheme != 'https' ||
              url.host.isEmpty ||
              url.userInfo.isNotEmpty ||
              url.hasQuery ||
              url.hasFragment) {
            throw const FormatException('Требуется HTTPS control URL');
          }
          final exit = _text(j['exitNode'], max: 253);
          _text(j['authKey'], max: 1024);
          final hostname = _text(j['hostname'] ?? 'xio', max: 63);
          return ExtendedProfile._('tailscale', url.host, {
            'protocol': 'tailscale',
            'controlURL': url.toString(),
            'authKey': j['authKey'],
            'exitNode': exit,
            'hostname': hostname,
            if (j['controlCA'] != null) 'controlCA': j['controlCA'],
          });
        }
        // strongSwan portable IKEv2/EAP export.
        if (j['vpn_type'] == 'ikev2-eap' && j['remote'] is Map) {
          final remote = j['remote'] as Map;
          return parse(
            jsonEncode({
              'protocol': 'ikev2',
              'server': remote['addr'],
              'identity': remote['id'] ?? remote['addr'],
              'username': j['local']?['eap_id'],
              'password': j['local']?['eap_secret'],
              'ca': remote['cert'],
            }),
          );
        }
      }
      if (RegExp(r'^\s*client\s*$', multiLine: true).hasMatch(raw)) {
        return openVpn(raw);
      }
      throw const FormatException('Неподдерживаемая конфигурация');
    } on FormatException {
      rethrow;
    } catch (_) {
      throw const FormatException('Некорректная конфигурация');
    }
  }

  static ExtendedProfile openVpn(
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
