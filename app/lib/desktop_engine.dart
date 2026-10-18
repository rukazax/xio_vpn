import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';

import 'credentials.dart';

/// The UI keeps encrypted profiles. The elevated helper receives one selected
/// profile over authenticated loopback IPC; it never accepts shell commands.
class DesktopEngine {
  static bool enabled = false;
  static Set<String> supported = {};
  static const _daemonKey =
      'vpn0000000000000000000000000000000000000000000000000000000000000000';
  static Map<String, String>? _worker;
  static Future<void>? _starting;
  static String _hex(int n) => List.generate(
    n,
    (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0'),
  ).join();
  static String configKey(String id) {
    if (!RegExp(r'^[a-z0-9]{1,80}$').hasMatch(id)) {
      throw const FormatException('Invalid profile identifier');
    }
    return 'vpn${sha256.convert(utf8.encode(id))}';
  }

  static String get helper {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir${Platform.pathSeparator}libexec${Platform.pathSeparator}xio-tunnel${Platform.isWindows ? '.exe' : ''}';
  }

  static Future<void> initialise() async {
    enabled = true;
    if (!File(helper).existsSync()) return;
    final p = await Process.start(helper, ['--stdio']);
    p.stdin.writeln(jsonEncode({'Method': 'capabilities'}));
    await p.stdin.close();
    final stdout = p.stdout.transform(utf8.decoder).join();
    final drain = p.stderr.drain<void>();
    try {
      if (await p.exitCode.timeout(const Duration(seconds: 15)) == 0) {
        final j = jsonDecode((await stdout).trim()) as Map;
        supported = (j['value'] as List).cast<String>().toSet();
      }
    } on TimeoutException {
      p.kill();
    } finally {
      await drain;
    }
    try {
      _worker = await CredentialVault.read(_daemonKey);
    } catch (_) {
      _worker = null;
    }
  }

  static Future<Map<String, dynamic>> _json(
    Uri uri, {
    Map<String, dynamic>? body,
    String? token,
  }) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    client.findProxy = (_) => 'DIRECT';
    try {
      final req = await (body == null
          ? client.getUrl(uri)
          : client.postUrl(uri));
      req.followRedirects = false;
      if (token != null) req.headers.set('Authorization', 'Bearer $token');
      if (body != null) {
        req.headers.contentType = ContentType.json;
        req.write(jsonEncode(body));
      }
      final response = await req.close().timeout(
        Duration(seconds: body == null ? 3 : 70),
      );
      if (response.statusCode != 200) {
        throw const SocketException('Local engine authentication failed');
      }
      final bytes = <int>[];
      await for (final part in response) {
        bytes.addAll(part);
        if (bytes.length > 262144) {
          throw const FormatException('Local response too large');
        }
      }
      return Map<String, dynamic>.from(jsonDecode(utf8.decode(bytes)) as Map);
    } finally {
      client.close(force: true);
    }
  }

  static Future<bool> _authenticate(Map<String, String> worker) async {
    try {
      final port = int.parse(worker['port']!);
      if (port < 1024 || port > 65535) return false;
      final token = worker['token']!;
      if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(token)) return false;
      final nonce = _hex(32);
      final expected = Hmac(
        sha256,
        List.generate(
          32,
          (i) => int.parse(token.substring(i * 2, i * 2 + 2), radix: 16),
        ),
      ).convert(utf8.encode('XIO-019:$nonce')).toString();
      final j = await _json(
        Uri.http('127.0.0.1:$port', '/challenge', {'nonce': nonce}),
      );
      return j['proof'] == expected;
    } catch (_) {
      return false;
    }
  }

  static Future<void> _ensureWorker() async {
    if (_worker != null && await _authenticate(_worker!)) return;
    if (_starting != null) return _starting;
    final f = _launch();
    _starting = f;
    try {
      await f;
    } finally {
      _starting = null;
    }
  }

  static Future<void> _launch() async {
    if (!File(helper).existsSync()) {
      throw PlatformException(
        code: 'UNAVAILABLE',
        message: 'VPN helper is missing from the installed package.',
      );
    }
    final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = socket.port;
    await socket.close();
    final token = _hex(32);
    final temp = await Directory.systemTemp.createTemp('xio-auth-');
    if (Platform.isLinux) {
      await Process.run('/usr/bin/chmod', ['700', temp.path]);
    }
    final file = File('${temp.path}/token');
    await file.writeAsString(token, flush: true);
    if (Platform.isLinux) {
      await Process.run('/usr/bin/chmod', ['600', file.path]);
    }
    final args = ['--http', '127.0.0.1:$port', '--token-file', file.path];
    Process? process;
    try {
      if (Platform.isLinux) {
        process = await Process.start('/usr/bin/pkexec', [helper, ...args]);
      } else {
        String quote(String s) => "'${s.replaceAll("'", "''")}'";
        final argString = args
            .map((s) => '"${s.replaceAll('"', '')}"')
            .join(' ');
        process = await Process.start('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          "\$ErrorActionPreference='Stop'; Start-Process -FilePath ${quote(helper)} -ArgumentList ${quote(argString)} -Verb RunAs -WindowStyle Hidden",
        ]);
      }
      // Never log elevated-process output: configurations must stay off logs.
      unawaited(process.stdout.drain<void>());
      unawaited(process.stderr.drain<void>());
      int? code;
      unawaited(process.exitCode.then((c) => code = c));
      final candidate = {'port': '$port', 'token': token};
      for (var i = 0; i < 120; i++) {
        if (await _authenticate(candidate)) {
          await CredentialVault.write(_daemonKey, candidate);
          _worker = candidate;
          return;
        }
        if (code != null && code != 0) {
          throw PlatformException(
            code: 'DENIED',
            message:
                'System administrator authorization was cancelled or refused.',
          );
        }
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
      throw PlatformException(
        code: 'DENIED',
        message: 'The VPN helper did not start. Complete the system administrator authorization and try again.',
      );
    } finally {
      if (await temp.exists()) await temp.delete(recursive: true);
    }
  }

  static Future<dynamic> _rpc(
    String method, [
    Map<String, dynamic> extra = const {},
  ]) async {
    final w = _worker;
    if (w == null || !await _authenticate(w)) return {'active': false};
    final response = await _json(
      Uri.http('127.0.0.1:${w['port']}', '/rpc'),
      body: {'Method': method, ...extra},
      token: w['token'],
    );
    if (response['ok'] != true) {
      throw PlatformException(
        code: 'ENGINE',
        message:
            response['error'] as String? ??
            'The local engine rejected the request.',
      );
    }
    return response['value'];
  }

  static Future<dynamic> invoke(String method, dynamic arguments) async {
    final a = Map<String, dynamic>.from(arguments as Map? ?? {});
    switch (method) {
      case 'supportedProtocols':
        return supported.toList();
      case 'saveConfig':
        await CredentialVault.write(configKey(a['id']), {
          'config': a['config'],
        });
        return null;
      case 'readConfig':
        return (await CredentialVault.read(configKey(a['id'])))?['config'];
      case 'deleteConfig':
        await CredentialVault.delete(configKey(a['id']));
        return null;
      case 'activeId':
        return (await _rpc('status'))['id'];
      case 'status':
        return await _rpc('status');
      case 'connectionBusy':
        return _starting != null;
      case 'disconnect':
        if (_worker != null) await _rpc('disconnect');
        return null;
      case 'connect':
        final id = a['id'] as String;
        final saved = await CredentialVault.read(configKey(id));
        if (saved == null) {
          throw PlatformException(
            code: 'CONFIG',
            message: 'Client profile is missing.',
          );
        }
        final config = saved['config']!;
        final protocol = id.startsWith('wg')
            ? 'wireguard'
            : id.startsWith('awg')
            ? 'awg'
            : jsonDecode(config)['protocol'] as String;
        if (!supported.contains(protocol)) {
          throw PlatformException(
            code: 'UNAVAILABLE',
            message: 'This protocol has no desktop engine in this build.',
          );
        }
        await _ensureWorker();
        return await _rpc('connect', {
          'ID': id,
          'Protocol': protocol,
          'Config': config,
          'TimeoutMillis': a['timeoutMillis'] ?? 15000,
        });
      case 'routingSummary':
        return {'enabled': false, 'supported': false};
      default:
        throw MissingPluginException('Unsupported desktop operation: $method');
    }
  }
}
