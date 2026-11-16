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

  /// Canonical product-store identity for the elevated helper. A versioned
  /// helper is launched only with this binding; without it, policy/activation
  /// requests must fail closed instead of launching an unbound helper.
  static String? storeIdentity;

  /// Runtime build constant bound to the helper; never read from the document.
  static bool? clientOnly;
  static const _daemonKey =
      'vpn0000000000000000000000000000000000000000000000000000000000000000';

  /// Exact elevated-helper arguments. The store identity is mandatory here (not
  /// inferred from a cached port) so a helper can reject receipt-free legacy and
  /// scope its cooperating claim to this product store.
  static List<String> helperArguments({
    required String port,
    required String tokenFile,
  }) {
    final identity = storeIdentity;
    if (identity == null) {
      throw const FormatException('Versioned helper needs a store identity');
    }
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(identity)) {
      throw const FormatException('Invalid store identity');
    }
    final buildClientOnly = clientOnly;
    if (buildClientOnly == null) {
      throw const FormatException('Versioned helper needs the client-only flag');
    }
    return [
      '--http',
      '127.0.0.1:$port',
      '--token-file',
      tokenFile,
      '--store-identity=$identity',
      '--client-only=$buildClientOnly',
    ];
  }
  static Map<String, String>? _worker;
  // A failed/not-yet-completed vault read is not proof that no helper is live.
  static bool _workerStateKnown = false;
  static Future<void>? _starting;
  static int _connectionEpoch = 0;
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
      _workerStateKnown = true;
    } catch (_) {
      _worker = null;
      _workerStateKnown = false;
    }
  }

  /// One keep-alive client for the local engine. The 3 s status poll used to
  /// open and force-close two fresh loopback sockets on every tick; reusing the
  /// connection removes that churn without changing any request.
  static HttpClient? _client;

  static HttpClient get _http {
    final cached = _client;
    if (cached != null) return cached;
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    client.findProxy = (_) => 'DIRECT';
    return _client = client;
  }

  static void _dropClient() {
    _client?.close(force: true);
    _client = null;
  }

  static Future<Map<String, dynamic>> _json(
    Uri uri, {
    Map<String, dynamic>? body,
    String? token,
  }) async {
    final client = _http;
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
    } catch (_) {
      // Never hand out a connection that may be half-dead: the engine can be
      // restarted between polls and the next call must start clean.
      _dropClient();
      rethrow;
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
    final args = helperArguments(port: '$port', tokenFile: file.path);
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
          _workerStateKnown = true;
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
    Map<String, dynamic> Function()? remainingRequest,
  ]) async {
    remainingRequest
        ?.call(); // Expired/revoked work cannot even begin authentication.
    final w = _worker;
    if (w == null) {
      return {
        'active': false,
        if (method == 'status' && !_workerStateKnown) 'phase': 'unknown',
      };
    }
    if (!await _authenticate(w)) {
      return {'active': false, if (method == 'status') 'phase': 'unknown'};
    }
    final request = remainingRequest?.call() ?? extra;
    final response = await _json(
      Uri.http('127.0.0.1:${w['port']}', '/rpc'),
      body: {'Method': method, ...request},
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

  /// Versioned policy RPC. A missing/unreachable helper is an explicit failure,
  /// never a silent `active:false` map and never a launch: changing settings must
  /// not elevate merely to talk to a helper (WIRE-V1/V2).
  static Future<dynamic> _policyRpc(
    String method,
    Map<String, dynamic> request,
  ) async {
    final w = _worker;
    if (w == null) {
      throw PlatformException(
        code: 'POLICY_UNSUPPORTED',
        message: 'No local helper is available for versioned policy',
      );
    }
    if (!await _authenticate(w)) {
      throw PlatformException(
        code: 'POLICY_UNKNOWN',
        message: 'The local helper identity could not be authenticated',
      );
    }
    final response = await _json(
      Uri.http('127.0.0.1:${w['port']}', '/rpc'),
      body: {'Method': method, ...request},
      token: w['token'],
    );
    if (response['ok'] != true) {
      final error = response['error'];
      final code = error is String && RegExp(r'^POLICY_[A-Z]+$').hasMatch(error)
          ? error
          : 'POLICY';
      throw PlatformException(
        code: code,
        message: error is String ? error : 'The local helper refused the policy request.',
      );
    }
    return response['value'];
  }

  /// The Go read-only policyState query accepts only the Method key. Validate
  /// the exact internal query shape at the desktop boundary before projecting
  /// it, so unknown/missing/bad payloads are rejected rather than stripped.
  static void _requireStateQuery(Map<String, dynamic> a) {
    const keys = {'version', 'instanceNonce'};
    final version = a['version'];
    final instance = a['instanceNonce'];
    if (a.length != keys.length ||
        !keys.containsAll(a.keys) ||
        version is! int ||
        version != 1 ||
        instance is! String ||
        instance.isEmpty) {
      throw PlatformException(
        code: 'POLICY_INVALID',
        message: 'Invalid desktop policyState query shape',
      );
    }
  }

  static Future<dynamic> invoke(String method, dynamic arguments) async {
    final a = Map<String, dynamic>.from(arguments as Map? ?? {});
    switch (method) {
      case 'policyState':
        _requireStateQuery(a);
        // Exact Go read-only query contract: Method only, no extra keys.
        return await _policyRpc(method, const <String, dynamic>{});
      case 'policyCapabilities':
      case 'policyValidate':
      case 'policyBegin':
      case 'policyCommit':
      case 'policyAbort':
      case 'policyReconcile':
        // Exact lowerCamelCase identity fields are forwarded as the Go json tags
        // define them; no transport is invented for policy.
        return await _policyRpc(method, a);
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
        _connectionEpoch++; // Revoke a connect still waiting on credentials/UAC/auth.
        final cleanupClock = Stopwatch()..start();
        final cleanupBudget = Duration(
          milliseconds: (a['timeoutMillis'] as num?)?.toInt() ?? 30000,
        );
        if (_worker != null) {
          await _rpc('disconnect', const {}, () {
            final left = cleanupBudget - cleanupClock.elapsed;
            if (left <= Duration.zero) {
              throw TimeoutException('Connection cleanup deadline');
            }
            return {'TimeoutMillis': left.inMilliseconds.clamp(1, 30000)};
          });
        }
        return null;
      case 'connect':
        final epoch = ++_connectionEpoch;
        final clock = Stopwatch()..start();
        final attempt = Duration(
          milliseconds: (a['timeoutMillis'] as num?)?.toInt() ?? 15000,
        );
        final round = Duration(
          milliseconds: (a['roundMillis'] as num?)?.toInt() ?? 30000,
        );
        void requireCurrent() {
          if (epoch != _connectionEpoch ||
              clock.elapsed >= attempt ||
              clock.elapsed >= round) {
            throw TimeoutException('Connection activation deadline');
          }
        }
        final id = a['id'] as String;
        final saved = await CredentialVault.read(configKey(id));
        requireCurrent();
        if (saved == null) {
          throw PlatformException(
            code: 'CONFIG',
            message: 'Client profile is missing.',
          );
        }
        final config = saved['config']!;
        final protocol = id.startsWith('awg')
            ? 'awg'
            : jsonDecode(config)['protocol'] as String;
        if (!supported.contains(protocol)) {
          throw PlatformException(
            code: 'UNAVAILABLE',
            message: 'This protocol has no desktop engine in this build.',
          );
        }
        final left = attempt - clock.elapsed;
        await _ensureWorker().timeout(left);
        requireCurrent();
        return await _rpc('connect', const {}, () {
          requireCurrent();
          return {
            'ID': id,
            'Protocol': protocol,
            'Config': config,
            'TimeoutMillis': (attempt - clock.elapsed).inMilliseconds.clamp(
              1,
              30000,
            ),
            'RoundMillis': (round - clock.elapsed).inMilliseconds.clamp(
              1,
              30000,
            ),
            'PolicyJSON': jsonEncode(
              a['policy'] ?? {'mode': 'automatic', 'roundMillis': 30000},
            ),
            // Same six-field receipt as Android, encoded as one JSON string
            // because the existing desktop connect request is capitalized.
            if (a['policyReceipt'] != null)
              'PolicyReceiptJSON': jsonEncode(a['policyReceipt']),
          };
        });
      case 'sharingStatus':
        if (!Platform.isWindows) return {'supported': false, 'enabled': false};
        if (_worker == null || !await _authenticate(_worker!)) {
          return {'supported': true, 'enabled': false, 'candidates': []};
        }
        return await _rpc('sharingStatus');
      case 'sharingSet':
        await _ensureWorker();
        return await _rpc('sharingSet', {
          'SharingEnabled': a['enabled'] == true,
          'SharingInterface': a['interface'] ?? '',
        });
      case 'routingSummary':
        return {'enabled': false, 'supported': false};
      default:
        throw MissingPluginException('Unsupported desktop operation: $method');
    }
  }
}
