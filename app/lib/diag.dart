import 'dart:async';
import 'dart:io';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'version.dart';

/// Compile-time switch for the diagnostic ("test") build.
///
/// A test build keeps the window capturable, writes a persistent on-device log
/// and, when an endpoint is compiled in, uploads log bundles to the panel.
/// Release builds must be produced without any of these constants.
const bool xioTestBuild = bool.fromEnvironment('XIO_TEST_BUILD');

/// Panel endpoint, e.g. `https://79e.ru/xio/api/diag`. Empty disables upload.
const String xioDiagEndpoint = String.fromEnvironment('XIO_DIAG_URL');

/// Scoped upload token. Never logged, never written to the device log.
const String xioDiagToken = String.fromEnvironment('XIO_DIAG_TOKEN');

const MethodChannel _native = MethodChannel('app.xio/engine');

/// Process-wide diagnostic log.
///
/// On Android the Kotlin [Diag] object owns the file, captures the process
/// logcat and survives the UI: this class only forwards lines and asks for a
/// bundle. Other platforms print to stderr, so a desktop run still has output.
class XioDiag {
  XioDiag._();

  static final List<String> _buffer = <String>[];
  static bool _installed = false;
  static bool _dirty = false;
  static DateTime? _lastUpload;
  static Future<String?>? _uploading;
  static Timer? _timer;

  static bool get available => xioTestBuild;
  static bool get canUpload => xioTestBuild && xioDiagEndpoint.isNotEmpty && xioDiagToken.isNotEmpty;

  static void install() {
    if (_installed) return;
    _installed = true;
    final previous = FlutterError.onError;
    FlutterError.onError = (details) {
      log('flutter', '${details.exceptionAsString()} @ ${details.library ?? ''}');
      previous?.call(details);
    };
    PlatformDispatcher.instance.onError = (error, stack) {
      log('uncaught', '$error');
      return false;
    };
    if (xioTestBuild) {
      log('app', 'test build $xioVersion ($xioBuild) endpoint=${xioDiagEndpoint.isEmpty ? 'off' : Uri.parse(xioDiagEndpoint).host}');
      _startAutoUpload();
    }
  }

  /// Redacts anything that looks like key material or a complete profile.
  static String _redact(String message) {
    for (final marker in const ['PrivateKey', 'PresharedKey', 'xio://', 'vpn://']) {
      if (message.toLowerCase().contains(marker.toLowerCase())) return '[redacted: $marker]';
    }
    return message.replaceAll(RegExp(r'[A-Za-z0-9+/=_-]{80,}'), '[redacted:long-token]');
  }

  static void log(String tag, String message) {
    final line = '${DateTime.now().toUtc().toIso8601String()} $tag: ${_redact(message)}';
    _dirty = true;
    if (Platform.isAndroid) {
      // Fire and forget: logging must never block a connection or a frame.
      unawaited(_native.invokeMethod<void>('diagLog', {'tag': tag, 'message': message}).catchError((_) {}));
    } else if (xioTestBuild || kDebugMode) {
      debugPrint('XIO $line');
      _buffer.add(line);
      if (_buffer.length > 1000) _buffer.removeAt(0);
    }
  }

  static Future<String> snapshot({int max = 200000}) async {
    if (Platform.isAndroid) {
      try {
        return await _native.invokeMethod<String>('diagSnapshot', {'max': max}) ??
            _buffer.join('\n');
      } catch (_) {
        return _buffer.join('\n');
      }
    }
    return _buffer.join('\n');
  }

  /// Local bundle path on Android, null elsewhere/unavailable.
  static Future<String?> bundlePath() async {
    if (!Platform.isAndroid) return null;
    try {
      return await _native.invokeMethod<String>('diagBundle');
    } catch (error) {
      log('diag', 'bundle failed: $error');
      return null;
    }
  }

  static void markDirty() => _dirty = true;

  static void _startAutoUpload() {
    if (!canUpload) return;
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 90), (_) {
      if (!_dirty) return;
      unawaited(upload(silent: true));
    });
  }

  /// Uploads the current bundle. Returns the panel id, or an error text.
  static Future<String?> upload({bool silent = false}) {
    if (!canUpload) return Future.value(silent ? null : 'Не настроен адрес журнала');
    final running = _uploading;
    if (running != null) return running;
    final task = _upload().whenComplete(() => _uploading = null);
    _uploading = task;
    return task;
  }

  static Future<String?> _upload() async {
    final path = await bundlePath();
    if (path == null) {
      log('diag', 'upload skipped: no bundle');
      return null;
    }
    final file = File(path);
    if (!await file.exists()) return null;
    final bytes = gzip.encode(await file.readAsBytes());
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 20);
    try {
      final request = await client.postUrl(Uri.parse(xioDiagEndpoint));
      request.headers.set('X-XIO-Diag-Token', xioDiagToken);
      request.headers.contentType = ContentType('application', 'gzip');
      request.headers.set('X-XIO-Version', '$xioVersion+$xioBuild');
      // The panel requires an exact Content-Length; dart:io would otherwise
      // send chunked encoding and the upload is rejected with 413.
      request.contentLength = bytes.length;
      request.add(bytes);
      final response = await request.close().timeout(const Duration(seconds: 40));
      final body = await response.transform(utf8.decoder).join();
      if (response.statusCode != 200) {
        log('diag', 'upload refused: HTTP ${response.statusCode}');
        return null;
      }
      final id = (jsonDecode(body) as Map)['id'] as String?;
      _dirty = false;
      _lastUpload = DateTime.now();
      log('diag', 'uploaded $id (${bytes.length} bytes)');
      unawaited(file.delete().catchError((_) => file));
      return id;
    } catch (error) {
      log('diag', 'upload failed: $error');
      return null;
    } finally {
      client.close(force: true);
      unawaited(file.delete().catchError((_) => file));
    }
  }

  static DateTime? get lastUpload => _lastUpload;
}

/// Debug command dispatcher used by the test build only.
///
/// Kotlin queues `--es xioTest '<json>'` commands from `am start`; this class
/// polls them and runs them against the real store, so a protocol matrix is
/// driven by adb instead of fragile screen taps.
class XioTestDriver {
  static Future<void> Function(String json)? runner;
  static Timer? _poll;

  static void start(Future<void> Function(String json) run) {
    if (!xioTestBuild) return;
    runner = run;
    _poll?.cancel();
    _poll = Timer.periodic(const Duration(milliseconds: 700), (_) async {
      if (!Platform.isAndroid) return;
      try {
        final raw = await _native.invokeMethod<String>('consumeTestCommand');
        if (raw == null || raw.isEmpty) return;
        await runner!(raw);
      } catch (error) {
        XioDiag.log('test', 'command failed: $error');
      }
    });
  }
}
