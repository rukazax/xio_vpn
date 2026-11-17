import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'awg_export.dart';
import 'core.dart';
import 'diag.dart';
import 'policy_channel.dart';
import 'version.dart';

/// Executes JSON commands delivered by `adb shell am start ... --es xioTest`.
///
/// Only compiled into behaviour when `XIO_TEST_BUILD=true`; the Kotlin side also
/// refuses to queue commands in a release build. Results are written to the
/// diagnostic log as a single `TEST <json>` line so they arrive with the log
/// upload even when nobody is watching the screen.
class TestCommands {
  TestCommands(this.store);
  final AppStore store;
  bool _busy = false;

  static Future<void> run(AppStore store, String raw) async {
    final driver = TestCommands(store);
    await driver._execute(raw);
  }

  Future<void> _execute(String raw) async {
    if (_busy) {
      XioDiag.log('test', 'busy, ignored: $raw');
      return;
    }
    _busy = true;
    try {
      final command = jsonDecode(raw);
      if (command is! Map) throw const FormatException('not an object');
      final action = command['action'];
      XioDiag.log('test', 'run $raw'.replaceAll(RegExp(r'\s+'), ' '));
      switch (action) {
        case 'ping':
          _emit({'ok': true, 'version': xioVersion, 'build': xioBuild});
        case 'profiles':
          _emit({
            'ok': true,
            'selected': store.selectedId,
            'profiles': [
              for (final p in store.profiles)
                {
                  'id': p.id,
                  'protocol': p.protocol,
                  'endpoint': p.endpoint,
                  'name': p.name,
                },
            ],
          });
        case 'status':
          _emitStatus();
        case 'connect':
          await _connect(command['protocol'] as String?);
        case 'select':
          await _select(
            command['id'] as String?,
            command['protocol'] as String?,
            (command['index'] as num?)?.toInt(),
          );
        case 'delete':
          await _delete(
            command['id'] as String?,
            command['protocol'] as String?,
          );
        case 'switch':
          await _switch(command['protocol'] as String?);
        case 'disconnect':
          await store.disconnect();
          _emitStatus();
        case 'wait':
          final ms = (command['ms'] as num?)?.toInt() ?? 1000;
          await Future<void>.delayed(Duration(milliseconds: ms.clamp(0, 60000)));
          _emitStatus();
        case 'http':
          await _http(command['url'] as String?);
        case 'awg':
          await _awg();
        case 'policy':
          await _policy();
        case 'import':
          await _import(command['text'] as String?);
        case 'config':
          await _config(
            command['id'] as String?,
            command['protocol'] as String?,
          );
        default:
          _emit({'ok': false, 'error': 'unknown action $action'});
      }
    } catch (error) {
      XioDiag.log('test', 'error: $error');
      _emit({'ok': false, 'error': '$error'});
    } finally {
      _busy = false;
    }
  }

  List<Profile> _byProtocol(String? protocol) => store.profiles
      .where((p) => protocol == null || p.protocol == protocol)
      .toList();

  Future<void> _connect(String? protocol) async {
    // No protocol: connect the CURRENT selection, so a test can select a
    // deliberately unreachable profile and exercise automatic failover without
    // the driver silently rewriting the selection.
    final pool = protocol == null
        ? [if (store.selected != null) store.selected!]
        : _byProtocol(protocol);
    if (pool.isEmpty) {
      _emit({'ok': false, 'error': 'no profile for $protocol'});
      return;
    }
    final target = pool.first;
    if (store.status.active) await store.disconnect();
    if (protocol != null) await store.select(target.id);
    final started = DateTime.now().millisecondsSinceEpoch;
    await store.connect();
    final ms = DateTime.now().millisecondsSinceEpoch - started;
    _emitStatus({
      'ok': store.status.active,
      'requested': target.protocol,
      'candidates': [
        for (final p in store.connectionCandidates(store.selected)) p.protocol,
      ],
      'accepted': store.activeProfile?.protocol,
      'elapsedMillis': ms,
    });
  }

  /// Selects a profile by exact id, by protocol (first match) or by index, so a
  /// failover scenario can be staged without the UI.
  Future<void> _select(String? id, String? protocol, int? index) async {
    Profile? target;
    if (id != null) {
      target = store.profiles.where((p) => p.id == id).firstOrNull;
    } else if (protocol != null) {
      target = store.profiles.where((p) => p.protocol == protocol).firstOrNull;
    } else if (index != null && index >= 0 && index < store.profiles.length) {
      target = store.profiles[index];
    }
    if (target == null) {
      _emit({'ok': false, 'error': 'no such profile'});
      return;
    }
    await store.select(target.id);
    _emit({
      'ok': true,
      'selected': store.selectedId,
      'protocol': target.protocol,
      'endpoint': target.endpoint,
      'mode': store.connectionPolicy.name,
      'candidates': [
        for (final p in store.connectionCandidates(store.selected))
          '${p.protocol}@${p.endpoint}',
      ],
    });
  }

  /// Removes a profile (and its user reference) so a test target can be cleaned
  /// up without the UI. Refused while the tunnel is up, like the real screen.
  Future<void> _delete(String? id, String? protocol) async {
    Profile? target;
    if (id != null) {
      target = store.profiles.where((p) => p.id == id).firstOrNull;
    } else if (protocol != null) {
      target = store.profiles.where((p) => p.protocol == protocol).lastOrNull;
    }
    if (target == null) {
      _emit({'ok': false, 'error': 'no such profile'});
      return;
    }
    try {
      await store.remove(target.id);
      _emit({
        'ok': true,
        'deleted': target.id,
        'selected': store.selectedId,
        'profiles': [for (final p in store.profiles) p.id],
      });
    } catch (error) {
      _emit({'ok': false, 'id': target.id, 'error': '$error'});
    }
  }

  Future<void> _switch(String? protocol) async {
    final pool = _byProtocol(protocol);
    if (pool.isEmpty) {
      _emit({'ok': false, 'error': 'no profile for $protocol'});
      return;
    }
    final target = pool.first;
    final started = DateTime.now().millisecondsSinceEpoch;
    try {
      await store.switchProfile(target.id);
      _emitStatus({
        'ok': store.status.active,
        'requested': target.protocol,
        'elapsedMillis': DateTime.now().millisecondsSinceEpoch - started,
      });
    } catch (error) {
      _emitStatus({
        'ok': false,
        'requested': target.protocol,
        'error': '$error',
        'elapsedMillis': DateTime.now().millisecondsSinceEpoch - started,
      });
    }
  }

  Future<void> _http(String? url) async {
    final uri = Uri.tryParse(url ?? 'https://api.ipify.org?format=json');
    if (uri == null || uri.scheme != 'https') {
      _emit({'ok': false, 'error': 'https url required'});
      return;
    }
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 12);
    final started = DateTime.now().millisecondsSinceEpoch;
    try {
      final request = await client.getUrl(uri);
      request.headers.set('User-Agent', 'XIO-test/$xioVersion');
      final response = await request.close().timeout(const Duration(seconds: 15));
      final body = await response.transform(utf8.decoder).join();
      _emit({
        'ok': response.statusCode == 200,
        'status': response.statusCode,
        'url': uri.toString(),
        'body': body.length > 300 ? body.substring(0, 300) : body,
        'elapsedMillis': DateTime.now().millisecondsSinceEpoch - started,
      });
    } catch (error) {
      _emit({'ok': false, 'url': uri.toString(), 'error': '$error'});
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _awg() async {    final profile = store.profiles.where((p) => p.protocol == 'awg').firstOrNull;
    if (profile == null) {
      _emit({'ok': false, 'error': 'no awg profile'});
      return;
    }
    final raw = await store.readProfileConfig(profile.id);
    final exported = AwgProfile.parse(raw);
    _emit({
      'ok': true,
      'endpoint': exported.endpoint,
      'obfuscated': exported.obfuscated,
      'file': AwgProfile.fileName(profile.name),
      'text': exported.text,
    });
  }

  /// Read-only view of the native policy lane; no publication is started.
  Future<void> _policy() async {
    PolicyNativeState? state;
    try {
      state = await store.nativePolicyState();
    } catch (error) {
      _emit({
        'ok': false,
        'capable': store.policyCapable,
        'error': '$error',
      });
      return;
    }
    if (state == null) {
      _emit({'ok': true, 'capable': false, 'policyCapable': store.policyCapable});
      return;
    }
    _emit({
      'ok': true,
      'capable': true,
      'state': state.state,
      'phase': state.phase,
      'resourceState': state.resourceState,
      'transactionId': state.transactionId,
      'planGeneration': state.planGeneration,
      'pendingTransaction': state.pendingTransaction,
      'receipt': state.receipt == null
          ? null
          : {
              'planGeneration': state.receipt!.planGeneration,
              'transactionId': state.receipt!.transactionId,
            },
      'error': state.error,
      'policyCapable': store.policyCapable,
      'mode': store.connectionPolicy.name,
      'receiptRequired': store.policyReceiptRequired,
      'reconcilePending': store.policyReconciliationPending,
      'unconfirmed': store.policyUnconfirmed,
    });
  }

  /// Imports a capsule/profile exactly like the paste field (test automation).
  Future<void> _import(String? text) async {
    final raw = (text ?? '').trim();
    if (raw.isEmpty) {
      _emit({'ok': false, 'error': 'text required'});
      return;
    }
    final before = store.profiles.length;
    try {
      await store.importConnection(raw);
      _emit({
        'ok': true,
        'imported': store.profiles.length - before,
        'selected': store.selectedId,
        'profiles': [
          for (final p in store.profiles)
            {'id': p.id, 'protocol': p.protocol, 'name': p.name},
        ],
      });
    } catch (error) {
      // Never echo the payload: it carries issuance secrets and the diagnostic
      // log uploads it to the panel. Markers are stripped so the line is not
      // dropped by redaction before it can be read.
      final text = '${error is FormatException ? error.message : error}'
          .replaceAll(RegExp('xio://', caseSensitive: false), 'xio-')
          .replaceAll(RegExp('vpn://', caseSensitive: false), 'vpn-')
          .replaceAll(RegExp(r'[A-Za-z0-9+/=_-]{80,}'), '<token>');
      // Test builds only: stdout reaches logcat unredacted, which is the only
      // way to read a pre-sanitized import failure without the diag redactor.
      if (xioTestBuild) {
        // ignore: avoid_print
        print('XIO-IMPORT-FAIL ${error.runtimeType}: $text');
      }
      _emit({
        'ok': false,
        'type': '${error.runtimeType}',
        'error': text.length > 400 ? text.substring(0, 400) : text,
      });
    }
  }

  /// Raw stored profile document (test builds only; the diagnostic log is
  /// scoped to the panel and never leaves the device otherwise).
  Future<void> _config(String? id, String? protocol) async {
    final profile = store.profiles
        .where((p) => id != null ? p.id == id : p.protocol == protocol)
        .firstOrNull;
    if (profile == null) {
      _emit({'ok': false, 'error': 'no such profile'});
      return;
    }
    try {
      final raw = await store.readProfileConfig(profile.id);
      _emit({
        'ok': true,
        'id': profile.id,
        'protocol': profile.protocol,
        'endpoint': profile.endpoint,
        'config': raw,
      });
    } catch (error) {
      _emit({'ok': false, 'error': '$error'});
    }
  }

  void _emitStatus([Map<String, Object?> extra = const {}]) {
    final status = store.status;
    _emit({
      'ok': status.active,
      'active': status.active,
      'state': status.state,
      'path': status.path,
      'phase': status.phase,
      'handshake': status.handshake,
      'rx': status.rx,
      'tx': status.tx,
      'selected': store.selectedId,
      'error': store.error,
      ...extra,
    });
  }

  void _emit(Map<String, Object?> payload) {
    XioDiag.log('TEST', jsonEncode(payload));
  }
}
