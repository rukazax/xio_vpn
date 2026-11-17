import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_native.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';

/// Live verification of the two-stage installer against the real cascade pair.
///
/// The suite is skipped unless `XIO_LIVE=1`; normal test runs and CI never touch
/// a server. It uses the same [CascadeInstaller] the wizard calls, so a pass here
/// is evidence about the shipped code path, not about a copy of it.
///
///   XIO_LIVE=1 \
///   XIO_EXIT_HOST=… XIO_EXIT_PASSWORD=… \
///   XIO_BRIDGE_HOST=… XIO_BRIDGE_KEY=/path/to/key \
///   flutter test test/cascade_live_test.dart
final _live = Platform.environment['XIO_LIVE'] == '1';
final _exitHost = Platform.environment['XIO_EXIT_HOST'] ?? '';
final _exitPassword = Platform.environment['XIO_EXIT_PASSWORD'] ?? '';
final _bridgeHost = Platform.environment['XIO_BRIDGE_HOST'] ?? '';
final _bridgeKeyPath = Platform.environment['XIO_BRIDGE_KEY'] ?? '';

Future<VpsService> _open(String host, {String password = '', String key = ''}) async {
  final ssh = VpsService();
  await ssh.open(SshTarget(host, 22, 'root', ''), password, key, '');
  return ssh;
}

void main() {
  // rootBundle is used by ManagedService.purge to upload admin.py.
  TestWidgetsFlutterBinding.ensureInitialized();
  group('Живой каскад: этапы и очистка', () {
    late VpsService exit, bridge;

    setUpAll(() async {
      exit = await _open(_exitHost, password: _exitPassword);
      bridge = await _open(
        _bridgeHost,
        key: File(_bridgeKeyPath).readAsStringSync(),
      );
    });

    tearDownAll(() async {
      await exit.close();
      await bridge.close();
    });

    test('dry-run очистки ничего не меняет и перечисляет цели', () async {
      final result = await ManagedService(exit).purge(
        AppStore(),
        dryRun: true,
      );
      expect(result['dryRun'], isTrue);
      final removed = [for (final e in (result['removed'] as List)) '$e'];
      // The exit was installed by this very project, so at least its unit and
      // its state directory must be listed.
      expect(
        removed.any((path) => path.contains('xio-cascade-exit')),
        isTrue,
        reason: 'dry-run must list the owned unit',
      );
      // A dry run never claims a clean host: nothing was removed.
      expect(result['clean'], isFalse);
    });

    test('очистка действительно возвращает хост к состоянию до установки', () async {
      final result = await ManagedService(exit).purge(AppStore());
      expect(result['clean'], isTrue, reason: '${result['remaining']}');
      expect([for (final e in (result['remaining'] as List)) '$e'], isEmpty);

      // Independent read-back: the unit and the tunnel must be gone.
      final probe = await exit.executeInput(
        'systemctl is-active xio-cascade-exit.service || true; '
        'ip -4 addr show tun0 2>/dev/null | grep -c 10.250.0. || true',
        const <int>[],
        timeout: const Duration(seconds: 30),
      );
      final text = utf8.decode(probe, allowMalformed: true);
      expect(text.trim().split('\n').first.trim(), isNot('active'));
      expect(text.trim().split('\n').last.trim(), '0');
    });

    test('этап 1 ставит exit и подтверждает адреса', () async {
      final evidence = await CascadeInstaller(exit).installExit();
      expect(evidence, isNotEmpty);
      expect(evidence.join(' '), contains('10.250.0.2/30'));
      expect(evidence.join(' '), contains('forward=1'));

      // A second run must be idempotent: same state, no duplicate rules.
      final again = await CascadeInstaller(exit).installExit();
      expect(again.join(' '), contains('10.250.0.2/30'));
      final rules = await exit.executeInput(
        'iptables -t nat -S POSTROUTING | grep -c "10.78.0.0/24" || true',
        const <int>[],
        timeout: const Duration(seconds: 30),
      );
      expect(utf8.decode(rules).trim(), '1');
    });

    test('этап 2 поднимает bridge, туннель и помеченный выход', () async {
      final publicKey = await readCascadeKey(bridge);
      await authorizeCascadeKey(exit, publicKey);
      final evidence = await CascadeInstaller(
        bridge,
      ).installBridge(_exitHost);
      expect(evidence.join(' '), contains('10.250.0.1/30'));
      expect(evidence.join(' '), contains('ping'));

      // Locally generated traffic marked with XIO_CASCADE_MARK must leave
      // through the exit: this is the path Xray and the RIVET gateway use,
      // because they have no input interface for the iif rule.
      final marked = await bridge.executeInput(
        r'''python3 - <<'PY'
import socket
s=socket.socket(); s.settimeout(15)
s.setsockopt(socket.SOL_SOCKET, 36, 0x518)
s.connect(("api.ipify.org", 80))
s.sendall(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
d=b""
while True:
    c=s.recv(4096)
    if not c: break
    d+=c
print(d.decode(errors="replace").split("\r\n\r\n")[-1].strip())
PY''',
        const <int>[],
        timeout: const Duration(seconds: 60),
      );
      expect(utf8.decode(marked).trim(), _exitHost);
    });
  }, skip: _live ? false : 'set XIO_LIVE=1 and the host variables to run');
}
