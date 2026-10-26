import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

String profile({
  String extra = '',
  String allowed = '0.0.0.0/0, ::/0',
  String endpoint = 'vpn.example:51820',
}) =>
    '''
[Interface]
PrivateKey = ${base64Encode(List.generate(32, (i) => i + 1))}
Address = 10.77.0.2/32
$extra
[Peer]
PublicKey = ${base64Encode(List.generate(32, (i) => 32 - i))}
Endpoint = $endpoint
AllowedIPs = $allowed
''';
void main() {
  test('accept standard profile and identify full tunnel', () {
    expect(WireGuardProfile.parse(profile()).fullTunnel, isTrue);
    expect(
      WireGuardProfile.parse(profile(allowed: '10.77.0.0/24')).fullTunnel,
      isFalse,
    );
  });
  test('reject shell hooks and Amnezia-specific configuration', () {
    for (final field in ['PostUp = rm -rf /', 'PreDown = echo x', 'Jc = 4']) {
      expect(
        () => WireGuardProfile.parse(profile(extra: field)),
        throwsFormatException,
      );
    }
  });
  test(
    'AWG mode accepts extensions but rejects commands and oversized padding',
    () {
      expect(
        WireGuardProfile.parse(
          profile(extra: 'Jc = 4\nS4 = 12\nH1 = 123-456\nI2 ='),
          amnezia: true,
        ).endpoint,
        'vpn.example:51820',
      );
      for (final field in [
        'PostUp = id',
        'Jc = 999999',
        'S1 = -1',
        'Jmin = 80\nJmax = 40',
        'H1 = 4294967296',
        'H1 = 9-4',
        'HeaderProtectionKey = invalid',
      ]) {
        expect(
          () => WireGuardProfile.parse(profile(extra: field), amnezia: true),
          throwsFormatException,
        );
      }
    },
  );
  test('reject duplicate secrets, invalid CIDR and invalid endpoints', () {
    expect(
      () => WireGuardProfile.parse(profile(extra: 'PrivateKey = xxx')),
      throwsFormatException,
    );
    for (final cidr in ['0.0.0.0/33', '::/129', 'no-ip/24']) {
      expect(
        () => WireGuardProfile.parse(profile(allowed: cidr)),
        throwsFormatException,
      );
    }
    for (final e in ['-host:443', 'host:65536', 'a;echo:22', 'host:0']) {
      expect(
        () => WireGuardProfile.parse(profile(endpoint: e)),
        throwsFormatException,
      );
    }
  });
  test('reject extra peer and missing interface', () {
    expect(
      () => WireGuardProfile.parse('${profile()}\n[Peer]\nPublicKey=x'),
      throwsFormatException,
    );
    expect(
      () => WireGuardProfile.parse('[Peer]\nEndpoint=x'),
      throwsFormatException,
    );
  });
  test(
    'host validation allows automatic SSH trust and optional explicit pin',
    () {
      final fp = 'SHA256:${'a' * 43}';
      SshTarget('host.example', 22, 'root', fp).validate();
      const SshTarget('host.example', 22, 'root').validate();
      for (final t in [
        SshTarget('a;id', 22, 'root', fp),
        SshTarget('host', 0, 'root', fp),
        SshTarget('host', 22, 'root;id', fp),
        const SshTarget('host', 22, 'root', 'invalid'),
      ]) {
        expect(t.validate, throwsFormatException);
      }
    },
  );
  test('removal of active profile is blocked', () async {
    final s = AppStore();
    s.busy = true;
    expect(() => s.remove('any'), throwsStateError);
    s.dispose();
  });
  test('diagnostic export excludes profiles and private material', () {
    final s = AppStore();
    s.profiles.add(
      const Profile(
        id: 'private',
        name: 'secret-name',
        protocol: 'wireguard',
        endpoint: 'private.example',
      ),
    );
    final raw = jsonEncode(s.diagnosticReport([]));
    expect(raw, isNot(contains('secret-name')));
    expect(raw, isNot(contains('private.example')));
    expect(raw, isNot(contains('PrivateKey')));
    s.dispose();
  });
  test('concurrent profile saves leave the newest complete snapshot', () async {
    final dir = await Directory.systemTemp.createTemp('xio-store-');
    final store = AppStore()..directory = dir;
    try {
      final writes = <Future<void>>[];
      for (var i = 0; i < 20; i++) {
        store.profiles.add(
          Profile(
            id: 'id$i',
            name: 'name$i',
            protocol: 'tailscale',
            endpoint: 'local',
          ),
        );
        writes.add(store.save());
      }
      await Future.wait(writes);
      final j = jsonDecode(
        await File('${dir.path}/profiles.json').readAsString(),
      );
      expect(j['profiles'].length, 20);
      expect(j['profiles'].last['id'], 'id19');
      expect(await File('${dir.path}/profiles.json.tmp').exists(), isFalse);
    } finally {
      store.dispose();
      await dir.delete(recursive: true);
    }
  });
  test('TCP diagnostic exercises an actual local socket', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final sub = server.listen((s) => s.destroy());
    try {
      final result = await NetworkChecks.run('127.0.0.1', server.port);
      expect(result.last['ok'], isTrue);
      expect(result.last['detail'], contains('3/3'));
    } finally {
      await sub.cancel();
      await server.close();
    }
  });
  test('closed TCP endpoint is not reported as healthy', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = server.port;
    await server.close();
    final result = await NetworkChecks.run('127.0.0.1', port);
    expect(result.last['ok'], isFalse);
    expect(result.last['ms'], isNull);
  });
}
