import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';

import 'security_test.dart' show profile;

void main() {
  test('foreign WireGuard detection ignores misleading names and comments', () {
    final c = ClientImport.parse(
      '\uFEFF  # Exported by foreign provider\n${profile()}\n# Jc = 9\n',
    );
    expect(c.protocol, 'wireguard');
    expect(c.config, contains('PrivateKey'));
  });
  test('AWG extensions including zero and empty fields select AWG', () {
    for (final field in ['Jc = 0', 'I2 =', 'S4 = 0', 'H1 = 1-2']) {
      expect(ClientImport.parse(profile(extra: field)).protocol, 'awg');
    }
    expect(
      () => ClientImport.parse(profile(extra: 'Jc = 999')),
      throwsFormatException,
    );
  });
  test(
    'reject hooks, foreign protocols, subscriptions and oversized input',
    () {
      for (final raw in [
        profile(extra: 'PostUp = id'),
        'vless://secret@host',
        'https://provider.example/subscription',
        'client\ndev tun',
        'x' * 200001,
      ]) {
        expect(() => ClientImport.parse(raw), throwsFormatException);
      }
    },
  );
  test('new XIO exports retain legacy import and detect protocol mismatch', () {
    final b = UserBundle('Name', 'a' * 32, 'external', {
      'wireguard': profile(),
    });
    expect(b.encode(), startsWith('xio://'));
    expect(ClientImport.parse(b.encode()).bundle!.name, 'Name');
    expect(
      ClientImport.parse(b.encode().replaceFirst('xio://', 'x1o://'))
          .bundle!
          .configs,
      b.configs,
    );
    expect(
      () => ClientImport.parse(
        UserBundle('Name', 'b' * 32, 'external', {
          'wireguard': profile(extra: 'Jc = 0'),
        }).encode(),
      ),
      throwsFormatException,
    );
  });
  Map<String, Object> export(String conf) => {
    'description': 'Foreign server',
    'containers': [
      {
        'container': 'amnezia-awg',
        'awg': {
          'last_config': jsonEncode({'config': conf}),
        },
      },
    ],
  };
  String compressed(Map data, {int? claimedLength}) {
    final raw = utf8.encode(jsonEncode(data));
    final size = claimedLength ?? raw.length;
    return 'vpn://${base64Url.encode([size >> 24 & 255, size >> 16 & 255, size >> 8 & 255, size & 255, ...zlib.encode(raw)])}';
  }

  test(
    'Amnezia client JSON and Qt compressed vpn keys import client data only',
    () {
      final conf = profile(extra: 'Jc = 4');
      for (final raw in [jsonEncode(export(conf)), compressed(export(conf))]) {
        final c = ClientImport.parse(raw).bundle!;
        expect(c.configs, {'awg': conf.trim()});
        expect(c.serverId, startsWith('external-'));
        expect(c.name, 'Foreign server');
      }
      expect(
        () =>
            ClientImport.parse(compressed(export(conf), claimedLength: 200001)),
        throwsFormatException,
      );
      expect(
        () => ClientImport.parse(compressed(export(conf), claimedLength: 1)),
        throwsFormatException,
      );
      final admin = export(conf)..['password'] = 'do-not-import';
      expect(
        () => ClientImport.parse(jsonEncode(admin)),
        throwsFormatException,
      );
    },
  );
  test('structured Amnezia export retains explicit route policy and rejects missing routes', () {
    final key = base64Encode(List.generate(32, (i) => i + 1));
    final client = <String, Object>{
      'hostName': 'foreign.example',
      'port': 51821,
      'client_ip': '10.8.0.2',
      'client_priv_key': key,
      'server_pub_key': key,
      'allowed_ips': ['10.0.0.0/8'],
      'Jc': '0',
    };
    Map wrap() => {
      'containers': [
        {
          'container': 'amnezia-awg',
          'awg': {'last_config': jsonEncode(client)},
        },
      ],
    };
    final result = ClientImport.parse(jsonEncode(wrap()))
        .bundle!
        .configs['awg']!;
    expect(result, contains('Address = 10.8.0.2/32'));
    expect(result, contains('AllowedIPs = 10.0.0.0/8'));
    expect(result, isNot(contains('0.0.0.0/0')));
    client.remove('allowed_ips');
    expect(() => ClientImport.parse(jsonEncode(wrap())), throwsFormatException);
  });
  test('decompression bomb with falsely small Qt length is bounded', () {
    final oversized = export('x' * 1000000);
    expect(
      () => ClientImport.parse(compressed(oversized, claimedLength: 1)),
      throwsFormatException,
    );
  });
}
