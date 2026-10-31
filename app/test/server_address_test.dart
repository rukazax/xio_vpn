import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/server_address.dart';

class _Assets extends CachingAssetBundle {
  final loaded = <String>[];
  @override
  Future<ByteData> load(String key) async {
    loaded.add(key);
    final fixture = key == 'assets/xio-server-release.json'
        ? '{"schema":1,"recipeVersion":24,"sha256":"e3a77c1dfb880b0a94ce3932913c47f4e4d758a9fb1dcda11e47bb29ee6783d4"}'
        : '# fixture only';
    return ByteData.sublistView(Uint8List.fromList(utf8.encode(fixture)));
  }
}

class _Ssh extends VpsService {
  _Ssh() {
    verifiedFingerprint = 'SHA256:${'a' * 43}';
  }
  int uploads = 0;
  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    uploads++;
    return [];
  }
}

class _Store extends AppStore {
  UserBundle? lastBundle;
  @override
  Future<void> save() async {}
  @override
  Future<ManagedUser> importBundle(UserBundle bundle) async {
    lastBundle = bundle;
    return ManagedUser(
      id: bundle.userId,
      name: bundle.name,
      serverId: bundle.serverId,
      profileIds: {},
    );
  }
}

class _Service extends ManagedService {
  final requests = <Map<String, dynamic>>[];
  _Service(super.ssh, _Assets assets) : super(assets: assets);
  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (request['action'] == 'inspect') {
      throw StateError('no installation');
    }
    requests.add(request);
    if (request['action'] == 'init') {
      return {
        'server': {
          'id': 'fixture-server',
          'host': request['host'],
          'country': 'DE',
        },
      };
    }
    return {
      'server': {
        'publicKeys': {'awg': base64Encode(List.filled(32, 1))},
        'awg': {
          'Jc': 4,
          'Jmin': 40,
          'Jmax': 70,
          'S1': 32,
          'S2': 40,
          'H1': 100001,
          'H2': 200001,
          'H3': 300001,
          'H4': 400001,
        },
        'rivet': {
          'serverName': 'gateway.example',
          'pin': base64Encode(List.filled(32, 2)),
          'gatewayId': base64Encode(List.filled(16, 3)),
          'ipv6': true,
        },
      },
      'user': {'slot': 2},
    };
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  group('IPv4/IPv6 host and endpoint boundary', () {
    for (final host in ['198.51.100.42', 'vpn.example', '2001:db8::42']) {
      test('raw host remains separate from port: $host', () {
        expect(normalizeServerHost(' $host '), host);
        final bracket = host.contains(':') ? '[$host]' : host;
        expect(serverEndpoint(host, 8443), '$bracket:8443');
        if (host.contains(':')) {
          expect(normalizeServerHost('[$host]'), host);
          expect(serverEndpoint('[$host]', 8443), '$bracket:8443');
        }
      });
    }
    for (final bad in [
      '',
      'https://vpn.example',
      'user@vpn.example',
      'vpn.example;id',
      'a b',
      ':::',
      '[198.51.100.42]',
      '[::1',
      '256.256.256.256',
      '-vpn.example',
      'vpn..example',
      'a_1.example',
      'vpn.example:443',
    ]) {
      test('reject malformed address before installation: $bad', () {
        expect(() => normalizeServerHost(bad), throwsFormatException);
      });
    }
    test('reject invalid endpoint ports', () {
      for (final port in [0, -1, 65536]) {
        expect(() => serverEndpoint('::1', port), throwsFormatException);
      }
    });
  });
  test('legacy management metadata retains its direct VPN host', () {
    final server = ManagedServer.fromJson({
      'id': 'legacy',
      'host': 'vpn.example',
    });
    expect(server.publicHost, 'vpn.example');
    expect(
      ManagedServer.fromJson(server.toJson()).publicHost,
      server.publicHost,
    );
  });
  test('proxy SSH and public IPv6 survive management export metadata', () {
    final server = ManagedServer(
      id: 'proxy',
      host: 'ssh-proxy.example',
      port: 9046,
      publicHost: '[2001:db8::42]',
    );
    final restored = ManagedServer.fromJson(server.toJson());
    expect(restored.host, 'ssh-proxy.example');
    expect(restored.port, 9046);
    expect(restored.publicHost, '2001:db8::42');
  });
  test(
    'install sends public IPv6 to server init, retaining SSH proxy for control',
    () async {
      final ssh = _Ssh()
        ..target = const SshTarget('ssh-proxy.example', 9046, 'root');
      final assets = _Assets();
      final service = _Service(ssh, assets);
      final store = _Store();
      try {
        final server = await service.install(
          store,
          publicHost: '[2001:db8::42]',
        );
        expect(service.requests.single['host'], '2001:db8::42');
        expect(server.host, 'ssh-proxy.example');
        expect(server.port, 9046);
        expect(server.publicHost, '2001:db8::42');
        expect(ssh.uploads, 1);
        expect(assets.loaded, [
          'assets/xio-server-release.json',
          'assets/xio-server.tar.gz',
          'assets/xio-bootstrap.sh',
        ]);
      } finally {
        store.dispose();
      }
    },
  );
  test('invalid public host performs no upload or init', () async {
    final ssh = _Ssh()
      ..target = const SshTarget('ssh-proxy.example', 9046, 'root');
    final assets = _Assets();
    final service = _Service(ssh, assets);
    final store = _Store();
    try {
      await expectLater(
        service.install(store, publicHost: 'bad;id'),
        throwsFormatException,
      );
      expect(ssh.uploads, 0);
      expect(service.requests, isEmpty);
      expect(assets.loaded, isEmpty);
    } finally {
      store.dispose();
    }
  });
  for (final publicHost in ['198.51.100.42', 'vpn.example', '2001:db8::42']) {
    test(
      'AWG and both RIVET profiles use public host not SSH proxy: $publicHost',
      () async {
        final ssh = _Ssh();
        final service = _Service(ssh, _Assets());
        final store = _Store();
        final server = ManagedServer(
          id: 'fixture-server',
          host: 'ssh-proxy.example',
          port: 9046,
          publicHost: publicHost,
        );
        try {
          await service.createUser(store, server, 'Fixture');
          final configs = store.lastBundle!.configs;
          expect(
            configs['awg'],
            contains('Endpoint = ${serverEndpoint(publicHost, 51821)}'),
          );
          for (final protocol in ['rivet-h3', 'rivet-s1']) {
            final profile = jsonDecode(configs[protocol]!) as Map;
            expect(profile['endpoint'], serverEndpoint(publicHost, 8443));
            expect(profile['serverName'], 'gateway.example');
            expect(profile['ip6'], 'fd79:1::2');
          }
          expect(
            configs.values.any((v) => v.contains('ssh-proxy.example')),
            isFalse,
          );
        } finally {
          store.dispose();
        }
      },
    );
  }
}
