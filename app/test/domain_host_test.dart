import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/server_address.dart';
import 'package:xio/subclients.dart';
import 'package:xio/workspace_ui.dart';

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

class _ClosedSocket implements SSHSocket {
  final _in = StreamController<Uint8List>();
  final _out = StreamController<List<int>>();
  _ClosedSocket() {
    unawaited(_in.close());
    unawaited(_out.stream.drain<void>());
  }
  @override
  Stream<Uint8List> get stream => _in.stream;
  @override
  StreamSink<List<int>> get sink => _out.sink;
  @override
  Future<void> get done => _out.done;
  @override
  Future<void> close() async {
    await _out.close();
    await _in.close();
  }

  @override
  void destroy() {
    unawaited(_in.close());
    unawaited(_out.close());
  }

  @override
  Future<void> flush() async {}
}

String _wgProfile({String endpoint = 'fr-host.fr:51821'}) =>
    '''
[Interface]
PrivateKey = ${base64Encode(List.generate(32, (i) => i + 1))}
Address = 10.78.0.2/32, fd78:1::2/128
[Peer]
PublicKey = ${base64Encode(List.generate(32, (i) => 32 - i))}
Endpoint = $endpoint
AllowedIPs = 0.0.0.0/0, ::/0
''';

Map<String, dynamic> _rivetFixture({
  String endpoint = 'fr-host.fr:8443',
  String serverName = 'gateway.example',
}) => {
  'protocol': 'rivet-h3',
  'endpoint': endpoint,
  'serverName': serverName,
  'pin': base64Encode(List.filled(32, 1)),
  'gatewayId': base64Encode(List.filled(16, 2)),
  'id': 'a' * 32,
  'secret': base64Encode(List.filled(32, 3)),
  'entryToken': base64Encode(List.filled(32, 4)),
  'ip': '10.79.0.2',
};

void main() {
  group('domain, IPv4 and IPv6 share one validated host boundary', () {
    test('accepts real-shaped domain names and both IP families', () {
      for (final host in [
        'fr-host.fr',
        'VPS-721137.ssh.vps1euro.fr',
        '198.51.100.42',
        '2001:db8::42',
      ]) {
        expect(normalizeServerHost(' $host '), host);
      }
      expect(normalizeServerHost('[2001:db8::42]'), '2001:db8::42');
      expect(serverEndpoint('fr-host.fr', 9046), 'fr-host.fr:9046');
      expect(
        serverEndpoint('VPS-721137.ssh.vps1euro.fr', 9046),
        'VPS-721137.ssh.vps1euro.fr:9046',
      );
      expect(serverEndpoint('198.51.100.42', 8443), '198.51.100.42:8443');
      expect(serverEndpoint('2001:db8::42', 8443), '[2001:db8::42]:8443');
    });

    test('rejects schemes, host:port and injection in a host field', () {
      for (final bad in [
        '',
        'https://fr-host.fr',
        'fr-host.fr:9046',
        'user@fr-host.fr',
        'fr-host.fr;id',
        'fr_host.fr',
        '-fr-host.fr',
        'fr-host..fr',
        '[198.51.100.42]',
        '[::1',
        '256.256.256.256',
        'fr-host.fr/path',
        'fr-host.fr?x',
        'fr-host.fr#x',
      ]) {
        expect(() => normalizeServerHost(bad), throwsFormatException);
      }
    });

    test('parses endpoint hosts with explicit port and IPv6 brackets', () {
      expect(
        ServerEndpoint.parse('fr-host.fr:51821').formatted,
        'fr-host.fr:51821',
      );
      expect(
        ServerEndpoint.parse('VPS-721137.ssh.vps1euro.fr:9046').formatted,
        'VPS-721137.ssh.vps1euro.fr:9046',
      );
      expect(
        ServerEndpoint.parse('[2001:db8::42]:8443').formatted,
        '[2001:db8::42]:8443',
      );
      for (final bad in [
        'fr-host.fr',
        'https://fr-host.fr:443',
        'fr-host.fr:0',
        'fr-host.fr:65536',
        'fr-host.fr:44x',
        'fr-host.fr:443/path',
        'user@fr-host.fr:443',
        '[198.51.100.42]:443',
        '2001:db8::42:443',
        'fr-host.fr:443:1',
        '[::1]',
      ]) {
        expect(() => ServerEndpoint.parse(bad), throwsFormatException);
      }
    });

    test('SshTarget validates the same host before a socket exists', () {
      expect(
        const SshTarget('VPS-721137.ssh.vps1euro.fr', 9046, 'root').validate,
        returnsNormally,
      );
      expect(
        const SshTarget('[2001:db8::42]', 22, 'root').validate,
        returnsNormally,
      );
      for (final host in [
        'https://fr-host.fr',
        'fr-host.fr:9046',
        'user@fr-host.fr',
        'fr_host.fr',
        '[198.51.100.42]',
      ]) {
        expect(
          () => SshTarget(host, 22, 'root').validate(),
          throwsFormatException,
        );
      }
      for (final port in [0, 65536]) {
        expect(
          () => SshTarget('fr-host.fr', port, 'root').validate(),
          throwsFormatException,
        );
      }
    });

    test('known-hosts keys a bracketed IPv6 by its raw host', () async {
      final dir = await Directory.systemTemp.createTemp('xio-known-');
      final file = File('${dir.path}/known.json');
      final fingerprint = 'SHA256:${'a' * 43}';
      try {
        await SshHostKeyStore(file)
            .verify(const SshTarget('[2001:db8::42]', 22, 'root'), fingerprint);
        expect(jsonDecode(await file.readAsString()), {
          '[2001:db8::42]:22': fingerprint,
        });
      } finally {
        await dir.delete(recursive: true);
      }
    });

    test('managed metadata keeps the proxy and VPN host independent', () {
      final server = ManagedServer(
        id: 'proxy',
        host: 'VPS-721137.ssh.vps1euro.fr',
        port: 9046,
        publicHost: 'fr-host.fr',
      );
      final restored = ManagedServer.fromJson(server.toJson());
      expect(restored.host, 'VPS-721137.ssh.vps1euro.fr');
      expect(restored.port, 9046);
      expect(restored.publicHost, 'fr-host.fr');
      expect(restored.toJson()['publicHost'], 'fr-host.fr');

      final legacy = ManagedServer.fromJson({
        'id': 'legacy',
        'host': 'fr-host.fr',
      });
      expect(legacy.publicHost, 'fr-host.fr');

      final empty = ManagedServer.fromJson({
        'id': 'empty',
        'host': 'fr-host.fr',
        'publicHost': '',
      });
      expect(empty.publicHost, 'fr-host.fr');

      final v6 = ManagedServer.fromJson({
        'id': 'v6',
        'host': '[2001:db8::42]',
        'publicHost': '[2001:db8::43]',
      });
      expect(v6.host, '2001:db8::42');
      expect(v6.publicHost, '2001:db8::43');

      expect(
        () =>
            ManagedServer.fromJson({'id': 'bad', 'host': 'https://fr-host.fr'}),
        throwsFormatException,
      );
    });

    test('DNS candidate resolution asks A and AAAA separately', () async {
      final calls = <String>[];
      final candidates = await resolveServerHost(
        'fr-host.fr',
        lookup: (host, type) async {
          calls.add(type == InternetAddressType.IPv4 ? 'IPv4' : 'IPv6');
          return type == InternetAddressType.IPv4
              ? [InternetAddress.tryParse('203.0.113.10')!]
              : [InternetAddress.tryParse('2001:db8::10')!];
        },
      );
      expect(calls.toSet(), {'IPv4', 'IPv6'});
      expect(candidates.map((c) => c.family), ['IPv4', 'IPv6']);
      expect(candidates.map((c) => c.host), ['203.0.113.10', '2001:db8::10']);

      var called = false;
      final literal = await resolveServerHost(
        '2001:db8::42',
        lookup: (host, type) async {
          called = true;
          return [];
        },
      );
      expect(called, isFalse);
      expect(literal.single.host, '2001:db8::42');
      expect(literal.single.family, 'IPv6');

      final onlyV6 = await resolveServerHost(
        'fr-host.fr',
        lookup: (host, type) async => type == InternetAddressType.IPv6
            ? [InternetAddress.tryParse('2001:db8::10')!]
            : [],
      );
      expect(onlyV6.single.family, 'IPv6');

      await expectLater(
        resolveServerHost('fr-host.fr', lookup: (host, type) async => []),
        throwsFormatException,
      );
    });

    test('three A answers never starve the single AAAA answer', () async {
      final candidates = await resolveServerHost(
        'fr-host.fr',
        lookup: (host, type) async => type == InternetAddressType.IPv4
            ? [
                InternetAddress.tryParse('203.0.113.10')!,
                InternetAddress.tryParse('203.0.113.11')!,
                InternetAddress.tryParse('203.0.113.12')!,
              ]
            : [InternetAddress.tryParse('2001:db8::10')!],
      );
      expect(candidates.map((c) => c.host).toList(), [
        '203.0.113.10',
        '2001:db8::10',
        '203.0.113.11',
        '203.0.113.12',
      ]);
      expect(candidates.indexWhere((c) => c.family == 'IPv6'), 1);
    });

    test('three AAAA answers never starve the single A answer', () async {
      final candidates = await resolveServerHost(
        'fr-host.fr',
        lookup: (host, type) async => type == InternetAddressType.IPv6
            ? [
                InternetAddress.tryParse('2001:db8::10')!,
                InternetAddress.tryParse('2001:db8::11')!,
                InternetAddress.tryParse('2001:db8::12')!,
              ]
            : [InternetAddress.tryParse('203.0.113.10')!],
      );
      expect(candidates.map((c) => c.host).toList(), [
        '203.0.113.10',
        '2001:db8::10',
        '2001:db8::11',
        '2001:db8::12',
      ]);
      expect(candidates.indexWhere((c) => c.family == 'IPv4'), 0);
    });

    test('socket attempts try the AAAA answer before extra A records', () async {
      final tried = <String>[];
      final service = VpsService(
        lookup: (host, type) async => type == InternetAddressType.IPv4
            ? [
                InternetAddress.tryParse('203.0.113.10')!,
                InternetAddress.tryParse('203.0.113.11')!,
                InternetAddress.tryParse('203.0.113.12')!,
              ]
            : [InternetAddress.tryParse('2001:db8::10')!],
        socketConnector: (host, port, timeout) async {
          tried.add(host);
          throw const SocketException('unreachable');
        },
      );
      await expectLater(
        service.open(const SshTarget('fr-host.fr', 22, 'root'), '', '', ''),
        throwsA(isA<SocketException>()),
      );
      // With 5 s per attempt and a 12 s socket budget, the second candidate is
      // always reachable; the old A-then-AAAA order hid it behind three A's.
      expect(tried, [
        '203.0.113.10',
        '2001:db8::10',
        '203.0.113.11',
        '203.0.113.12',
      ]);
      expect(tried.indexOf('2001:db8::10'), 1);
    });

    test(
      'an established socket is never replaced by another address',
      () async {
        var connects = 0;
        final service = VpsService(
          lookup: (host, type) async => type == InternetAddressType.IPv4
              ? [InternetAddress.tryParse('203.0.113.10')!]
              : [InternetAddress.tryParse('2001:db8::10')!],
          socketConnector: (host, port, timeout) async {
            connects++;
            return _ClosedSocket();
          },
        );
        await expectLater(
          service.open(const SshTarget('fr-host.fr', 22, 'root'), 'pw', '', ''),
          throwsA(anything),
        );
        // The pin check lives inside this one session; a failed session (including
        // a host-key mismatch) must abort instead of dialling the next address.
        expect(connects, 1);
      },
    );

    test('a changed key for the domain aborts before authentication', () async {
      final dir = await Directory.systemTemp.createTemp('xio-pin-');
      final file = File('${dir.path}/known.json');
      final first = 'SHA256:${'a' * 43}', changed = 'SHA256:${'b' * 43}';
      const target = SshTarget('fr-host.fr', 22, 'root');
      try {
        await SshHostKeyStore(file).verify(target, first);
        await expectLater(
          SshHostKeyStore(file).verify(target, changed),
          throwsFormatException,
        );
        expect(jsonDecode(await file.readAsString()), {
          '[fr-host.fr]:22': first,
        });
      } finally {
        await dir.delete(recursive: true);
      }
    });
  });

  group('managed install and profiles use the VPN domain, not the proxy', () {
    test(
      'install sends fr-host.fr while SSH stays on the proxy:9046',
      () async {
        final ssh = _Ssh()
          ..target = const SshTarget(
            'VPS-721137.ssh.vps1euro.fr',
            9046,
            'root',
          );
        final assets = _Assets();
        final service = _Service(ssh, assets);
        final store = _Store();
        try {
          final server = await service.install(store, publicHost: 'fr-host.fr');
          expect(service.requests.single['host'], 'fr-host.fr');
          expect(server.host, 'VPS-721137.ssh.vps1euro.fr');
          expect(server.port, 9046);
          expect(server.publicHost, 'fr-host.fr');
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

    test('AWG and both RIVET profiles use the VPN domain and SNI', () async {
      final server = ManagedServer(
        id: 'fixture-server',
        host: 'VPS-721137.ssh.vps1euro.fr',
        port: 9046,
        publicHost: 'fr-host.fr',
      );
      final service = _Service(_Ssh(), _Assets());
      final store = _Store();
      try {
        await service.createUser(store, server, 'Fixture');
        final configs = store.lastBundle!.configs;
        expect(configs['awg'], contains('Endpoint = fr-host.fr:51821'));
        for (final protocol in ['rivet-h3', 'rivet-s1']) {
          final profile = jsonDecode(configs[protocol]!) as Map;
          expect(profile['endpoint'], 'fr-host.fr:8443');
          expect(profile['serverName'], 'gateway.example');
          expect(profile['ip6'], 'fd79:1::2');
        }
        expect(
          configs.values.any(
            (value) => value.contains('VPS-721137.ssh.vps1euro.fr'),
          ),
          isFalse,
        );
      } finally {
        store.dispose();
      }
    });

    test('invalid public host performs no upload or init', () async {
      for (final bad in [
        'https://fr-host.fr',
        'fr-host.fr:8443',
        'fr-host.fr;id',
        'user@fr-host.fr',
      ]) {
        final ssh = _Ssh()
          ..target = const SshTarget(
            'VPS-721137.ssh.vps1euro.fr',
            9046,
            'root',
          );
        final assets = _Assets();
        final service = _Service(ssh, assets);
        final store = _Store();
        try {
          await expectLater(
            service.install(store, publicHost: bad),
            throwsFormatException,
          );
          expect(ssh.uploads, 0);
          expect(service.requests, isEmpty);
          expect(assets.loaded, isEmpty);
        } finally {
          store.dispose();
        }
      }
    });
  });

  group('profile parsers preserve a domain and reject ambiguous endpoints', () {
    test(
      'AWG accepts a domain endpoint and rejects schemes or extra parts',
      () {
        expect(
          WireGuardProfile.parse(_wgProfile()).endpoint,
          'fr-host.fr:51821',
        );
        for (final endpoint in [
          'https://fr-host.fr:51821',
          'fr-host.fr:51821/path',
          '[198.51.100.42]:51821',
          '2001:db8::42:51821',
          'fr-host.fr:51821:1',
        ]) {
          expect(
            () => WireGuardProfile.parse(_wgProfile(endpoint: endpoint)),
            throwsFormatException,
          );
        }
      },
    );

    test('RIVET keeps endpoint domain and independent TLS serverName', () {
      final profile = RivetProfile.parse(jsonEncode(_rivetFixture()));
      expect(profile.endpoint, 'fr-host.fr:8443');
      expect(profile.data['serverName'], 'gateway.example');
      expect(profile.encoded, contains('"endpoint":"fr-host.fr:8443"'));
      expect(profile.encoded, contains('"serverName":"gateway.example"'));

      for (final endpoint in [
        'https://fr-host.fr:8443',
        'fr-host.fr:8443/path',
        'fr-host.fr:8443?q=x',
        'u:p@fr-host.fr:8443',
        'fr-host.fr',
        '2001:db8::42:8443',
        '[198.51.100.42]:8443',
      ]) {
        expect(
          () =>
              RivetProfile.parse(jsonEncode(_rivetFixture(endpoint: endpoint))),
          throwsFormatException,
        );
      }
      for (final serverName in [
        'https://gateway.example',
        'gateway.example:443',
        'gateway..example',
        'gateway_example',
        '[2001:db8::42]',
      ]) {
        expect(
          () => RivetProfile.parse(
            jsonEncode(_rivetFixture(serverName: serverName)),
          ),
          throwsFormatException,
        );
      }
      expect(
        RivetProfile.parse(
          jsonEncode(_rivetFixture(serverName: '2001:db8::42')),
        ).data['serverName'],
        '2001:db8::42',
      );
    });

    test('extended outbound keeps address domain and TLS SNI identity', () {
      final uuid = 'a' * 32;
      final profile = ExtendedProfile.parse(
        'vless://$uuid@fr-host.fr:443'
        '?encryption=none&security=tls&sni=gateway.example&type=ws'
        '&path=%2Fws#Node',
      );
      expect(profile.protocol, 'xray');
      expect(profile.endpoint, 'fr-host.fr:443');
      final outbound = profile.data['outbound'] as Map;
      final settings = outbound['settings'] as Map;
      final vnext = (settings['vnext'] as List).single as Map;
      expect(vnext['address'], 'fr-host.fr');
      final stream = outbound['streamSettings'] as Map;
      final tls = stream['tlsSettings'] as Map;
      expect(tls['serverName'], 'gateway.example');

      final v6 = ExtendedProfile.parse(
        'vless://$uuid@[2001:db8::42]:443'
        '?encryption=none&security=tls&sni=gateway.example&type=ws'
        '&path=%2Fws',
      );
      expect(v6.endpoint, '[2001:db8::42]:443');
      expect(
        (((v6.data['outbound'] as Map)['settings'] as Map)['vnext'] as List)
            .single['address'],
        '2001:db8::42',
      );
      final trojan = ExtendedProfile.parse(
        'trojan://secret@fr-host.fr:443?security=tls&sni=gateway.example'
        '&type=tcp',
      );
      expect(trojan.endpoint, 'fr-host.fr:443');
      final trojanOutbound = trojan.data['outbound'] as Map;
      final trojanServer =
          ((trojanOutbound['settings'] as Map)['servers'] as List).single
              as Map;
      expect(trojanServer['address'], 'fr-host.fr');
      expect(
        ((trojanOutbound['streamSettings'] as Map)['tlsSettings']
            as Map)['serverName'],
        'gateway.example',
      );
      expect(
        () => ExtendedProfile.parse(
          'vless://$uuid@fr-host.fr:443'
          '?encryption=none&security=tls&sni=https%3A%2F%2Fbad.example'
          '&type=ws',
        ),
        throwsFormatException,
      );
    });

    test('subclient provisioning uses the same domain endpoint rules', () {
      final uid = 'b' * 32;
      final secret = base64Encode(List.filled(32, 5));
      final response = {
        'server': {
          'id': 'srv',
          'host': 'fr-host.fr',
          'publicKeys': {'awg': base64Encode(List.filled(32, 1))},
          'awg': {'Jc': 4, 'Jmin': 40, 'Jmax': 70},
          'rivet': {
            'serverName': 'gateway.example',
            'pin': base64Encode(List.filled(32, 2)),
            'gatewayId': base64Encode(List.filled(16, 3)),
            'ipv6': true,
          },
        },
        'user': {'id': uid, 'slot': 2},
      };
      final request = {
        'id': uid,
        'name': 'Child',
        'rivet': {
          'secret': secret,
          'entryToken': base64Encode(List.filled(32, 6)),
        },
      };
      final bundle = provisioningBundle(response, request, {
        'awg': base64Encode(List.filled(32, 7)),
      }, 'srv');
      expect(bundle.configs['awg'], contains('Endpoint = fr-host.fr:51821'));
      for (final protocol in ['rivet-h3', 'rivet-s1']) {
        final profile = jsonDecode(bundle.configs[protocol]!) as Map;
        expect(profile['endpoint'], 'fr-host.fr:8443');
        expect(profile['serverName'], 'gateway.example');
      }
      expect(
        bundle.configs.values.any(
          (value) => value.contains('VPS-721137.ssh.vps1euro.fr'),
        ),
        isFalse,
      );

      for (final host in ['https://fr-host.fr', 'fr-host.fr:8443']) {
        expect(
          () => provisioningBundle(
            {
              'server': {...(response['server'] as Map), 'host': host},
              'user': response['user'],
            },
            request,
            {'awg': base64Encode(List.filled(32, 7))},
            'srv',
          ),
          throwsFormatException,
        );
      }
    });
  });

  testWidgets('server wizard names domain, IPv4 and IPv6 together', (
    tester,
  ) async {
    final store = AppStore();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: ManagedAdminDialog(store: store)),
      ),
    );
    await tester.pumpAndSettle();
    expect(
      find.text('IPv4, IPv6 или домен; SSH-порт — в отдельном поле.'),
      findsOneWidget,
    );
    expect(find.text('vpn.example'), findsWidgets);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
