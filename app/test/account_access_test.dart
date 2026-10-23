import 'dart:convert';
import 'dart:async';
import 'dart:io';

import 'package:crypto/crypto.dart' as hashes;
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/account_access.dart';
import 'package:x1o/core.dart';
import 'package:x1o/subclients.dart';

import 'security_test.dart' show profile;

class ImportStore extends AppStore {
  UserBundle? imported;
  @override
  Future<ManagedUser> importBundle(UserBundle bundle) async {
    imported = bundle;
    final child = ManagedUser(
      id: bundle.userId,
      name: bundle.name,
      serverId: bundle.serverId,
      profileIds: {'awg': 'awg1'},
    );
    users.add(child);
    return child;
  }
}

class RecordedApi extends SubclientApi {
  final Future<Map<String, dynamic>> Function(Map<String, dynamic>) handler;
  RecordedApi(super.access, this.handler);
  @override
  Future<Map<String, dynamic>> call(Map<String, dynamic> body) => handler(body);
}

void main() {
  final uid = 'a' * 32;
  Map<String, String> access() => {
    'endpoint': 'https://example.org:9444/v1/subclients',
    'certificateSha256': 'a' * 64,
    'token': 'b' * 64,
    'userId': uid,
    'serverId': 'server',
  };
  test('only a bounded HTTPS capability can enter schema 3', () {
    final bundle = UserBundle('Account', uid, 'server', {
      'awg': profile(extra: 'Jc = 4'),
    }, clientAccess: access());
    final decoded = UserBundle.decode(bundle.encode());
    expect(decoded.clientAccess, access());
    expect(decoded.adminAccess, isNull);
    for (final mutation in [
      {...access(), 'endpoint': 'http://example.org:9444/v1/subclients'},
      {...access(), 'endpoint': 'https://user:pass@example.org/v1/subclients'},
      {
        ...access(),
        'endpoint': 'https://example.org/v1/subclients?token=secret',
      },
      {...access(), 'endpoint': 'https://example.org/admin'},
      {...access(), 'token': '-----BEGIN OPENSSH PRIVATE KEY-----'},
      {...access(), 'rootKey': 'never-allowed'},
      {...access(), 'password': 'never-allowed'},
      {...access(), 'serverId': 'foreign'},
    ]) {
      expect(
        () => AccountAccess.parse(mutation, uid, 'server'),
        throwsFormatException,
      );
    }
    final mixed = UserBundle(
      'Account',
      uid,
      'server',
      bundle.configs,
      clientAccess: access(),
      adminAccess: {'key': 'never-allowed'},
    );
    expect(() => UserBundle.decode(mixed.encode()), throwsFormatException);
  });
  test(
    'subclient material excludes parent API and administrator credentials',
    () {
      final conf = profile(extra: 'Jc = 4');
      final private = RegExp(r'PrivateKey = (.+)').firstMatch(conf)![1]!;
      final public = RegExp(r'PublicKey = (.+)').firstMatch(conf)![1]!;
      final bundle = provisioningBundle(
        {
          'user': {'id': uid, 'slot': 4},
          'server': {
            'id': 'server',
            'host': 'example.org',
            'publicKeys': {'awg': public},
            'awg': {'Jc': 4},
          },
          'configs': {},
        },
        {'id': uid, 'name': 'Child', 'rivet': {}},
        {'awg': private},
        'server',
      );
      final encoded = jsonDecode(
        utf8.decode(base64Url.decode(bundle.encode().substring(6))),
      );
      expect(encoded['schema'], 1);
      expect(encoded.keys.toSet(), {
        'schema',
        'name',
        'userId',
        'serverId',
        'configs',
      });
      final awg = WireGuardProfile.parse(bundle.configs['awg']!, amnezia: true);
      expect(awg.endpoint, 'example.org:51821');
      expect(bundle.configs['awg'], contains('DNS = 9.9.9.9\n'));
      expect(bundle.adminAccess, isNull);
      expect(bundle.clientAccess, isNull);
      expect(ClientImport.parse(bundle.encode()).bundle!.userId, uid);
    },
  );
  test('IPv6 DNS is issued only with an explicit gateway capability', () {
    expect(managedDnsServers({}), '9.9.9.9');
    expect(
      managedDnsServers({
        'rivet': {'ipv6': false},
      }),
      '9.9.9.9',
    );
    expect(
      managedDnsServers({
        'rivet': {'ipv6': 'true'},
      }),
      '9.9.9.9',
    );
    final conf = profile(extra: 'Jc = 4');
    final private = RegExp(r'PrivateKey = (.+)').firstMatch(conf)![1]!;
    final public = RegExp(r'PublicKey = (.+)').firstMatch(conf)![1]!;
    final secret = base64Encode(List.filled(32, 7));
    final bundle = provisioningBundle(
      {
        'user': {'id': uid, 'slot': 4},
        'server': {
          'id': 'server',
          'host': 'example.org',
          'publicKeys': {'awg': public},
          'awg': {'Jc': 4},
          'rivet': {
            'ipv6': true,
            'serverName': 'example.org',
            'pin': secret,
            'gatewayId': base64Encode(List.filled(16, 8)),
          },
        },
        'configs': {},
      },
      {
        'id': uid,
        'name': 'Child',
        'rivet': {
          'secret': secret,
          'entryToken': base64Encode(List.filled(32, 9)),
        },
      },
      {'awg': private},
      'server',
    );
    expect(bundle.configs['awg'], contains('DNS = 9.9.9.9, 2620:fe::fe\n'));
    expect(
      RivetProfile.parse(bundle.configs['rivet-s1']!).data['ip6'],
      'fd79:1::4',
    );
  });
  test('unknown response retains exact operation and local keys for explicit reconciliation', () async {
    var durable = <String, dynamic>{'access': access()};
    final attempts = <Map<String, dynamic>>[];
    final store = ImportStore();
    final parent = ManagedUser(
      id: uid,
      name: 'Parent',
      serverId: 'server',
      profileIds: {},
    );
    final client = Subclients(
      store,
      parent,
      readRecord: () async =>
          Map<String, dynamic>.from(jsonDecode(jsonEncode(durable))),
      writeRecord: (record) async {
        durable = Map<String, dynamic>.from(jsonDecode(jsonEncode(record)));
      },
      apiFactory: (cap) => RecordedApi(cap, (body) async {
        attempts.add(Map<String, dynamic>.from(jsonDecode(jsonEncode(body))));
        expect(durable['pending'], isNotNull);
        if (attempts.length == 1) throw TimeoutException('response lost');
        return {
          'user': {'id': body['id'], 'slot': 4},
          'server': {
            'id': 'server',
            'host': 'example.org',
            'publicKeys': body['publicKeys'],
            'awg': {'Jc': 4},
          },
          'configs': {},
        };
      }),
    );
    await expectLater(client.create('Child'), throwsA(isA<TimeoutException>()));
    expect(attempts, hasLength(1));
    final pending = jsonEncode(durable['pending']);
    expect(store.imported, isNull);
    final result = await client.create(
      'This new name must not start a new operation',
    );
    expect(attempts, hasLength(2));
    expect(attempts[0], attempts[1]);
    expect(result.name, 'Child');
    expect(result.userId, attempts[0]['id']);
    expect(result.adminAccess, isNull);
    expect(result.clientAccess, isNull);
    expect(
      result.configs['awg'],
      contains(jsonDecode(pending)['private']['awg']),
    );
    expect(durable.containsKey('pending'), false);
    expect(durable['access'], access());
    expect(store.imported, result);
  });

  for (final address in [
    InternetAddress.loopbackIPv4,
    InternetAddress.loopbackIPv6,
  ]) {
    test('TLS pin and redirect protection on ${address.type.name}', () async {
      if (address.type == InternetAddressType.IPv6) {
        try {
          final probe = await ServerSocket.bind(address, 0);
          await probe.close();
        } on SocketException {
          markTestSkipped(
            'IPv6 loopback unavailable; isolated IPv6 namespace required',
          );
          return;
        }
      }
      final temp = await Directory.systemTemp.createTemp('xio-api-tls-');
      addTearDown(() => temp.delete(recursive: true));
      final cert = '${temp.path}/cert.pem', key = '${temp.path}/key.pem';
      final result = await Process.run('openssl', [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-keyout',
        key,
        '-out',
        cert,
      ]);
      expect(result.exitCode, 0);
      final pem = await File(cert).readAsString();
      final der = base64Decode(
        pem.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''),
      );
      final context = SecurityContext()
        ..useCertificateChain(cert)
        ..usePrivateKey(key);
      final server = await HttpServer.bindSecure(address, 0, context);
      addTearDown(() => server.close(force: true));
      var received = 0;
      var redirect = false;
      server.listen((request) async {
        expect(request.contentLength, greaterThan(0));
        expect(request.headers.value('transfer-encoding'), isNull);
        expect(request.headers.contentType?.mimeType, 'application/json');
        received++;
        expect(request.headers.value('authorization'), 'Bearer ${'b' * 64}');
        if (redirect) {
          request.response.statusCode = 302;
          request.response.headers.set(
            'location',
            'https://foreign.invalid/steal',
          );
        } else {
          request.response.headers.contentType = ContentType.json;
          request.response.write('{"ok":true,"value":7}');
        }
        await request.response.close();
      });
      AccountAccess capability(String pin) => AccountAccess(
        Uri.parse(
          'https://${address.type == InternetAddressType.IPv6 ? '[::1]' : '127.0.0.1'}:${server.port}/v1/subclients',
        ),
        pin,
        'b' * 64,
        uid,
        'server',
      );
      await expectLater(
        SubclientApi(capability('f' * 64)).call({'action': 'status'}),
        throwsA(isA<HandshakeException>()),
      );
      expect(received, 0);
      final api = SubclientApi(
        capability(hashes.sha256.convert(der).toString()),
      );
      expect((await api.call({'action': 'status'}))['value'], 7);
      redirect = true;
      await expectLater(api.call({'action': 'status'}), throwsStateError);
      expect(received, 2);
    });
  }
}
