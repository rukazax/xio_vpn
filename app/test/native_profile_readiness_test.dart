import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/native_profile_readiness.dart';
import 'package:xio/subclients.dart';

final _key = base64Encode(List.filled(32, 7));
Map<String, dynamic> _metadata({bool ipv4 = true, bool ipv6 = true}) {
  final now = DateTime.now().toUtc();
  return {
    'schema': 1,
    'enabled': true,
    'connectorId': 'fixture',
    'revision': 1,
    'observedAt': now.subtract(const Duration(seconds: 1)).toIso8601String(),
    'expiresAt': now.add(const Duration(seconds: 30)).toIso8601String(),
    'awg': <String, dynamic>{'ipv4': ipv4, 'ipv6': ipv6},
    'rivet': <String, dynamic>{'ipv4': ipv4, 'ipv6': ipv6},
    'requiredFamilies': {
      'awg': <String, dynamic>{'ipv4': ipv4, 'ipv6': ipv6},
      'rivet': <String, dynamic>{'ipv4': ipv4, 'ipv6': ipv6},
    },
  };
}

Map<String, dynamic> _server([Map<String, dynamic>? metadata]) => {
  'id': 'server', 'host': 'gateway.example',
  'publicKeys': {'awg': _key}, 'awg': {'Jc': 4},
  // Deliberately conflicting legacy flag: explicit metadata must win.
  'rivet': {
    'ipv6': true,
    'serverName': 'gateway.example',
    'pin': _key,
    'gatewayId': base64Encode(List.filled(16, 8)),
  },
  'nativeProfileReadiness': ?metadata,
};

Map<String, dynamic> _request(String id) => {
  'id': id,
  'name': 'Fixture',
  'rivet': {'secret': _key, 'entryToken': base64Encode(List.filled(32, 9))},
};

String _proxy() {
  final key = base64Url.encode(List.generate(32, (i) => i)).replaceAll('=', '');
  return ExtendedProfile.parse(
    'vless://b3b2eb49-e41f-41df-9761-0956785a236b@example.org:4443?security=reality&sni=example.com&pbk=$key&sid=abcdef12&flow=xtls-rprx-vision',
  ).encoded;
}

UserBundle _bundle(
  Map<String, dynamic>? metadata, {
  Map<String, String>? configs,
}) => provisioningBundle(
  {
    'user': {'id': 'b' * 32, 'slot': 4},
    'server': _server(metadata),
    'configs': configs ?? {},
  },
  _request('b' * 32),
  {'awg': _key},
  'server',
);

class _Store extends AppStore {
  UserBundle? imported;
  @override
  Future<void> save() async {}
  @override
  Future<ManagedUser> importBundle(UserBundle bundle) async {
    imported = bundle;
    return ManagedUser(
      id: bundle.userId,
      name: bundle.name,
      serverId: bundle.serverId,
      profileIds: {},
    );
  }
}

class _Owner extends ManagedService {
  final Map<String, dynamic> metadata;
  final calls = <Map<String, dynamic>>[];
  _Owner(this.metadata) : super(VpsService());
  @override
  Future<void> refreshMtprotoLink(AppStore store) async {}
  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    calls.add(request);
    if (request['action'] == 'revoke') return {'revoked': request['id']};
    return {
      'user': {'id': request['id'], 'slot': 4},
      'server': _server(metadata),
      'configs': {'xray': _proxy()},
    };
  }
}

class _Api extends SubclientApi {
  final Future<Map<String, dynamic>> Function(Map<String, dynamic>) handler;
  _Api(super.access, this.handler);
  @override
  Future<Map<String, dynamic>> call(Map<String, dynamic> request) =>
      handler(request);
}

void main() {
  test('absent metadata preserves native legacy behavior', () {
    expect(NativeProfileReadiness.forProtocol({}, 'awg').ipv6, isTrue);
    expect(NativeProfileReadiness.forProtocol({}, 'rivet').ipv6, isFalse);
    final bundle = _bundle(null, configs: {'xray': _proxy()});
    expect(
      bundle.configs.keys,
      containsAll(['awg', 'rivet-h3', 'rivet-s1', 'xray']),
    );
  });

  test(
    'policy-only IPv6 readiness issues IPv6 despite no host default field',
    () {
      final bundle = _bundle(_metadata());
      expect(jsonDecode(bundle.configs['rivet-s1']!)['ip6'], 'fd79:1::4');
      expect(bundle.configs['awg'], contains('fd78:1::4/128'));
    },
  );

  test('explicit IPv4-only overrides old IPv6 flag and resolver', () {
    final metadata = _metadata(ipv6: false);
    final bundle = _bundle(metadata);
    expect(
      bundle.configs['awg'],
      contains('Address = 10.78.0.4/32, fd78:1::4/128\n'),
    );
    expect(bundle.configs['awg'], contains('AllowedIPs = 0.0.0.0/0, ::/0\n'));
    expect(bundle.configs['awg'], contains('DNS = 9.9.9.9\n'));
    expect(jsonDecode(bundle.configs['rivet-h3']!), isNot(contains('ip6')));
    expect(
      () => managedDnsServers(_server(metadata), ['2620:fe::fe']),
      throwsStateError,
    );
    expect(managedDnsServers(_server(metadata), ['1.1.1.1']), '1.1.1.1');
  });

  test(
    'explicit IPv6-only requires no IPv4 exit and retains RIVET identity',
    () {
      final metadata = _metadata(ipv4: false);
      final bundle = _bundle(metadata);
      expect(
        bundle.configs['awg'],
        contains('Address = 10.78.0.4/32, fd78:1::4/128\n'),
      );
      expect(bundle.configs['awg'], contains('AllowedIPs = 0.0.0.0/0, ::/0\n'));
      expect(bundle.configs['awg'], contains('DNS = 2620:fe::fe\n'));
      expect(jsonDecode(bundle.configs['rivet-s1']!)['ip'], '10.79.0.4');
      expect(
        () => managedDnsServers(_server(metadata), ['9.9.9.9']),
        throwsStateError,
      );
    },
  );

  test('unselected transport and unsupported proxy configs are omitted', () {
    final metadata = _metadata();
    (metadata['requiredFamilies'] as Map)['awg'] = {
      'ipv4': false,
      'ipv6': false,
    };
    final bundle = _bundle(
      metadata,
      configs: {'xray': _proxy(), 'cloak': 'must-not-export'},
    );
    expect(bundle.configs.keys.toSet(), {'rivet-s1', 'rivet-h3'});
  });

  test(
    'requested dual-family is never downgraded or recovered via legacy true',
    () {
      for (final protocol in ['awg', 'rivet']) {
        final metadata = _metadata();
        (metadata[protocol] as Map)['ipv6'] = false;
        expect(() => _bundle(metadata), throwsStateError);
      }
    },
  );

  test('selected RIVET metadata cannot silently disappear', () {
    final server = _server(_metadata())..remove('rivet');
    expect(
      () => provisioningBundle(
        {
          'user': {'id': 'b' * 32, 'slot': 4},
          'server': server,
          'configs': {},
        },
        _request('b' * 32),
        {'awg': _key},
        'server',
      ),
      throwsFormatException,
    );
  });

  test('stale malformed missing and non-boolean metadata fail closed', () {
    for (final mutate in <void Function(Map<String, dynamic>)>[
      (m) => m['expiresAt'] = DateTime.now()
          .toUtc()
          .subtract(const Duration(minutes: 1))
          .toIso8601String(),
      (m) => m['observedAt'] = DateTime.now()
          .toUtc()
          .add(const Duration(minutes: 1))
          .toIso8601String(),
      (m) => m['observedAt'] = '2026-02-31T12:00:00Z',
      (m) => m['expiresAt'] = 123,
      (m) => m.remove('requiredFamilies'),
      (m) => m.remove('connectorId'),
      (m) => m['revision'] = true,
      (m) => (m['awg'] as Map)['ipv6'] = 'true',
    ]) {
      final metadata = _metadata();
      mutate(metadata);
      expect(
        () => _bundle(metadata),
        throwsA(anyOf(isA<StateError>(), isA<FormatException>())),
      );
    }
    expect(
      () => NativeProfileReadiness.forProtocol({
        'nativeProfileReadiness': null,
      }, 'awg'),
      throwsFormatException,
    );
  });

  test('readiness enforces 60-second age and TTL with five-second skew', () {
    final now = DateTime.utc(2026, 11, 5, 12);
    for (final (observedMs, expiresMs, ready) in [
      (-86400000, 31536000000, false),
      (-1000, 60000, false),
      (-1000, 59000, true),
      (-60000, 0, false),
      (-60001, 1, false),
      (-59999, 1, true),
      (0, 60000, true),
      (0, 60001, false),
      (5000, 65000, true),
      (5001, 65001, false),
      (-1000, 0, false),
      (0, 0, false),
      (1000, 0, false),
    ]) {
      final metadata = _metadata()
        ..['observedAt'] = now
            .add(Duration(milliseconds: observedMs))
            .toIso8601String()
        ..['expiresAt'] = now
            .add(Duration(milliseconds: expiresMs))
            .toIso8601String();
      for (final protocol in ['awg', 'rivet']) {
        if (ready) {
          expect(
            NativeProfileReadiness.forProtocol(
              _server(metadata),
              protocol,
              now: now,
            ).selected,
            isTrue,
          );
        } else {
          expect(
            () => NativeProfileReadiness.forProtocol(
              _server(metadata),
              protocol,
              now: now,
            ),
            throwsStateError,
          );
        }
      }
    }
  });

  test(
    'oversized or old evidence fails issuance, not proxy/direct fallback',
    () {
      for (final old in [false, true]) {
        final now = DateTime.now().toUtc();
        final metadata = _metadata()
          ..['observedAt'] = now
              .subtract(Duration(seconds: old ? 86400 : 1))
              .toIso8601String()
          ..['expiresAt'] = now
              .add(const Duration(days: 365))
              .toIso8601String();
        expect(
          () => _bundle(metadata, configs: {'xray': _proxy()}),
          throwsStateError,
        );
      }
    },
  );

  test('UTC and revision compatibility remain strict and compatible', () {
    final now = DateTime.utc(2026, 11, 5, 12);
    for (final revision in [0, 1, 'opaque-revision']) {
      final metadata = _metadata()
        ..['revision'] = revision
        ..['observedAt'] = '2026-11-05T11:59:59+00:00'
        ..['expiresAt'] = '2026-11-05T12:00:30Z';
      expect(
        NativeProfileReadiness.forProtocol(
          _server(metadata),
          'awg',
          now: now,
        ).selected,
        isTrue,
      );
    }
    for (final invalid in [
      true,
      123,
      null,
      '2026-11-05T11:59:59',
      '2026-11-05T12:59:59+01:00',
      '2026-02-31T11:59:59Z',
    ]) {
      final metadata = _metadata()..['observedAt'] = invalid;
      expect(
        () => NativeProfileReadiness.forProtocol(
          _server(metadata),
          'awg',
          now: now,
        ),
        throwsFormatException,
      );
    }
  });

  test(
    'owner issuance uses policy-only readiness and excludes proxy bypass',
    () async {
      final owner = _Owner(_metadata());
      final store = _Store();
      addTearDown(store.dispose);
      await owner.createUser(
        store,
        ManagedServer(id: 'server', host: 'gateway.example'),
        'Fixture',
      );
      expect(store.imported!.configs.keys.toSet(), {
        'awg',
        'rivet-s1',
        'rivet-h3',
      });
      expect(
        jsonDecode(store.imported!.configs['rivet-h3']!)['ip6'],
        'fd79:1::4',
      );
    },
  );

  test(
    'owner issuance failure compensates newly registered identity',
    () async {
      final metadata = _metadata();
      (metadata['rivet'] as Map)['ipv6'] = false;
      final owner = _Owner(metadata);
      final store = _Store();
      addTearDown(store.dispose);
      await expectLater(
        owner.createUser(
          store,
          ManagedServer(id: 'server', host: 'gateway.example'),
          'Fixture',
        ),
        throwsStateError,
      );
      expect(owner.calls.map((c) => c['action']).toList(), ['add', 'revoke']);
      expect(owner.calls.last['id'], owner.calls.first['id']);
      expect(store.imported, isNull);
    },
  );

  for (final unknownRevoke in [false, true]) {
    test(
      'delegated readiness rejection compensates; unknown=$unknownRevoke retains intent',
      () async {
        final access = {
          'endpoint': 'https://example.org:9444/v1/subclients',
          'certificateSha256': 'a' * 64,
          'token': 'b' * 64,
          'userId': 'a' * 32,
          'serverId': 'server',
        };
        var durable = <String, dynamic>{'access': access};
        final calls = <Map<String, dynamic>>[];
        final store = _Store();
        addTearDown(store.dispose);
        final parent = ManagedUser(
          id: 'a' * 32,
          name: 'Parent',
          serverId: 'server',
          profileIds: {},
        );
        final client = Subclients(
          store,
          parent,
          readRecord: () async =>
              Map<String, dynamic>.from(jsonDecode(jsonEncode(durable))),
          writeRecord: (value) async {
            durable = Map<String, dynamic>.from(jsonDecode(jsonEncode(value)));
          },
          apiFactory: (access) => _Api(access, (request) async {
            calls.add(request);
            if (request['action'] == 'revoke') {
              if (unknownRevoke) throw TimeoutException('unknown revoke');
              return {'revoked': request['id']};
            }
            final metadata = _metadata();
            (metadata['awg'] as Map)['ipv6'] = false;
            return {
              'user': {'id': request['id'], 'slot': 4},
              'server': _server(metadata),
              'configs': {},
            };
          }),
        );
        await expectLater(
          client.create('Child'),
          unknownRevoke ? throwsA(isA<TimeoutException>()) : throwsStateError,
        );
        expect(calls.map((c) => c['action']).toList(), ['add', 'revoke']);
        expect(calls.last['id'], calls.first['id']);
        expect(durable.containsKey('pending'), unknownRevoke);
        expect(store.imported, isNull);
      },
    );
  }
}
