import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/account_access.dart';
import 'package:xio/app_settings.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/subclients.dart';

class _Owner extends ManagedService {
  _Owner() : super(VpsService());
  int calls = 0;
  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    calls++;
    throw StateError('Unexpected remote effect');
  }
}

class _Api extends SubclientApi {
  _Api(super.access);
  int calls = 0;
  @override
  Future<Map<String, dynamic>> call(Map<String, dynamic> body) async {
    calls++;
    throw StateError('Unexpected remote effect');
  }
}

class _MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

Map<String, dynamic> _response(Map<String, dynamic> request) => {
  'user': {'id': request['id'], 'slot': 4},
  'server': {
    'id': 'server',
    'host': 'example.invalid',
    'publicKeys': request['publicKeys'],
    'awg': {'Jc': 4},
  },
  'configs': <String, String>{},
};

class _ImportStore extends _MemoryStore {
  UserBundle? imported;
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

class _IssuanceOwner extends ManagedService {
  _IssuanceOwner(this.store) : super(VpsService());
  final AppStore store;
  @override
  Future<void> refreshMtprotoLink(AppStore store) async {}
  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    store.dnsServers = ['changed.example.org'];
    return _response(request);
  }
}

class _ReplyApi extends SubclientApi {
  _ReplyApi(super.access, this.store);
  final AppStore store;
  @override
  Future<Map<String, dynamic>> call(Map<String, dynamic> request) async {
    store.dnsServers = ['changed.example.org'];
    return _response(request);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('DNS setting and AWG writer reject hostname and mixed selections', () {
    for (final values in [
      ['dns.example.org'],
      ['1.1.1.1', 'DNS.Example.ORG'],
      ['https://dns.example.org/dns-query'],
      ['tls://dns.example.org'],
      ['fe80::1%eth0'],
      ['[2620:fe::fe]:53'],
    ]) {
      expect(() => validateDnsServers(values), throwsFormatException);
      expect(() => managedDnsServers({}, values), throwsFormatException);
      expect(
        () => managedDnsServers({
          'rivet': {'ipv6': true},
        }, values),
        throwsFormatException,
      );
    }
  });

  test('DNS setting matches native unicast address policy without lookup', () {
    for (final value in [
      '1.1.1.1',
      '192.0.2.53',
      '10.0.0.53',
      '172.16.0.53',
      '192.168.1.53',
      '2606:4700:4700::1111',
      '2001:db8::53',
      'fd00::53',
    ]) {
      expect(validateDnsServer(value), value);
    }
    for (final value in [
      '0.0.0.0',
      '::',
      '127.0.0.1',
      '::1',
      '169.254.1.53',
      'fe80::53',
      '224.0.0.53',
      'ff02::53',
      '255.255.255.255',
      '::ffff:192.0.2.53',
      '::ffff:c000:235',
      '01.1.1.1',
    ]) {
      expect(
        () => validateDnsServer(value),
        throwsFormatException,
        reason: value,
      );
      expect(
        () => managedDnsServers({}, ['1.1.1.1', value]),
        throwsFormatException,
        reason: value,
      );
    }
  });

  test('DNS rejects every second-octet boundary in IPv6 fe80::/10', () {
    for (var octet = 0x80; octet <= 0xbf; octet++) {
      final value = 'fe${octet.toRadixString(16)}::53';
      expect(
        () => validateDnsServer(value),
        throwsFormatException,
        reason: value,
      );
      expect(
        () => managedDnsServers({}, ['192.0.2.53', value]),
        throwsFormatException,
        reason: value,
      );
    }
  });

  test(
    'DNS accepts non-link-local fe00::/8 including site-local fec0::/10',
    () {
      for (var octet = 0; octet <= 0xff; octet++) {
        if (octet >= 0x80 && octet <= 0xbf) continue;
        final value = 'fe${octet.toRadixString(16).padLeft(2, '0')}::53';
        expect(validateDnsServer(value), value, reason: value);
      }
      expect(validateDnsServer('169.253.1.53'), '169.253.1.53');
      expect(validateDnsServer('169.255.1.53'), '169.255.1.53');
      expect(() => validateDnsServer('169.254.1.53'), throwsFormatException);
    },
  );

  for (final empty in <List<String>?>[
    null,
    [],
    ['', '  '],
  ]) {
    test('missing/empty legacy DNS retains default: $empty', () async {
      final directory = await Directory.systemTemp.createTemp(
        'xio-dns-default-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final file = File('${directory.path}/profiles.json');
      await file.writeAsString(
        jsonEncode({'schema': 2, 'profiles': [], 'dnsServers': ?empty}),
      );
      final store = AppStore()..directory = directory;
      addTearDown(store.dispose);
      await store.load();
      expect(store.dnsServers, defaultDnsServers);
      await store.save();
      expect(
        jsonDecode(await file.readAsString())['dnsServers'],
        defaultDnsServers,
      );
    });
  }

  for (final legacy in ['DNS.Example.ORG', '127.0.0.1', '::ffff:192.0.2.53']) {
    test(
      'legacy DNS $legacy survives actual load-save and literal repair',
      () async {
        final directory = await Directory.systemTemp.createTemp(
          'xio-dns-legacy-',
        );
        addTearDown(() => directory.delete(recursive: true));
        final file = File('${directory.path}/profiles.json');
        final original = ['1.1.1.1', legacy];
        await file.writeAsString(
          jsonEncode({
            'schema': 2,
            'profiles': [],
            'dnsServers': original,
            'siteCheckEnabled': true,
          }),
        );
        final store = AppStore()..directory = directory;
        addTearDown(store.dispose);
        await store.load();
        expect(store.dnsServers, original);
        expect(store.siteCheckEnabled, true);
        expect(
          () => managedDnsServers({}, store.dnsServers),
          throwsFormatException,
        );
        await store.save();
        expect(jsonDecode(await file.readAsString())['dnsServers'], original);
        await expectLater(
          store.setDnsServers(['other.example.org']),
          throwsFormatException,
        );
        expect(store.dnsServers, original);
        await store.setDnsServers(['192.0.2.53', '2001:db8::53']);
        final reloaded = AppStore()..directory = directory;
        addTearDown(reloaded.dispose);
        await reloaded.load();
        expect(reloaded.dnsServers, ['192.0.2.53', '2001:db8::53']);
        await reloaded
            .save(); // A bad DNS setting must not poison storage health.
        expect(
          managedDnsServers({
            'rivet': {'ipv6': true},
          }, reloaded.dnsServers),
          '192.0.2.53, 2001:db8::53',
        );
      },
    );
  }

  for (final bad in [
    'dns.example.org',
    '127.0.0.1',
    '::ffff:192.0.2.53',
    for (var octet = 0x80; octet <= 0xbf; octet++)
      'fe${octet.toRadixString(16)}::1',
  ]) {
    test('invalid owner DNS $bad has zero remote effects', () async {
      final store = AppStore()..dnsServers = ['1.1.1.1', bad];
      addTearDown(store.dispose);
      final owner = _Owner();
      final server = ManagedServer(
        id: 'server',
        host: 'example.invalid',
        name: 'Fixture',
        country: '',
      );
      await expectLater(
        owner.createUser(store, server, 'Child'),
        throwsFormatException,
      );
      expect(owner.calls, 0);
      expect(store.users, isEmpty);
    });

    for (final pending in [false, true]) {
      test(
        'invalid delegated DNS $bad has zero effects with pending=$pending',
        () async {
          final store = AppStore()..dnsServers = ['1.1.1.1', bad];
          addTearDown(store.dispose);
          final access = AccountAccess(
            Uri.parse('https://example.invalid/v1/subclients'),
            'a' * 64,
            'b' * 64,
            'user',
            'server',
          );
          final record = <String, dynamic>{
            'access': access.toJson(),
            if (pending)
              'pending': {
                'request': {'id': 'keep-id'},
                'private': {'awg': 'keep-synthetic-key'},
              },
          };
          final original = jsonEncode(record);
          final api = _Api(access);
          var writes = 0;
          final user = ManagedUser(
            id: 'user',
            name: 'Parent',
            serverId: 'server',
            profileIds: {},
          );
          final client = Subclients(
            store,
            user,
            readRecord: () async => record,
            writeRecord: (_) async {
              writes++;
            },
            apiFactory: (_) => api,
          );
          await expectLater(client.create('Child'), throwsFormatException);
          expect(api.calls, 0);
          expect(writes, 0);
          expect(jsonEncode(record), original);
        },
      );
    }
  }

  for (final resolver in ['192.0.2.53', 'fec0::53']) {
    test(
      'owner and delegated issuance use pre-effect DNS snapshot $resolver',
      () async {
        final ownerStore = _ImportStore()..dnsServers = [resolver];
        addTearDown(ownerStore.dispose);
        await _IssuanceOwner(ownerStore).createUser(
          ownerStore,
          ManagedServer(id: 'server', host: 'example.invalid'),
          'Child',
        );
        expect(
          ownerStore.imported!.configs['awg'],
          contains('DNS = $resolver\n'),
        );
        expect(ownerStore.dnsServers, ['changed.example.org']);
        final store = _ImportStore()..dnsServers = [resolver];
        addTearDown(store.dispose);
        final access = AccountAccess(
          Uri.parse('https://example.invalid/v1/subclients'),
          'a' * 64,
          'b' * 64,
          'user',
          'server',
        );
        var record = <String, dynamic>{'access': access.toJson()};
        final client = Subclients(
          store,
          ManagedUser(
            id: 'user',
            name: 'Parent',
            serverId: 'server',
            profileIds: {},
          ),
          readRecord: () async => record,
          writeRecord: (value) async {
            record = value;
          },
          apiFactory: (_) => _ReplyApi(access, store),
        );
        final bundle = await client.create('Child');
        expect(bundle.configs['awg'], contains('DNS = $resolver\n'));
        expect(store.dnsServers, ['changed.example.org']);
        expect(record.containsKey('pending'), false);
      },
    );
  }

  testWidgets(
    'legacy DNS remains visible with unsupported error and can be repaired',
    (tester) async {
      final store = _MemoryStore()..dnsServers = ['dns.example.org'];
      addTearDown(store.dispose);
      await tester.pumpWidget(MaterialApp(home: DnsSettingsPage(store: store)));
      await tester.pumpAndSettle();
      expect(find.text('dns.example.org'), findsOneWidget);
      expect(
        find.text(
          'DNS: укажите IPv4 или IPv6 — без домена, порта, схемы и пути',
        ),
        findsOneWidget,
      );
      await tester.enterText(find.byType(TextField).first, '1.1.1.1');
      await tester.ensureVisible(find.text('Сохранить'));
      await tester.tap(find.text('Сохранить'));
      await tester.pumpAndSettle();
      expect(store.dnsServers, ['1.1.1.1']);
    },
  );
}
