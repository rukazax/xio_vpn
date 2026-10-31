import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as hashes;
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/server_address.dart';

class _FakeAssets extends CachingAssetBundle {
  _FakeAssets(this.files);
  final Map<String, List<int>> files;
  final List<String> loaded = [];

  @override
  Future<ByteData> load(String key) async {
    loaded.add(key);
    final data = files[key];
    if (data == null) throw StateError('Missing asset: $key');
    return ByteData.sublistView(Uint8List.fromList(data));
  }

  @override
  Future<String> loadString(String key, {bool cache = true}) async {
    if (!loaded.contains(key)) loaded.add(key);
    final data = files[key];
    if (data == null) throw StateError('Missing asset: $key');
    return utf8.decode(data);
  }
}

class _RecordingSsh extends VpsService {
  _RecordingSsh({String host = 'ssh-proxy.example', int port = 9046}) {
    target = SshTarget(host, port, 'root');
    verifiedFingerprint = 'SHA256:${'a' * 43}';
  }

  final uploads = <({String command, List<int> input, Duration timeout})>[];

  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    uploads.add((
      command: command,
      input: List<int>.from(input),
      timeout: timeout,
    ));
    return [];
  }
}

class _InstallService extends ManagedService {
  _InstallService(
    super.ssh,
    AssetBundle assets, {
    this.inspectResult,
    this.initServer,
    this.addResponse,
  }) : super(assets: assets);

  final Map<String, dynamic>? inspectResult;
  final Map<String, dynamic>? initServer;
  final Map<String, dynamic>? addResponse;
  final requests = <Map<String, dynamic>>[];

  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (request['action'] == 'inspect') {
      final result = inspectResult;
      if (result == null) throw StateError('no owned installation');
      return result;
    }
    requests.add(request);
    if (request['action'] == 'init') {
      return {
        'server':
            initServer ??
            {'id': 'fixture-server', 'host': request['host'], 'country': 'DE'},
      };
    }
    return addResponse ??
        {
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

class _Store extends AppStore {
  UserBundle? lastBundle;

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

const _bootstrap = '#!/bin/sh\nset -eu\n# fixture bootstrap\n';
final _archive = List<int>.generate(257, (i) => i & 255);

String _manifest({List<int>? archive, int recipe = 24}) => jsonEncode({
  'schema': 1,
  'recipeVersion': recipe,
  'sha256': hashes.sha256.convert(archive ?? _archive).toString(),
  'bootstrapSha256': hashes.sha256.convert(utf8.encode(_bootstrap)).toString(),
});

_FakeAssets _assets({List<int>? archive, int recipe = 24}) => _FakeAssets({
  'assets/xio-server-release.json': utf8.encode(
    _manifest(archive: archive, recipe: recipe),
  ),
  'assets/xio-server.tar.gz': archive ?? _archive,
  'assets/xio-bootstrap.sh': utf8.encode(_bootstrap),
});

class _IdleSocket implements SSHSocket {
  final _in = StreamController<Uint8List>();
  final _out = StreamController<List<int>>();
  bool _closed = false;

  @override
  Stream<Uint8List> get stream => _in.stream;
  @override
  StreamSink<List<int>> get sink => _out.sink;
  @override
  Future<void> get done => _out.done;
  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    // The fake client never completes an SSH handshake; do not wait for the
    // transport to drain a stream it does not own.
    unawaited(_in.close());
    unawaited(_out.close());
  }

  @override
  void destroy() => unawaited(close());
  @override
  Future<void> flush() async {}
}

class _FakeSshClient extends SSHClient {
  _FakeSshClient({
    required SSHSocket socket,
    required this.passwordRequest,
    required this.verifyHostKey,
    required this.scenario,
  }) : super(socket, username: 'root');

  final String Function() passwordRequest;
  final SSHHostkeyVerifyHandler verifyHostKey;
  final Future<void> Function(_FakeSshClient) scenario;
  int passwordRequests = 0;
  String? passwordValue;

  @override
  Future<void> get authenticated => scenario(this);

  @override
  Future<void> close() => socket.close();

  Future<void> acceptAndRequestPassword(String fingerprint) async {
    final accepted = await verifyHostKey(
      'ssh-ed25519',
      Uint8List.fromList(utf8.encode(fingerprint)),
    );
    if (!accepted) throw StateError('host key rejected');
    passwordRequests++;
    passwordValue = passwordRequest();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  late _Store store;
  const pin = 'SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const changedPin = 'SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-install-domain-');
    store = _Store()..directory = directory;
  });
  tearDown(() async {
    store.dispose();
    await directory.delete(recursive: true);
  });

  test('server release manifest binds the exact archive bytes', () {
    final release = ServerRelease.parse(_manifest());
    expect(release.recipeVersion, 24);
    expect(() => release.verifyArchive(_archive), returnsNormally);
    expect(() => release.verifyArchive([..._archive, 0]), throwsStateError);
    for (final bad in [
      '{}',
      '{"schema":2,"recipeVersion":24,"sha256":"${'0' * 64}"}',
      '{"schema":1,"recipeVersion":0,"sha256":"${'0' * 64}"}',
      '{"schema":1,"recipeVersion":24,"sha256":"short"}',
    ]) {
      expect(() => ServerRelease.parse(bad), throwsFormatException);
    }
  });

  test(
    'install uploads the manifest-matched archive and bootstrap verbatim',
    () async {
      final assets = _assets();
      final ssh = _RecordingSsh();
      final service = _InstallService(ssh, assets);
      final server = await service.install(store, publicHost: 'fr-host.fr');

      expect(service.requests, hasLength(1));
      final init = service.requests.single;
      expect(init.keys.toSet(), {'action', 'host', 'restrictedNetwork'});
      expect(init['action'], 'init');
      expect(init['host'], 'fr-host.fr');
      expect(init['restrictedNetwork'], isTrue);

      expect(ssh.uploads, hasLength(1));
      final upload = ssh.uploads.single;
      // The manifest digest is exported ahead of the verbatim script body, so the
      // packager's bootstrap hash keeps applying while the archive is pinned.
      expect(
        upload.command,
        "export XIO_EXPECTED_ARCHIVE_SHA256='${hashes.sha256.convert(_archive)}'\n"
        '$_bootstrap',
      );
      expect(upload.input, _archive);
      expect(upload.timeout, const Duration(minutes: 30));
      expect(assets.loaded, [
        'assets/xio-server-release.json',
        'assets/xio-server.tar.gz',
        'assets/xio-bootstrap.sh',
      ]);

      expect(server.host, 'ssh-proxy.example');
      expect(server.port, 9046);
      expect(server.username, 'root');
      expect(server.publicHost, 'fr-host.fr');
      expect(server.hostKey, pin);
      expect(store.servers.single, same(server));
    },
  );

  test('a stale or corrupted archive is refused before any upload', () async {
    final assets = _FakeAssets({
      'assets/xio-server-release.json': utf8.encode(
        jsonEncode({'schema': 1, 'recipeVersion': 24, 'sha256': '0' * 64}),
      ),
      'assets/xio-server.tar.gz': _archive,
      'assets/xio-bootstrap.sh': utf8.encode(_bootstrap),
    });
    final ssh = _RecordingSsh();
    final service = _InstallService(ssh, assets);
    await expectLater(
      service.install(store, publicHost: 'fr-host.fr'),
      throwsStateError,
    );
    expect(ssh.uploads, isEmpty);
    expect(service.requests, isEmpty);
    expect(store.servers, isEmpty);
  });

  for (final host in [
    'fr-host.fr',
    'xn--bcher-kva.example',
    'XN--BCHER-KVA.example',
    '198.51.100.42',
    '2001:db8::42',
    '[2001:db8::42]',
  ]) {
    test(
      'install and generated profiles use VPN host $host, not SSH proxy',
      () async {
        final normalized = normalizeServerHost(host);
        final assets = _assets();
        final ssh = _RecordingSsh();
        final service = _InstallService(ssh, assets);
        final local = _Store()..directory = directory;
        try {
          final server = await service.install(local, publicHost: host);
          expect(service.requests.single['host'], normalized);
          expect(server.host, 'ssh-proxy.example');
          expect(server.port, 9046);
          expect(server.publicHost, normalized);

          await service.createUser(local, server, 'Fixture');
          final bundle = local.lastBundle!;
          final awg = WireGuardProfile.parse(
            bundle.configs['awg']!,
            amnezia: true,
          );
          expect(awg.endpoint, serverEndpoint(normalized, 51821));
          for (final protocol in ['rivet-h3', 'rivet-s1']) {
            final profile = RivetProfile.parse(bundle.configs[protocol]!);
            expect(profile.endpoint, serverEndpoint(normalized, 8443));
            expect(profile.data['serverName'], 'gateway.example');
          }
          expect(
            bundle.configs.values.any(
              (value) => value.contains('ssh-proxy.example'),
            ),
            isFalse,
          );
        } finally {
          local.dispose();
        }
      },
    );
  }

  test(
    'malformed hosts perform no inspect, upload, init or store write',
    () async {
      final overlong = '${'a' * 64}.${'b' * 64}.${'c' * 64}.${'d' * 61}';
      for (final bad in [
        'https://fr-host.fr',
        'fr-host.fr:9046',
        '198.51.100.42:22',
        'user@fr-host.fr',
        'fr-host.fr;id',
        'fr-host.fr/path',
        'fr-host.fr?x',
        'fr-host.fr#x',
        'fr_host.fr',
        '-fr-host.fr',
        'fr-host-.fr',
        'fr-host..fr',
        '[2001:db8::42]:22',
        '[2001:db8::42]x',
        'fe80::1%eth0',
        'xn--',
        'bücher.example',
        overlong,
      ]) {
        final assets = _assets();
        final ssh = _RecordingSsh();
        final service = _InstallService(ssh, assets);
        final local = _Store()..directory = directory;
        try {
          await expectLater(
            service.install(local, publicHost: bad),
            throwsFormatException,
            reason: bad,
          );
          expect(ssh.uploads, isEmpty, reason: bad);
          expect(service.requests, isEmpty, reason: bad);
          expect(assets.loaded, isEmpty, reason: bad);
          expect(local.servers, isEmpty, reason: bad);
        } finally {
          local.dispose();
        }
      }
    },
  );

  test(
    'a ready installation is reused without uploading the old bundle',
    () async {
      final assets = _assets();
      final ssh = _RecordingSsh();
      final service = _InstallService(
        ssh,
        assets,
        inspectResult: {
          'phase': 'ready',
          'server': {
            'id': 'fixture-server',
            'host': 'old.example',
            'country': 'DE',
          },
        },
      );
      final server = await service.install(store);
      expect(server.publicHost, 'old.example');
      expect(server.host, 'ssh-proxy.example');
      expect(ssh.uploads, isEmpty);
      expect(service.requests, isEmpty);
      expect(assets.loaded, isEmpty);
    },
  );

  test(
    'a different explicit host on a ready server is refused before upload',
    () async {
      final assets = _assets();
      final ssh = _RecordingSsh();
      final service = _InstallService(
        ssh,
        assets,
        inspectResult: {
          'phase': 'ready',
          'server': {
            'id': 'fixture-server',
            'host': 'old.example',
            'country': 'DE',
          },
        },
      );
      await expectLater(
        service.install(store, publicHost: 'new.example'),
        throwsStateError,
      );
      expect(ssh.uploads, isEmpty);
      expect(service.requests, isEmpty);
      expect(assets.loaded, isEmpty);
      expect(store.servers, isEmpty);
    },
  );

  test('an incomplete installation is a hard stop before upload', () async {
    final assets = _assets();
    final ssh = _RecordingSsh();
    final service = _InstallService(
      ssh,
      assets,
      inspectResult: {
        'phase': 'installing',
        'server': {'id': 'fixture-server', 'host': 'old.example'},
      },
    );
    await expectLater(service.install(store), throwsStateError);
    expect(ssh.uploads, isEmpty);
    expect(service.requests, isEmpty);
    expect(assets.loaded, isEmpty);
    expect(store.servers, isEmpty);
  });

  test('a fresh init mismatch never registers a different VPN host', () async {
    final assets = _assets();
    final ssh = _RecordingSsh();
    final service = _InstallService(
      ssh,
      assets,
      initServer: {
        'id': 'fixture-server',
        'host': 'other.example',
        'country': 'DE',
      },
    );
    await expectLater(
      service.install(store, publicHost: 'fr-host.fr'),
      throwsStateError,
    );
    expect(ssh.uploads, hasLength(1));
    expect(service.requests.single['host'], 'fr-host.fr');
    expect(store.servers, isEmpty);
  });

  test(
    'a malicious server AWG extension is rejected and the user revoked',
    () async {
      final service = _InstallService(
        _RecordingSsh(),
        _assets(),
        addResponse: {
          'server': {
            'publicKeys': {'awg': base64Encode(List.filled(32, 1))},
            'awg': {'Jc': '4\nPostUp = id'},
          },
          'user': {'slot': 2},
        },
      );
      final server = await service.install(store, publicHost: 'fr-host.fr');
      await expectLater(
        service.createUser(store, server, 'Fixture'),
        throwsFormatException,
      );
      expect(service.requests.any((r) => r['action'] == 'revoke'), isTrue);
      expect(store.servers.single, same(server));
      expect(store.lastBundle, isNull);
    },
  );

  test('password is released only after the host key gate accepts', () {
    final gate = SshPasswordGate();
    expect(() => gate.release('secret'), throwsStateError);
    gate.accept(pin);
    expect(gate.release('secret'), 'secret');
    expect(() => gate.accept(changedPin), throwsFormatException);
    for (final bad in ['', 'SHA256:short', 'MD5:${'a' * 43}']) {
      expect(() => gate.accept(bad), throwsFormatException);
    }
    gate.close();
    expect(() => gate.release('secret'), throwsStateError);
  });

  test(
    'client factory wires pin verification before password release',
    () async {
      late _FakeSshClient client;
      final service = VpsService(
        hostKeys: SshHostKeyStore(File('${directory.path}/known-hosts.json')),
        lookup: (host, type) async => type == InternetAddressType.IPv4
            ? [InternetAddress.loopbackIPv4]
            : const <InternetAddress>[],
        socketConnector: (host, port, timeout) async => _IdleSocket(),
        clientFactory:
            ({
              required SSHSocket socket,
              required String username,
              required List<SSHKeyPair> identities,
              required String Function() onPasswordRequest,
              required SSHHostkeyVerifyHandler onVerifyHostKey,
            }) {
              client = _FakeSshClient(
                socket: socket,
                passwordRequest: onPasswordRequest,
                verifyHostKey: onVerifyHostKey,
                scenario: (c) => c.acceptAndRequestPassword(pin),
              );
              return client;
            },
      );
      try {
        await service.open(
          const SshTarget('fr-host.fr', 22, 'root'),
          'secret',
          '',
          '',
        );
        expect(service.target, isNotNull);
        expect(service.verifiedFingerprint, pin);
        expect(client.passwordRequests, 1);
        expect(client.passwordValue, 'secret');
      } finally {
        await service.close();
      }
    },
  );

  test('a pinned host rejects a different key before the password', () async {
    late _FakeSshClient client;
    final service = VpsService(
      hostKeys: SshHostKeyStore(File('${directory.path}/known-hosts.json')),
      lookup: (host, type) async => type == InternetAddressType.IPv4
          ? [InternetAddress.loopbackIPv4]
          : const <InternetAddress>[],
      socketConnector: (host, port, timeout) async => _IdleSocket(),
      clientFactory:
          ({
            required SSHSocket socket,
            required String username,
            required List<SSHKeyPair> identities,
            required String Function() onPasswordRequest,
            required SSHHostkeyVerifyHandler onVerifyHostKey,
          }) {
            client = _FakeSshClient(
              socket: socket,
              passwordRequest: onPasswordRequest,
              verifyHostKey: onVerifyHostKey,
              scenario: (c) => c.acceptAndRequestPassword(changedPin),
            );
            return client;
          },
    );
    try {
      await expectLater(
        service.open(
          const SshTarget('fr-host.fr', 22, 'root', pin),
          'secret',
          '',
          '',
        ),
        throwsA(anything),
      );
      expect(service.target, isNull);
      expect(client.passwordRequests, 0);
    } finally {
      await service.close();
    }
  });

  test('case and trailing-dot aliases share one host-key pin', () async {
    final file = File('${directory.path}/known-hosts.json');
    await SshHostKeyStore(file)
        .verify(const SshTarget('fr-host.fr.', 22, 'root'), pin);
    late _FakeSshClient client;
    final service = VpsService(
      hostKeys: SshHostKeyStore(file),
      lookup: (host, type) async => type == InternetAddressType.IPv4
          ? [InternetAddress.loopbackIPv4]
          : const <InternetAddress>[],
      socketConnector: (host, port, timeout) async => _IdleSocket(),
      clientFactory:
          ({
            required SSHSocket socket,
            required String username,
            required List<SSHKeyPair> identities,
            required String Function() onPasswordRequest,
            required SSHHostkeyVerifyHandler onVerifyHostKey,
          }) {
            client = _FakeSshClient(
              socket: socket,
              passwordRequest: onPasswordRequest,
              verifyHostKey: onVerifyHostKey,
              scenario: (c) => c.acceptAndRequestPassword(changedPin),
            );
            return client;
          },
    );
    try {
      await expectLater(
        service.open(
          const SshTarget('FR-HOST.FR', 22, 'root'),
          'secret',
          '',
          '',
        ),
        throwsA(anything),
      );
      expect(client.passwordRequests, 0);
      expect(service.target, isNull);
      expect(jsonDecode(await file.readAsString()), {'[fr-host.fr]:22': pin});
    } finally {
      await service.close();
    }
  });

  test(
    'DNS resolution keeps a Punycode name, never substitutes an address',
    () async {
      final asked = <String>[];
      final candidates = await resolveServerHost(
        'xn--bcher-kva.example',
        lookup: (host, type) async {
          asked.add('$host/${type == InternetAddressType.IPv4 ? 'A' : 'AAAA'}');
          return type == InternetAddressType.IPv4
              ? [InternetAddress.tryParse('203.0.113.10')!]
              : [InternetAddress.tryParse('2001:db8::10')!];
        },
      );
      expect(asked.toSet(), {
        'xn--bcher-kva.example/A',
        'xn--bcher-kva.example/AAAA',
      });
      expect(candidates.map((c) => c.host), ['203.0.113.10', '2001:db8::10']);
    },
  );
}
