import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_native.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';

class _FakeSsh extends VpsService {
  _FakeSsh() {
    target = SshTarget('203.0.113.9', 22, 'root');
    verifiedFingerprint = 'SHA256:${'a' * 43}';
  }

  final commands = <String>[];
  final uploaded = <String, String>{};
  final written = <String, List<int>>{};
  final responses = <String, String>{};
  final stdin = <String, List<int>>{};

  @override
  Future<void> upload(String path, List<int> bytes) async {
    written[path] = List<int>.from(bytes);
    uploaded[path] = utf8.decode(bytes);
  }

  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    commands.add(command);
    stdin[command] = List<int>.from(input);
    if (command.contains('cat /root/.ssh/xio_cascade.pub')) {
      return utf8.encode('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY xio-cascade\n');
    }
    for (final entry in responses.entries) {
      if (command.contains(entry.key)) return utf8.encode(entry.value);
    }
    return const <int>[];
  }
}

class _FakeAssets extends CachingAssetBundle {
  _FakeAssets(this.files);
  final Map<String, List<int>> files;

  @override
  Future<ByteData> load(String key) async {
    final data = files[key];
    if (data == null) throw StateError('Missing asset: $key');
    return ByteData.sublistView(Uint8List.fromList(data));
  }
}

class _PurgeService extends ManagedService {
  _PurgeService(super.ssh, AssetBundle assets, this.response)
    : super(assets: assets);

  final Map<String, dynamic> response;
  final requests = <Map<String, dynamic>>[];

  @override
  Future<Map<String, dynamic>> command(
    Map<String, dynamic> request, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    requests.add(Map<String, dynamic>.from(request));
    return response;
  }
}

void main() {
  group('Каскад: этап 1 — exit', () {
    test('ставит unit и подтверждает адреса только по маркеру', () async {
      final ssh = _FakeSsh();
      ssh.responses['systemctl enable --now xio-cascade-exit.service'] =
          'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';
      final evidence = await CascadeInstaller(ssh).installExit();

      expect(
        ssh.written.keys,
        containsAll(<String>[
          '/usr/local/sbin/xio-cascade-exit-up.sh',
          '/usr/local/sbin/xio-cascade-exit-down.sh',
          '/etc/systemd/system/xio-cascade-exit.service',
        ]),
      );
      expect(
        ssh.commands.any((c) => c.contains('PermitTunnel yes')),
        isTrue,
        reason: 'drop-in с PermitTunnel должен ставиться до запуска unit',
      );
      expect(ssh.commands.any((c) => c.contains('sshd -t')), isTrue);
      expect(evidence, hasLength(5));
      expect(evidence[1], contains('10.250.0.2/30'));
      expect(evidence.join(' '), contains('forward=1'));
    });

    test('без маркера этап падает и не выдаёт успех', () async {
      final ssh = _FakeSsh();
      await expectLater(
        CascadeInstaller(ssh).installExit(),
        throwsA(
          isA<CascadeStageFailure>().having(
            (e) => e.stage,
            'stage',
            contains('exit'),
          ),
        ),
      );
    });

    test('команды этапа не содержат пароля и ключей', () async {
      final ssh = _FakeSsh();
      ssh.responses['systemctl enable --now xio-cascade-exit.service'] =
          'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';
      await CascadeInstaller(ssh).installExit();
      expect(ssh.commands.join('\n'), isNot(contains('password')));
    });
  });

  group('Каскад: этап 2 — bridge', () {
    test('некорректный exit отвергается до любых изменений', () async {
      final ssh = _FakeSsh();
      await expectLater(
        CascadeInstaller(ssh).installBridge('не-адрес'),
        throwsA(isA<CascadeStageFailure>()),
      );
      expect(ssh.commands, isEmpty);
      expect(ssh.written, isEmpty);
    });

    test('bridge.env получает проверенный exit, туннель подтверждается', () async {
      final ssh = _FakeSsh();
      ssh.responses['systemctl enable --now xio-cascade-bridge.service'] =
          'XIO_CASCADE_BRIDGE_READY tun=10.250.0.1/30 ssh=ok ping=ok\n';
      final evidence = await CascadeInstaller(ssh).installBridge('203.0.113.7');

      expect(
        ssh.uploaded['/etc/xio-cascade/bridge.env'],
        'XIO_CASCADE_EXIT_HOST=203.0.113.7\n',
      );
      expect(evidence.join(' '), contains('203.0.113.7'));
      expect(evidence.join(' '), contains('10.250.0.1/30'));
      expect(evidence.join(' '), contains('ping'));
    });

    test('IPv6-exit передаётся без квадратных скобок', () async {
      final ssh = _FakeSsh();
      ssh.responses['systemctl enable --now xio-cascade-bridge.service'] =
          'XIO_CASCADE_BRIDGE_READY tun=10.250.0.1/30 ssh=ok ping=ok\n';
      await CascadeInstaller(ssh).installBridge('[fd79:1::fe]');
      expect(
        ssh.uploaded['/etc/xio-cascade/bridge.env'],
        'XIO_CASCADE_EXIT_HOST=fd79:1::fe\n',
      );
    });

    test('без подтверждения туннеля этап падает', () async {
      final ssh = _FakeSsh();
      await expectLater(
        CascadeInstaller(ssh).installBridge('203.0.113.7'),
        throwsA(isA<CascadeStageFailure>()),
      );
    });
  });

  group('Ключ каскада', () {
    test('публичный ключ уходит на exit через stdin, не в命令行', () async {
      final exit = _FakeSsh();
      const key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY xio-cascade';
      await authorizeCascadeKey(exit, key);
      final entry = exit.stdin.entries.single;
      expect(utf8.decode(entry.value), '$key\n');
      expect(entry.key, isNot(contains('AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY')));
    });

    test('посторонняя строка вместо ключа отвергается', () async {
      final exit = _FakeSsh();
      await expectLater(
        authorizeCascadeKey(exit, 'ssh-rsa AAAA not-ed25519'),
        throwsA(isA<StateError>()),
      );
      expect(exit.commands, isEmpty);
    });

    test('ключ читается с bridge и проверяется на формат', () async {
      final bridge = _FakeSsh();
      expect(await readCascadeKey(bridge), startsWith('ssh-ed25519 '));
    });
  });

  group('Очистка сервера', () {
    test('запрос уходит с подтверждением и возвращает чистый сервер', () async {
      final ssh = _FakeSsh();
      final service = _PurgeService(ssh, _FakeAssets({
        'assets/xio-admin.py': utf8.encode('print(1)'),
      }), {'purged': true, 'clean': true, 'removed': ['/etc/xio-managed']});
      final store = AppStore();
      final result = await service.purge(store);
      expect(result['clean'], isTrue);
      final request = service.requests.single;
      expect(request['action'], 'purge');
      expect(request['confirm'], isTrue);
      expect(request['dryRun'], isFalse);
      expect(request.containsKey('serverId'), isFalse);
      final write = ssh.stdin.entries.singleWhere(
        (entry) => entry.key.contains('/usr/local/lib/xio-managed/admin.py.next'),
        orElse: () => throw StateError('admin.py должен загружаться даже без XIO'),
      );
      expect(utf8.decode(write.value), 'print(1)');
    });

    test('неполная очистка — это ошибка, а не «сервер очищен»', () async {
      final ssh = _FakeSsh();
      final service = _PurgeService(ssh, _FakeAssets({
        'assets/xio-admin.py': utf8.encode('print(1)'),
      }), {
        'purged': true,
        'clean': false,
        'removed': <String>[],
        'remaining': ['/etc/xio-stack'],
      });
      await expectLater(
        service.purge(AppStore()),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('/etc/xio-stack'),
          ),
        ),
      );
    });

    test('при активном VPN очистка не начинается', () async {
      final ssh = _FakeSsh();
      final service = _PurgeService(ssh, _FakeAssets({}), {'clean': true});
      final store = AppStore()..status = const TunnelStatus(active: true);
      await expectLater(service.purge(store), throwsA(isA<StateError>()));
      expect(service.requests, isEmpty);
      expect(ssh.written, isEmpty);
    });
  });
}
