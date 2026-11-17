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
      return utf8.encode(
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY xio-cascade\n',
      );
    }
    for (final entry in responses.entries) {
      if (command.contains(entry.key)) return utf8.encode(entry.value);
    }
    return const <int>[];
  }
}

/// A host that refuses to install the tools a stage needs: the wizard must name
/// them instead of failing later with a restart storm and a generic message.
class _ToolsMissingSsh extends _FakeSsh {
  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (command.contains('tools=missing')) {
      throw SshCommandFailure(
        3,
        utf8.encode('tools=missing: iptables'),
        const [],
      );
    }
    return super.executeInput(command, input, timeout: timeout);
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
      ssh.responses['systemctl restart xio-cascade-exit.service'] =
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
      ssh.responses['systemctl restart xio-cascade-exit.service'] =
          'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';
      await CascadeInstaller(ssh).installExit();
      expect(ssh.commands.join('\n'), isNot(contains('password')));
    });

    test('недостающие инструменты ставятся до записи скриптов', () async {
      final ssh = _FakeSsh();
      ssh.responses['apt-get install -y -qq'] =
          'tools=installed:iptables,iputils-ping\n';
      ssh.responses['systemctl restart xio-cascade-exit.service'] =
          'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';
      final evidence = await CascadeInstaller(ssh).installExit();

      expect(evidence.join(' '), contains('installed prerequisites'));
      expect(evidence.join(' '), contains('iptables'));
      final tools = ssh.commands.indexWhere(
        (c) => c.contains('command -v iptables'),
      );
      final firstWrite = ssh.commands.indexWhere(
        (c) => c.contains('xio-cascade-exit-up.sh'),
      );
      expect(tools, isNonNegative);
      expect(tools, lessThan(firstWrite));
    });

    test(
      'если инструменты не установились — этап падает с их именами',
      () async {
        final ssh = _ToolsMissingSsh();
        await expectLater(
          CascadeInstaller(ssh).installExit(),
          throwsA(
            isA<CascadeStageFailure>()
                .having((e) => e.stage, 'stage', 'exit')
                .having((e) => e.message, 'message', contains('iptables')),
          ),
        );
        expect(
          ssh.written,
          isEmpty,
          reason: 'ничего не пишется, пока не подтверждены инструменты',
        );
      },
    );
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

    test(
      'bridge.env получает проверенный exit, туннель подтверждается',
      () async {
        final ssh = _FakeSsh();
        ssh.responses['XIO_CASCADE_TUNNEL_READY'] =
            'XIO_CASCADE_TUNNEL_READY tun=10.250.0.1/30\n';
        ssh.responses['XIO_CASCADE_BRIDGE_READY'] =
            'XIO_CASCADE_BRIDGE_READY ssh=ok ping=ok\n';
        final evidence = await CascadeInstaller(ssh)
            .installBridge('203.0.113.7');

        expect(
          ssh.uploaded['/etc/xio-cascade/bridge.env'],
          'XIO_CASCADE_EXIT_HOST=203.0.113.7\n',
        );
        expect(evidence.join(' '), contains('203.0.113.7'));
        expect(evidence.join(' '), contains('10.250.0.1/30'));
        expect(evidence.join(' '), contains('ping'));
      },
    );

    test('этап 2 проверяет инструменты раньше ключа и unit', () async {
      final ssh = _FakeSsh();
      ssh.responses['apt-get install -y -qq'] = 'tools=installed:iptables\n';
      ssh.responses['XIO_CASCADE_TUNNEL_READY'] =
          'XIO_CASCADE_TUNNEL_READY tun=10.250.0.1/30\n';
      ssh.responses['XIO_CASCADE_BRIDGE_READY'] =
          'XIO_CASCADE_BRIDGE_READY ssh=ok ping=ok\n';
      final evidence = await CascadeInstaller(ssh).installBridge('203.0.113.7');

      expect(evidence.join(' '), contains('installed prerequisites'));
      final tools = ssh.commands.indexWhere(
        (c) => c.contains('command -v iptables'),
      );
      final key = ssh.commands.indexWhere(
        (c) => c.contains('cat /root/.ssh/xio_cascade.pub'),
      );
      expect(tools, isNonNegative);
      expect(tools, lessThan(key));
    });

    test('причина падения unit попадает в сообщение, а не теряется', () async {
      final ssh = _FakeSsh();
      ssh.responses['systemctl restart xio-cascade-bridge.service'] =
          'bridge did not come up\n'
          'xio-cascade-bridge-up.sh: line 48: iptables: command not found\n';
      await expectLater(
        CascadeInstaller(ssh).installBridge('203.0.113.7'),
        throwsA(
          isA<CascadeStageFailure>().having(
            (e) => e.message,
            'message',
            contains('iptables: command not found'),
          ),
        ),
      );
    });

    test('IPv6-exit передаётся без квадратных скобок', () async {
      final ssh = _FakeSsh();
      ssh.responses['XIO_CASCADE_TUNNEL_READY'] =
          'XIO_CASCADE_TUNNEL_READY tun=10.250.0.1/30\n';
      ssh.responses['XIO_CASCADE_BRIDGE_READY'] =
          'XIO_CASCADE_BRIDGE_READY ssh=ok ping=ok\n';
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

  group('Установка в один проход', () {
    _FakeSsh exitHost() {
      final ssh = _FakeSsh();
      ssh.responses['XIO_CASCADE_EXIT_READY'] =
          'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';
      return ssh;
    }

    _FakeSsh bridgeHost() {
      final ssh = _FakeSsh();
      ssh.responses['XIO_CASCADE_TUNNEL_READY'] =
          'XIO_CASCADE_TUNNEL_READY tun=10.250.0.1/30\n';
      ssh.responses['XIO_CASCADE_BRIDGE_READY'] =
          'XIO_CASCADE_BRIDGE_READY ssh=ok ping=ok\n';
      return ssh;
    }

    test(
      'один вызов ставит exit, затем bridge, и события идут по плану',
      () async {
        final exit = exitHost();
        final bridge = bridgeHost();
        final events = <CascadeStepEvent>[];

        final result = await installCascade(
          exitSsh: exit,
          bridgeSsh: bridge,
          exitHost: '203.0.113.7',
          onStep: events.add,
        );

        expect(result.exitEvidence.join(' '), contains('10.250.0.2/30'));
        expect(result.bridgeEvidence.join(' '), contains('10.250.0.1/30'));

        final done = <String>[
          for (final event in events)
            if (event.state == CascadeStepState.done)
              '${event.stage.name}:${event.id}',
        ];
        expect(done, <String>[
          for (final step in <CascadePlanStep>[
            ...cascadePlanSteps(CascadeInstallStage.exit),
            ...cascadePlanSteps(CascadeInstallStage.bridge),
          ])
            '${step.stage.name}:${step.id}',
        ], reason: 'картинка шагов должна совпадать с тем, что выполняется');

        expect(events.first.state, CascadeStepState.running);
        final lastExitDone = events.lastIndexWhere(
          (e) =>
              e.stage == CascadeInstallStage.exit &&
              e.state == CascadeStepState.done,
        );
        final firstBridgeStep = events.indexWhere(
          (e) => e.stage == CascadeInstallStage.bridge,
        );
        expect(
          lastExitDone,
          lessThan(firstBridgeStep),
          reason: 'exit должен завершиться до первого шага bridge',
        );
        expect(
          exit.stdin.values.any(
            (value) => utf8.decode(value).startsWith('ssh-ed25519 '),
          ),
          isTrue,
          reason: 'ключ bridge должен попасть на exit через exit-соединение',
        );
      },
    );

    test(
      'очистка становится первым шагом, а не скрытым предисловием',
      () async {
        final exit = exitHost();
        final bridge = bridgeHost();
        final cleaned = <String>[];
        final events = <CascadeStepEvent>[];

        await installCascade(
          exitSsh: exit,
          bridgeSsh: bridge,
          exitHost: '203.0.113.7',
          cleanExit: (ssh) async => cleaned.add('exit'),
          cleanBridge: (ssh) async => cleaned.add('bridge'),
          onStep: events.add,
        );

        expect(events.first.id, 'clean');
        expect(events.first.stage, CascadeInstallStage.exit);
        expect(cleaned, <String>['exit', 'bridge']);
        expect(
          events.where(
            (e) => e.id == 'clean' && e.state == CascadeStepState.done,
          ),
          hasLength(2),
        );
        expect(
          cascadePlanSteps(CascadeInstallStage.exit, clean: true).first.id,
          'clean',
          reason: 'план с очисткой должен начинаться с этого шага',
        );
      },
    );

    test('падение отдаёт описание шага, вывод хоста и журнал юнита', () async {
      final exit = exitHost();
      // A bridge whose tunnel step fails: the success marker is deliberately
      // absent, so the step under test is the one that reports the reason.
      final bridge = _FakeSsh();
      bridge.responses['systemctl restart xio-cascade-bridge.service'] =
          'bridge did not come up\n'
          'xio-cascade-bridge-up.sh: line 48: iptables: command not found\n';
      bridge.responses['journalctl -u xio-cascade-bridge.service -n 40'] =
          'xio-cascade-bridge.service: status=127/INVALIDARGUMENT\n';

      Object? failure;
      try {
        await installCascade(
          exitSsh: exit,
          bridgeSsh: bridge,
          exitHost: '203.0.113.7',
        );
      } catch (error) {
        failure = error;
      }

      expect(failure, isA<CascadeStageFailure>());
      final failed = failure! as CascadeStageFailure;
      expect(failed.stage, 'bridge');
      expect(failed.step, 'SSH TUN and addresses');
      expect(failed.message, contains('iptables: command not found'));
      expect(failed.logs.join('\n'), contains('iptables: command not found'));
      expect(
        failed.logs.join('\n'),
        contains('--- journalctl -u xio-cascade-bridge.service -n 40 ---'),
      );
      expect(failed.logs.join('\n'), contains('status=127'));
      expect(failed.toString(), contains('SSH TUN and addresses'));
    });
  });

  group('Ключ каскада', () {
    test(
      'публичный ключ уходит на exit через stdin, не в командной строке',
      () async {
        final exit = _FakeSsh();
        const key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY xio-cascade';
        await authorizeCascadeKey(exit, key);
        final entry = exit.stdin.entries.single;
        expect(utf8.decode(entry.value), '$key\n');
        expect(entry.key, isNot(contains('AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY')));
      },
    );

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
      final service = _PurgeService(
        ssh,
        _FakeAssets({'assets/xio-admin.py': utf8.encode('print(1)')}),
        {
          'purged': true,
          'clean': true,
          'removed': ['/etc/xio-managed'],
        },
      );
      final store = AppStore();
      final result = await service.purge(store);
      expect(result['clean'], isTrue);
      final request = service.requests.single;
      expect(request['action'], 'purge');
      expect(request['confirm'], isTrue);
      expect(request['dryRun'], isFalse);
      expect(request.containsKey('serverId'), isFalse);
      final write = ssh.stdin.entries.singleWhere(
        (entry) =>
            entry.key.contains('/usr/local/lib/xio-managed/admin.py.next'),
        orElse: () =>
            throw StateError('admin.py должен загружаться даже без XIO'),
      );
      expect(utf8.decode(write.value), 'print(1)');
    });

    test('неполная очистка — это ошибка, а не «сервер очищен»', () async {
      final ssh = _FakeSsh();
      final service = _PurgeService(
        ssh,
        _FakeAssets({'assets/xio-admin.py': utf8.encode('print(1)')}),
        {
          'purged': true,
          'clean': false,
          'removed': <String>[],
          'remaining': ['/etc/xio-stack'],
        },
      );
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
