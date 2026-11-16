import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/workspace_ui.dart';

/// Fake remote that drives [VpsService.executeInput] directly, matching the
/// established double pattern in the other test files. It records the command
/// and stdin input so tests can assert the exit host never reaches the shell
/// string.
class _FakeSsh extends VpsService {
  _FakeSsh(this._handler);

  final Future<List<int>> Function(
    String command,
    List<int> input,
    Duration timeout,
  ) _handler;

  final commands = <String>[];
  final inputs = <List<int>>[];

  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) {
    commands.add(command);
    inputs.add(List<int>.from(input));
    return _handler(command, input, timeout);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('executeInput failure contract', () {
    test('non-zero exit with non-empty stdout is reported as failure', () {
      final stdoutBytes = utf8.encode('partial output that must not look ok');
      expect(
        () => sshCommandOutcome(1, stdoutBytes, const <int>[]),
        throwsA(
          isA<SshCommandFailure>()
              .having((e) => e.exitCode, 'exitCode', 1)
              .having((e) => e.stdoutBytes, 'stdoutBytes', stdoutBytes)
              .having((e) => e.stderrBytes, 'stderrBytes', isEmpty),
        ),
      );
    });

    test('exit 0 returns stdout bytes unchanged', () {
      final stdoutBytes = utf8.encode('{"ok":true}');
      expect(sshCommandOutcome(0, stdoutBytes, const <int>[]), stdoutBytes);
    });

    test('a missing exit code (signal) is still a failure', () {
      expect(
        () => sshCommandOutcome(null, utf8.encode('x'), const <int>[]),
        throwsA(
          isA<SshCommandFailure>().having((e) => e.exitCode, 'exitCode', -1),
        ),
      );
    });
  });

  group('structured JSON decode path', () {
    test('a successful exit-0 response still decodes', () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        expect(command, 'python3 /usr/local/lib/xio-managed/admin.py');
        expect(jsonDecode(utf8.decode(input))['action'], 'inspect');
        return utf8.encode(jsonEncode({'ok': true, 'server': {'id': 'srv'}}));
      });
      final service = ManagedService(ssh);
      final result = await service.command({'action': 'inspect'});
      expect(result['ok'], isTrue);
      expect((result['server'] as Map)['id'], 'srv');
    });

    test('a non-zero exit JSON error body is decoded deliberately', () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        throw SshCommandFailure(
          1,
          utf8.encode(jsonEncode({
            'ok': false,
            'error': 'Operation not permitted',
          })),
          const <int>[],
        );
      });
      final service = ManagedService(ssh);
      await expectLater(
        service.command({'action': 'mtproto'}),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            'Операция недоступна администратору',
          ),
        ),
      );
    });
  });

  group('cascade installer command', () {
    test('checksum mismatch aborts before executing the bootstrap', () {
      final command = buildCascadeInstallCommand();

      // Unique, unpredictable temp path instead of the fixed /tmp/xio-cascade.sh.
      expect(command, contains('mktemp -d '));
      expect(command, contains('xio-cascade-install.XXXXXXXX'));

      // The bootstrap digest is pinned and verified before any bash execution.
      expect(command, contains(cascadeBootstrapSha256));
      expect(command, contains('sha256sum --check --status'));

      // The bootstrap download and archive both carry their pinned digests.
      expect(command, contains(cascadeBundleSha256));
      expect(command, contains(cascadeBootstrapUrl));

      // The checksum gate (|| exit 93) runs before the bash line.
      final checkIndex = command.indexOf('sha256sum --check --status || exit 93');
      final bashIndex = command.indexOf('bash "\$tmp/terminal-install.sh"');
      expect(checkIndex, greaterThanOrEqualTo(0));
      expect(bashIndex, greaterThan(checkIndex));

      // The untrusted exit host is never interpolated into the command string.
      expect(command, isNot(contains("--exit-host '\$exit'")));
      expect(command, contains('IFS= read -r exit_host'));
    });

    test('the exit host is delivered over stdin, never into the shell', () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        return utf8.encode('...\n$cascadeInstallSuccessMarker\n');
      });
      await runCascadeInstall(ssh, '2001:db8::42');
      expect(ssh.commands, hasLength(1));
      expect(ssh.commands.single, isNot(contains('2001:db8::42')));
      expect(ssh.inputs.single, utf8.encode('2001:db8::42\n'));
    });
  });

  group('cascade installer success is only claimed from evidence', () {
    test('success is not claimed when the installer reports failure', () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        throw SshCommandFailure(
          2,
          utf8.encode('tail\ncascade-install: --exit-pubkey required'),
          const <int>[],
        );
      });
      await expectLater(
        runCascadeInstall(ssh, '203.0.113.7'),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            allOf(contains('код 2'), contains('--exit-pubkey required')),
          ),
        ),
      );
    });

    test('exit 0 without explicit success evidence is still a failure', () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        return utf8.encode('docker build finished');
      });
      await expectLater(
        runCascadeInstall(ssh, '203.0.113.7'),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('не подтвердил установку'),
          ),
        ),
      );
    });

    test('verified checksum, success evidence and exit 0 are required together',
        () async {
      final ssh = _FakeSsh((command, input, timeout) async {
        // A genuine success: the command verified the bootstrap digest (exit 0)
        // and the installer printed its explicit confirmation.
        return utf8.encode('container 123\n$cascadeInstallSuccessMarker, '
            'NOT an egress acceptance test.');
      });
      final output = await runCascadeInstall(ssh, '203.0.113.7');
      expect(output, contains(cascadeInstallSuccessMarker));
    });
  });

  group('the digest gate is ordered before any execution', () {
    test('sha256 verification precedes the bootstrap invocation', () {
      final command = buildCascadeInstallCommand();
      final verify = command.indexOf('sha256sum --check --status');
      final execute = command.indexOf(r'bash "$tmp/terminal-install.sh"');
      expect(verify, isNonNegative, reason: 'the digest check must exist');
      expect(execute, isNonNegative, reason: 'the bootstrap must be invoked');
      expect(
        verify,
        lessThan(execute),
        reason: 'nothing may execute before the pinned digest is verified',
      );
    });

    test('a failed verification aborts the shell chain', () {
      final command = buildCascadeInstallCommand();
      // The check is followed by `|| exit`, so a mismatch ends the script
      // instead of falling through to the installer.
      final verify = command.indexOf('sha256sum --check --status');
      final afterVerify = command.substring(verify);
      expect(afterVerify, startsWith('sha256sum --check --status'));
      expect(
        afterVerify.substring(0, afterVerify.indexOf('\n')),
        contains('|| exit'),
      );
    });
  });

  group('the failure boundary never degrades into an empty success', () {
    test('a non-zero exit with empty stdout still throws', () {
      expect(
        () => sshCommandOutcome(1, const <int>[], const <int>[]),
        throwsA(
          isA<SshCommandFailure>()
              .having((e) => e.exitCode, 'exitCode', 1)
              .having((e) => e.stdoutBytes, 'stdoutBytes', isEmpty),
        ),
      );
    });

    test('the typed failure preserves the code and both raw streams', () {
      final out = utf8.encode('{"ok":false}');
      final err = utf8.encode('boom');
      final failure = SshCommandFailure(7, out, err);
      expect(failure.exitCode, 7);
      expect(failure.stdoutBytes, out);
      expect(failure.stderrBytes, err);
      expect(failure.toString(), isNot(contains('boom')));
    });
  });
}
