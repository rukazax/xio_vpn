import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';

void main() {
  test(
    'real SSH uses automatic persistent trust and rejects changed key',
    () async {
      final j = jsonDecode(
        await File('../.build-support/lab/ssh.json').readAsString(),
      );
      final dir = await Directory.systemTemp.createTemp('x1o-ssh-integration-');
      final file = File('${dir.path}/known.json');
      final t = SshTarget(j['host'], j['port'], j['username']);
      try {
        for (var attempt = 0; attempt < 2; attempt++) {
          final service = VpsService(hostKeys: SshHostKeyStore(file));
          try {
            await service.open(t, j['password'], '', '');
            expect(service.target, isNotNull);
            expect(
              (jsonDecode(await file.readAsString()) as Map).values.single,
              j['fingerprint'],
            );
          } finally {
            await service.close();
          }
        }
        final saved = jsonDecode(await file.readAsString()) as Map;
        saved[saved.keys.single] = 'SHA256:${'a' * 43}';
        await file.writeAsString(jsonEncode(saved));
        final authCount = File('../.build-support/lab/ssh-auth-count');
        final before = await authCount.readAsString();
        final rejected = VpsService(hostKeys: SshHostKeyStore(file));
        try {
          await expectLater(
            rejected.open(t, j['password'], '', ''),
            throwsFormatException,
          );
          expect(rejected.target, isNull);
          expect(await authCount.readAsString(), before);
          expect(jsonDecode(await file.readAsString()), saved);
        } finally {
          await rejected.close();
        }
      } finally {
        await dir.delete(recursive: true);
      }
    },
    skip: !const bool.fromEnvironment('X1O_LAB_SSH'),
  );
  test('real SSH handshake accepts pinned key and rejects mismatch', () async {
    final j = jsonDecode(
      await File('../.build-support/lab/ssh.json').readAsString(),
    );
    final service = VpsService();
    try {
      await service.open(
        SshTarget(j['host'], j['port'], j['username'], j['fingerprint']),
        j['password'],
        '',
        '',
      );
      expect(service.target, isNotNull);
      await service.close();
      final wrong = 'SHA256:${'a' * 43}';
      await expectLater(
        service.open(
          SshTarget(j['host'], j['port'], j['username'], wrong),
          j['password'],
          '',
          '',
        ),
        throwsA(anything),
      );
      expect(service.target, isNull);
    } finally {
      await service.close();
    }
  }, skip: !const bool.fromEnvironment('X1O_LAB_SSH'));
}
