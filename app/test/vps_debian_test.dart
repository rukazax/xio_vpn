import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';

void main() {
  test(
    'real Debian VPS SSH pin, preflight and application WG installer',
    () async {
      final password = Platform.environment['X1O_VPS_PASSWORD']!;
      final host = Platform.environment['X1O_VPS_HOST']!;
      final fingerprint = Platform.environment['X1O_VPS_FINGERPRINT']!;
      final service = VpsService();
      try {
        await expectLater(
          service.open(
            SshTarget(host, 22, 'root', 'SHA256:${'a' * 43}'),
            password,
            '',
            '',
          ),
          throwsA(anything),
        );
        expect(service.target, isNull);
        await service.open(
          SshTarget(host, 22, 'root', fingerprint),
          password,
          '',
          '',
        );
        final preflight = await service.preflight();
        expect(preflight, contains('OS: debian 12'));
        expect(preflight, contains('UID: 0'));
        final config = await service.installWireGuard(
          await File('assets/install-wireguard.sh').readAsString(),
        );
        final parsed = WireGuardProfile.parse(config);
        expect(parsed.endpoint, '$host:51820');
        final privateFile = File(
          '../.build-support/vps-private/wg-client.conf',
        );
        await privateFile.writeAsString(config, flush: true);
        await Process.run('chmod', ['600', privateFile.path]);
        await File('../verification/vps-application-installer.json')
            .writeAsString(
              jsonEncode({
                'host': host,
                'os': 'Debian 12',
                'sshAuthenticated': true,
                'mismatchedPinRejected': true,
                'applicationInstallerCompleted': true,
                'clientPrivateKeyGeneratedLocally': true,
                'endpoint': parsed.endpoint,
                'date': DateTime.now().toUtc().toIso8601String(),
              }),
            );
        // ignore: avoid_print
        print(
          'X1O_VPS_INSTALLER=authenticated, mismatched pin rejected, Debian preflight and application installer passed',
        );
      } finally {
        await service.close();
      }
    },
    skip: Platform.environment['X1O_VPS_INSTALL'] != '1',
    timeout: const Timeout(Duration(minutes: 6)),
  );
}
