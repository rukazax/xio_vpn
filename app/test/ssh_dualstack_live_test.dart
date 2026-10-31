import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

// Opt-in only. Credentials are ephemeral process input, never test fixtures.
void main() {
  final enabled = Platform.environment['XIO_LIVE_SSH'] == '1';
  for (final literal in [false, true]) {
    test(
      'live shared SSH client: pinned IPv4 ${literal ? 'literal' : 'DNS'} transport',
      () async {
        final host = Platform.environment['XIO_LIVE_SSH_HOST']!;
        final password = Platform.environment['XIO_LIVE_SSH_PASSWORD']!;
        final pin = Platform.environment['XIO_LIVE_SSH_PIN']!;
        final port = int.parse(Platform.environment['XIO_LIVE_SSH_PORT']!);
        final transportHost = literal
            ? (await InternetAddress.lookup(
                host,
                type: InternetAddressType.IPv4,
              )).first.address
            : host;
        final dir = await Directory.systemTemp.createTemp(
          'xio-live-pinned-ssh-',
        );
        final service = VpsService(
          hostKeys: SshHostKeyStore(File('${dir.path}/known.json')),
        );
        try {
          await service.open(
            SshTarget(transportHost, port, 'root', pin),
            password,
            '',
            '',
          );
          expect(service.verifiedFingerprint, pin);
          final response = String.fromCharCodes(
            await service.executeInput(
              "printf 'UID='; id -u; printf 'HOST='; hostname; ip -6 -o address show scope global",
              [],
            ),
          );
          expect(response, contains('UID=0'));
          expect(response, contains('HOST=VPS-721137'));
          expect(response, contains('2a0c:b641:1a0:800::2a2/128'));
        } finally {
          await service.close();
          await dir.delete(recursive: true);
        }
      },
      skip: !enabled,
      timeout: const Timeout(Duration(seconds: 55)),
    );
  }
}
