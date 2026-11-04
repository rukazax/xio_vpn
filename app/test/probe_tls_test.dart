import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/probe_tls.dart';

import 'support/tls_fixtures.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'legacy compatibility roots do not trust arbitrary self-signed certificates',
    () async {
      final previous = HttpOverrides.current;
      HttpOverrides.global = null;
      HttpServer? server;
      HttpClient? client;
      HttpClient? control;
      try {
        // A checked-in self-signed certificate instead of `openssl` output: the
        // test needs no external binary and no network. The fixture has SAN
        // `IP:127.0.0.1`, so hostname verification would pass if the trust
        // store contained it — the rejection below is about trust only.
        final tls = tlsServerContext(name: untrustedFixture);
        server = await HttpServer.bindSecure(
          InternetAddress.loopbackIPv4,
          0,
          tls,
        );
        server.listen((request) {
          request.response.write('must not be trusted');
          request.response.close();
        }, onError: (Object _) {});
        final url = Uri.parse('https://127.0.0.1:${server.port}/');
        client = HttpClient(context: await ProbeTls.context)
          ..connectionTimeout = const Duration(seconds: 3);
        await expectLater(
          client.getUrl(url).then((r) => r.close()),
          throwsA(isA<HandshakeException>()),
        );
        // Control: the same server and the same URL complete when the
        // certificate is trusted explicitly, so the negative result above is
        // caused by the trust store, not by a broken or unreachable server.
        control = HttpClient(context: tlsClientContext(name: untrustedFixture))
          ..connectionTimeout = const Duration(seconds: 3);
        final response = await (await control.getUrl(url)).close();
        expect(response.statusCode, HttpStatus.ok);
        await response.drain<void>();
      } finally {
        client?.close(force: true);
        control?.close(force: true);
        await server?.close(force: true);
        HttpOverrides.global = previous;
      }
    },
  );
}
