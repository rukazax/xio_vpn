import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/probe_tls.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('legacy compatibility roots do not trust arbitrary self-signed certificates', () async {
    final previous = HttpOverrides.current;
    HttpOverrides.global = null;
    final dir = await Directory.systemTemp.createTemp('xio-tls-negative-');
    HttpServer? server;
    HttpClient? client;
    try {
      final cert = '${dir.path}/cert.pem', key = '${dir.path}/key.pem';
      final result = await Process.run('openssl', [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        key,
        '-out',
        cert,
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost',
        '-days',
        '1',
      ]);
      expect(result.exitCode, 0);
      final tls = SecurityContext()
        ..useCertificateChain(cert)
        ..usePrivateKey(key);
      server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        tls,
      );
      server.listen((request) {
        request.response.write('must not be trusted');
        request.response.close();
      }, onError: (Object _) {});
      client = HttpClient(context: await ProbeTls.context)
        ..connectionTimeout = const Duration(seconds: 3);
      await expectLater(
        client
            .getUrl(Uri.parse('https://localhost:${server.port}'))
            .then((r) => r.close()),
        throwsA(isA<HandshakeException>()),
      );
    } finally {
      client?.close(force: true);
      await server?.close(force: true);
      await dir.delete(recursive: true);
      HttpOverrides.global = previous;
    }
  });
}
