import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

void main() {
  late Directory dir;
  late SecurityContext serverTls, clientTls;
  HttpOverrides? previous;
  setUpAll(() async {
    previous = HttpOverrides.current;
    HttpOverrides.global = null;
    dir = await Directory.systemTemp.createTemp('xio-https-tests-');
    final p = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      '${dir.path}/key.pem',
      '-out',
      '${dir.path}/cert.pem',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost',
      '-days',
      '1',
    ]);
    expect(p.exitCode, 0);
    serverTls = SecurityContext()
      ..useCertificateChain('${dir.path}/cert.pem')
      ..usePrivateKey('${dir.path}/key.pem');
    clientTls = SecurityContext()
      ..setTrustedCertificates('${dir.path}/cert.pem');
  });
  tearDownAll(() async {
    HttpOverrides.global = previous;
    await dir.delete(recursive: true);
  });
  test('a stalled first response recovers on a fresh connection within the same budget', () async {
    final server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      serverTls,
    );
    var requests = 0;
    server.listen((r) {
      requests++;
      if (requests > 1) {
        r.response.write('OK');
        r.response.close();
      }
    }, onError: (Object _) {});
    final store = AppStore(probeSecurityContext: clientTls)
      ..status = const TunnelStatus(active: true)
      ..checkSite = 'https://localhost:${server.port}/';
    final clock = Stopwatch()..start();
    try {
      // A single absolute deadline governs every retry; the value only has to
      // exceed one stalled-response phase budget so a slower CI runner can still
      // complete the retry inside the same deadline.
      expect(
        await store.checkConnection(timeout: const Duration(seconds: 30)),
        isTrue,
      );
      expect(requests, 2);
      expect(clock.elapsed, lessThan(const Duration(seconds: 30)));
    } finally {
      store.dispose();
      await server.close(force: true);
    }
  });
  test(
    'HTTPS redirects may not downgrade the control request to plaintext',
    () async {
      var plaintextRequests = 0;
      final clear = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      clear.listen((r) {
        plaintextRequests++;
        r.response.write('not allowed');
        r.response.close();
      });
      final server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        serverTls,
      );
      server.listen((r) {
        r.response.statusCode = 302;
        r.response.headers.set('location', 'http://127.0.0.1:${clear.port}/');
        r.response.close();
      }, onError: (Object _) {});
      final store = AppStore(probeSecurityContext: clientTls)
        ..status = const TunnelStatus(active: true)
        ..checkSite = 'https://localhost:${server.port}/';
      try {
        expect(
          await store.checkConnection(timeout: const Duration(seconds: 3)),
          isFalse,
        );
        expect(plaintextRequests, 0);
      } finally {
        store.dispose();
        await server.close(force: true);
        await clear.close(force: true);
      }
    },
  );
  test('one absolute deadline also limits stalled response retries', () async {
    final server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      serverTls,
    );
    server.listen((_) {}, onError: (Object _) {});
    final store = AppStore(probeSecurityContext: clientTls)
      ..status = const TunnelStatus(active: true)
      ..checkSite = 'https://localhost:${server.port}/';
    final clock = Stopwatch()..start();
    try {
      expect(
        await store.checkConnection(timeout: const Duration(seconds: 2)),
        isFalse,
      );
      expect(clock.elapsed, lessThan(const Duration(seconds: 3)));
    } finally {
      store.dispose();
      await server.close(force: true);
    }
  });
}
