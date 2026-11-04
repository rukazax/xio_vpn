import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

import 'support/tls_fixtures.dart';

void main() {
  late SecurityContext serverTls, clientTls;
  HttpOverrides? previous;
  setUpAll(() {
    previous = HttpOverrides.current;
    HttpOverrides.global = null;
    // Checked-in self-signed certificate instead of shelling out to `openssl`:
    // the probe tests must run on a bare host without external tools or network.
    // SAN `localhost`, EKU serverAuth and CA:FALSE are part of the fixture, which
    // platform TLS verifiers require.
    serverTls = tlsServerContext();
    clientTls = tlsClientContext();
  });
  tearDownAll(() {
    HttpOverrides.global = previous;
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
      final outcome = await store.checkConnection(
        timeout: const Duration(seconds: 30),
      );
      // ignore: avoid_print
      print(
        'PROBE-DIAG ok=$outcome requests=$requests '
        'elapsedMs=${clock.elapsedMilliseconds} '
        'check="${store.connectionCheck}"',
      );
      expect(outcome, isTrue);
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
