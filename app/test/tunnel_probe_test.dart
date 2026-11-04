import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

/// A local stand-in for the gateway responder (`server/managed/readiness.py`):
/// 16 bytes in, `0x01` + SHA-256(nonce)[:31] out.
///
/// [correct] = false replies with a wrong status byte and a wrong digest, which
/// is what a stale or foreign peer would look like; [silent] accepts the
/// connection and never answers, which is what a hung far side looks like.
Future<ServerSocket> startResponder({
  bool correct = true,
  bool silent = false,
}) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    final buffer = <int>[];
    socket.listen(
      (chunk) async {
        buffer.addAll(chunk);
        if (silent || buffer.length < TunnelReadinessProbe.nonceBytes) return;
        final nonce = buffer.sublist(0, TunnelReadinessProbe.nonceBytes);
        final digest = sha256.convert(nonce).bytes;
        socket.add([correct ? 0x01 : 0x02, ...digest.take(31)]);
        await socket.flush();
      },
      onError: (Object _) => socket.destroy(),
      onDone: socket.destroy,
    );
  });
  return server;
}

void main() {
  test('readiness reply is 0x01 plus the first 31 bytes of SHA-256(nonce)', () {
    final nonce = List<int>.generate(16, (i) => i);
    final digest = sha256.convert(nonce).bytes;
    final good = [0x01, ...digest.take(31)];
    expect(TunnelReadinessProbe.isReadinessReply(nonce, good), isTrue);

    // A reply for another nonce never validates, so nobody can replay an old
    // answer into a live-looking tunnel.
    final other = List<int>.generate(16, (i) => i + 1);
    expect(TunnelReadinessProbe.isReadinessReply(other, good), isFalse);
    // Wrong status byte, truncated reply, empty reply.
    expect(
      TunnelReadinessProbe.isReadinessReply(nonce, [0x02, ...digest.take(31)]),
      isFalse,
    );
    expect(
      TunnelReadinessProbe.isReadinessReply(nonce, good.sublist(0, 31)),
      isFalse,
    );
    expect(TunnelReadinessProbe.isReadinessReply(nonce, const []), isFalse);
  });

  test('gateway ring is chosen from the transport', () {
    expect(TunnelReadinessProbe.gatewaysFor('awg'), ['10.78.0.1']);
    expect(TunnelReadinessProbe.gatewaysFor('rivet-s1'), [
      '10.79.0.1',
      '10.78.0.1',
    ]);
    expect(TunnelReadinessProbe.gatewaysFor('rivet-h3'), [
      '10.79.0.1',
      '10.78.0.1',
    ]);
    // An unknown transport still gets a ring that exists on every installation.
    expect(
      TunnelReadinessProbe.gatewaysFor('wireguard'),
      tunnelReadinessFallbacks,
    );
  });

  test('a real responder confirms the data path', () async {
    final server = await startResponder();
    addTearDown(server.close);
    const probe = TunnelReadinessProbe();
    final result = await probe.probeHosts(
      ['127.0.0.1'],
      const Duration(seconds: 2),
      port: server.port,
    );
    expect(result, TunnelProbeResult.confirmed);
    expect(result.alive, isTrue);
  });

  test('an answer without a nonce proof is still a live path', () async {
    // Some other service on the readiness port, or an installation without the
    // responder: the transport answered, so packets do cross the tunnel.
    final server = await startResponder(correct: false);
    addTearDown(server.close);
    const probe = TunnelReadinessProbe();
    final result = await probe.probeHosts(
      ['127.0.0.1'],
      const Duration(seconds: 2),
      port: server.port,
    );
    expect(result, TunnelProbeResult.reachable);
    expect(result.alive, isTrue);
  });

  test(
    'a peer that accepts and never answers is reachable, not dead',
    () async {
      final server = await startResponder(silent: true);
      addTearDown(server.close);
      const probe = TunnelReadinessProbe();
      final result = await probe.probeHosts(
        ['127.0.0.1'],
        const Duration(milliseconds: 600),
        port: server.port,
      );
      // The TCP handshake itself came back through the tunnel.
      expect(result, TunnelProbeResult.reachable);
    },
  );

  test('a closed readiness port proves the gateway is alive (reset)', () async {
    // This is what an installation without xio-ready looks like: the gateway
    // host resets the connection, which is an answer, not silence.
    final server = await startResponder();
    final port = server.port;
    await server.close();
    const probe = TunnelReadinessProbe();
    final result = await probe.probeHosts(
      ['127.0.0.1'],
      const Duration(seconds: 2),
      port: port,
    );
    expect(result, TunnelProbeResult.reachable);
  });

  test('silence is dead and stays inside the deadline', () async {
    const probe = TunnelReadinessProbe();
    final clock = Stopwatch()..start();
    // TEST-NET-1 is never routed: the probe must give up, not hang.
    final result = await probe.probeHosts([
      '192.0.2.1',
    ], const Duration(milliseconds: 500));
    expect(result, TunnelProbeResult.dead);
    expect(result.alive, isFalse);
    expect(clock.elapsed, lessThan(const Duration(seconds: 3)));
  });
}
