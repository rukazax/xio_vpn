import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:xio/core.dart';
import 'package:xio/main.dart';

Future<List<int>> get(Uri uri) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 12);
  try {
    final request = await client
        .getUrl(uri)
        .timeout(const Duration(seconds: 15));
    final response = await request.close().timeout(const Duration(seconds: 15));
    if (response.statusCode != 200) {
      throw StateError('HTTP ${response.statusCode}');
    }
    return await response
        .fold<List<int>>([], (a, b) => a..addAll(b))
        .timeout(const Duration(seconds: 20));
  } finally {
    client.close(force: true);
  }
}

Future<bool> probe(String server) async {
  Socket? socket;
  try {
    socket = await Socket.connect(
      server,
      8080,
      timeout: const Duration(seconds: 3),
    );
    socket.write(
      'GET /whoami HTTP/1.1\r\nHost: xio-vps\r\nConnection: close\r\n\r\n',
    );
    await socket.flush();
    final text = await socket
        .cast<List<int>>()
        .transform(utf8.decoder)
        .join()
        .timeout(const Duration(seconds: 3));
    return text.contains('xio-real-debian-vps');
  } on IOException {
    return false;
  } on TimeoutException {
    return false;
  } finally {
    socket?.destroy();
  }
}

Future<bool> dns() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  final done = Completer<bool>();
  final id = DateTime.now().microsecondsSinceEpoch & 65535;
  final packet = <int>[id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (final label in ['www', 'cloudflare', 'com']) {
    packet.add(label.length);
    packet.addAll(ascii.encode(label));
  }
  packet.addAll([0, 0, 1, 0, 1]);
  final subscription = socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final datagram = socket.receive();
    if (datagram == null ||
        datagram.address.address != '1.1.1.1' ||
        datagram.port != 53 ||
        datagram.data.length < 12) {
      return;
    }
    final bytes = datagram.data;
    if ((bytes[0] << 8 | bytes[1]) == id && !done.isCompleted) {
      done.complete(
        (bytes[2] & 128) != 0 &&
            (bytes[3] & 15) == 0 &&
            (bytes[6] << 8 | bytes[7]) > 0,
      );
    }
  });
  try {
    socket.send(packet, InternetAddress('1.1.1.1'), 53);
    return await done.future.timeout(const Duration(seconds: 10));
  } finally {
    await subscription.cancel();
    socket.close();
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'real Debian VPS: WG/AWG encrypted HTTP, DNS, exit IP and split policies',
    (tester) async {
      final store = AppStore();
      await store.load();
      await tester.pumpWidget(XioApp(store: store));
      await tester.pumpAndSettle();
      await store.disconnect();
      const own = 'app.xio.xio';
      final apps = await native.invokeListMethod<dynamic>('routingApps');
      final other =
          apps!.firstWhere((app) => app['package'] != own)['package'] as String;
      final reports = <Map<String, dynamic>>[];
      try {
        for (final awg in [false, true]) {
          final encoded = awg
              ? const String.fromEnvironment('VPS_AWG_CONFIG')
              : const String.fromEnvironment('VPS_WG_CONFIG');
          expect(encoded, isNotEmpty);
          await native.invokeMethod('routingSave', {
            'mode': 'all',
            'packages': <String>[],
          });
          await store.addWireGuard(
            awg ? 'VPS · AmneziaWG' : 'VPS · WireGuard',
            utf8.decode(base64Decode(encoded)),
            amnezia: awg,
          );
          final id = store.selectedId!;
          final server = awg ? '10.78.0.1' : '10.77.0.1';
          final report = <String, dynamic>{
            'engine': awg ? 'amneziawg' : 'wireguard',
          };
          await store.connect().timeout(const Duration(seconds: 90));
          expect(store.error, isNull);
          expect(store.status.active, isTrue);
          await Future<void>.delayed(const Duration(seconds: 1));
          final who = jsonDecode(
            utf8.decode(await get(Uri.parse('http://$server:8080/whoami'))),
          );
          expect(who['marker'], 'xio-real-debian-vps');
          expect(who['client'], awg ? '10.78.0.2' : '10.77.0.2');
          report['peerSourceIp'] = who['client'];
          final watch = Stopwatch()..start();
          final payload = await get(Uri.parse('http://$server:8080/payload'));
          watch.stop();
          expect(payload.length, 16 * 65536);
          expect(
            sha256.convert(payload).toString(),
            sha256.convert(ascii.encode('xio-vps-payload-' * 65536)).toString(),
          );
          report['payloadBytes'] = payload.length;
          report['payloadElapsedMs'] = watch.elapsedMilliseconds;
          report['payloadSha256'] = sha256.convert(payload).toString();
          expect(await dns(), isTrue);
          report['explicitUdpDnsVia1111'] = true;
          expect(
            await InternetAddress.lookup('www.cloudflare.com'),
            isNotEmpty,
          );
          report['systemDnsResolved'] = true;
          final trace = utf8.decode(
            await get(Uri.parse('https://www.cloudflare.com/cdn-cgi/trace')),
          );
          expect(trace.split('\n'), contains('ip=81.177.142.37'));
          report['httpsVerifiedExitIp'] = '81.177.142.37';
          var ipv6Reached = false;
          try {
            final socket = await Socket.connect(
              InternetAddress('2606:4700:4700::1111'),
              443,
              timeout: const Duration(seconds: 3),
            );
            ipv6Reached = true;
            socket.destroy();
          } on IOException {
            // The explicit external IPv6 probe must not connect.
          } on TimeoutException {
            // This confirms only this probe, not a general leak audit.
          }
          expect(ipv6Reached, isFalse);
          report['singleExternalIpv6ProbeBlocked'] = true;
          await store.refresh();
          expect(store.status.handshake, greaterThan(0));
          expect(store.status.rx, greaterThan(900000));
          expect(store.status.tx, greaterThan(0));
          report.addAll({
            'handshakeEpochMs': store.status.handshake,
            'rx': store.status.rx,
            'tx': store.status.tx,
          });
          await store.disconnect();
          final cases = <Map<String, dynamic>>[];
          for (final entry in [
            ('include', <String>[own], <String>[], true),
            ('include', <String>[other], <String>[], false),
            ('exclude', <String>[own], <String>[], false),
            ('exclude', <String>[other], <String>[], true),
            ('ipInclude', <String>[], <String>['$server/32'], true),
            (
              'ipInclude',
              <String>[],
              <String>[awg ? '10.78.0.99/32' : '10.77.0.99/32'],
              false,
            ),
            ('ipExclude', <String>[], <String>['$server/32'], false),
            (
              'ipExclude',
              <String>[],
              <String>[awg ? '10.78.0.99/32' : '10.77.0.99/32'],
              true,
            ),
          ]) {
            await native.invokeMethod('routingSave', {
              'mode': entry.$1,
              'packages': entry.$2,
              'networks': entry.$3,
            });
            await store.connect();
            expect(store.error, isNull);
            expect(store.status.active, isTrue);
            await Future<void>.delayed(const Duration(seconds: 1));
            final reached = await probe(server);
            expect(
              reached,
              entry.$4,
              reason: '${report['engine']} ${entry.$1}',
            );
            await expectLater(
              native.invokeMethod('routingSave', {
                'mode': 'all',
                'packages': <String>[],
              }),
              throwsA(isA<PlatformException>()),
            );
            cases.add({
              'mode': entry.$1,
              'selfSelected': entry.$2.contains(own),
              'subnets': entry.$3,
              'httpReached': reached,
              'activeEditRejected': true,
            });
            await store.disconnect();
          }
          report['splitCases'] = cases;
          reports.add(report);
          await store.remove(id);
        }
        // ignore: avoid_print
        print(
          'XIO_REAL_VPS_VERIFICATION=${jsonEncode({'host': '81.177.142.37', 'os': 'Debian 12', 'scope': 'Android API35 emulator via public internet; not physical phone or censorship-resistance audit', 'protocols': reports, 'date': DateTime.now().toUtc().toIso8601String()})}',
        );
      } finally {
        await store.disconnect();
        await native.invokeMethod('routingSave', {
          'mode': 'all',
          'packages': <String>[],
        });
        store.dispose();
      }
    },
    timeout: const Timeout(Duration(minutes: 10)),
  );
}
