import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:xio/core.dart';
import 'package:xio/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('native Android WireGuard encrypts a real HTTP exchange', (
    tester,
  ) async {
    const encoded = String.fromEnvironment('LAB_WG_CONFIG');
    expect(
      encoded,
      isNotEmpty,
      reason: 'Start the isolated lab and pass its ephemeral config using --dart-define-from-file.',
    );
    final raw = utf8.decode(base64Decode(encoded));
    final store = AppStore();
    await store.load();
    await tester.pumpWidget(XioApp(store: store));
    await tester.pumpAndSettle();
    await store.addWireGuard('Лаборатория · временный профиль', raw);
    final id = store.selectedId;
    try {
      // Android's system VPN permission is approved by the test operator outside
      // the app. There is no production bypass or test-only native entry point.
      await store.connect().timeout(const Duration(seconds: 90));
      expect(store.error, isNull);
      expect(store.status.active, isTrue);
      final socket = await Socket.connect(
        '10.77.0.1',
        8080,
        timeout: const Duration(seconds: 20),
      );
      String response;
      try {
        socket.write(
          'GET / HTTP/1.1\r\nHost: xio-lab\r\nConnection: close\r\n\r\n',
        );
        await socket.flush();
        response = await socket
            .cast<List<int>>()
            .transform(utf8.decoder)
            .join()
            .timeout(const Duration(seconds: 20));
      } finally {
        socket.destroy();
      }
      expect(response, contains('xio-wireguard-lab-ok'));
      await store.refresh();
      expect(store.status.handshake, greaterThan(0));
      expect(store.status.rx, greaterThan(0));
      expect(store.status.tx, greaterThan(0));
      final cipher = await File(
        '${store.directory!.parent.path}/no_backup/vault/$id.bin',
      ).readAsBytes();
      final privateKey = raw
          .split('\n')
          .firstWhere((l) => l.startsWith('PrivateKey'))
          .split('=')
          .skip(1)
          .join('=')
          .trim();
      final ciphertext = latin1.decode(cipher);
      expect(cipher.first, 12);
      expect(ciphertext, isNot(contains(raw)));
      expect(ciphertext, isNot(contains(privateKey)));
      final metadata = await File('${store.directory!.path}/profiles.json')
          .readAsString();
      expect(metadata, isNot(contains(privateKey)));
      final report = {
        'test': 'android-emulator-wireguard',
        'scope': 'isolated virtual subnet; not public VPS or physical phone',
        'httpPayloadConfirmed': true,
        'handshakeEpochMs': store.status.handshake,
        'rx': store.status.rx,
        'tx': store.status.tx,
        'encryptedVaultChecked': true,
        'profileId': id,
        'date': DateTime.now().toUtc().toIso8601String(),
      };
      await store.disconnect();
      expect(store.status.active, isFalse);
      report['disconnectConfirmed'] = true;
      // Non-secret machine-readable evidence survives test tool uninstall.
      // ignore: avoid_print
      print('XIO_VERIFICATION=${jsonEncode(report)}');
      await File('${store.directory!.path}/wireguard-verification.json')
          .writeAsString(jsonEncode(report));
    } finally {
      if (store.status.active) await store.disconnect();
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    }
  });
}
