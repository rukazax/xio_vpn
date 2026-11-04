import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

const _native = MethodChannel('app.xio/engine');
const _enabled = bool.fromEnvironment('XIO_DUALSTACK_DISPOSABLE_APP');

// Operator-supplied ephemeral profiles and tunnel-only HTTP endpoints. Nothing
// here starts ADB, configures a network, installs a server or bypasses VPN consent.
String _outerHost(String engine, String raw) {
  if (engine == 'awg') {
    final matches = RegExp(
      r'^\s*Endpoint\s*=\s*(\S+)\s*$',
      multiLine: true,
    ).allMatches(raw).toList();
    expect(
      matches.length,
      1,
      reason: 'Use one lab peer, not an automatic plan.',
    );
    return Uri.parse('https://${matches.single[1]}').host;
  }
  final cfg = jsonDecode(raw) as Map<String, dynamic>;
  expect(cfg['protocol'], engine);
  if (engine.startsWith('rivet-')) {
    return Uri.parse('https://${cfg['endpoint']}').host;
  }
  if (engine == 'cloak') {
    return (cfg['cloak'] as Map)['RemoteHost'] as String;
  }
  final outbound = cfg['outbound'] as Map;
  final settings = outbound['settings'] as Map;
  final servers = (settings['vnext'] ?? settings['servers']) as List;
  expect(servers.length, 1);
  return (servers.single as Map)['address'] as String;
}

Uri _payloadUrl(String raw, InternetAddressType family) {
  final url = Uri.parse(raw);
  final address = InternetAddress.tryParse(url.host);
  expect(
    address,
    isNotNull,
    reason: 'Use a literal tunnel-only HTTP endpoint.',
  );
  expect(address!.type, family);
  expect(url.scheme, 'http');
  expect(url.userInfo, isEmpty);
  expect(url.fragment, isEmpty);
  return url;
}

Future<bool> _payload(Uri url, String marker) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 4)
    ..findProxy = (_) => 'DIRECT';
  final watchdog = Timer(
    const Duration(seconds: 6),
    () => client.close(force: true),
  );
  try {
    final request = await client
        .getUrl(url)
        .timeout(const Duration(seconds: 5));
    request.followRedirects =
        false; // Never replace IPv6 with an IPv4 redirect.
    final response = await request.close().timeout(const Duration(seconds: 5));
    final bytes = <int>[];
    await for (final chunk in response.timeout(const Duration(seconds: 5))) {
      bytes.addAll(chunk);
      if (bytes.length > 16384) return false;
    }
    return response.statusCode == 200 &&
        utf8.decode(bytes, allowMalformed: true).contains(marker);
  } on IOException {
    return false;
  } on TimeoutException {
    return false;
  } finally {
    watchdog.cancel();
    client.close(force: true);
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'XIO Android dualstack literal VPN payload',
    (tester) async {
      expect(Platform.isAndroid, isTrue);
      const engine = String.fromEnvironment('XIO_DUALSTACK_ENGINE');
      const variant = String.fromEnvironment('XIO_DUALSTACK_VARIANT');
      const family = String.fromEnvironment('XIO_DUALSTACK_OUTER_FAMILY');
      const encoded = String.fromEnvironment('XIO_DUALSTACK_PROFILE_B64');
      const marker = String.fromEnvironment('XIO_DUALSTACK_MARKER');
      const site = String.fromEnvironment('XIO_DUALSTACK_PROBE_SITE');
      const prefixes = {
        'awg': 'awg',
        'rivet-h3': 'rvh',
        'rivet-s1': 'rvs',
        'xray': 'xr',
        'cloak': 'ck',
      };
      expect(prefixes.containsKey(engine), isTrue);
      expect(['full', 'client'], contains(variant));
      final expectedPackage = variant == 'client'
          ? 'app.xio.client'
          : 'app.xio.xio';
      final directory = await _native.invokeMethod<String>('dataDirectory');
      expect(
        directory?.endsWith('/$expectedPackage/files'),
        isTrue,
        reason: 'Verify the installed Full/Client variant, not only a label.',
      );
      expect(['ipv4', 'ipv6', 'dns'], contains(family));
      expect(encoded, isNotEmpty);
      expect(marker.length, inInclusiveRange(16, 128));
      final probeSite = Uri.parse(site);
      expect(probeSite.scheme, 'https');
      expect(probeSite.host, isNotEmpty);
      expect(probeSite.userInfo, isEmpty);
      late String raw;
      late String outerHost;
      try {
        raw = utf8.decode(base64Decode(encoded));
        outerHost = _outerHost(engine, raw);
      } catch (_) {
        fail('Invalid lab profile structure or encoding (material hidden).');
      }
      final outer = InternetAddress.tryParse(outerHost);
      if (family == 'dns') {
        expect(outer, isNull);
      } else {
        expect(
          outer?.type,
          family == 'ipv4'
              ? InternetAddressType.IPv4
              : InternetAddressType.IPv6,
        );
      }
      final v4 = _payloadUrl(
        const String.fromEnvironment('XIO_DUALSTACK_V4_URL'),
        InternetAddressType.IPv4,
      );
      final v6 = _payloadUrl(
        const String.fromEnvironment('XIO_DUALSTACK_V6_URL'),
        InternetAddressType.IPv6,
      );
      final initial = await _native.invokeMapMethod<String, dynamic>('status');
      expect(
        initial!['active'],
        isFalse,
        reason: 'Refuse to interrupt another VPN.',
      );
      expect(await _native.invokeMethod<bool>('connectionBusy'), isFalse);
      expect(
        await _payload(v4, marker),
        isFalse,
        reason: 'IPv4 endpoint must not be reachable outside the VPN.',
      );
      expect(
        await _payload(v6, marker),
        isFalse,
        reason: 'IPv6 endpoint must not be reachable outside the VPN.',
      );
      final id =
          '${prefixes[engine]}999${DateTime.now().microsecondsSinceEpoch}';
      var profileSaved = false;
      var attempted = false;
      try {
        await _native.invokeMethod('setConsent', {'revision': '2026-10-18'});
        await _native.invokeMethod('routingSave', {
          'mode': 'all',
          'packages': <String>[],
          'networks': <String>[],
        });
        await _native.invokeMethod('saveConfig', {'id': id, 'config': raw});
        profileSaved = true;
        await _native.invokeMethod(
          'saveConnectionPlan',
          jsonEncode({
            'ids': [id],
            'site': site,
            'timeoutSeconds': 60,
          }),
        );
        final started = DateTime.now().millisecondsSinceEpoch;
        attempted = true;
        await _native
            .invokeMethod('connect', {'id': id})
            .timeout(const Duration(seconds: 90));
        await Future<void>.delayed(const Duration(seconds: 1));
        final before = await _native.invokeMapMethod<String, dynamic>('status');
        expect(before!['active'], isTrue);
        expect(
          before['protocol'],
          engine,
          reason: 'No silent cross-engine fallback.',
        );
        expect(
          await _payload(v4, marker),
          isTrue,
          reason: 'Encrypted IPv4 tunnel payload required.',
        );
        expect(
          await _payload(v6, marker),
          isTrue,
          reason: 'Encrypted IPv6 tunnel payload required.',
        );
        final after = await _native.invokeMapMethod<String, dynamic>('status');
        expect(
          (after!['handshake'] as num).toInt(),
          greaterThanOrEqualTo(started - 2000),
        );
        expect((after['rx'] as num).toInt(), greaterThan(0));
        expect((after['tx'] as num).toInt(), greaterThan(0));
        await _native.invokeMethod('disconnect');
        attempted = false;
        expect(
          (await _native.invokeMapMethod<String, dynamic>('status'))!['active'],
          isFalse,
        );
        await Future<void>.delayed(const Duration(seconds: 1));
        expect(await _payload(v4, marker), isFalse);
        expect(await _payload(v6, marker), isFalse);
        // No profile, marker, peer IP, credentials or raw exception in evidence.
        // This does NOT certify outer packet family, DNS, public egress or leaks.
        // Those require the independent lab evidence in android-report.ru.md.
        // ignore: avoid_print
        print(
          'XIO_DUALSTACK_DEVICE_PAYLOAD=${jsonEncode({'engine': engine, 'variantVerified': variant, 'outerConfigFamily': family, 'innerIpv4Http': true, 'innerIpv6Http': true, 'freshHandshake': true, 'disconnectConfirmed': true, 'outerCaptureVerified': false, 'dnsVerified': false, 'leakCaptureVerified': false})}',
        );
      } finally {
        try {
          if (attempted) await _native.invokeMethod('disconnect');
        } finally {
          try {
            await _native.invokeMethod('saveConnectionPlan', '{}');
          } finally {
            if (profileSaved) {
              await _native.invokeMethod('deleteConfig', {'id': id});
            }
          }
        }
      }
    },
    skip: !_enabled,
    timeout: const Timeout(Duration(minutes: 4)),
  );
}
