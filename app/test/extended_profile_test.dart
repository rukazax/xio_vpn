import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:xio/core.dart';

void main() {
  const uuid = 'b3b2eb49-e41f-41df-9761-0956785a236b';
  test('VLESS REALITY round trip and automatic import', () {
    final key = base64Url
        .encode(List.generate(32, (i) => i))
        .replaceAll('=', '');
    final raw =
        'vless://$uuid@example.org:4443?security=reality&sni=example.com&pbk=$key&sid=abcdef12&flow=xtls-rprx-vision#My%20VPN';
    final p = ClientImport.parse(raw);
    expect(p.protocol, 'xray');
    final parsed = ExtendedProfile.parse(p.config!);
    expect(parsed.endpoint, 'example.org:4443');
    expect(
      parsed
          .data['outbound']['streamSettings']['realitySettings']['serverName'],
      'example.com',
    );
  });
  test('removed protocols cannot be imported', () {
    for (final raw in [
      'ss://YWVzLTI1Ni1nY206cGFzcw@example.org:8388',
      'client\ndev tun\nremote example.org 1194',
      '{"protocol":"ikev2"}',
      '{"protocol":"tailscale"}',
    ]) {
      expect(() => ExtendedProfile.parse(raw), throwsFormatException);
    }
  });
  test('reject insecure TLS, plain VLESS and local API/import files', () {
    for (final raw in [
      'vless://$uuid@example.org:443?security=tls&allowInsecure=1',
      'vless://$uuid@example.org:80',
      '{"outbounds":[{"protocol":"freedom"}]}',
    ]) {
      expect(() => ExtendedProfile.parse(raw), throwsFormatException);
    }
  });
  test('XHTTP modes preserve upstream Encryption and reject unsafe extras', () {
    final key = base64Url.encode(List.filled(1184, 1)).replaceAll('=', '');
    for (final mode in ['auto', 'packet-up', 'stream-up', 'stream-one']) {
      final encryption = 'mlkem768x25519plus.native.1rtt.$key';
      final uri = Uri(
        scheme: 'vless',
        userInfo: uuid,
        host: 'vpn.example',
        port: 443,
        queryParameters: {
          'security': 'tls',
          'sni': 'vpn.example',
          'type': 'xhttp',
          'mode': mode,
          'encryption': encryption,
        },
      );
      final parsed = ExtendedProfile.parse(uri.toString());
      expect(
        parsed
            .data['outbound']['settings']['vnext'][0]['users'][0]['encryption'],
        encryption,
      );
      expect(
        parsed.data['outbound']['streamSettings']['xhttpSettings']['mode'],
        mode,
      );
      expect(
        () => ExtendedProfile.parse(
          uri
              .replace(
                queryParameters: {...uri.queryParameters, 'mode': 'invalid'},
              )
              .toString(),
        ),
        throwsFormatException,
      );
      for (final extra in [
        {
          'downloadSettings': {'address': 'elsewhere.example'},
        },
        {
          'sockopt': {'dialerProxy': 'direct'},
        },
      ]) {
        expect(
          () => ExtendedProfile.parse(
            uri
                .replace(
                  queryParameters: {
                    ...uri.queryParameters,
                    'extra': jsonEncode(extra),
                  },
                )
                .toString(),
          ),
          throwsFormatException,
        );
      }
    }
    expect(
      () => ExtendedProfile.parse(
        'vless://$uuid@vpn.example:443?security=tls&encryption=mlkem768x25519plus.native.1rtt.bad',
      ),
      throwsFormatException,
    );
  });
}
