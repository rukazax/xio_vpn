import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:x1o/core.dart';

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
  test('Shadowsocks SIP002 passwords with colon and IPv6', () {
    final user = base64Url
        .encode(utf8.encode('aes-256-gcm:a:password'))
        .replaceAll('=', '');
    final p = ExtendedProfile.parse('ss://$user@[2001:db8::1]:8388#SS');
    expect(p.protocol, 'shadowsocks');
    expect(p.endpoint, '[2001:db8::1]:8388');
    expect(
      p.data['outbound']['settings']['servers'][0]['password'],
      'a:password',
    );
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
  const ovpn =
      'client\ndev tun\nremote example.org 1194\nremote-cert-tls server\n<auth-user-pass>\nusername\npassword\n</auth-user-pass>\n<ca>\nCERTIFICATE-FIXTURE\n</ca>\n<cert>\nCLIENT-CERT-FIXTURE\n</cert>\n<tls-crypt-v2>\nTLS-CRYPT-FIXTURE\n</tls-crypt-v2>\n';
  test(
    'OpenVPN embedded credentials do not drop following certificate blocks',
    () {
      final p = ExtendedProfile.parse(ovpn);
      expect(p.protocol, 'openvpn');
      expect(p.data['username'], 'username');
      expect(
        p.data['config'],
        contains('<cert>\nCLIENT-CERT-FIXTURE\n</cert>'),
      );
      expect(p.data['config'], contains('auth-user-pass\n'));
      expect(p.data['config'], isNot(contains('password')));
    },
  );
  test('OpenVPN rejects scripts, compression and referenced files', () {
    for (final extra in [
      'up /tmp/run',
      'ca /etc/passwd',
      'compress lz4',
      'auth-user-pass /tmp/secret',
    ]) {
      expect(
        () => ExtendedProfile.parse('$ovpn\n$extra'),
        throwsFormatException,
      );
    }
  });
  test('XIO bundle accepts all integrated engines without engine selector', () {
    final key = base64Url.encode(utf8.encode('aes-256-gcm:test'));
    final p = ExtendedProfile.parse('ss://$key@example.org:8388');
    final b = UserBundle(
      'test',
      '0123456789abcdef0123456789abcdef',
      'b3b2eb49-e41f-41df-9761-0956785a236b',
      {'shadowsocks': p.encoded},
    );
    expect(ClientImport.parse(b.encode()).bundle!.configs.keys, [
      'shadowsocks',
    ]);
  });
}
