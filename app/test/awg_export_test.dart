import 'package:flutter_test/flutter_test.dart';
import 'package:xio/awg_export.dart';

const _base = '''
[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.78.0.7/24, fd78:1::7/64
DNS = 9.9.9.9, 2620:fe::fe
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 32
S2 = 40
H1 = 118262
H2 = 251233
H3 = 327867
H4 = 418217
I1 = <b 0x0102030405>

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 81.177.142.37:51821
PersistentKeepalive = 25
''';

void main() {
  test('normalises a stored profile into a full-tunnel import', () {
    final profile = AwgProfile.parse(_base);
    expect(profile.endpoint, '81.177.142.37:51821');
    expect(profile.host, '81.177.142.37');
    expect(profile.obfuscated, isTrue);
    expect(profile.text, contains('AllowedIPs = 0.0.0.0/0, ::/0'));
    expect(profile.text, contains('Jc = 4'));
    expect(profile.text, contains('I1 = <b 0x0102030405>'));
    expect(profile.text, contains('Endpoint = 81.177.142.37:51821'));
    expect(profile.text, isNot(contains('10.78.0.0/24')));
    expect(profile.text.indexOf('[Interface]'), 0);
    expect(profile.text.indexOf('[Peer]'), greaterThan(0));
  });

  test('keeps an IPv6 endpoint bracket intact', () {
    final profile = AwgProfile.parse(
      _base.replaceAll('81.177.142.37:51821', '[2001:db8::1]:51821'),
    );
    expect(profile.endpoint, '[2001:db8::1]:51821');
    expect(profile.host, '2001:db8::1');
  });

  test('adds DNS and MTU when the server omitted them', () {
    final profile = AwgProfile.parse('''
[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.78.0.2/24
[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = 203.0.113.9:51821
''');
    expect(profile.text, contains('DNS = '));
    expect(profile.text, contains('MTU = 1280'));
  });

  test('rejects a profile without the private key', () {
    expect(
      () => AwgProfile.parse(_base.replaceAll('PrivateKey', 'FakeKey')),
      throwsA(isA<AwgExportError>()),
    );
  });

  test('rejects plain text and empty input', () {
    expect(() => AwgProfile.parse('hello'), throwsA(isA<AwgExportError>()));
    expect(() => AwgProfile.parse(''), throwsA(isA<AwgExportError>()));
  });

  test('does not force IPv6 when the server profile has none', () {
    final profile = AwgProfile.parse(
      _base.replaceAll('AllowedIPs = 0.0.0.0/0, ::/0', 'AllowedIPs = 0.0.0.0/0'),
    );
    expect(profile.text, contains('AllowedIPs = 0.0.0.0/0\n'));
    expect(profile.text, isNot(contains('::/0')));
  });

  test('file name is portable', () {
    expect(AwgProfile.fileName('Дача / router #1'), 'router-1.conf');
    expect(AwgProfile.fileName('router-jeton'), 'router-jeton.conf');
  });
}
