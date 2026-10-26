import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

void main() {
  test('retired engines are absent from the supported catalogue', () {
    expect(nativeProtocols.toSet(), {
      'xray',
      'rivet-s1',
      'rivet-h3',
      'awg',
      'cloak',
    });
    for (final value in [
      'tailscale',
      'headscale',
      'wireguard',
      'openvpn',
      'ikev2',
      'shadowsocks',
    ]) {
      expect(nativeProtocols, isNot(contains(value)));
    }
  });
}
