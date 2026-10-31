import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

Map<String, dynamic> fixture(String protocol) => {
  'protocol': protocol,
  'endpoint': 'vpn.example:8443',
  'serverName': 'vpn.example',
  'pin': base64Encode(List.filled(32, 1)),
  'gatewayId': base64Encode(List.filled(16, 2)),
  'id': 'a' * 32,
  'secret': base64Encode(List.filled(32, 3)),
  'entryToken': base64Encode(List.filled(32, 4)),
  'ip': '10.79.0.2',
};
void main() {
  test('IPv6 endpoints and inner addresses stay bound to the authenticated user slot', () {
    for (final protocol in rivetProtocols) {
      final value = {
        ...fixture(protocol),
        'endpoint': '[2001:db8::1]:8443',
        'ip6': 'fd79:1::2',
      };
      expect(
        RivetProfile.parse(jsonEncode(value)).endpoint,
        '[2001:db8::1]:8443',
      );
      for (final wrong in ['fd79:1::3', '2001:db8::2', true]) {
        expect(
          () => RivetProfile.parse(jsonEncode({...value, 'ip6': wrong})),
          throwsFormatException,
        );
      }
    }
  });
  test(
    'automatic plan contains only supported engines and respects maintenance',
    () {
      final store = AppStore(nativeTunnelOverride: true);
      for (final id in nativeProtocols) {
        store.profiles.add(
          Profile(id: id, name: id, protocol: id, endpoint: 'test.invalid:443'),
        );
      }
      store.users.add(
        ManagedUser(
          id: 'a' * 32,
          name: 'test',
          serverId: 's',
          profileIds: {for (final id in nativeProtocols) id: id},
        ),
      );
      expect(
        store.connectionCandidates(store.profiles.first).map((p) => p.protocol),
        restrictedNetworkProtocols,
      );
      store.serverMaintenance = true;
      expect(store.connectionCandidates(store.profiles.first), isEmpty);
      store.serverMaintenance = false;
      store.users.clear();
      // Without a managed user the selected profile stays first, and the other
      // local profiles follow it as fallbacks (same principle on every build).
      final withoutUser = store.connectionCandidates(store.profiles.first);
      expect(withoutUser.first.protocol, nativeProtocols.first);
      expect(withoutUser.length, greaterThan(1));
      store.dispose();
    },
  );
  test(
    'protocol preference keeps paired RIVET fallback before legacy paths',
    () {
      final paths = ['wireguard', 'awg', 'rivet-h3', 'rivet-s1'];
      paths.sort(
        (a, b) => protocolPreference(
          a,
          'rivet-h3',
        ).compareTo(protocolPreference(b, 'rivet-h3')),
      );
      expect(paths, ['rivet-h3', 'rivet-s1', 'awg', 'wireguard']);
      expect(protocolPreference('rivet-h3', 'rivet-h3'), 0);
    },
  );
  test(
    'RIVET client profiles detect both transports without engine selection',
    () {
      for (final p in rivetProtocols) {
        final raw = jsonEncode(fixture(p));
        expect(ClientImport.parse(raw).protocol, p);
        expect(ClientImport.detect(raw), p);
      }
    },
  );
  test('multi-protocol export preserves all four keys without SSH access', () {
    final b = UserBundle('A', 'a' * 32, 's', {
      'rivet-h3': jsonEncode(fixture('rivet-h3')),
      'rivet-s1': jsonEncode(fixture('rivet-s1')),
      'wireguard': 'wg',
      'awg': 'awg',
    });
    final decoded = UserBundle.decode(b.encode());
    expect(decoded.configs.keys.toSet(), {'rivet-h3', 'rivet-s1', 'awg'});
    expect(decoded.adminAccess, isNull);
  });
  test(
    'reject unsafe endpoints, unsupported fields and inconsistent credentials',
    () {
      for (final patch in <Map<String, dynamic>>[
        {'endpoint': 'u:p@vpn.example:8443'},
        {'endpoint': 'vpn.example:8443/path'},
        {'endpoint': 'vpn.example:8443?q=x'},
        {'endpoint': 'vpn.example'},
        {'ip': '10.79.0.1'},
        {'ip': '10.79.0.255'},
        {'ip': '192.168.1.2'},
        {'pin': base64Encode(List.filled(31, 1))},
        {'id': '../x'},
        {'entryToken': base64Encode(List.filled(32, 3))},
        {'insecureSkipVerify': true},
        {'secret': 'bad'},
      ]) {
        expect(
          () => RivetProfile.parse(
            jsonEncode({...fixture('rivet-h3'), ...patch}),
          ),
          throwsFormatException,
          reason: patch.keys.join(','),
        );
      }
    },
  );
}
