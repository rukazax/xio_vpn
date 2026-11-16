import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/native_cascade_plan.dart';

const v4 = NativeCascadeFamily.ipv4;
const v6 = NativeCascadeFamily.ipv6;
final _pin = 'SHA256:${'A' * 43}';
NativeCascadeTarget _bridge({
  String id = 'bridge-id',
  String host = '198.51.100.10',
}) => NativeCascadeTarget(
  serverId: id,
  hostKey: _pin,
  publicHost: host,
  exit: false,
);
NativeCascadeTarget _exit({
  String id = 'exit-id',
  String host = '2001:db8::20',
}) => NativeCascadeTarget(
  serverId: id,
  hostKey: _pin,
  publicHost: host,
  exit: true,
);
NativeCascadePlan _plan({
  Set<NativeCascadeFamily> families = const {v4, v6},
  String host = '2001:db8::20',
}) => NativeCascadePlan(
  bridge: _bridge(),
  exit: _exit(host: host),
  families: families,
  exitInterfaces: {for (final family in families) family: 'eth0'},
);
String _b64(String hex) => base64Encode([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);
// Public RFC7748 test vectors, not installation/private user material.
Map<String, String> _vectors() => {
  'schema': '1',
  'bridgePrivate': _b64(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  ),
  'bridgePublic': _b64(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  ),
  'exitPrivate': _b64(
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  ),
  'exitPublic': _b64(
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  ),
  'preshared': base64Encode(List<int>.filled(32, 42)),
};

void main() {
  test('targets use canonical literal exit and exact verified identities', () {
    expect(_exit(host: '[2001:0DB8:0:0::20]').publicHost, '2001:db8::20');
    expect(_bridge(host: 'BRIDGE.Example').publicHost, 'bridge.example');
    for (final bad in [
      '',
      '127.1',
      '010.1.2.3',
      'exit.example',
      '1.2.3.4:443',
      '::1%eth0',
      "1.2.3.4' ; id",
    ]) {
      expect(() => _exit(host: bad), throwsFormatException, reason: bad);
    }
    for (final bad in ['', 'pin', '$_pin\n']) {
      expect(
        () => NativeCascadeTarget(
          serverId: 'server',
          hostKey: bad,
          publicHost: '1.2.3.4',
          exit: true,
        ),
        throwsFormatException,
      );
    }
    expect(() => _bridge(id: ' bridge-id'), throwsFormatException);
  });
  test('no same installation or guessed exit target', () {
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: _exit(id: 'bridge-id'),
        families: {v4},
        exitInterfaces: {v4: 'eth0'},
      ),
      throwsFormatException,
    );
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: _exit(host: '198.51.100.10'),
        families: {v4},
        exitInterfaces: {v4: 'eth0'},
      ),
      throwsFormatException,
    );
    final dns = _bridge(id: 'different-id', host: 'exit.example');
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: dns,
        families: {v4},
        exitInterfaces: {v4: 'eth0'},
      ),
      throwsFormatException,
    );
  });
  test('endpoint family never guesses supported inner egress', () {
    expect(_plan(families: {v4}, host: '2001:db8::20').familyNames, ['ipv4']);
    expect(_plan(families: {v6}, host: '203.0.113.20').familyNames, ['ipv6']);
    expect(_plan(host: '203.0.113.20').familyNames, ['ipv4', 'ipv6']);
  });
  test('explicit family and safe physical egress map required', () {
    for (final bad in [
      '',
      'eth0\n',
      'eth0;id',
      '/dev/eth0',
      'xiocascade0',
      'xioawg0',
      'xiorivet',
      'abcdefghijklmnop',
    ]) {
      expect(
        () => NativeCascadePlan(
          bridge: _bridge(),
          exit: _exit(),
          families: {v4},
          exitInterfaces: {v4: bad},
        ),
        throwsFormatException,
        reason: bad,
      );
    }
    for (final bad in [0, 65536, -1]) {
      expect(
        () => NativeCascadePlan(
          bridge: _bridge(),
          exit: _exit(),
          families: {v4},
          exitInterfaces: {v4: 'eth0'},
          exitPort: bad,
        ),
        throwsFormatException,
      );
    }
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: _exit(),
        families: {},
        exitInterfaces: {},
      ),
      throwsFormatException,
    );
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: _exit(),
        families: {v4, v6},
        exitInterfaces: {v4: 'eth0'},
      ),
      throwsFormatException,
    );
    expect(
      () => NativeCascadePlan(
        bridge: _bridge(),
        exit: _exit(),
        families: {v4},
        exitInterfaces: {v4: 'eth0', v6: 'eth0'},
      ),
      throwsFormatException,
    );
  });
  test('intent snapshots cannot drift with caller collections', () {
    final families = <NativeCascadeFamily>{v4};
    final interfaces = <NativeCascadeFamily, String>{v4: 'eth0'};
    final plan = NativeCascadePlan(
      bridge: _bridge(),
      exit: _exit(),
      families: families,
      exitInterfaces: interfaces,
    );
    final identity = plan.identity;
    families.add(v6);
    interfaces[v4] = 'evil0';
    expect(plan.familyNames, ['ipv4']);
    expect(plan.exitInterfaces[v4], 'eth0');
    expect(plan.identity, identity);
    expect(() => plan.families.add(v6), throwsUnsupportedError);
    expect(() => plan.exitInterfaces[v4] = 'changed', throwsUnsupportedError);
  });
  test('public plan stable roundtrip and set-order-independent identity', () {
    final plan = _plan();
    expect(
      NativeCascadePlan.fromJson(jsonDecode(jsonEncode(plan.toJson())))
          .identity,
      plan.identity,
    );
    expect(_plan(families: {v6, v4}).identity, plan.identity);
    expect(_plan(families: {v4}).identity, isNot(plan.identity));
    expect(_plan(host: '203.0.113.20').identity, isNot(plan.identity));
    expect(plan.toJson()['sourceMode'], 'hop-snat');
  });
  test('journal plan rejects unknown fields/modes/families/schema', () {
    final cases = <Map<String, Object>>[
      {..._plan().toJson(), 'privateKey': 'not allowed'},
      {..._plan().toJson(), 'sourceMode': 'preserve'},
      {..._plan().toJson(), 'schema': 2},
      {..._plan().toJson(), 'schema': 1.0},
      {
        ..._plan().toJson(),
        'innerFamilies': ['ipv4', 'ipv4'],
      },
      {
        ..._plan().toJson(),
        'innerFamilies': ['IPv4'],
      },
      {..._plan().toJson(), 'exitPort': '9443'},
      {
        ..._plan().toJson(),
        'exitInterfaces': {'ipv4': 'eth0', 'ipv6': 7},
      },
    ];
    for (final value in cases) {
      expect(() => NativeCascadePlan.fromJson(value), throwsFormatException);
    }
  });
  test(
    'configuration hashes match the real Python connector normalizer',
    () async {
      final keys = await NativeCascadeKeys.fromVault(_vectors());
      expect(
        _plan().configurationHash(NativeCascadeRole.bridge, keys),
        '0d96f1e7a5d9702c9998cc4d77a3156cfd84a0c9b067aea76c7aa9a60e805378',
      );
      expect(
        _plan().configurationHash(NativeCascadeRole.exit, keys),
        'ed6a92120f7306d03a1b114605d9c28a1d9401f4e5a57c3d3a68927292be76c9',
      );
    },
  );

  test('RFC7748 keys restore and recover exact secret material', () async {
    final keys = await NativeCascadeKeys.fromVault(_vectors());
    expect(keys.toVault(), _vectors());
    expect(keys.toString(), 'NativeCascadeKeys([redacted])');
  });
  test('generated keys are distinct, canonical and recoverable', () async {
    final keys = await NativeCascadeKeys.generate();
    expect(keys.bridgePublic, isNot(keys.exitPublic));
    final restored = await NativeCascadeKeys.fromVault(keys.toVault());
    expect(restored.toVault(), keys.toVault());
    for (final field in keys.toVault().entries.where(
      (e) => e.key != 'schema',
    )) {
      expect(base64Decode(field.value), hasLength(32));
    }
  });
  test('corrupt vault records reject without echoing private data', () async {
    for (final patch in <Map<String, String>>[
      {'schema': '2'},
      {'extra': 'not allowed'},
      {'bridgePrivate': 'PRIVATE_SENTINEL'},
      {'bridgePublic': _vectors()['exitPublic']!},
      {'preshared': '${_vectors()['preshared']}\n'},
      {
        'exitPrivate': _vectors()['bridgePrivate']!,
        'exitPublic': _vectors()['bridgePublic']!,
      },
    ]) {
      try {
        await NativeCascadeKeys.fromVault({..._vectors(), ...patch});
        fail('accepted corrupt record');
      } on FormatException catch (error) {
        expect(error.toString(), isNot(contains('PRIVATE_SENTINEL')));
      }
    }
  });
  test('paired configs move keys both ways and use hop-snat for overlapping full nodes', () async {
    final keys = await NativeCascadeKeys.fromVault(_vectors());
    final bridge = _plan().configuration(NativeCascadeRole.bridge, keys);
    final exit = _plan().configuration(NativeCascadeRole.exit, keys);
    expect((bridge['peer'] as Map)['publicKey'], keys.exitPublic);
    expect((exit['peer'] as Map)['publicKey'], keys.bridgePublic);
    expect((bridge['peer'] as Map)['host'], '2001:db8::20');
    expect((exit['peer'] as Map).containsKey('host'), isFalse);
    expect(bridge['localAddresses'], exit['peerAddresses']);
    expect(exit['localAddresses'], bridge['peerAddresses']);
    expect(bridge['sourceMode'], 'hop-snat');
    expect(exit['sourceMode'], 'hop-snat');
    expect(bridge['privateKey'], _vectors()['bridgePrivate']);
    expect(exit['privateKey'], _vectors()['exitPrivate']);
    expect(exit['presharedKey'], bridge['presharedKey']);
  });
  test(
    'ordinary plan/public config serialization never contains tunnel secrets',
    () async {
      final keys = await NativeCascadeKeys.fromVault(_vectors());
      final public = jsonEncode([
        _plan().toJson(),
        _plan().publicConfiguration(NativeCascadeRole.bridge, keys),
        _plan().publicConfiguration(NativeCascadeRole.exit, keys),
      ]);
      expect(public, isNot(contains('privateKey')));
      expect(public, isNot(contains('preshared')));
      for (final name in ['bridgePrivate', 'exitPrivate', 'preshared']) {
        expect(public, isNot(contains(_vectors()[name]!)));
      }
      expect(
        () => jsonEncode(keys),
        throwsA(isA<JsonUnsupportedObjectError>()),
      );
    },
  );
}
