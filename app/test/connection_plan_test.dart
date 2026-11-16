import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_plan.dart';

const goldenAwg =
    '[Interface]\nAddress = 10.7.0.2/32\nDNS = 9.9.9.9\n'
    'PrivateKey = priv\n[Peer]\nPublicKey = pub\n'
    'Endpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n';
const goldenAwgDigest =
    '39f8033617d67670c707dde7332ad7e616ef4902d4b7e6cf797e102af1611389';
const goldenXray = '{"protocol":"vless","serverName":"example.invalid","port":443}';
const goldenXrayDigest =
    'c40bb489a48a897507a8a486f6403b631ed8b518d9077a7a9102058cfc2c9542';

Map<String, dynamic> document(String mode) => {
  'selected': 'awg1',
  'connectionPolicy': {'mode': mode, 'roundMillis': 30000},
  'priorityProtocol': 'xray',
  'profiles': [
    {'id': 'awg1', 'protocol': 'awg', 'endpoint': 'one.invalid:1'},
    {'id': 'xr2', 'protocol': 'xray', 'endpoint': 'one.invalid:1'},
    {'id': 'awg3', 'protocol': 'awg', 'endpoint': 'two.invalid:2'},
  ],
  'users': [],
};

const configs = {
  'awg1': goldenAwg,
  'xr2': goldenXray,
  'awg3': goldenAwg,
};

const routing = {
  'mode': 'ipInclude',
  'packages': <String>[],
  'networks': ['10.0.0.0/8', '192.168.1.0/24'],
  'domains': ['b.example.com', 'a.example.com'],
};

void main() {
  const supported = {'awg', 'xray'};
  ConnectionPlan plan(
    Map<String, dynamic> d, {
    PolicyPlatform platform = PolicyPlatform.android,
    Object? routingPolicy = routing,
    Map<String, String?> configBytes = configs,
  }) => ConnectionPlan.fromDocument(
    d,
    supportedProtocols: supported,
    clientOnly: false,
    platform: platform,
    routing: platform == PolicyPlatform.desktop ? null : routingPolicy,
    config: (id) => configBytes[id],
  );

  test('config digest is exact UTF-8 SHA-256, including a trailing newline', () {
    expect(ConnectionPlan.configDigest(goldenAwg), goldenAwgDigest);
    expect(
      ConnectionPlan.configDigest(goldenAwg.substring(0, goldenAwg.length - 1)),
      'b5e42d837f2cb7c753fe7434430003707486498d92ab39e51af562696182b34d',
    );
    expect(ConnectionPlan.configDigest(goldenXray), goldenXrayDigest);
    expect(
      ConnectionPlan.configDigest(''),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  test('manual means the selected profile only, never another protocol', () {
    final d = document('selectedOnly');
    final value = plan(d).json;
    expect(value['ids'], ['awg1']);
    expect(value['profiles'], [
      {
        'id': 'awg1',
        'protocol': 'awg',
        'endpoint': 'one.invalid:1',
        'configDigest': goldenAwgDigest,
      },
    ]);
    expect(value['schema'], 2);
    expect(value['roundMillis'], 30000);
    expect(value['policy'], {'mode': 'selectedOnly', 'roundMillis': 30000});
  });

  test('automatic keeps selected, same endpoint, then the rest', () {
    expect(plan(document('automatic')).json['ids'], ['awg1', 'xr2', 'awg3']);
  });

  for (final selected in [null, 'missing']) {
    test('manual absent/unavailable selection $selected is empty, not repaired', () {
      final d = document('selectedOnly')..['selected'] = selected;
      final value = plan(d).json;
      expect(value['ids'], isEmpty);
      expect(value['profiles'], isEmpty);
      expect(value['selectedId'], selected);
    });
  }

  test('manual unsupported selected does not choose an available xray', () {
    expect(
      ConnectionPlan.fromDocument(
        document('selectedOnly'),
        supportedProtocols: {'xray'},
        clientOnly: false,
        routing: routing,
        config: (id) => configs[id],
      ).json['ids'],
      isEmpty,
    );
  });

  test('revoked selected account permits no alternatives', () {
    final d = document('automatic')
      ..['users'] = [
        {
          'profileIds': {'awg': 'awg1', 'xray': 'xr2'},
          'revoked': true,
        },
      ];
    expect(plan(d).json['ids'], isEmpty);
  });

  test('full account restricts other profiles, client keeps the pool rule', () {
    final d = document('automatic')
      ..['users'] = [
        {
          'profileIds': {'awg': 'awg1', 'xray': 'xr2'},
          'revoked': false,
        },
      ];
    expect(plan(d).json['ids'], ['awg1', 'xr2']);
    expect(
      ConnectionPlan.fromDocument(
        d,
        supportedProtocols: supported,
        clientOnly: true,
        routing: routing,
        config: (id) => configs[id],
      ).json['ids'],
      ['awg1', 'xr2', 'awg3'],
    );
  });

  test('unreadable non-selected config only drops that candidate', () {
    final value = plan(
      document('automatic'),
      configBytes: {'awg1': goldenAwg, 'xr2': null, 'awg3': goldenAwg},
    ).json;
    expect(value['ids'], ['awg1', 'awg3']);
    expect(value['profiles'], hasLength(2));
  });

  for (final empty in ['', '   ', '\n\t ', ' \n ']) {
    test('empty/whitespace stored config ${empty.codeUnits} is unreadable', () {
      // Empty input has a legitimate SHA-256, but it is never an admission:
      // "no configuration" cannot authorize any protocol.
      expect(
        () => plan(
          document('selectedOnly'),
          configBytes: {'awg1': empty, 'xr2': goldenXray, 'awg3': goldenAwg},
        ),
        throwsFormatException,
      );
      final automatic = plan(
        document('automatic'),
        configBytes: {'awg1': goldenAwg, 'xr2': empty, 'awg3': goldenAwg},
      ).json;
      expect(automatic['ids'], ['awg1', 'awg3']);
    });
  }

  test('unreadable selected config is POLICY_INVALID, never another profile', () {
    expect(
      () => plan(
        document('selectedOnly'),
        configBytes: {'awg1': null, 'xr2': goldenXray, 'awg3': goldenAwg},
      ),
      throwsFormatException,
    );
  });

  test('routing snapshot is typed, deduped and byte-sorted', () {
    final value = plan(
      document('selectedOnly'),
      routingPolicy: {
        'mode': 'ipInclude',
        'packages': ['org.demo', 'com.example.app', 'com.example.app'],
        'networks': ['192.168.1.0/24', '10.0.0.0/8'],
        'domains': ['B.Example.com', 'a.example.com', '*.c.example.com'],
        // Native routingGet also returns unrelated identity fields.
        'revision': 'r1',
        'resolutionId': 'n1',
      },
    ).json;
    expect(value['routing'], {
      'mode': 'ipInclude',
      'packages': ['com.example.app', 'org.demo'],
      'networks': ['10.0.0.0/8', '192.168.1.0/24'],
      'domains': ['*.c.example.com', 'a.example.com', 'b.example.com'],
    });
  });

  for (final entry in <String, Object?>{
    'unknown mode': {'mode': 'future', 'packages': [], 'networks': [], 'domains': []},
    'missing mode': {'packages': [], 'networks': [], 'domains': []},
    'non-list packages': {'mode': 'all', 'packages': 'com.x', 'networks': [], 'domains': []},
    'invalid network': {'mode': 'ipInclude', 'packages': [], 'networks': ['not an ip'], 'domains': []},
    'invalid domain': {'mode': 'ipInclude', 'packages': [], 'networks': [], 'domains': ['https://x/']},
    'wildcard package': {'mode': 'include', 'packages': ['com.*'], 'networks': [], 'domains': []},
    'absent snapshot': null,
    'non-map snapshot': 'all',
  }.entries) {
    test('android ${entry.key} is rejected, not normalized', () {
      expect(
        () => plan(document('selectedOnly'), routingPolicy: entry.value),
        throwsFormatException,
      );
    });
  }

  test('desktop publishes null routing and rejects a non-null one', () {
    expect(plan(document('selectedOnly'), platform: PolicyPlatform.desktop).json['routing'], isNull);
    expect(
      () => ConnectionPlan.fromDocument(
        document('selectedOnly'),
        supportedProtocols: supported,
        clientOnly: false,
        platform: PolicyPlatform.desktop,
        routing: routing,
        config: (id) => configs[id],
      ),
      throwsFormatException,
    );
  });

  test('priorityProtocol is copied verbatim, absent is null, wrong type rejects', () {
    expect(plan(document('automatic')).json['priorityProtocol'], 'xray');
    final absent = document('automatic')..remove('priorityProtocol');
    expect(plan(absent).json['priorityProtocol'], isNull);
    final nil = document('automatic')..['priorityProtocol'] = null;
    expect(plan(nil).json['priorityProtocol'], isNull);
    final broken = document('automatic')..['priorityProtocol'] = 7;
    expect(() => plan(broken), throwsFormatException);
  });

  test('unrelated screenshot/language changes preserve the immutable plan', () {
    final d = document('selectedOnly');
    final old = plan(d);
    d['allowScreenshots'] = true;
    d['language'] = 'en';
    expect(plan(d).bytes, old.bytes);
    d['selected'] = 'awg3';
    expect(plan(d).bytes, isNot(old.bytes));
    expect(old.json['ids'], ['awg1']);
  });

  test('strict duplicate graph/typed site check and timeout reject', () {
    final d = document('automatic');
    (d['profiles'] as List).add((d['profiles'] as List).first);
    expect(() => plan(d), throwsFormatException);
    for (final entry in <String, Object>{
      'siteCheckEnabled': 'true',
      'protocolTimeoutSeconds': 15.0,
    }.entries) {
      expect(
        () => plan(document('automatic')..[entry.key] = entry.value),
        throwsFormatException,
      );
    }
  });

  test('plan bytes are an immutable deep copy of the produced document', () {
    final value = plan(document('automatic'));
    final decoded = value.json;
    (decoded['ids'] as List).clear();
    expect(value.json['ids'], ['awg1', 'xr2', 'awg3']);
  });

  test('mixed-protocol ordering oracle: restricted preference then source order', () {
    final d = document('automatic')
      ..['selected'] = 'awg1'
      ..['priorityProtocol'] = 'rivet-h3'
      ..['profiles'] = [
        {'id': 'awg1', 'protocol': 'awg', 'endpoint': 'same.invalid:1'},
        {'id': 'x2', 'protocol': 'xray', 'endpoint': 'same.invalid:1'},
        {'id': 'x3', 'protocol': 'xray', 'endpoint': 'same.invalid:1'},
        {'id': 'r3', 'protocol': 'rivet-s1', 'endpoint': 'same.invalid:1'},
        {'id': 'h5', 'protocol': 'rivet-h3', 'endpoint': 'same.invalid:1'},
        {'id': 'o6', 'protocol': 'xray', 'endpoint': 'other.invalid:2'},
      ];
    final configs = {
      for (final profile in (d['profiles'] as List).cast<Map>())
        profile['id'] as String: 'cfg-${profile['id']}',
    };
    final value = ConnectionPlan.fromDocument(
      d,
      supportedProtocols: {'xray', 'rivet-s1', 'awg', 'rivet-h3'},
      clientOnly: false,
      platform: PolicyPlatform.desktop,
      routing: null,
      config: (id) => configs[id],
    ).json;
    // Selected first; within the same endpoint the preferred protocol wins
    // (rivet-h3), then restricted-list order xray/rivet-s1, with source
    // document order as the only tie-break; other endpoints come last.
    expect(value['ids'], ['awg1', 'h5', 'x2', 'x3', 'r3', 'o6']);
    expect(value['priorityProtocol'], 'rivet-h3');
  });}
