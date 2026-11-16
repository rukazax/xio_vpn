import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_plan.dart';
import 'package:xio/core.dart';
import 'package:xio/legal_record.dart';

/// Emits the coordinated desktop validation fixture from the actual Store
/// serializer. Run manually:
///   flutter test --no-pub test/desktop_projection_fixture_test.dart
/// copy the single-line FIXTURE stdout into
/// test/fixtures/desktop-validation-projection.json; the second test keeps the
/// committed file byte-identical to the current serializer.
// Syntactically valid AmneziaWG configs taken from the current native parser
// fixture shape (protocol/rivet/internal/desktop/profile_test.go): base64 keys,
// Address/DNS, Peer/PublicKey/Endpoint/AllowedIPs. Synthetic, no real secrets.
const _awgKey = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';
const _awgPeer = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=';
String _awg(String address, String endpoint) =>
    '[Interface]\nPrivateKey = $_awgKey\nAddress = $address\nDNS = 1.1.1.1\n'
    '[Peer]\nPublicKey = $_awgPeer\nEndpoint = $endpoint\n'
    'AllowedIPs = 0.0.0.0/0, ::/0\n';

final _documentConfigs = {
  'awg1': _awg('10.77.0.2/32', '203.0.113.4:51820'),
  'awg2': _awg('10.77.0.3/32', '203.0.113.4:51820'),
  'rv1': _awg('10.77.0.4/32', '203.0.113.5:51820'),
};

// Previous hash-only goldens are preserved separately and are NOT parser-valid;
// they must never be used as a validate happy-path fixture.
const _legacyHashGoldens = {
  'awg1': {
    'config': '[Interface]\nPrivateKey = priv\n[Peer]\nPublicKey = pub\n'
        'Endpoint = 203.0.113.9:51820\n',
    'sha256': 'e326d3839b2340ab9feb51ac8c17052a606367232d7e2f5ad39f7f3f48c692af',
  },
  'xr1': {
    'config': '{"protocol":"vless","serverName":"example.invalid","port":443}',
    'sha256': 'c40bb489a48a897507a8a486f6403b631ed8b518d9077a7a9102058cfc2c9542',
  },
};

Map<String, dynamic> build() {
  const profiles = [
    Profile(id: 'awg1', name: 'home', protocol: 'awg', endpoint: '203.0.113.4:51820'),
    Profile(id: 'awg2', name: 'home-alt', protocol: 'awg', endpoint: '203.0.113.4:51820'),
    Profile(id: 'rv1', name: 'other', protocol: 'awg', endpoint: '203.0.113.5:51820'),
  ];
  final store = AppStore(nativeTunnelOverride: true)
    ..selectedId = 'awg1'
    ..connectionPolicyForTesting = ConnectionPolicy.selectedOnly
    ..checkSite = 'https://probe.invalid/check'
    ..siteCheckEnabled = true
    ..protocolTimeoutSeconds = 25
    ..autoReconnect = false
    ..allowScreenshots = true
    ..legalRecord = const LegalRecord(
      '2026-10-18',
      '2026-11-06T07:00:00.000Z',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'ru',
    )
    ..vpnDisclosure = vpnDisclosureRevision;
  store.profiles.addAll(profiles);
  store.users.addAll([
    ManagedUser(
      id: 'b' * 32,
      name: 'owner',
      serverId: 'srv',
      profileIds: const {'awg': 'awg1', 'awg-alt': 'awg2'},
    ),
    ManagedUser(
      id: 'c' * 32,
      name: 'revoked',
      serverId: 'srv2',
      profileIds: const {'awg-other': 'rv1'},
    )..revoked = true,
  ]);
  final base = Map<String, dynamic>.from(store.documentPayload());
  // Legacy variant: absence of the property is the ONLY automatic default.
  base.remove('priorityProtocol');
  store.dispose();

  Map<String, dynamic> variant({
    required Map<String, dynamic> document,
    required String transactionId,
    required String planGeneration,
  }) {
    final plan = ConnectionPlan.fromDocument(
      document,
      supportedProtocols: {'awg'},
      clientOnly: false,
      platform: PolicyPlatform.desktop,
      routing: null,
      config: (id) => _documentConfigs[id],
    ).json;
    final withReceipt = Map<String, dynamic>.from(document)
      ..['connectionPlanReceipt'] = {
        'schema': 1,
        'transactionId': transactionId,
        'planGeneration': planGeneration,
        'plan': plan,
      };
    final bytes = utf8.encode(jsonEncode(withReceipt));
    final digest = crypto.sha256.convert(bytes).toString();
    // Exact correspondence: only the plan's own ids, in plan order.
    final planIds = (plan['ids'] as List).cast<String>();
    final configs = [
      for (final id in planIds)
        {
          'id': id,
          'bytesBase64': base64Encode(utf8.encode(_documentConfigs[id]!)),
          'sha256': crypto.sha256
              .convert(utf8.encode(_documentConfigs[id]!))
              .toString(),
        },
    ];
    return {
      'transactionId': transactionId,
      'planGeneration': planGeneration,
      'document': withReceipt,
      'documentBytesBase64': base64Encode(bytes),
      'documentDigest': digest,
      'plan': plan,
      'configs': configs,
    };
  }

  final manualDocument = Map<String, dynamic>.from(base)
    ..['connectionPolicy'] = {'mode': 'selectedOnly', 'roundMillis': 30000};
  final automaticDocument = Map<String, dynamic>.from(base)
    ..['connectionPolicy'] = {'mode': 'automatic', 'roundMillis': 30000};
  final manual = variant(
    document: manualDocument,
    transactionId: 'd' * 32,
    planGeneration: 'e' * 32,
  );
  final automatic = variant(
    document: automaticDocument,
    transactionId: '3' * 32,
    planGeneration: '4' * 32,
  );

  Map<String, Object?> validateRequest(Map<String, dynamic> variant) => {
    'version': 1,
    'storeIdentity': 'f' * 64,
    'controllerNonce': '2' * 32,
    'instanceNonce': '1' * 32,
    'transactionId': variant['transactionId'],
    'expectedGeneration': null,
    'planGeneration': variant['planGeneration'],
    'plan': variant['plan'],
    'validation': {
      'schema': 1,
      'documentDigest': variant['documentDigest'],
      'documentBytesBase64': variant['documentBytesBase64'],
      'configs': [
        for (final config in (variant['configs'] as List).cast<Map>())
          {'id': config['id'], 'bytesBase64': config['bytesBase64']},
      ],
    },
  };

  return {
    'schema': 1,
    'note': 'desktop validation fixture generated from the actual AppStore '
        'serializer; legacy absent priorityProtocol; manual and automatic '
        'variants each carry a consistent document policy + embedded receipt',
    'storeIdentity': 'f' * 64,
    'instanceNonce': '1' * 32,
    'controllerNonce': '2' * 32,
    // Not a validate happy path until the independent Go parser lane ACCEPTs.
    'parserAcceptance': 'pending-independent-Go-parser-lane',
    'legacyHashGoldens': _legacyHashGoldens,
    'manual': {...manual, 'validateRequest': validateRequest(manual)},
    'automatic': {...automatic, 'validateRequest': validateRequest(automatic)},
  };
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('emit fixture', () {
    final text = jsonEncode(build());
    // ignore: avoid_print
    print('FIXTURE_SHA256 ${crypto.sha256.convert(utf8.encode(text))}');
    // ignore: avoid_print
    print('FIXTURE_BYTES ${utf8.encode(text).length}');
    // ignore: avoid_print
    print('FIXTURE_BEGIN$text');
  });

  test('committed fixture matches the actual serializer', () {
    final file = File('test/fixtures/desktop-validation-projection.json');
    if (!file.existsSync()) return;
    final committed = jsonDecode(file.readAsStringSync()) as Map;
    final generated = build();
    expect(
      crypto.sha256.convert(utf8.encode(jsonEncode(generated))).toString(),
      crypto.sha256.convert(utf8.encode(jsonEncode(committed))).toString(),
    );
  });

  test('config ids match plan ids exactly and acceptance is not claimed', () {
    final value = build();
    for (final name in ['manual', 'automatic']) {
      final variant = value[name] as Map;
      final ids = (variant['plan']['ids'] as List).cast<String>();
      final request = variant['validateRequest'] as Map;
      final configIds = ((request['validation'] as Map)['configs'] as List)
          .map((entry) => (entry as Map)['id'])
          .toList();
      expect(configIds, ids, reason: 'configs must match plan.ids for $name');
    }
    expect(value['parserAcceptance'], 'pending-independent-Go-parser-lane');
  });

  test('LegalRecord timestamp equivalence used by the projection', () {
    const base = {
      'revision': '2026-10-18',
      'textSha256':
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'language': 'ru',
    };
    for (final timestamp in [
      '2026-11-06T07:00:00Z',
      '2026-11-06T07:00:00z',
      '2026-11-06T07:00:00+00:00',
      '2026-11-06T10:00:00+03:00',
      '2026-11-06T07:00:00.000Z',
    ]) {
      expect(
        LegalRecord.parse({...base, 'timestamp': timestamp}),
        isNotNull,
        reason: timestamp,
      );
    }
    expect(
      LegalRecord.parse({...base, 'timestamp': '2026-11-06T07:00:00'}),
      isNull,
    );
  });}
