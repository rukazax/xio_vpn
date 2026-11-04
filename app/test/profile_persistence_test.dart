import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

/// Profile parsing/serialization covers both halves of persistence:
///
/// * the plain `Profile` JSON shape that is written into `profiles.json`, and
/// * a real `AppStore.save()` → `AppStore.load()` cycle on a temporary
///   directory, so the parser and the writer cannot drift apart silently.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory directory;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('xio-profiles-');
  });
  tearDown(() async {
    if (directory.existsSync()) await directory.delete(recursive: true);
  });

  test('profile JSON round-trips unicode names and IPv6 endpoints', () {
    const profile = Profile(
      id: 'awg1',
      name: 'Дом · Москва',
      protocol: 'awg',
      endpoint: '[2001:db8::7]:51821',
    );
    final json = profile.toJson();
    expect(json, {
      'id': 'awg1',
      'name': 'Дом · Москва',
      'protocol': 'awg',
      'endpoint': '[2001:db8::7]:51821',
    });
    final restored = Profile.fromJson(
      Map<String, dynamic>.from(jsonDecode(jsonEncode(json)) as Map),
    );
    expect(restored.id, profile.id);
    expect(restored.name, profile.name);
    expect(restored.protocol, profile.protocol);
    expect(restored.endpoint, profile.endpoint);
    expect(restored.toJson(), json);
  });

  test('save/load keeps profiles and the selected id', () async {
    const profiles = <Profile>[
      Profile(
        id: 'xr1',
        name: 'Первый',
        protocol: 'xray',
        endpoint: 'vpn.example.org:443',
      ),
      Profile(
        id: 'awg1',
        name: 'Amnezia',
        protocol: 'awg',
        endpoint: '[2001:db8::1]:51821',
      ),
    ];
    final store = AppStore()..directory = directory;
    store.profiles.addAll(profiles);
    store.selectedId = 'awg1';
    await store.save();

    final reloaded = AppStore()..directory = directory;
    await reloaded.load();
    expect(
      reloaded.profiles.map((profile) => profile.toJson()).toList(),
      profiles.map((profile) => profile.toJson()).toList(),
    );
    expect(reloaded.selectedId, 'awg1');

    // A second save must be idempotent: no duplicated profiles, same payload.
    await reloaded.save();
    final payload = File('${directory.path}/profiles.json').readAsStringSync();
    final decoded = jsonDecode(payload) as Map<String, dynamic>;
    expect((decoded['profiles'] as List), hasLength(2));
    expect(decoded['selected'], 'awg1');
  });

  test('foreign profiles.json parses and drops unknown protocols', () async {
    // Shaped like a file written by another build: unknown protocol, stale
    // selection and an extra key the current schema does not know.
    File('${directory.path}/profiles.json').writeAsStringSync(
      jsonEncode({
        'schema': 2,
        'profiles': [
          {
            'id': 'xr1',
            'name': 'Keep',
            'protocol': 'xray',
            'endpoint': 'vpn.example.org:443',
          },
          {
            'id': 'legacy',
            'name': 'Drop',
            'protocol': 'openvpn',
            'endpoint': 'old.example.org:1194',
          },
        ],
        'selected': 'legacy',
        'unknownField': {'ignored': true},
      }),
    );
    final store = AppStore()..directory = directory;
    await store.load();
    expect(store.profiles.map((profile) => profile.id).toList(), ['xr1']);
    // The stale selection falls back to the first surviving profile.
    expect(store.selectedId, 'xr1');
  });
}
