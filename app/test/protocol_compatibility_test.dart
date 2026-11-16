import 'dart:io';


import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/build_identity.dart';
import 'package:xio/protocol_compatibility.dart';

import 'rivet_profile_test.dart' show fixture;
import 'security_test.dart' show profile;

class LimitedEngineStore extends AppStore {
  final Set<String> engines;
  LimitedEngineStore(this.engines) : super(nativeTunnelOverride: true);
  @override
  Set<String> get supportedProtocols => engines;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('wire export preserves all protocols regardless of runtime target', () {
    final xray = ClientImport.parse(
      'vless://b3b2eb49-e41f-41df-9761-0956785a236b@example.org:443?security=tls&sni=example.org',
    ).config!;
    final configs = {
      'awg': profile(extra: 'Jc = 4'),
      'rivet-h3': jsonEncode(fixture('rivet-h3')),
      'rivet-s1': jsonEncode(fixture('rivet-s1')),
      'xray': xray,
    };
    for (final target in ClientPlatform.values) {
      final restored = UserBundle.decode(
        UserBundle('Portable', 'a' * 32, 'server', configs).encode(),
      );
      expect(restored.configs, configs, reason: target.name);
      expect(restored.configs.keys.toSet(), universalProtocolIds);
      expect(restored.adminAccess, isNull);
    }
  });
  test(
    'unimplemented engines are explicit and not simulated by reducing Android',
    () {
      expect(missingProtocolsFor(ClientPlatform.android), isEmpty);
      expect(missingProtocolsFor(ClientPlatform.windows), isEmpty);
      expect(missingProtocolsFor(ClientPlatform.ubuntu), isEmpty);
      expect(missingProtocolsFor(ClientPlatform.ios), {'xray', 'awg'});
      expect(completeProtocolParity, isFalse);
    },
  );
  test(
    'client and administrative desktop storage identities stay separate',
    () {
      expect(
        credentialProductDirectory,
        clientOnlyBuild ? 'app.xio.client' : 'app.xio.xio',
      );
      expect(
        desktopProductDirectory(windows: true),
        clientOnlyBuild ? 'xio-client' : 'xio',
      );
      expect(
        desktopProductDirectory(windows: false),
        clientOnlyBuild ? 'app.xio.client' : 'app.xio.xio',
      );
    },
  );

  test(
    'limited native engines retain every imported profile for re-export',
    () async {
      final configs = {
        'awg': profile(extra: 'Jc = 4'),
        'rivet-h3': jsonEncode(fixture('rivet-h3')),
        'rivet-s1': jsonEncode(fixture('rivet-s1')),
        'xray': ClientImport.parse(
          'vless://b3b2eb49-e41f-41df-9761-0956785a236b@example.org:443?security=tls&sni=example.org',
        ).config!,
      };
      for (final target in ClientPlatform.values) {
        final saved = <String, String>{};
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, (call) async {
              final args = Map<String, dynamic>.from(
                call.arguments as Map? ?? {},
              );
              if (call.method == 'saveConfig') {
                saved[args['id']] = args['config'];
                return null;
              }
              if (call.method == 'readConfig') return saved[args['id']];
              return null;
            });
        final folder = await Directory.systemTemp.createTemp(
          'xio-portable-test-',
        );
        try {
          final store = LimitedEngineStore(nativeProtocolTargets[target]!)
            ..directory = folder;
          final imported = await store.importBundle(
            ClientImport.parse(
              UserBundle('Portable', 'a' * 32, 'server', configs).encode(),
            ).bundle!,
          );
          final exported = ClientImport.parse(
            (await store.exportUser(imported)).encode(),
          ).bundle!;
          expect(
            exported.configs.keys.toSet(),
            universalProtocolIds,
            reason: target.name,
          );
          expect(exported.userId, 'a' * 32);
          expect(exported.serverId, 'server');
          expect(exported.adminAccess, isNull);
          for (final kind in configs.keys) {
            expect(ClientImport.detect(exported.configs[kind]!), kind);
          }
        } finally {
          await folder.delete(recursive: true);
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
              .setMockMethodCallHandler(native, null);
        }
      }
    },
  );

  test('OpenVPN / Cloak profiles are rejected, not repaired', () {
    expect(
      () => ExtendedProfile.parse(
        jsonEncode({
          'protocol': 'cloak',
          'config': 'client\ndev tun\n',
          'cloak': <String, Object?>{},
        }),
      ),
      throwsFormatException,
    );
    expect(nativeProtocols, isNot(contains('cloak')));
    expect(protocols.map((p) => p.id), isNot(contains('cloak')));
  });
}
