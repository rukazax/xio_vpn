import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/desktop_engine.dart';

String canonical(String protocol, String raw) =>
    extendedProtocols.contains(protocol)
    ? ExtendedProfile.parse(raw).encoded
    : raw;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final path = Platform.environment['XIO_DESKTOP_PRIVATE_BUNDLE'];
  test('desktop encrypted import/export keeps all ten protocols', () async {
    DesktopEngine.enabled = true;
    DesktopEngine.supported = {
      'wireguard',
      'awg',
      'rivet-h3',
      'rivet-s1',
      'xray',
      'shadowsocks',
      'tailscale',
    };
    final bundle = UserBundle.decode(await File(path!).readAsString());
    final store = AppStore();
    try {
      await store.load();
      final user = await store.importBundle(bundle);
      final exported = await store.exportUser(user);
      expect(exported.configs.length, 10);
      expect(
        bundle.configs.keys.every(
          (p) => canonical(p, bundle.configs[p]!) == exported.configs[p],
        ),
        true,
        reason: 'portable configs must survive without printing their contents',
      );
      expect(
        store.profiles
            .where((p) => DesktopEngine.supported.contains(p.protocol))
            .length,
        7,
      );
      final state = File(
        '${(await applicationDirectory()).path}/profiles.json',
      );
      expect((await state.readAsString()).contains('PrivateKey ='), false);
      final reload = AppStore();
      try {
        await reload.load();
        expect(reload.profiles.length, 10);
        final again = await reload.exportUser(reload.users.single);
        expect(
          bundle.configs.keys.every(
            (p) => canonical(p, bundle.configs[p]!) == again.configs[p],
          ),
          true,
        );
      } finally {
        reload.dispose();
      }
    } finally {
      store.dispose();
      DesktopEngine.enabled = false;
      DesktopEngine.supported = {};
    }
  }, skip: path == null ? 'Private isolated profile required' : false);
}
