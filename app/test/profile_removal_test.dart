import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

import 'security_test.dart' show profile;

/// The user record created by an import is what blocks importing the same
/// xio:// container again. Removing the profile must release that record,
/// otherwise "delete profile" followed by "import the same file" fails with
/// "user already added" while nothing is actually configured on the device.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('removing a profile releases its user for re-import', () async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(native, (call) async => null);
    addTearDown(() => messenger.setMockMethodCallHandler(native, null));

    final store = AppStore(nativeTunnelOverride: true);
    try {
      await store.load();
      // Unique per run: the store is backed by the real profile directory.
      final random = Random.secure();
      final userId = List.generate(
        16,
        (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
      ).join();
      // A private endpoint keeps import offline (no country lookup).
      final bundle = UserBundle('Reimport $userId', userId, 'reimport-test', {
        'awg': profile(extra: 'Jc = 4', endpoint: '10.0.0.1:51820'),
      });

      final user = await store.importBundle(bundle);
      final profileId = user.profileIds['awg'];
      expect(profileId, isNotNull);
      expect(store.profiles.any((p) => p.id == profileId), isTrue);

      await store.remove(profileId!);
      expect(store.profiles.any((p) => p.id == profileId), isFalse);
      expect(
        store.users
            .where((u) => u.id == userId && u.serverId == 'reimport-test')
            .any((u) => u.profileIds.containsValue(profileId)),
        isFalse,
        reason: 'no user may keep a reference to a removed profile',
      );

      final again = await store.importBundle(bundle);
      expect(again.profileIds.length, 1);
      expect(store.profiles.any((p) => p.id == again.profileIds['awg']), isTrue);
    } finally {
      store.dispose();
    }
  });
}
