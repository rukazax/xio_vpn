import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/client_main.dart';
import 'package:x1o/client_policy.dart';
import 'package:x1o/core.dart';
import 'package:x1o/l10n.dart';
import 'package:x1o/legal_record.dart';
import 'package:x1o/main.dart';

class PreviewStore extends AppStore {
  PreviewStore() : super(nativeTunnelOverride: true) {
    profiles.add(
      const Profile(
        id: 'xr1',
        name: 'IPv6 test server',
        protocol: 'xray',
        endpoint: '[2001:db8::42]:4443',
      ),
    );
    servers.add(
      ManagedServer(id: 's', host: '2001:db8::42', name: 'IPv6 test server'),
    );
    users.add(
      ManagedUser(
        id: 'a' * 32,
        name: 'Test account',
        serverId: 's',
        profileIds: {'xray': 'xr1'},
        admin: !clientOnlyBuild,
        userLimit: 3,
      ),
    );
    legalRecord = LegalRecord.acknowledge('Synthetic preview terms', 'en');
    vpnDisclosure = vpnDisclosureRevision;
    selectedId = 'xr1';
    ready = true;
  }
  @override
  Future<void> save() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await AppLanguages.load();
    final emoji = File('/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf');
    if (emoji.existsSync()) {
      await (FontLoader('X1oCJK')
            ..addFont(emoji.readAsBytes().then((b) => ByteData.sublistView(b))))
          .load();
    }
    for (final font in {
      'X1oSans': 'assets/fonts/NotoSans-Regular.ttf',
      'MaterialIcons': 'fonts/MaterialIcons-Regular.otf',
    }.entries) {
      await (FontLoader(font.key)..addFont(rootBundle.load(font.value))).load();
    }
  });
  testWidgets(
    'RU EN previews of the real home widgets use synthetic profiles',
    (tester) async {
      tester.view.physicalSize = const Size(392, 844);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(() => AppLanguages.set(null));
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            native,
            (call) async => call.method == 'routingGet'
                ? {
                    'mode': 'all',
                    'packages': <String>[],
                    'networks': <String>[],
                  }
                : null,
          );
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, null),
      );
      final kind = clientOnlyBuild ? 'client' : 'owner';
      for (final language in ['ru', 'en']) {
        for (final brightness in Brightness.values) {
          AppLanguages.set(language);
          tester.platformDispatcher.platformBrightnessTestValue = brightness;
          final store = PreviewStore();
          final key = GlobalKey();
          await tester.pumpWidget(
            RepaintBoundary(
              key: key,
              child: clientOnlyBuild
                  ? ClientApp(key: UniqueKey(), store: store)
                  : X1oApp(key: UniqueKey(), store: store),
            ),
          );
          await tester.pumpAndSettle();
          expect(tester.takeException(), isNull);
          expect(
            find
                .text(language == 'ru' ? 'Подключиться' : 'Connect')
                .hitTestable(),
            findsOneWidget,
          );
          expect(find.text('Test account'), findsAtLeastNWidgets(1));
          await tester.runAsync(() async {
            final boundary =
                key.currentContext!.findRenderObject() as RenderRepaintBoundary;
            final image = await boundary.toImage(pixelRatio: 2);
            final data = await image.toByteData(format: ui.ImageByteFormat.png);
            final folder = Directory(
              '../.build-support/dualstack-20261023/previews',
            )..createSync(recursive: true);
            await File('${folder.path}/$kind-$language-${brightness.name}.png')
                .writeAsBytes(data!.buffer.asUint8List());
            image.dispose();
          });
          await tester.pumpWidget(const SizedBox());
          store.dispose();
        }
        tester.platformDispatcher.clearPlatformBrightnessTestValue();
      }
    },
  );
}
