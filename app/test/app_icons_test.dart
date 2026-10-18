import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/app_icons.dart';
import 'package:x1o/core.dart';
import 'package:x1o/l10n.dart';

void main() {
  setUpAll(AppLanguages.load);
  testWidgets(
    'icon choices fit narrow large-text and RTL layouts and persist through native state',
    (tester) async {
      var nativeIcon = 'green_dark_0';
      final store = AppStore();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (MethodCall call) async {
            if (call.method == 'getAppIcon') return nativeIcon;
            if (call.method == 'setAppIcon') {
              nativeIcon = call.arguments as String;
            }
            return null;
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, null);
        AppLanguages.set(null);
        store.dispose();
      });
      tester.view.physicalSize = const Size(320, 800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      for (final language in ['en', 'ru', 'ar', 'de']) {
        AppLanguages.set(language);
        await tester.pumpWidget(
          MaterialApp(
            key: ValueKey(language),
            home: MediaQuery(
              data: const MediaQueryData(
                size: Size(320, 800),
                textScaler: TextScaler.linear(1.3),
              ),
              child: Directionality(
                textDirection: language == 'ar'
                    ? TextDirection.rtl
                    : TextDirection.ltr,
                child: Scaffold(
                  body: SingleChildScrollView(
                    child: AppIconPicker(store: store),
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        final last = find.byKey(const ValueKey('icon-white_clear_270'));
        await tester.ensureVisible(last);
        await tester.tap(last);
        await tester.pumpAndSettle();
        expect(nativeIcon, 'white_clear_270');
        expect(tester.takeException(), isNull);
      }
    },
  );
}
