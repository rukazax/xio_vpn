import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';
import 'package:x1o/l10n.dart';

void main() {
  setUpAll(() async {
    await AppLanguages.load();
    for (final entry in {
      'X1oSans': 'assets/fonts/NotoSans-Regular.ttf',
      'MaterialIcons': 'fonts/MaterialIcons-Regular.otf',
    }.entries) {
      await (FontLoader(
        entry.key,
      )..addFont(rootBundle.load(entry.value))).load();
    }
  });
  for (final language in ['ru', 'en']) {
    testWidgets('settings hierarchy and screenshots $language', (tester) async {
      tester.view.physicalSize = const Size(420, 850);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      AppLanguages.set(language);
      addTearDown(() => AppLanguages.set(null));
      String t(String value) => AppLanguages.text(value);
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      final store = AppStore();
      final boundaryKey = GlobalKey();
      Future<void> capture(String name) async {
        await tester.runAsync(() async {
          final boundary =
              boundaryKey.currentContext!.findRenderObject()
                  as RenderRepaintBoundary;
          final image = await boundary.toImage(pixelRatio: 1.5);
          final data = await image.toByteData(format: ui.ImageByteFormat.png);
          File('../docs/images/$name-$language.png')
              .writeAsBytesSync(data!.buffer.asUint8List());
          image.dispose();
        });
      }

      await tester.pumpWidget(
        RepaintBoundary(
          key: boundaryKey,
          child: X1oApp(store: store),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      for (final title in [
        'Справка и FAQ',
        'Лицензия и ответственность',
        'Диагностика',
        'Протоколы',
      ]) {
        expect(find.text(t(title)).hitTestable(), findsNothing);
      }
      await capture('settings');
      await tester.tap(find.text(t('О XIO')).hitTestable());
      await tester.pumpAndSettle();
      expect(find.text(t('Справка и FAQ')).hitTestable(), findsOneWidget);
      expect(
        find.text(t('Лицензия и ответственность')).hitTestable(),
        findsOneWidget,
      );
      expect(find.text(t('WireGuard')).hitTestable(), findsNothing);
      await capture('about');
      await tester.tap(find.text(t('Протоколы')).hitTestable());
      await tester.pumpAndSettle();
      expect(find.text(t('WireGuard')).hitTestable(), findsOneWidget);
      await capture('protocols');
      await tester.tap(find.byType(BackButton).hitTestable());
      await tester.pumpAndSettle();
      await tester.tap(find.text(t('Справка и FAQ')).hitTestable());
      await tester.pumpAndSettle();
      expect(find.text(t('Справка и FAQ')).hitTestable(), findsOneWidget);
      await tester.tap(find.byType(BackButton).hitTestable());
      await tester.pumpAndSettle();
      await tester.tap(find.byType(BackButton).hitTestable());
      await tester.pumpAndSettle();
      await tester.tap(
        find
            .descendant(
              of: find.byType(ListTile),
              matching: find.text(t('Соединение')),
            )
            .hitTestable(),
      );
      await tester.pumpAndSettle();
      await capture('connection');
      await tester.tap(find.text(t('Диагностика')).hitTestable());
      await tester.pumpAndSettle();
      expect(find.text(t('Журнал сеанса')), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    });
  }
}
