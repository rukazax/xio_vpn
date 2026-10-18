import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';

void main() {
  setUpAll(() async {
    await (FontLoader(
      'X1oSans',
    )..addFont(rootBundle.load('assets/fonts/NotoSans-Regular.ttf'))).load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  testWidgets(
    'system brightness changes all surfaces without losing selected page or profile',
    (tester) async {
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      final store = AppStore()
        ..profiles.add(
          const Profile(
            id: 'wg123',
            name: 'Существующий профиль',
            protocol: 'wireguard',
            endpoint: 'test.invalid:51820',
          ),
        )
        ..selectedId = 'wg123';
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      final light = Theme.of(tester.element(find.byType(Scaffold).first));
      expect(light.brightness, Brightness.light);
      expect(light.scaffoldBackgroundColor.computeLuminance(), greaterThan(.8));
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
      await tester.pumpAndSettle();
      final dark = Theme.of(tester.element(find.byType(Scaffold).first));
      expect(dark.brightness, Brightness.dark);
      expect(dark.scaffoldBackgroundColor.computeLuminance(), lessThan(.03));
      expect(
        tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
        1,
      );
      expect(store.selectedId, 'wg123');
      for (final theme in [light, dark]) {
        for (final fg in [
          theme.colorScheme.primary,
          theme.colorScheme.onSurfaceVariant,
        ]) {
          final a = fg.computeLuminance(),
              b = theme.colorScheme.surface.computeLuminance();
          final contrast = a > b
              ? (a + .05) / (b + .05)
              : (b + .05) / (a + .05);
          expect(contrast, greaterThanOrEqualTo(4.5));
        }
      }
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      await tester.pumpAndSettle();
      expect(
        Theme.of(tester.element(find.byType(Scaffold).first)).brightness,
        Brightness.light,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );

  for (final size in [
    const Size(320, 740),
    const Size(360, 800),
    const Size(390, 844),
    const Size(784, 720),
    const Size(900, 780),
  ]) {
    for (final brightness in Brightness.values) {
      testWidgets('safe compact controls $size $brightness with larger text', (
        tester,
      ) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1;
        tester.view.padding = const FakeViewPadding(top: 24, bottom: 24);
        tester.view.viewPadding = const FakeViewPadding(top: 24, bottom: 24);
        tester.platformDispatcher.textScaleFactorTestValue = 1.3;
        tester.platformDispatcher.platformBrightnessTestValue = brightness;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.view.resetPadding);
        addTearDown(tester.view.resetViewPadding);
        addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
        final store = AppStore()
          ..profiles.add(
            const Profile(
              id: 'wg123',
              name: 'Мой сервер — очень длинное название подключения',
              protocol: 'wireguard',
              endpoint: 'test.invalid:51820',
            ),
          )
          ..selectedId = 'wg123'
          ..status = const TunnelStatus(
            active: true,
            state: 'Интерфейс активен',
            rx: 12345678,
            tx: 4567890,
          );
        await tester.pumpWidget(X1oApp(store: store));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        if (size.width < 850) {
          final bar = find.byType(NavigationBar);
          expect(tester.widget<NavigationBar>(bar).height, 72);
          final navRect = tester.getRect(bar);
          expect(navRect.bottom, lessThanOrEqualTo(size.height));
          expect(
            tester.widget<NavigationBar>(bar).labelBehavior,
            NavigationDestinationLabelBehavior.alwaysHide,
          );
          for (final destination
              in tester.widget<NavigationBar>(bar).destinations) {
            final icon = (destination as NavigationDestination).icon as Icon;
            expect(icon.size, greaterThanOrEqualTo(30));
          }
          expect(
            tester.getRect(find.text('Отключиться')).bottom,
            lessThan(navRect.top),
          );
        }
        await tester.pumpWidget(const SizedBox());
        store.dispose();
      });
    }
  }
  testWidgets(
    'fold and unfold preserve the current tab and scrollable content',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(390, 844);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final store = AppStore();
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      tester.view.physicalSize = const Size(900, 780);
      await tester.pumpAndSettle();
      expect(find.byType(NavigationBar), findsOneWidget);
      expect(find.text('Серверы').hitTestable(), findsOneWidget);
      tester.view.physicalSize = const Size(390, 844);
      await tester.pumpAndSettle();
      expect(
        tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
        1,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
  testWidgets('capture cover and unfolded light/dark layouts', (tester) async {
    for (final size in [const Size(390, 844), const Size(784, 720)]) {
      for (final brightness in Brightness.values) {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = size;
        tester.platformDispatcher.platformBrightnessTestValue = brightness;
        final store = AppStore();
        final key = GlobalKey();
        await tester.pumpWidget(
          RepaintBoundary(
            key: key,
            child: X1oApp(store: store),
          ),
        );
        await tester.pumpAndSettle();
        await tester.runAsync(() async {
          final image =
              await (key.currentContext!.findRenderObject()
                      as RenderRepaintBoundary)
                  .toImage();
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          await File(
            '../verification/${size.width < 600 ? 'cover' : 'unfolded'}-${brightness.name}-0.13.png',
          ).writeAsBytes(bytes!.buffer.asUint8List());
          image.dispose();
        });
        await tester.pumpWidget(const SizedBox());
        store.dispose();
      }
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
    tester.platformDispatcher.clearPlatformBrightnessTestValue();
  });
}
