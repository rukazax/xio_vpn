import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/main.dart';
import 'package:xio/core.dart';

void main() {
  setUpAll(() async {
    final font = FontLoader('X1oSans')
      ..addFont(rootBundle.load('assets/fonts/NotoSans-Regular.ttf'));
    await font.load();
    final icons = FontLoader('MaterialIcons')
      ..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'));
    await icons.load();
  });
  for (final size in [
    const Size(320, 740),
    const Size(390, 844),
    const Size(1280, 900),
  ]) {
    testWidgets('navigation, empty state, and layout $size', (tester) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final s = AppStore();
      await tester.pumpWidget(XioApp(store: s));
      await tester.pumpAndSettle();
      expect(find.text('Отключено'), findsOneWidget);
      expect(tester.takeException(), isNull);
      for (final index in [1, 2, 0]) {
        await tester.tap(find.byType(NavigationDestination).at(index));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
      await tester.pumpWidget(const SizedBox());
      s.dispose();
    });
  }
  testWidgets('capture desktop and phone product screens', (tester) async {
    for (final item in [
      ('desktop', const Size(1280, 900)),
      ('phone', const Size(390, 844)),
    ]) {
      tester.view.physicalSize = item.$2;
      tester.view.devicePixelRatio = 1;
      final s = AppStore();
      final key = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: key,
          child: XioApp(store: s),
        ),
      );
      await tester.pumpAndSettle();
      await tester.runAsync(() async {
        final image =
            await (key.currentContext!.findRenderObject()
                    as RenderRepaintBoundary)
                .toImage(pixelRatio: 1);
        final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
        await Directory('../verification').create(recursive: true);
        await File('../verification/${item.$1}-0.13.png')
            .writeAsBytes(bytes!.buffer.asUint8List());
        image.dispose();
      });
      await tester.pumpWidget(const SizedBox());
      s.dispose();
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });
  testWidgets('primary action stays visible with larger phone text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 740);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final store = AppStore();
    await tester.pumpWidget(XioApp(store: store));
    await tester.pumpAndSettle();
    expect(
      tester.getRect(find.text('Добавить подключение')).bottom,
      lessThan(tester.getTopLeft(find.byType(NavigationBar)).dy),
    );
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
  testWidgets('tab navigation does not inherit another page scroll offset', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 740);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final store = AppStore();
    await tester.pumpWidget(XioApp(store: store));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(1));
    await tester.pumpAndSettle();
    await tester.drag(
      find.byType(SingleChildScrollView).hitTestable(),
      const Offset(0, -1400),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(0));
    await tester.pumpAndSettle();
    expect(
      tester.getRect(find.text('Добавить подключение')).bottom,
      lessThan(tester.getTopLeft(find.byType(NavigationBar)).dy),
    );
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
