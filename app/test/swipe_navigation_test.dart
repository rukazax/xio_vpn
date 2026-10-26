import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/main.dart';

int selected(WidgetTester tester) =>
    tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex;
Future<void> swipe(WidgetTester tester, {bool forward = true}) async {
  final r = tester.getRect(find.byType(PageView));
  await tester.dragFrom(
    Offset(r.left + r.width * (forward ? .85 : .15), r.top + r.height * .8),
    Offset(r.width * (forward ? -.7 : .7), 0),
  );
  await tester.pumpAndSettle();
}

void main() {
  for (final size in [const Size(360, 800), const Size(784, 720)]) {
    testWidgets('three destination swipes, boundaries and tap sync $size', (
      tester,
    ) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final store = AppStore();
      await tester.pumpWidget(XioApp(store: store));
      await tester.pumpAndSettle();
      await swipe(tester, forward: false);
      expect(selected(tester), 0);
      for (var i = 1; i < 3; i++) {
        await swipe(tester);
        expect(selected(tester), i);
      }
      await swipe(tester);
      expect(selected(tester), 2);
      for (var i = 1; i >= 0; i--) {
        await swipe(tester, forward: false);
        expect(selected(tester), i);
      }
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      expect(selected(tester), 1);
      await swipe(tester, forward: false);
      expect(selected(tester), 0);
      await tester.tap(find.byType(NavigationDestination).at(0));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Добавить подключение'));
      await tester.pumpAndSettle();
      expect(selected(tester), 2);
      expect(find.text('VPN на своём сервере').hitTestable(), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    });
  }
  testWidgets('user form survives tab switches, notifications and fold', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final store = AppStore();
    await tester.pumpWidget(XioApp(store: store));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(2));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Добавить пользователя'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).hitTestable(), 'Алиса');
    tester.testTextInput.hide();
    store.changed();
    await tester.pumpAndSettle();
    tester.view.physicalSize = const Size(900, 780);
    await tester.pumpAndSettle();
    expect(find.text('Алиса').hitTestable(), findsOneWidget);
    tester.view.physicalSize = const Size(390, 844);
    await tester.pumpAndSettle();
    expect(find.text('Алиса').hitTestable(), findsOneWidget);
    await tester.tap(find.byType(BackButton).first);
    await tester.pumpAndSettle();
    expect(selected(tester), 2);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
  testWidgets('home has server selector and no manual protocol menu', (
    tester,
  ) async {
    final store = AppStore()
      ..profiles.add(
        const Profile(
          id: 'wg1',
          name: 'Сервер',
          protocol: 'wireguard',
          endpoint: 'vpn.invalid:51820',
        ),
      )
      ..selectedId = 'wg1';
    await tester.pumpWidget(XioApp(store: store));
    await tester.pumpAndSettle();
    expect(find.text('🌐 Сервер').hitTestable(), findsOneWidget);
    expect(
      find.byType(DropdownButtonFormField<String>).hitTestable(),
      findsNothing,
    );
    await tester.tap(find.text('🌐 Сервер'));
    await tester.pumpAndSettle();
    expect(find.text('Серверы и подключения'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
