import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_model.dart';
import 'package:xio/cascade_ui.dart';

/// Wraps the screen the way the application does (Material theme + Scaffold
/// inside [CascadeScreen]); no localization is required, the screen is
/// self-contained.
Widget _host(Widget child) => MaterialApp(
  theme: ThemeData(colorSchemeSeed: const Color(0xFF2ECC71)),
  home: child,
);

void main() {
  for (final size in const <Size>[Size(360, 640), Size(412, 915)]) {
    testWidgets(
      'cascade screen fits ${size.width.toInt()}×${size.height.toInt()} without overflow',
      (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        await tester.pumpWidget(
          _host(
            const CascadeScreen(
              subscription: CascadeSubscription(
                entitled: true,
                planLabel: 'XIO Cascade',
              ),
            ),
          ),
        );
        await tester.pump();

        // A RenderFlex overflow would have surfaced here as a FlutterError.
        expect(tester.takeException(), isNull);
        expect(find.text('Каскад'), findsOneWidget);
        expect(find.text('XIO Cascade'), findsOneWidget);
        expect(find.text('Переподключить'), findsOneWidget);
        expect(
          find.text(cascadeStatusCaption(CascadeStage.active)),
          findsOneWidget,
        );

        // Every station label stays inside the viewport: the scheme shrinks
        // through FittedBox instead of painting outside the screen.
        for (final label in const <String>['Устройство', 'Bridge', 'Exit']) {
          expect(find.text(label), findsOneWidget, reason: label);
          final rect = tester.getRect(find.text(label));
          expect(rect.left, greaterThanOrEqualTo(0), reason: label);
          expect(rect.top, greaterThanOrEqualTo(0), reason: label);
          expect(rect.right, lessThanOrEqualTo(size.width), reason: label);
          expect(rect.bottom, lessThanOrEqualTo(size.height), reason: label);
        }
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('cascade screen keeps large text inside the same viewport', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 640);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.4;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await tester.pumpWidget(_host(const CascadeScreen()));
    await tester.pump();
    expect(tester.takeException(), isNull);
    for (final label in const <String>['Устройство', 'Bridge', 'Exit']) {
      final rect = tester.getRect(find.text(label));
      expect(rect.right, lessThanOrEqualTo(360), reason: label);
      expect(rect.bottom, lessThanOrEqualTo(640), reason: label);
    }
  });

  testWidgets('locked cascade shows the paid-feature banner and lock overlay', (
    tester,
  ) async {
    await tester.pumpWidget(_host(const CascadeScreen()));
    await tester.pump();
    expect(tester.takeException(), isNull);
    expect(find.text(CascadeFeatureGate.bannerText), findsOneWidget);
    expect(find.text('Платная функция'), findsOneWidget);
    // The AppBar action is the only button that requests activation.
    expect(find.byTooltip(CascadeFeatureGate.bannerText), findsOneWidget);
  });

  testWidgets('activation enables the cascade for free until billing lands', (
    tester,
  ) async {
    var unlocked = 0;
    await tester.pumpWidget(
      _host(CascadeScreen(onUnlock: () async => unlocked++)),
    );
    await tester.pump();
    await tester.tap(find.byTooltip(CascadeFeatureGate.bannerText));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    expect(unlocked, 1);
    expect(find.text('Каскад включён — оплата пока не требуется'), findsOneWidget);
    // The paid banner is replaced by the enabled state.
    expect(find.text('Включено'), findsOneWidget);
    // Drain the SnackBar timeout so no timer outlives the test.
    await tester.pump(const Duration(seconds: 5));
    await tester.pumpAndSettle();
  });

  testWidgets('reconnect walks device → bridge → exit through its two timers', (
    tester,
  ) async {
    await tester.pumpWidget(_host(CascadeScreen(initialRoute: CascadeRoute.idle())));
    await tester.pump();
    await tester.tap(find.text('Переподключить'));
    await tester.pump();
    expect(
      find.text(cascadeStatusCaption(CascadeStage.deviceToBridge)),
      findsOneWidget,
    );
    await tester.pump(const Duration(milliseconds: 1800));
    expect(
      find.text(cascadeStatusCaption(CascadeStage.bridgeToExit)),
      findsOneWidget,
    );
    await tester.pump(const Duration(milliseconds: 1600));
    expect(
      find.text(cascadeStatusCaption(CascadeStage.active)),
      findsOneWidget,
    );
    // The "running dots" animation is stopped once the cascade is active.
    await tester.pump(const Duration(seconds: 1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('cascade step timers are cancelled when the screen is disposed', (
    tester,
  ) async {
    await tester.pumpWidget(_host(CascadeScreen(initialRoute: CascadeRoute.idle())));
    await tester.pump();
    await tester.tap(find.text('Переподключить'));
    await tester.pump(const Duration(milliseconds: 50));
    expect(
      find.text(cascadeStatusCaption(CascadeStage.deviceToBridge)),
      findsOneWidget,
    );
    // Dispose while the 1800 ms step timer (and the repeating dots ticker) are
    // still pending. If `dispose` forgot `_stepTimer?.cancel()` /
    // `_dots.dispose()`, flutter_test fails the test with a pending timer or an
    // active ticker, so no further pumping is needed to prove the cancellation.
    await tester.pumpWidget(const SizedBox());
    expect(tester.takeException(), isNull);
  });

  test('feature gate stays closed until a real subscription is wired', () async {
    expect(CascadeFeatureGate.enabled, isFalse);
    expect(await CascadeFeatureGate.instance.requestActivation(), isFalse);
    expect(CascadeFeatureGate.bannerText, isNotEmpty);
    expect(CascadeFeatureGate.notConnectedMessage, isNotEmpty);
    const free = CascadeSubscription();
    expect(free.entitled, isFalse);
    final paid = free.copyWith(entitled: true, planLabel: 'XIO Cascade');
    expect(paid.entitled, isTrue);
    expect(paid.copyWith().planLabel, 'XIO Cascade');
    expect(paid.copyWith(entitled: false).entitled, isFalse);
  });
}
