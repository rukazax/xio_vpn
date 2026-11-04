import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_health.dart';
import 'package:xio/cascade_model.dart';
import 'package:xio/cascade_ui.dart';

/// Wraps the screen the way the application does (Material theme + Scaffold
/// inside [CascadeScreen]); no localization is required, the screen is
/// self-contained.
Widget _host(Widget child) => MaterialApp(
  theme: ThemeData(colorSchemeSeed: const Color(0xFF2ECC71)),
  home: child,
);

const String _bridge = '81.177.142.37';
const String _exit = '2a0c:b641:1a0:800::2a2';

/// A real healthcheck answer: every check passed, the exit reports the IPv6
/// address an outside service actually saw.
const String _healthyJson = '''
{"ok": true, "role": "bridge", "time": "2026-11-04T20:41:07Z",
 "runtime": "systemd", "exit_host": "2a0c:b641:1a0:800::2a2",
 "egress6": "2a0c:b641:1a0:800::9a9",
 "checks": [
   {"name": "bridge.service", "ok": true, "detail": "systemd xio-cascade: active"},
   {"name": "bridge.tunnel", "ok": true, "detail": "tun0 поднят"},
   {"name": "bridge.exit_route", "ok": true, "detail": "IPv6 по умолчанию: default via fd00:201::2 dev tun0"},
   {"name": "exit.egress6", "ok": true, "detail": "выходной IPv6: 2a0c:b641:1a0:800::9a9"}
 ]}
''';

/// Bridge is fine, the exit never answered over IPv6.
const String _exitBrokenJson = '''
{"ok": false, "role": "bridge", "runtime": "systemd",
 "checks": [
   {"name": "bridge.tunnel", "ok": true, "detail": "tun0 поднят"},
   {"name": "bridge.exit_route", "ok": true, "detail": "маршрут есть"},
   {"name": "exit.egress6", "ok": false, "detail": "нет ответа по IPv6 (curl/timeout)"}
 ]}
''';

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
              bridgeAddress: _bridge,
              exitAddress: _exit,
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
        expect(find.text('Проверить каскад'), findsOneWidget);
        // Without a real poll the screen must not pretend the tunnel is up.
        expect(
          find.text(cascadeStatusCaption(CascadeStage.active)),
          findsNothing,
        );
        expect(
          find.text(cascadeStatusCaption(CascadeStage.idle)),
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

    await tester.pumpWidget(
      _host(const CascadeScreen(bridgeAddress: _bridge, exitAddress: _exit)),
    );
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
    expect(
      find.text('Каскад включён — оплата пока не требуется'),
      findsOneWidget,
    );
    // The paid banner is replaced by the enabled state.
    expect(find.text('Включено'), findsOneWidget);
    // Drain the SnackBar timeout so no timer outlives the test.
    await tester.pump(const Duration(seconds: 5));
    await tester.pumpAndSettle();
  });

  testWidgets('an unconfigured cascade says so instead of running a check', (
    tester,
  ) async {
    var calls = 0;
    await tester.pumpWidget(
      _host(
        CascadeScreen(
          onUnlock: () async {},
          healthProbe: (bridge) async {
            calls++;
            return CascadeHealth.unconfigured();
          },
        ),
      ),
    );
    await tester.pump();

    expect(tester.takeException(), isNull);
    expect(find.text('Каскад не настроен · укажите серверы'), findsOneWidget);
    // No demo stage and no fake latency before a real poll.
    expect(find.text(cascadeStatusCaption(CascadeStage.active)), findsNothing);
    expect(find.text('38 мс'), findsNothing);

    await tester.tap(find.text('Проверить каскад'));
    await tester.pump();
    expect(calls, 0, reason: 'без адресов проверять нечего');
    expect(find.text('Каскад не настроен · укажите серверы'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('the check button is busy-locked and applies the real answer', (
    tester,
  ) async {
    final answer = Completer<CascadeHealth>();
    var calls = 0;
    String? requested;
    await tester.pumpWidget(
      _host(
        CascadeScreen(
          bridgeAddress: _bridge,
          exitAddress: _exit,
          subscription: const CascadeSubscription(
            entitled: true,
            planLabel: 'XIO Cascade',
          ),
          healthProbe: (bridge) {
            calls++;
            requested = bridge;
            return answer.future;
          },
        ),
      ),
    );
    await tester.pump();

    await tester.tap(find.text('Проверить каскад'));
    await tester.pump();
    expect(calls, 1);
    expect(requested, _bridge);
    // While the SSH command runs the button is disabled and cannot be queued.
    expect(find.text('Проверка…'), findsOneWidget);
    expect(find.text('Проверка bridge и exit по SSH…'), findsOneWidget);
    final button = tester.widget<FilledButton>(find.byType(FilledButton));
    expect(button.onPressed, isNull);
    await tester.tap(find.text('Проверка…'), warnIfMissed: false);
    await tester.pump();
    expect(calls, 1);

    answer.complete(CascadeHealth.parse(_healthyJson, latencyMs: 842));
    await tester.pump();
    await tester.pump();

    expect(tester.takeException(), isNull);
    expect(
      find.text('Защищённый туннель только IPv6 · проверено'),
      findsOneWidget,
    );
    expect(find.text('842 мс'), findsOneWidget);
    expect(find.text('2a0c:b641:1a0:800::9a9'), findsOneWidget);
    expect(find.text('Проверить каскад'), findsOneWidget);
    expect(find.text('Причина'), findsNothing);

    // No delayed fake stages: five seconds later the real answer is unchanged.
    await tester.pump(const Duration(seconds: 5));
    expect(
      find.text('Защищённый туннель только IPv6 · проверено'),
      findsOneWidget,
    );
    expect(find.text('842 мс'), findsOneWidget);
  });

  testWidgets(
    'a broken exit puts the scheme on bridge → exit with the reason',
    (tester) async {
      await tester.pumpWidget(
        _host(
          CascadeScreen(
            bridgeAddress: _bridge,
            exitAddress: _exit,
            subscription: const CascadeSubscription(entitled: true),
            healthProbe: (bridge) async =>
                CascadeHealth.parse(_exitBrokenJson, latencyMs: 1203),
          ),
        ),
      );
      await tester.pump();
      await tester.tap(find.text('Проверить каскад'));
      await tester.pump();
      await tester.pump();

      expect(tester.takeException(), isNull);
      expect(find.textContaining('Bridge → Exit · '), findsOneWidget);
      expect(find.text('Причина'), findsOneWidget);
      expect(find.text('1203 мс'), findsOneWidget);
      // The real egress address was never confirmed, so it is not invented.
      expect(find.text('Выходной IPv6'), findsOneWidget);
      expect(find.text('—'), findsWidgets);
    },
  );

  testWidgets('an SSH failure is reported as a failed cascade', (tester) async {
    await tester.pumpWidget(
      _host(
        CascadeScreen(
          bridgeAddress: _bridge,
          exitAddress: _exit,
          healthProbe: (bridge) async => CascadeHealth.failure(
            'Нет сохранённого сервера: добавьте bridge с SSH-доступом',
          ),
        ),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Проверить каскад'));
    await tester.pump();
    await tester.pump();

    expect(tester.takeException(), isNull);
    expect(
      find.textContaining('Каскад не построен · Нет сохранённого сервера'),
      findsOneWidget,
    );
    expect(find.text('Причина'), findsOneWidget);
    expect(find.textContaining('Нет сохранённого сервера'), findsWidgets);
  });

  testWidgets('a stuck check fails after the 15 s deadline', (tester) async {
    final never = Completer<CascadeHealth>();
    await tester.pumpWidget(
      _host(
        CascadeScreen(
          bridgeAddress: _bridge,
          exitAddress: _exit,
          healthProbe: (bridge) => never.future,
        ),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Проверить каскад'));
    await tester.pump();
    expect(find.text('Проверка…'), findsOneWidget);

    await tester.pump(const Duration(seconds: 16));
    expect(tester.takeException(), isNull);
    expect(
      find.textContaining('Каскад не построен · Проверка не уложилась в 15 с'),
      findsOneWidget,
    );
    // The button is usable again, so a retry is possible.
    expect(find.text('Проверить каскад'), findsOneWidget);
  });

  testWidgets('disposing the screen cancels the check deadline', (
    tester,
  ) async {
    final never = Completer<CascadeHealth>();
    await tester.pumpWidget(
      _host(
        CascadeScreen(
          bridgeAddress: _bridge,
          exitAddress: _exit,
          healthProbe: (bridge) => never.future,
        ),
      ),
    );
    await tester.pump();
    await tester.tap(find.text('Проверить каскад'));
    await tester.pump(const Duration(milliseconds: 50));
    // Dispose while the SSH check and the 15 s deadline are still pending. If
    // `dispose` forgot `_deadline?.cancel()`, flutter_test reports a pending
    // timer; a late answer must not call setState on a dead widget either.
    await tester.pumpWidget(const SizedBox());
    never.complete(CascadeHealth.parse(_healthyJson, latencyMs: 900));
    await tester.pump();
    expect(tester.takeException(), isNull);
  });

  test(
    'feature gate stays closed until a real subscription is wired',
    () async {
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
    },
  );
}
