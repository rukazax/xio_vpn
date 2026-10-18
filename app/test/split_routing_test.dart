import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';
import 'package:x1o/split_routing.dart';

void main() {
  for (final width in [320.0, 784.0]) {
    for (final brightness in Brightness.values) {
      testWidgets(
        'routing editor $width $brightness searches, persists and reports active tunnel',
        (tester) async {
          tester.view.physicalSize = Size(width, 780);
          tester.view.devicePixelRatio = 1;
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);
          Map<String, dynamic>? saved;
          var active = true;
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
              .setMockMethodCallHandler(native, (call) async {
                switch (call.method) {
                  case 'routingGet':
                    return {'mode': 'include', 'packages': <String>[]};
                  case 'routingApps':
                    return [
                      {'package': 'org.example.browser', 'label': 'Браузер'},
                      {'package': 'org.example.bank', 'label': 'Банк'},
                    ];
                  case 'routingSave':
                    if (active) {
                      throw PlatformException(
                        code: 'ENGINE',
                        message:
                            'Сначала отключите VPN, затем сохраните правила',
                      );
                    }
                    saved = Map<String, dynamic>.from(call.arguments as Map);
                    return saved;
                }
                return null;
              });
          addTearDown(
            () => TestDefaultBinaryMessengerBinding
                .instance
                .defaultBinaryMessenger
                .setMockMethodCallHandler(native, null),
          );
          await tester.pumpWidget(
            MaterialApp(
              theme: x1oTheme(brightness),
              builder: (context, child) => MediaQuery(
                data: MediaQuery.of(context)
                    .copyWith(textScaler: const TextScaler.linear(1.3)),
                child: child!,
              ),
              home: const SplitRoutingPage(),
            ),
          );
          await tester.pumpAndSettle();
          await tester.tap(find.text('Сохранить правила'));
          await tester.pumpAndSettle();
          await tester.scrollUntilVisible(
            find.text('Выберите хотя бы одно приложение для VPN'),
            180,
            scrollable: find.byType(Scrollable).first,
          );
          expect(
            find.text('Выберите хотя бы одно приложение для VPN'),
            findsOneWidget,
          );
          await tester.scrollUntilVisible(
            find.byType(TextField),
            -180,
            scrollable: find.byType(Scrollable).first,
          );
          await tester.enterText(find.byType(TextField), 'browser');
          await tester.pumpAndSettle();
          expect(find.text('Банк'), findsNothing);
          await tester.scrollUntilVisible(
            find.text('Браузер'),
            160,
            scrollable: find.byType(Scrollable).first,
          );
          await tester.tap(find.text('Браузер'));
          await tester.tap(find.text('Сохранить правила'));
          await tester.pumpAndSettle();
          expect(saved, isNull);
          await tester.scrollUntilVisible(
            find.text('Сначала отключите VPN, затем сохраните правила'),
            -160,
            scrollable: find.byType(Scrollable).first,
          );
          expect(
            find.text('Сначала отключите VPN, затем сохраните правила'),
            findsOneWidget,
          );
          active = false;
          await tester.tap(find.text('Сохранить правила'));
          await tester.pumpAndSettle();
          expect(saved, {
            'mode': 'include',
            'packages': ['org.example.browser'],
            'networks': <String>[],
          });
          expect(tester.takeException(), isNull);
        },
      );
    }
  }
  testWidgets('IP editor restores local subnets and saves only IP rules', (
    tester,
  ) async {
    Map<String, dynamic>? saved;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          if (call.method == 'routingGet') {
            return {
              'mode': 'ipExclude',
              'packages': <String>[],
              'networks': ['192.168.0.0/16', '2001:db8::/32'],
            };
          }
          if (call.method == 'routingApps') return <dynamic>[];
          if (call.method == 'routingSave') {
            saved = Map<String, dynamic>.from(call.arguments as Map);
          }
          return saved;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, null),
    );
    await tester.pumpWidget(
      MaterialApp(
        theme: x1oTheme(Brightness.light),
        home: const SplitRoutingPage(),
      ),
    );
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.byType(TextField),
      180,
      scrollable: find.byType(Scrollable).first,
    );
    expect(
      tester.widget<TextField>(find.byType(TextField)).controller!.text,
      '192.168.0.0/16\n2001:db8::/32',
    );
    await tester.enterText(find.byType(TextField), '10.0.0.0/8, ::1');
    await tester.tap(find.text('Сохранить правила'));
    await tester.pumpAndSettle();
    expect(saved, {
      'mode': 'ipExclude',
      'packages': <String>[],
      'networks': ['10.0.0.0/8', '::1'],
    });
    expect(tester.takeException(), isNull);
  });
  testWidgets(
    'cached home and settings entries both refresh when rules change',
    (tester) async {
      var mode = 'exclude';
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (call) async {
            if (call.method == 'routingGet') {
              return {
                'mode': mode,
                'packages': ['org.example.browser'],
                'networks': <String>[],
              };
            }
            if (call.method == 'routingApps') {
              return [
                {'package': 'org.example.browser', 'label': 'Браузер'},
              ];
            }
            if (call.method == 'routingSave') {
              mode = (call.arguments as Map)['mode'] as String;
              return null;
            }
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, null),
      );
      await tester.pumpWidget(
        MaterialApp(
          theme: x1oTheme(Brightness.light),
          home: const Scaffold(
            body: Column(
              children: [
                SplitRoutingControl(key: ValueKey('home')),
                SplitRoutingControl(key: ValueKey('settings')),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Выбранные приложения в обход VPN'), findsNWidgets(2));
      await tester.tap(find.byKey(const ValueKey('settings')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Выбранные приложения в обход VPN').last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Все приложения через VPN').last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Сохранить правила'));
      await tester.pumpAndSettle();
      expect(find.text('Все приложения через VPN'), findsNWidgets(2));
      expect(find.text('Выбранные приложения в обход VPN'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
