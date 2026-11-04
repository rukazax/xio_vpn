import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/main.dart';
import 'package:xio/split_routing.dart';
import 'package:xio/workspace_ui.dart';

/// Три правки интерфейса: режимы «IP/сайты», поле доменов и место
/// раздельного туннелирования в настройках.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
  });

  void mockRouting({
    String mode = 'ipInclude',
    List<String> networks = const ['10.0.0.0/8'],
    List<String> domains = const ['youtube.com'],
    void Function(MethodCall call)? onSave,
  }) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          switch (call.method) {
            case 'routingGet':
              return {
                'mode': mode,
                'packages': <String>[],
                'networks': networks,
                'domains': domains,
              };
            case 'routingApps':
              return <dynamic>[];
            case 'routingSave':
              onSave?.call(call);
              return null;
          }
          return null;
        });
  }

  test('подписи режимов называют и IP, и сайты', () {
    expect(routingLabel('ipInclude'), 'Только выбранные IP/сайты через VPN');
    expect(routingLabel('ipExclude'), 'Выбранные IP/сайты в обход VPN');
    expect(routingLabel('include'), 'Только выбранные приложения через VPN');
    expect(routingLabel('all'), 'Все приложения через VPN');
  });

  testWidgets('экран маршрутизации показывает новые режимы и поле доменов', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(420, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    mockRouting();
    await tester.pumpWidget(
      MaterialApp(
        theme: xioTheme(Brightness.light),
        home: const SplitRoutingPage(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Только выбранные IP/сайты через VPN'), findsOneWidget);
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    expect(find.text('Выбранные IP/сайты в обход VPN'), findsWidgets);
    expect(find.text('Только выбранные IP через VPN'), findsNothing);
    expect(find.text('Выбранные IP в обход VPN'), findsNothing);

    // Переключение режима сохраняет поля ввода IP и доменов.
    await tester.tap(find.text('Выбранные IP/сайты в обход VPN').last);
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.byKey(const ValueKey('routing-domains')),
      240,
      scrollable: find.byType(Scrollable).first,
    );
    expect(
      tester
          .widget<TextField>(find.byKey(const ValueKey('routing-domains')))
          .controller!
          .text,
      'youtube.com',
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('некорректный домен не сохраняется и объясняет причину', (
    tester,
  ) async {
    Map<String, dynamic>? saved;
    mockRouting(
      domains: const [],
      onSave: (call) => saved = Map<String, dynamic>.from(call.arguments as Map),
    );
    await tester.pumpWidget(
      MaterialApp(
        theme: xioTheme(Brightness.light),
        home: const SplitRoutingPage(),
      ),
    );
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.byKey(const ValueKey('routing-domains')),
      240,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.enterText(
      find.byKey(const ValueKey('routing-domains')),
      'https://rutube.ru',
    );
    await tester.tap(find.text('Сохранить правила'));
    await tester.pumpAndSettle();
    expect(saved, isNull);
    expect(find.textContaining('Некорректный домен'), findsOneWidget);

    await tester.enterText(
      find.byKey(const ValueKey('routing-domains')),
      'rutube.ru\n*.example.com',
    );
    await tester.tap(find.text('Сохранить правила'));
    await tester.pumpAndSettle();
    expect(saved?['domains'], ['rutube.ru', '*.example.com']);
  });

  testWidgets('раздельное туннелирование переехало в «Соединение»', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    tester.view.physicalSize = const Size(420, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    mockRouting(mode: 'ipExclude', networks: const [], domains: const []);
    final store = AppStore();
    await tester.pumpWidget(
      MaterialApp(
        theme: xioTheme(Brightness.light),
        home: WorkspaceShell(store: store),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(1));
    await tester.pumpAndSettle();

    // В разделе «Приложение» пункта больше нет.
    await tester.scrollUntilVisible(
      find.text('Приложение').hitTestable(),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.tap(find.text('Приложение').hitTestable());
    await tester.pumpAndSettle();
    expect(find.text('Раздельное туннелирование'), findsNothing);
    await tester.tap(find.byType(BackButton));
    await tester.pumpAndSettle();

    // В «Настройке соединений» он рядом с DNS-резолвером и протоколами.
    await tester.tap(
      find
          .descendant(
            of: find.byType(ListTile),
            matching: find.text('Настройка соединений'),
          )
          .hitTestable(),
    );
    await tester.pumpAndSettle();
    expect(find.text('Раздельное туннелирование'), findsOneWidget);
    expect(find.text('DNS-резолвер'), findsOneWidget);
    expect(find.text('Протоколы'), findsOneWidget);
    expect(tester.takeException(), isNull);
    // Оверрайд платформы проверяется в конце теста: binding сверяет
    // foundation-переменные до tearDown.
    debugDefaultTargetPlatformOverride = null;
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });

  testWidgets('на вкладке «Настройка соединений» нет подзаголовка', (
    tester,
  ) async {
    final store = AppStore();
    await tester.pumpWidget(
      MaterialApp(
        theme: xioTheme(Brightness.light),
        home: WorkspaceShell(store: store),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(2));
    await tester.pumpAndSettle();
    expect(
      find.text('Вставьте профиль XIO или конфигурацию VPN'),
      findsNothing,
    );
    expect(find.text('Вставить ключ или конфигурацию'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    store.dispose();
  });
}
