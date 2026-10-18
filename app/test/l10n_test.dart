import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/l10n.dart';
import 'package:x1o/main.dart';

class _MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await AppLanguages.load();
    for (final f in <String, String>{
      'X1oSans': 'NotoSans-Regular.ttf',
      'X1oArabic': 'NotoSansArabic-Regular.ttf',
      'X1oDevanagari': 'NotoSansDevanagari-Regular.ttf',
      'X1oCJK': 'NotoSansCJKsc-Regular.otf',
    }.entries) {
      await (FontLoader(
        f.key,
      )..addFont(rootBundle.load('assets/fonts/${f.value}'))).load();
    }
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  tearDown(() => AppLanguages.set(null));

  test(
    'all 13 catalogues are complete and preserve placeholder identities',
    () {
      final source = AppLanguages.catalogs['ru']!;
      expect(AppLanguages.catalogs.length, 13);
      final placeholders = RegExp(r'\{\d+\}');
      for (final entry in AppLanguages.catalogs.entries) {
        expect(
          entry.value.keys.toSet(),
          source.keys.toSet(),
          reason: entry.key,
        );
        for (final key in source.keys) {
          expect(entry.value[key]!.trim(), isNotEmpty);
          expect(
            placeholders.allMatches(entry.value[key]!).map((m) => m[0]).toList()
              ..sort(),
            placeholders.allMatches(key).map((m) => m[0]).toList()..sort(),
            reason: '${entry.key}: $key',
          );
          expect(entry.value[key], isNot(contains('ZXQ')));
        }
      }
    },
  );
  test(
    'system language resolution checks preferences and falls back to English',
    () {
      expect(AppLanguages.resolve([const Locale('ja', 'JP')]), 'ja');
      expect(
        AppLanguages.resolve([const Locale('fi'), const Locale('fr', 'CA')]),
        'fr',
      );
      expect(AppLanguages.resolve([const Locale('fi')]), 'en');
      expect(AppLanguages.resolve([]), 'en');
      expect(() => AppLanguages.set('xx'), throwsArgumentError);
    },
  );
  test(
    'dynamic status keeps technical arguments and specific message templates',
    () {
      AppLanguages.set('en');
      expect(
        AppLanguages.text('Проверка https://youtube.com…'),
        'Checking https://youtube.com…',
      );
      expect(AppLanguages.text('Получено: 1.0 kB'), 'Received: 1.0 kB');
      expect(
        AppLanguages.text('Сайт доступен · HTTP 204'),
        'Website reachable · HTTP 204',
      );
      expect(
        AppLanguages.text(
          'Неподдерживаемое поле: PostUp. Команды и поля другого режима не принимаются.',
        ),
        'Unsupported field: PostUp. Commands and fields for other modes are not accepted.',
      );
      expect(
        AppLanguages.text('12:34:56  Туннель отключён'),
        '12:34:56  Tunnel disconnected',
      );
      expect(AppLanguages.text('example.org:51820'), 'example.org:51820');
      AppLanguages.set('ar');
      expect(
        AppLanguages.text('Получено: 0 B', isolateArguments: true),
        contains('\u20660 B\u2069'),
      );
      expect(AppLanguages.text('Мой WireGuard'), isNot(contains('\u2066')));
    },
  );
  test(
    'explicit and system language persist without changing profiles',
    () async {
      final dir = await Directory.systemTemp.createTemp('x1o-l10n-');
      final store = AppStore()..directory = dir;
      addTearDown(() async {
        store.dispose();
        await dir.delete(recursive: true);
      });
      store.profiles.add(
        const Profile(
          id: 'wg1',
          name: 'Настройки',
          protocol: 'wireguard',
          endpoint: 'example.org:51820',
        ),
      );
      store.selectedId = 'wg1';
      await store.setLanguage('ar');
      var saved = jsonDecode(
        await File('${dir.path}/profiles.json').readAsString(),
      ) as Map;
      expect(saved['language'], 'ar');
      expect(saved['selected'], 'wg1');
      expect(saved['profiles'][0]['name'], 'Настройки');
      await store.setLanguage(null);
      saved = jsonDecode(
        await File('${dir.path}/profiles.json').readAsString(),
      ) as Map;
      expect(saved['language'], isNull);
    },
  );
  testWidgets(
    'language picker updates an open route, retains tab and form input',
    (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      AppLanguages.set('en');
      final store = _MemoryStore();
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Application').hitTestable());
      await tester.pumpAndSettle();
      await tester.tap(find.text('Language'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('العربية'));
      await tester.tap(find.text('العربية'));
      await tester.pumpAndSettle();
      expect(AppLanguages.selected, 'ar');
      expect(find.text('اللغة'), findsOneWidget);
      expect(find.text('التطبيق'), findsOneWidget);
      expect(
        Directionality.of(tester.element(find.text('اللغة'))),
        TextDirection.rtl,
      );
      await tester.tap(find.byType(BackButton).first);
      await tester.pumpAndSettle();
      expect(
        tester.widget<NavigationBar>(find.byType(NavigationBar)).selectedIndex,
        1,
      );
      await tester.tap(find.byType(NavigationDestination).at(2));
      await tester.pumpAndSettle();
      await tester.tap(find.text(AppLanguages.text('Добавить пользователя')));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, 'Настройки');
      await store.setLanguage('en');
      await tester.pumpAndSettle();
      expect(find.text('Настройки').hitTestable(), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
  testWidgets(
    '13 languages cover-sized and unfolded layouts with real fonts and RTL swipes',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      final evidence = <Map<String, dynamic>>[];
      for (final code in AppLanguages.names.keys) {
        for (final size in [const Size(360, 800), const Size(900, 780)]) {
          AppLanguages.set(code);
          tester.view.physicalSize = size;
          tester.platformDispatcher.textScaleFactorTestValue = size.width < 600
              ? 1.3
              : 1;
          tester.platformDispatcher.platformBrightnessTestValue =
              size.width < 600 ? Brightness.light : Brightness.dark;
          final store = _MemoryStore();
          final key = GlobalKey();
          await tester.pumpWidget(
            RepaintBoundary(
              key: key,
              child: X1oApp(key: UniqueKey(), store: store),
            ),
          );
          await tester.pumpAndSettle();
          final rtl = code == 'ar';
          expect(
            find.text(AppLanguages.text('Добавить подключение')),
            findsOneWidget,
          );
          expect(
            Directionality.of(tester.element(find.byType(PageView))),
            rtl ? TextDirection.rtl : TextDirection.ltr,
          );
          final r = tester.getRect(find.byType(PageView));
          await tester.dragFrom(
            Offset(
              r.left + r.width * (rtl ? .15 : .85),
              r.top + r.height * .85,
            ),
            Offset(r.width * (rtl ? .7 : -.7), 0),
          );
          await tester.pumpAndSettle();
          expect(
            tester
                .widget<NavigationBar>(find.byType(NavigationBar))
                .selectedIndex,
            1,
          );
          await tester.tap(find.text(AppLanguages.text('Пользователи')));
          await tester.pumpAndSettle();
          final usersLabel = find.descendant(
            of: find.byType(SegmentedButton<int>),
            matching: find.text(AppLanguages.text('Пользователи')),
          );
          await tester.tap(usersLabel);
          await tester.pumpAndSettle();
          final paragraph = tester.renderObject<RenderParagraph>(usersLabel);
          final boxes = paragraph.getBoxesForSelection(
            TextSelection(
              baseOffset: 0,
              extentOffset: AppLanguages.text('Пользователи').length,
            ),
          );
          expect(
            boxes.map((b) => b.top.round()).toSet().length,
            1,
            reason: 'Users must stay on one line: $code $size',
          );
          await tester.runAsync(() async {
            final boundary =
                key.currentContext!.findRenderObject() as RenderRepaintBoundary;
            final image = await boundary.toImage(pixelRatio: 1);
            final bytes = (await image.toByteData(
              format: ui.ImageByteFormat.png,
            ))!.buffer.asUint8List();
            await File(
              '../verification/users-$code-${size.width.toInt()}-0.16.png',
            ).writeAsBytes(bytes);
            image.dispose();
          });
          await tester.tap(find.byType(BackButton).first);
          await tester.pumpAndSettle();
          expect(
            find.text(AppLanguages.text('Приложение')).hitTestable(),
            findsOneWidget,
          );
          expect(tester.takeException(), isNull, reason: '$code $size');
          await tester.runAsync(() async {
            final boundary =
                key.currentContext!.findRenderObject() as RenderRepaintBoundary;
            final image = await boundary.toImage(pixelRatio: 1);
            final bytes = (await image.toByteData(
              format: ui.ImageByteFormat.png,
            ))!.buffer.asUint8List();
            await File(
              '../verification/l10n-$code-${size.width.toInt()}-0.16.png',
            ).writeAsBytes(bytes);
            image.dispose();
          });
          evidence.add({
            'language': code,
            'width': size.width,
            'height': size.height,
            'rtl': rtl,
            'textScale': size.width < 600 ? 1.3 : 1,
            'theme': size.width < 600 ? 'light' : 'dark',
            'swipePassed': true,
            'layoutException': false,
          });
          await tester.pumpWidget(const SizedBox());
          store.dispose();
        }
      }
      await tester.runAsync(
        () => File(
          '../verification/l10n-layouts-0.16.json',
        ).writeAsString(const JsonEncoder.withIndent('  ').convert(evidence)),
      );
    },
  );
}
