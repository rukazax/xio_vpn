import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_ui.dart';
import 'package:xio/core.dart';
import 'package:xio/l10n.dart';
import 'package:xio/main.dart';
import 'package:xio/mtproto_ui.dart';
import 'support/screenshots.dart';

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
    'every Russian literal in lib is a key in all 13 catalogues',
    () {
      // Files whose Russian text is deliberately paired with an English one
      // (legal disclosures), plus the language autonyms in l10n.dart.
      const skipped = {'client_policy.dart', 'help_legal_ui.dart', 'l10n.dart'};
      // Native language names are not translated: the picker shows them as-is.
      const allowed = {'Русский'};
      final cyrillic = RegExp(r'[\u0400-\u04FF]');
      final templates = <String>{};
      for (final file in Directory('lib').listSync().whereType<File>()) {
        if (!file.path.endsWith('.dart')) continue;
        final name = file.uri.pathSegments.last;
        if (skipped.contains(name)) continue;
        for (final literal in _stringLiterals(file.readAsStringSync())) {
          if (!cyrillic.hasMatch(literal.body)) continue;
          // Composed from already translated pieces (`${tr(context, …)}`).
          if (literal.body.contains('tr(') ||
              literal.body.contains('AppLanguages.text')) {
            continue;
          }
          final text = _collapse(literal.body);
          // The cascade probe embeds a shell script; it is code, not UI.
          if (text.length > 1000) continue;
          if (allowed.contains(text)) continue;
          templates.add(_template(text));
        }
      }
      expect(templates.length, greaterThan(250));
      for (final code in AppLanguages.names.keys) {
        final catalogue = AppLanguages.catalogs[code]!;
        for (final key in templates) {
          expect(
            catalogue.containsKey(key),
            isTrue,
            reason: '$code has no entry for «$key»',
          );
        }
      }
    },
  );
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
      final dir = await Directory.systemTemp.createTemp('xio-l10n-');
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
      await tester.pumpWidget(XioApp(store: store));
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
              child: XioApp(key: UniqueKey(), store: store),
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
          // Evidence screenshots are opt-in (XIO_CAPTURE_IMAGES=1); the layout
          // assertions above always run and need no ../verification directory.
          await captureScreenshot(
            tester,
            key,
            '../verification/users-$code-${size.width.toInt()}-0.16.png',
          );
          await tester.tap(find.byType(BackButton).first);
          await tester.pumpAndSettle();
          expect(
            find.text(AppLanguages.text('Приложение')).hitTestable(),
            findsOneWidget,
          );
          expect(tester.takeException(), isNull, reason: '$code $size');
          await captureScreenshot(
            tester,
            key,
            '../verification/l10n-$code-${size.width.toInt()}-0.16.png',
          );
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
      writeTextArtifact(
        '../verification/l10n-layouts-0.16.json',
        const JsonEncoder.withIndent('  ').convert(evidence),
      );
    },
  );
  testWidgets(
    'cascade screen fits 360×640 in every language, RTL included',
    (tester) async {
      tester.view.physicalSize = const Size(360, 640);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = 1.3;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      for (final code in AppLanguages.names.keys) {
        AppLanguages.set(code);
        await tester.pumpWidget(
          MaterialApp(
            locale: Locale(code),
            supportedLocales: AppLanguages.locales,
            localizationsDelegates: GlobalMaterialLocalizations.delegates,
            theme: ThemeData(colorSchemeSeed: const Color(0xFF2ECC71)),
            home: const CascadeScreen(
              bridgeAddress: '81.177.142.37',
              exitAddress: '2a0c:b641:1a0:800::2a2',
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull, reason: code);
        expect(
          Directionality.of(tester.element(find.byType(Scaffold))),
          code == 'ar' ? TextDirection.rtl : TextDirection.ltr,
          reason: code,
        );
        expect(
          find.text(AppLanguages.text('Каскад')),
          findsOneWidget,
          reason: code,
        );
        await tester.pumpWidget(const SizedBox());
      }
    },
  );
  testWidgets(
    'MTProto screen fits 360×640 in every language, RTL included',
    (tester) async {
      tester.view.physicalSize = const Size(360, 640);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = 1.3;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      final store = _MemoryStore();
      addTearDown(store.dispose);
      for (final code in AppLanguages.names.keys) {
        AppLanguages.set(code);
        await tester.pumpWidget(
          MaterialApp(
            locale: Locale(code),
            supportedLocales: AppLanguages.locales,
            localizationsDelegates: GlobalMaterialLocalizations.delegates,
            theme: ThemeData(colorSchemeSeed: const Color(0xFF2ECC71)),
            home: Scaffold(
              body: SingleChildScrollView(
                child: MtprotoProxyScreen(store: store),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull, reason: code);
        expect(
          find.text(AppLanguages.text('Установить MTProto на сервер')),
          findsNothing,
          reason: 'no server is saved in this test: $code',
        );
        expect(
          find.text(AppLanguages.text('Сохранить')),
          findsOneWidget,
          reason: code,
        );
        await tester.pumpWidget(const SizedBox());
      }
    },
  );
}

/// One Dart string literal with its nesting level inside `${…}`.
class _Literal {
  _Literal(this.body, this.start, this.end, this.level);

  String body;
  final int start;
  int end;
  final int level;
}

int _scanLiterals(
  String src,
  int i,
  int level,
  bool stopAtBrace,
  List<_Literal> out,
) {
  final n = src.length;
  var depth = 0;
  while (i < n) {
    final c = src[i];
    if (c == '/' && i + 1 < n && src[i + 1] == '/') {
      final j = src.indexOf('\n', i);
      i = j < 0 ? n : j;
      continue;
    }
    if (c == '/' && i + 1 < n && src[i + 1] == '*') {
      final j = src.indexOf('*/', i + 2);
      i = j < 0 ? n : j + 2;
      continue;
    }
    if (stopAtBrace && c == '}' && depth == 0) return i;
    if (c == '{') {
      depth++;
      i++;
      continue;
    }
    if (c == '}') {
      depth--;
      i++;
      continue;
    }
    final raw =
        c == 'r' && i + 1 < n && (src[i + 1] == "'" || src[i + 1] == '"');
    if (c == "'" || c == '"' || raw) {
      final start = i;
      if (raw) i++;
      final quote = src[i];
      i++;
      final triple = i + 1 < n && src[i] == quote && src[i + 1] == quote;
      final buffer = StringBuffer();
      if (triple) {
        i += 2;
        while (i < n) {
          if (src.startsWith(quote * 3, i)) {
            i += 3;
            break;
          }
          if (src[i] == '\\' && !raw && i + 1 < n) {
            buffer.write(src.substring(i, i + 2));
            i += 2;
            continue;
          }
          if (src.startsWith(r'${', i)) {
            final j = _scanLiterals(src, i + 2, level + 1, true, out);
            buffer.write(src.substring(i, j + 1));
            i = j + 1;
            continue;
          }
          buffer.write(src[i]);
          i++;
        }
      } else {
        while (i < n) {
          if (src[i] == '\\' && !raw && i + 1 < n) {
            buffer.write(src.substring(i, i + 2));
            i += 2;
            continue;
          }
          if (src[i] == quote) {
            i++;
            break;
          }
          if (src[i] == '\n') break;
          if (src.startsWith(r'${', i)) {
            final j = _scanLiterals(src, i + 2, level + 1, true, out);
            buffer.write(src.substring(i, j + 1));
            i = j + 1;
            continue;
          }
          buffer.write(src[i]);
          i++;
        }
      }
      out.add(_Literal(buffer.toString(), start, i, level));
      continue;
    }
    i++;
  }
  return i;
}

/// Literals of one file, with adjacent literals of the same level joined:
/// Dart concatenates `'a' 'b'` into a single runtime string.
List<_Literal> _stringLiterals(String src) {
  final all = <_Literal>[];
  _scanLiterals(src, 0, 0, false, all);
  all.sort((a, b) {
    final byStart = a.start.compareTo(b.start);
    return byStart != 0 ? byStart : a.level.compareTo(b.level);
  });
  final top = <_Literal>[];
  for (final literal in all.where((l) => l.level == 0)) {
    if (top.isNotEmpty) {
      final previous = top.last;
      final gap = src.substring(previous.end, literal.start);
      final code = gap.replaceAll(RegExp(r'//[^\n]*|/\*[\s\S]*?\*/'), '');
      if (code.trim().isEmpty) {
        previous.body += literal.body;
        previous.end = literal.end;
        continue;
      }
    }
    top.add(literal);
  }
  return [...top, ...all.where((l) => l.level > 0)];
}

/// Runtime string with every substitution replaced by a positional marker.
String _template(String s) {
  final out = StringBuffer();
  var index = 0;
  var i = 0;
  final identifier = RegExp(r'[A-Za-z0-9_]');
  while (i < s.length) {
    if (s.startsWith(r'${', i)) {
      var depth = 0;
      var j = i;
      while (j < s.length) {
        if (s[j] == '{') depth++;
        if (s[j] == '}') {
          depth--;
          if (depth == 0) break;
        }
        j++;
      }
      out.write('{$index}');
      index++;
      i = j + 1;
      continue;
    }
    if (s[i] == r'$' &&
        i + 1 < s.length &&
        RegExp(r'[A-Za-z_]').hasMatch(s[i + 1])) {
      var j = i + 1;
      while (j < s.length && identifier.hasMatch(s[j])) {
        j++;
      }
      out.write('{$index}');
      index++;
      i = j;
      continue;
    }
    out.write(s[i]);
    i++;
  }
  return out.toString();
}

String _collapse(String s) => s
    .replaceAll('\\n', ' ')
    .replaceAll("\\'", "'")
    .replaceAll('\\"', '"')
    .replaceAll(RegExp(r'\s+'), ' ')
    .trim();
