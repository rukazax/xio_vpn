import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/app_settings.dart';
import 'package:xio/core.dart';
import 'package:xio/main.dart' show ImportDialog;
import 'package:xio/client_main.dart' show ClientHome;
import 'package:xio/l10n.dart';
import 'package:xio/workspace_ui.dart' show WorkspaceShell;

class MemoryStore extends AppStore {
  bool failSave = false;
  @override
  Future<void> save() async {
    if (failSave) throw StateError('save failed');
  }
}

class SaveGateStore extends MemoryStore {
  final gate = Completer<void>();
  final saved = <bool>[];
  int writes = 0;
  @override
  Future<void> save() async {
    writes++;
    if (writes == 1) {
      await gate.future;
      throw StateError('first save failed');
    }
    saved.add(allowScreenshots);
  }
}

class PostRenameFailureStore extends AppStore {
  bool failOnce = true;
  @override
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    if (failOnce) {
      failOnce = false;
      throw StateError('native plan failed after rename');
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('app.xio/engine');
  final calls = <bool>[];
  setUp(() {
    calls.clear();
    AppLanguages.set('ru');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'secureScreen') {
            calls.add((call.arguments as Map)['enabled'] as bool);
          }
          return null; // The real Android handler ACKs with success(null).
        });
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    AppLanguages.set(null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final platform in [TargetPlatform.windows, TargetPlatform.linux]) {
    testWidgets('$platform does not offer working capture protection', (
      tester,
    ) async {
      debugDefaultTargetPlatformOverride = platform;
      final store = MemoryStore();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: AppBehaviorSettings(store: store)),
        ),
      );
      final tile = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'Разрешить скриншоты'),
      );
      expect(tile.onChanged, isNull);
      expect(
        find.text(
          'На этой платформе приложение не блокирует снимки и запись экрана.',
        ),
        findsOneWidget,
      );
      await expectLater(store.setAllowScreenshots(true), throwsStateError);
      expect(store.allowScreenshots, isFalse);
      expect(calls, isEmpty);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    });
  }

  test(
    'Android applies default, opt-in and opt-out using real Store/channel',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final store = MemoryStore();
      expect(store.screenSecurityEnabled, isNull);
      await store.applyScreenSecurity();
      expect(store.screenSecurityEnabled, isTrue);
      await store.setAllowScreenshots(true);
      expect(store.screenSecurityEnabled, isFalse);
      await store.setAllowScreenshots(false);
      expect(store.screenSecurityEnabled, isTrue);
      expect(calls, [true, false, true]);
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  test(
    'Android missing channel is not successful setting application',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
      final store = MemoryStore();
      await expectLater(store.setAllowScreenshots(true), throwsStateError);
      // Desired preference persists even when the native result is unknown.
      expect(store.allowScreenshots, isTrue);
      await store.applyScreenSecurity(); // Fire-and-forget callers remain safe.
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  test(
    'Android setters and reapplication cannot overtake pending native ACK',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final pending = Completer<void>();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            if (call.method == 'secureScreen') {
              calls.add((call.arguments as Map)['enabled'] as bool);
              if (calls.length == 1) await pending.future;
            }
            return null;
          });
      final store = MemoryStore();
      final published = <bool?>[];
      store.addListener(() => published.add(store.screenSecurityEnabled));
      final first = store.setAllowScreenshots(true);
      await Future<void>.delayed(Duration.zero);
      final second = store.setAllowScreenshots(false);
      final reapply = store.applyScreenSecurity();
      await Future<void>.delayed(Duration.zero);
      expect(calls, [false]);
      expect(store.screenSecurityEnabled, isNull);
      pending.complete();
      await Future.wait([first, second, reapply]);
      expect(calls, [false, true, true]);
      expect(published.whereType<bool>(), [true]);
      expect(store.allowScreenshots, isFalse);
      expect(store.screenSecurityEnabled, isTrue);
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  test(
    'native default is installed before Flutter startup (source invariant)',
    () {
      final source = File(
        'android/app/src/main/kotlin/app/xio/xio/MainActivity.kt',
      ).readAsStringSync();
      final start = source.indexOf('override fun onCreate(');
      final secure = source.indexOf(
        'window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)',
        start,
      );
      final flutter = source.indexOf(
        'super.onCreate(savedInstanceState)',
        start,
      );
      expect(start, greaterThan(0));
      expect(secure, greaterThan(start));
      expect(flutter, greaterThan(secure));
    },
  );

  test(
    'failed older save cannot roll back newer queued selection or reapply',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final store = SaveGateStore();
      final first = expectLater(
        store.setAllowScreenshots(true),
        throwsStateError,
      );
      await Future<void>.delayed(Duration.zero);
      final second = store.setAllowScreenshots(true);
      final reapply = store.applyScreenSecurity();
      expect(store.screenSecurityEnabled, isNull);
      expect(calls, isEmpty);
      store.gate.complete();
      await Future.wait([first, second, reapply]);
      expect(store.saved, [false, true]);
      expect(calls, [true, false, false]);
      expect(store.allowScreenshots, isTrue);
      expect(store.screenSecurityEnabled, isFalse);
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  test(
    'failed save after rename rolls back actual persisted permission',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final dir = await Directory.systemTemp.createTemp('c7-rollback-');
      final store = PostRenameFailureStore()..directory = dir;
      try {
        await expectLater(store.setAllowScreenshots(true), throwsStateError);
        expect(store.allowScreenshots, isFalse);
        expect(
          jsonDecode(
            await File('${dir.path}/profiles.json').readAsString(),
          )['allowScreenshots'],
          isFalse,
        );
        expect(store.screenSecurityPreferenceKnown, isTrue);
        expect(calls, [
          true,
        ]); // Never clears security on a failed permission save.
      } finally {
        store.dispose();
        debugDefaultTargetPlatformOverride = null;
        await dir.delete(recursive: true);
      }
    },
  );

  test('real save/load preserves opt-in and obtains a fresh ACK', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    final dir = await Directory.systemTemp.createTemp('c7-reload-');
    final store = AppStore()..directory = dir;
    final loaded = AppStore()..directory = dir;
    try {
      await store.setAllowScreenshots(true);
      expect(loaded.screenSecurityEnabled, isNull);
      await loaded.load();
      expect(loaded.allowScreenshots, isTrue);
      expect(loaded.screenSecurityEnabled, isFalse);
      expect(calls, [false, false]);
    } finally {
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
      loaded.dispose();
      await dir.delete(recursive: true);
    }
  });

  testWidgets(
    'Android UI says unknown on native error and shows saved preference',
    (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final store = MemoryStore();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: AppBehaviorSettings(store: store),
            ),
          ),
        ),
      );
      expect(
        find.text('Состояние флага Android не подтверждено.'),
        findsOneWidget,
      );
      await store.applyScreenSecurity();
      await tester.pump();
      expect(
        find.text('Android подтвердил включение FLAG_SECURE.'),
        findsOneWidget,
      );
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (_) async => throw PlatformException(code: 'FLAG'),
          );
      await tester.tap(find.text('Разрешить скриншоты'));
      await tester.pumpAndSettle();
      expect(store.allowScreenshots, isTrue);
      expect(store.screenSecurityEnabled, isNull);
      expect(
        find.text('Состояние флага Android не подтверждено.'),
        findsOneWidget,
      );
      expect(
        find.text('Не удалось подтвердить настройку снимков экрана.'),
        findsOneWidget,
      );
      expect(
        find.text('Android подтвердил включение FLAG_SECURE.'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox());
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  testWidgets(
    'persistent save/rollback failure is visible and retry recovers',
    (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final store = MemoryStore()..failSave = true;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: AppBehaviorSettings(store: store),
            ),
          ),
        ),
      );
      await tester.tap(find.text('Разрешить скриншоты'));
      await tester.pumpAndSettle();
      expect(store.allowScreenshots, isFalse);
      expect(store.screenSecurityPreferenceKnown, isFalse);
      expect(
        find.text('Сохранение разрешения не подтверждено. Повторите выбор.'),
        findsOneWidget,
      );
      expect(find.text('Не удалось сохранить настройку'), findsOneWidget);
      expect(calls, [true]);
      store.failSave = false;
      await tester.tap(find.text('Разрешить скриншоты'));
      await tester.pumpAndSettle();
      expect(store.screenSecurityPreferenceKnown, isTrue);
      expect(store.allowScreenshots, isTrue);
      expect(
        find.text('Android подтвердил отключение FLAG_SECURE.'),
        findsOneWidget,
      );
      await tester.pumpWidget(const SizedBox());
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  for (final allow in [false, true]) {
    testWidgets(
      'secret import dialog preserves global allow=$allow on open/close',
      (tester) async {
        debugDefaultTargetPlatformOverride = TargetPlatform.android;
        final store = MemoryStore();
        await store.setAllowScreenshots(allow);
        calls.clear();
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(body: ImportDialog(store: store)),
          ),
        );
        await tester.pumpAndSettle();
        expect(calls, [!allow]);
        await tester.pumpWidget(const SizedBox());
        await tester.pumpAndSettle();
        expect(calls, [!allow, !allow]);
        expect(store.screenSecurityEnabled, !allow);
        store.dispose();
        debugDefaultTargetPlatformOverride = null;
      },
    );
  }

  test(
    'background invalidates prior window ACK and resume reapplies opt-in',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      final store = MemoryStore()..ready = true;
      await store.setAllowScreenshots(true);
      store.setForeground(false);
      expect(store.screenSecurityEnabled, isNull);
      store.setForeground(true);
      await store.applyScreenSecurity();
      expect(calls, [false, false, false]);
      expect(store.screenSecurityEnabled, isFalse);
      store.dispose();
      debugDefaultTargetPlatformOverride = null;
    },
  );

  testWidgets('Full settings route uses the shared unsupported settings UI', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    final store = MemoryStore()..ready = true;
    await tester.pumpWidget(MaterialApp(home: WorkspaceShell(store: store)));
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Icons.settings_outlined));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Приложение'));
    await tester.tap(find.text('Приложение'));
    await tester.pumpAndSettle();
    expect(find.byType(AppBehaviorSettings), findsOneWidget);
    expect(
      tester
          .widget<SwitchListTile>(
            find.widgetWithText(SwitchListTile, 'Разрешить скриншоты'),
          )
          .onChanged,
      isNull,
    );
    expect(
      find.text(
        'На этой платформе приложение не блокирует снимки и запись экрана.',
      ),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox());
    store.dispose();
    debugDefaultTargetPlatformOverride = null;
  });

  testWidgets('Client settings route uses the shared unsupported settings UI', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    final store = MemoryStore()..ready = true;
    await tester.pumpWidget(MaterialApp(home: ClientHome(store: store)));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(find.text('Настройки приложения'), 250);
    await tester.tap(find.text('Настройки приложения'));
    await tester.pumpAndSettle();
    expect(find.byType(AppBehaviorSettings), findsOneWidget);
    expect(
      tester
          .widget<SwitchListTile>(
            find.widgetWithText(SwitchListTile, 'Разрешить скриншоты'),
          )
          .onChanged,
      isNull,
    );
    expect(
      find.text(
        'На этой платформе приложение не блокирует снимки и запись экрана.',
      ),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox());
    store.dispose();
    debugDefaultTargetPlatformOverride = null;
  });
}
