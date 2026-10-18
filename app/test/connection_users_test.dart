import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/l10n.dart';
import 'package:x1o/main.dart';
import 'package:x1o/startup_statistics.dart';
import 'package:x1o/status_poll.dart';
import 'package:x1o/workspace_ui.dart';

class ProbeStore extends AppStore {
  ProbeStore({super.siteProbe}) : super(nativeTunnelOverride: true);
  @override
  Future<void> save() async {}
  @override
  Future<void> refresh({bool fresh = false}) async {
    status = TunnelStatus(
      active: true,
      handshake: DateTime.now().millisecondsSinceEpoch,
    );
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await AppLanguages.load();
    for (final f in {
      'X1oSans': 'NotoSans-Regular.ttf',
      'X1oArabic': 'NotoSansArabic-Regular.ttf',
      'X1oDevanagari': 'NotoSansDevanagari-Regular.ttf',
      'X1oCJK': 'NotoSansCJKsc-Regular.otf',
      'MaterialIcons': 'MaterialIcons-Regular.otf',
    }.entries) {
      final path = f.key == 'MaterialIcons'
          ? 'fonts/${f.value}'
          : 'assets/fonts/${f.value}';
      await (FontLoader(f.key)..addFont(rootBundle.load(path))).load();
    }
  });
  tearDown(() => AppLanguages.set(null));
  test('fresh poll waits for older interface read and then reads the new interface', () async {
    final poll = StatusPoll();
    final old = Completer<void>(), next = Completer<void>();
    var reads = 0;
    final first = poll.run(() async {
      reads++;
      await old.future;
    });
    final periodic = poll.run(() async {
      throw StateError('Must coalesce');
    });
    final fresh = poll.run(() async {
      reads++;
      await next.future;
    }, fresh: true);
    await Future<void>.delayed(Duration.zero);
    expect(reads, 1);
    old.complete();
    await first;
    await periodic;
    await Future<void>.delayed(Duration.zero);
    expect(reads, 2);
    next.complete();
    await fresh;
  });
  test('startup statistics runs once despite repeat callers and one unavailable server', () async {
    final store = AppStore()..ready = true;
    store.servers.addAll([
      ManagedServer(id: 's1', host: 'one.invalid'),
      ManagedServer(id: 's2', host: 'two.invalid'),
    ]);
    final calls = <String>[];
    final snapshot = StartupStatistics(
      refreshServer: (store, server) async {
        calls.add(server.id);
        if (server.id == 's1') throw StateError('offline');
      },
    );
    await Future.wait([snapshot.run(store), snapshot.run(store)]);
    await snapshot.run(store);
    expect(calls, ['s1', 's2']);
    expect(store.events.length, 1);
    store.dispose();
  });
  testWidgets(
    'stalled probe falls back; late first result cannot replace success',
    (tester) async {
      final connected = <String>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (call) async {
            if (call.method == 'connect') {
              connected.add(call.arguments['id'] as String);
            }
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, null),
      );
      final first = Completer<bool>();
      var probes = 0;
      final store = ProbeStore(
        siteProbe: (_) => ++probes == 1 ? first.future : Future.value(true),
      )..protocolTimeoutSeconds = 5;
      store.profiles.addAll([
        const Profile(
          id: 'awg1',
          name: 'A',
          protocol: 'awg',
          endpoint: 'test.invalid:1',
        ),
        const Profile(
          id: 'wg2',
          name: 'B',
          protocol: 'wireguard',
          endpoint: 'test.invalid:2',
        ),
      ]);
      store.users.add(
        ManagedUser(
          id: 'a' * 32,
          name: 'A',
          serverId: 's',
          profileIds: {'awg': 'awg1', 'wireguard': 'wg2'},
        ),
      );
      store.selectedId = 'awg1';
      final operation = store.connect();
      await tester.pump();
      expect(connected, ['awg1']);
      await tester.pump(const Duration(seconds: 4));
      expect(connected, ['awg1']);
      await tester.pump(const Duration(seconds: 2));
      await operation;
      expect(connected, ['awg1', 'wg2']);
      expect(store.selectedId, 'wg2');
      expect(store.error, isNull);
      first.complete(false);
      await tester.pump();
      expect(store.selectedId, 'wg2');
      expect(store.connectionCheck, 'Сайт доступен');
      store.dispose();
    },
  );
  testWidgets('compact user cards in thirteen languages and two themes', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(360, 800);
    tester.platformDispatcher.textScaleFactorTestValue = 1.3;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final evidence = <String>[];
    for (final code in AppLanguages.names.keys) {
      AppLanguages.set(code);
      final store = AppStore();
      store.servers.add(ManagedServer(id: 's', host: 'test.invalid'));
      store.users.addAll([
        ManagedUser(
          id: 'a' * 32,
          name: 'Alexandra Long Name',
          serverId: 's',
          admin: true,
          profileIds: {'awg': 'awg1'},
          statistics: {'monthBytes': 12340000000, 'online': true},
        ),
        ManagedUser(
          id: 'b' * 32,
          name: 'Sam',
          serverId: 's',
          profileIds: {},
          statistics: {'monthBytes': 2400000000, 'online': false},
        ),
      ]);
      for (final brightness in Brightness.values) {
        final key = GlobalKey();
        await tester.pumpWidget(
          RepaintBoundary(
            key: key,
            child: MaterialApp(
              locale: Locale(code),
              supportedLocales: AppLanguages.locales,
              localizationsDelegates: GlobalMaterialLocalizations.delegates,
              theme: x1oTheme(brightness),
              home: Scaffold(
                body: SingleChildScrollView(
                  child: SharingPage(
                    key: UniqueKey(),
                    store: store,
                    initialTab: 1,
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.text('admin'), findsOneWidget);
        expect(find.text('online'), findsOneWidget);
        expect(find.text('offline'), findsOneWidget);
        expect(find.text('user'), findsNothing);
        expect(find.text('Обновить статистику'), findsNothing);
        expect(
          find.byWidgetPredicate(
            (w) =>
                w is Text &&
                (w.data ?? '').replaceAll(RegExp('[\u2066\u2069]'), '') ==
                    AppLanguages.text('Трафик мес: 12.34 GB'),
          ),
          findsOneWidget,
        );
        expect(find.byType(Card), findsNWidgets(2));
        expect(
          (tester
                      .getCenter(
                        find.text(AppLanguages.text('Поделиться')).first,
                      )
                      .dy -
                  tester
                      .getCenter(find.text(AppLanguages.text('Отозвать')).first)
                      .dy)
              .abs(),
          lessThan(1),
        );
        expect(tester.takeException(), isNull, reason: '$code $brightness');
        if (['ru', 'en', 'ar'].contains(code)) {
          await tester.runAsync(() async {
            final boundary =
                key.currentContext!.findRenderObject() as RenderRepaintBoundary;
            final image = await boundary.toImage();
            final bytes = await image.toByteData(
              format: ui.ImageByteFormat.png,
            );
            await File(
              '../verification/user-cards-$code-${brightness.name}-0.16.png',
            ).writeAsBytes(bytes!.buffer.asUint8List());
            image.dispose();
          });
        }
        evidence.add(
          '$code ${brightness.name}: 360dp, text 1.3, no overflow; actions share row',
        );
      }
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    }
    await tester.runAsync(() async {
      await File('../verification/user-cards-0.16.txt')
          .writeAsString(evidence.join('\n'));
    });
  });
}
