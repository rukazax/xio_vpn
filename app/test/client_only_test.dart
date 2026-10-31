import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:xio/app_theme.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/client_main.dart';
import 'package:xio/client_policy.dart';
import 'package:xio/core.dart';

class SwitchingStore extends AppStore {
  final calls = <String>[];
  bool failStop = false;
  SwitchingStore() : super(nativeTunnelOverride: true) {
    profiles.addAll(const [
      Profile(
        id: 'xr1',
        name: 'Сервер один',
        protocol: 'xray',
        endpoint: 'one.example:443',
      ),
      Profile(
        id: 'awg2',
        name: 'Сервер два',
        protocol: 'awg',
        endpoint: 'two.example:443',
      ),
    ]);
    selectedId = 'xr1';
    ready = true;
    status = const TunnelStatus(active: true);
  }
  @override
  Future<void> disconnect() async {
    calls.add('disconnect');
    status = TunnelStatus(active: failStop);
    if (failStop) error = 'stop failed';
    changed();
  }

  @override
  Future<void> refresh({bool fresh = false}) async {
    calls.add('refresh');
  }

  @override
  Future<void> select(String id) async {
    calls.add('select:$id');
    selectedId = id;
    changed();
  }

  @override
  Future<void> connect({bool resuming = false}) async {
    calls.add('connect:$selectedId${resuming ? ':resume' : ''}');
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  if (!clientOnlyBuild) {
    test('client tests require XIO_CLIENT_ONLY=true', () {}, skip: true);
    return;
  }
  test('client build is explicit and rejects administrative input before native IO', () async {
    expect(clientOnlyBuild, isTrue);
    final store = AppStore(nativeTunnelOverride: true);
    await expectLater(
      store.importServer('xio-server://anything'),
      throwsFormatException,
    );
    await expectLater(
      store.importBundle(
        UserBundle(
          'Admin',
          'a' * 32,
          'server',
          {},
          adminAccess: {'server': {}, 'key': 'never-read'},
        ),
      ),
      throwsFormatException,
    );
    expect(store.profiles, isEmpty);
    expect(store.servers, isEmpty);
  });
  test('selected profile stays first; fallbacks follow it', () {
    final store = SwitchingStore();
    store.priorityProtocol = 'awg';
    final ids = store
        .connectionCandidates(store.selected)
        .map((p) => p.id)
        .toList();
    // The explicitly selected profile is never replaced by the priority
    // protocol; other imported profiles only follow it as fallbacks.
    expect(ids.first, 'xr1');
    expect(ids, contains('awg2'));
  });
  test('same-endpoint variant goes before another endpoint profile', () {
    final store = SwitchingStore();
    store.profiles.addAll(const [
      Profile(
        id: 'variant',
        name: 'Тот же сервер, другой протокол',
        protocol: 'rivet-h3',
        endpoint: 'one.example:443',
      ),
      Profile(
        id: 'far',
        name: 'Другой сервер',
        protocol: 'awg',
        endpoint: 'three.example:443',
      ),
    ]);
    final ids = store
        .connectionCandidates(store.selected)
        .map((p) => p.id)
        .toList();
    expect(ids.first, 'xr1');
    expect(
      ids.indexOf('variant'),
      lessThan(ids.indexOf('awg2')),
      reason: 'вариант того же endpoint пробуется раньше чужих профилей',
    );
    expect(
      ids.indexOf('awg2'),
      lessThan(ids.indexOf('far')),
      reason: 'остальные профили идут последними',
    );
  });
  for (final fail in [false, true]) {
    testWidgets('switch waits for stop and refuses failed stop: $fail', (
      tester,
    ) async {
      final store = SwitchingStore()..failStop = fail;
      await tester.pumpWidget(MaterialApp(home: ClientHome(store: store)));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('client-server-picker')));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 350));
      await tester.tap(find.text('Сервер два'));
      await tester.pump(const Duration(milliseconds: 350));
      expect(store.calls, isEmpty);
      await tester.tap(find.widgetWithText(FilledButton, 'Переключить'));
      await tester.pumpAndSettle();
      expect(
        store.calls,
        fail
            ? ['disconnect', 'refresh']
            : ['disconnect', 'refresh', 'select:awg2', 'connect:awg2'],
      );
      expect(store.selectedId, fail ? 'xr1' : 'awg2');
    });
  }
  testWidgets('small display and large text keep client scrollable', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: const TextScaler.linear(1.5)),
          child: child!,
        ),
        home: ClientHome(store: SwitchingStore()),
      ),
    );
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(find.text('XIO Client'), findsOneWidget);
    expect(find.text('Установка сервера'), findsNothing);
  });
  testWidgets('shared home theme previews with test profiles', (tester) async {
    await (FontLoader(
      'X1oSans',
    )..addFont(rootBundle.load('assets/fonts/NotoSans-Regular.ttf'))).load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
    tester.view.physicalSize = const Size(392, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, (call) async {
          if (call.method == 'routingGet') {
            return {
              'mode': 'all',
              'packages': <String>[],
              'networks': <String>[],
            };
          }
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, null),
    );
    for (final brightness in Brightness.values) {
      final key = GlobalKey();
      final store = SwitchingStore()..status = const TunnelStatus();
      await tester.pumpWidget(
        MaterialApp(
          theme: xioTheme(brightness, client: true),
          home: RepaintBoundary(
            key: key,
            child: ClientHome(store: store),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      await tester.runAsync(() async {
        final boundary =
            key.currentContext!.findRenderObject() as RenderRepaintBoundary;
        final image = await boundary.toImage(pixelRatio: 2);
        final data = await image.toByteData(format: ui.ImageByteFormat.png);
        final folder = Directory('../.build-support/client-preview')
          ..createSync(recursive: true);
        await File('${folder.path}/home-${brightness.name}.png')
            .writeAsBytes(data!.buffer.asUint8List());
        image.dispose();
      });
    }
  });
}
