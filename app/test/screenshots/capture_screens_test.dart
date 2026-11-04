/// Documentation screenshots for `README.md` / `README.ru.md` / `docs/`.
///
/// Android builds set `FLAG_SECURE`, so `adb screencap` returns a black frame.
/// The honest way to get real XIO screens is to render the actual widgets here
/// and write the PNGs straight from the test: Flutter paints them, the system
/// screenshot protection never gets a say.
///
/// Rendering always runs (it is a layout assertion); files are only written
/// when capture is explicitly requested:
///
/// ```sh
/// XIO_CAPTURE_IMAGES=1 flutter test test/screenshots
/// ```
///
/// Output: `../docs/screenshots/*.png` (relative to `app/`, i.e. the repo root).
/// The table "file → what is on it → how to reproduce it" lives in
/// `docs/screenshots/README.md`.
library;

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/app_settings.dart';
import 'package:xio/app_theme.dart';
import 'package:xio/cascade_health.dart';
import 'package:xio/cascade_model.dart';
import 'package:xio/cascade_ui.dart';
import 'package:xio/core.dart';
import 'package:xio/l10n.dart';
import 'package:xio/mtproto_ui.dart';
import 'package:xio/workspace_ui.dart';

import '../support/screenshots.dart';

/// Portrait phone: 1080×2400 physical pixels at DPR 3 → 360×800 logical.
const Size _phonePhysical = Size(1080, 2400);
const double _phoneDpr = 3;

/// Wide phone used for one frame: 412×915 logical, captured at 2× (824×1830).
const Size _wideLogical = Size(412, 915);
const double _wideCapture = 2;

/// The fallback chain `xioTheme` declares. `X1oCJK` is the one that carries the
/// `→` arrow: the Latin subset has no `U+2192`, and without the fallback the
/// cascade captions would render `.notdef` boxes instead of the arrow the
/// application shows on a device.
const List<String> _themeFallback = <String>[
  'X1oArabic',
  'X1oDevanagari',
  'X1oCJK',
];

/// Optional emoji fallback. `NotoSans` has no regional indicators (🇷🇺), so the
/// server flags would render as `.notdef` boxes. The system emoji font is used
/// only when it exists — the test itself never depends on it.
String? _emojiFamily;

const List<String> _emojiFontCandidates = <String>[
  '/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf',
  '/usr/share/fonts/noto/NotoColorEmoji.ttf',
  '/usr/share/fonts/truetype/noto-emoji/NotoColorEmoji.ttf',
];

/// The install command is drawn with `fontFamily: 'monospace'`, which resolves
/// to a system font on a device. A test host has no system fonts, so without
/// this the command renders as `.notdef` boxes. A real monospace file is used
/// when present; the bundled sans font keeps the frame readable otherwise.
const List<String> _monoFontCandidates = <String>[
  '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
  '/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf',
  '/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf',
];

Future<void> _loadFonts() async {
  for (final font in <String, String>{
    'X1oSans': 'assets/fonts/NotoSans-Regular.ttf',
    // Arrows (`→`) live only in the CJK subset, exactly as in the app.
    'X1oCJK': 'assets/fonts/NotoSansCJKsc-Regular.otf',
    'MaterialIcons': 'fonts/MaterialIcons-Regular.otf',
  }.entries) {
    await (FontLoader(font.key)..addFont(rootBundle.load(font.value))).load();
  }
  for (final path in _emojiFontCandidates) {
    final file = File(path);
    if (!file.existsSync()) continue;
    final bytes = await file.readAsBytes();
    await (FontLoader('X1oEmoji')
          ..addFont(Future<ByteData>.value(ByteData.view(bytes.buffer))))
        .load();
    _emojiFamily = 'X1oEmoji';
    break;
  }
  for (final path in _monoFontCandidates) {
    final file = File(path);
    if (!file.existsSync()) continue;
    final bytes = await file.readAsBytes();
    await (FontLoader('monospace')
          ..addFont(Future<ByteData>.value(ByteData.view(bytes.buffer))))
        .load();
    return;
  }
  await (FontLoader('monospace')
        ..addFont(rootBundle.load('assets/fonts/NotoSans-Regular.ttf')))
      .load();
}

/// The application theme, plus the emoji fallback when the host has one.
ThemeData _theme(Brightness brightness) {
  final base = xioTheme(brightness);
  final fallback = <String>[..._themeFallback, ?_emojiFamily];
  return base.copyWith(
    textTheme: base.textTheme.apply(fontFamilyFallback: fallback),
    primaryTextTheme: base.primaryTextTheme.apply(fontFamilyFallback: fallback),
  );
}

/// The real shell, wrapped the way `XioApp` wraps it (see `lib/main.dart`).
Widget _app(AppStore store) => MaterialApp(
  locale: const Locale('ru'),
  supportedLocales: AppLanguages.locales,
  localizationsDelegates: GlobalMaterialLocalizations.delegates,
  localeListResolutionCallback: (_, _) => const Locale('ru'),
  debugShowCheckedModeBanner: false,
  theme: _theme(Brightness.dark),
  home: WorkspaceShell(store: store),
);

/// Wraps a single screen the way `XioApp` wraps the shell, for the frames that
/// are pages of their own (they still need the ru locale and the app theme).
Widget _page(Widget home) => MaterialApp(
  locale: const Locale('ru'),
  supportedLocales: AppLanguages.locales,
  localizationsDelegates: GlobalMaterialLocalizations.delegates,
  localeListResolutionCallback: (_, _) => const Locale('ru'),
  debugShowCheckedModeBanner: false,
  theme: _theme(Brightness.dark),
  home: home,
);

/// Store in the state the screenshots document: a configured server, the
/// tunnel is off (`TunnelStatus()` → «Отключено»), cascade addresses are saved.
class _ScreenshotStore extends AppStore {
  _ScreenshotStore() {
    ready = true;
    profiles.addAll(const <Profile>[
      Profile(
        id: 'shot-main',
        name: 'Основной сервер',
        protocol: 'xray',
        endpoint: '81.177.142.37:443',
      ),
      Profile(
        id: 'shot-backup',
        name: 'Резервный сервер',
        protocol: 'awg',
        endpoint: '185.14.30.7:51820',
      ),
    ]);
    selectedId = 'shot-main';
    endpointCountries['81.177.142.37:443'] = 'RU';
    endpointCountries['185.14.30.7:51820'] = 'NL';
    cascadeBridge = '81.177.142.37';
    cascadeExit = '2a0c:b641:1a0:800::2a2';
    // 0.24.2 settings: a third-party resolver, a saved MTProto link and the
    // three behaviour switches (autostart / auto-connect / screenshots).
    dnsServers = const <String>['1.1.1.1', '2606:4700:4700::1111'];
    mtprotoLink =
        'tg://proxy?server=proxy.xio.fr&port=443'
        '&secret=ee0f1e2d3c4b5a69788796a5b4c3d2e1f0';
    autoConnectOnStart = true;
    allowScreenshots = true;
  }
}

/// Renders [key]'s boundary, writes the PNG and proves it is a real frame:
/// file signature, expected pixel size and more than one flat colour.
Future<void> _shoot(
  WidgetTester tester,
  GlobalKey key,
  String name, {
  required double pixelRatio,
}) async {
  if (!screenshotsEnabled) return;
  final context = key.currentContext;
  expect(context, isNotNull, reason: 'nothing to capture for $name');
  final boundary = context!.findRenderObject() as RenderRepaintBoundary;
  await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: pixelRatio);
    final png = await image.toByteData(format: ui.ImageByteFormat.png);
    final rgba = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
    image.dispose();
    expect(png, isNotNull, reason: '$name: no PNG bytes');
    final bytes = png!.buffer.asUint8List();
    final file = File('../docs/screenshots/$name');
    file.parent.createSync(recursive: true);
    file.writeAsBytesSync(bytes);

    // PNG signature + IHDR: width/height are big-endian 32-bit at 16 and 20.
    expect(
      bytes.sublist(0, 8),
      <int>[137, 80, 78, 71, 13, 10, 26, 10],
      reason: '$name: not a PNG',
    );
    final header = ByteData.sublistView(bytes, 16, 24);
    final width = header.getUint32(0);
    final height = header.getUint32(4);
    expect(width, (boundary.size.width * pixelRatio).round(), reason: name);
    expect(height, (boundary.size.height * pixelRatio).round(), reason: name);

    // A black (or otherwise flat) frame is exactly the failure this test
    // exists to prevent, so count sampled colours instead of trusting bytes.
    final pixels = rgba!.buffer.asUint8List();
    final colours = <int>{};
    for (var i = 0; i + 3 < pixels.length; i += 4 * 97) {
      colours.add(
        pixels[i] << 24 | pixels[i + 1] << 16 | pixels[i + 2] << 8 | pixels[i + 3],
      );
      if (colours.length > 64) break;
    }
    expect(
      colours.length,
      greaterThan(8),
      reason: '$name looks like a flat/black frame',
    );
  });
}

void main() {
  setUpAll(() async {
    await AppLanguages.load();
    await _loadFonts();
  });

  setUp(() => AppLanguages.set('ru'));
  tearDown(() => AppLanguages.set(null));

  testWidgets('main screen: idle, server chosen', (tester) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(key: key, child: _app(store)),
    );
    await tester.pumpAndSettle();

    expect(find.text('Отключено'), findsOneWidget);
    expect(find.text('Подключиться'), findsOneWidget);
    expect(find.textContaining('Основной сервер'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'main-idle.png', pixelRatio: _phoneDpr);
  });

  testWidgets('connection tab: key, own server, cascade, user', (tester) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(key: key, child: _app(store)),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(2));
    await tester.pumpAndSettle();

    for (final item in const <String>[
      'Вставить ключ или конфигурацию',
      'VPN на своём сервере',
      'Каскад: IPv4-IPv6',
      'Добавить пользователя',
    ]) {
      expect(find.text(item).hitTestable(), findsOneWidget, reason: item);
    }
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'connection-tab.png', pixelRatio: _phoneDpr);
  });

  testWidgets('settings: list, then the application/locale screen', (
    tester,
  ) async {
    tester.view.physicalSize = _wideLogical;
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(key: key, child: _app(store)),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byType(NavigationDestination).at(1));
    await tester.pumpAndSettle();

    for (final item in const <String>[
      'Серверы',
      'Соединение',
      'Приложение',
      'Пользователи',
      'О XIO',
    ]) {
      // «Соединение» is also the bottom-bar label, so match the tile itself.
      expect(
        find.widgetWithText(ListTile, item).hitTestable(),
        findsOneWidget,
        reason: item,
      );
    }
    await _shoot(tester, key, 'settings.png', pixelRatio: _wideCapture);

    await tester.tap(find.text('Приложение').hitTestable());
    await tester.pumpAndSettle();
    expect(find.text('Проверить обновления').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
    await _shoot(tester, key, 'settings-locales.png', pixelRatio: _wideCapture);
  });

  testWidgets('cascade screen: configured bridge and IPv6 exit', (tester) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: _theme(Brightness.dark),
          home: const CascadeScreen(
            bridgeAddress: '81.177.142.37',
            exitAddress: '2a0c:b641:1a0:800::2a2',
            subscription: CascadeSubscription(
              entitled: true,
              planLabel: 'XIO Cascade',
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Каскад'), findsOneWidget);
    expect(find.textContaining('2a0c:b641:1a0:800::2a2'), findsWidgets);
    expect(find.text('XIO Cascade'), findsOneWidget);
    // P1 replaced the fake demo ping with the real healthcheck button.
    expect(find.text('Проверить каскад'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'cascade-configured.png', pixelRatio: _phoneDpr);
  });

  testWidgets('cascade health: result of «Проверить каскад»', (tester) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    // The probe is a stand-in for the SSH round-trip: the frame documents the
    // screen after a real check that came back alive, including the measured
    // latency and the egress IPv6 the server reported.
    var probedBridge = '';
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: _theme(Brightness.dark),
          home: CascadeScreen(
            bridgeAddress: '81.177.142.37',
            exitAddress: '2a0c:b641:1a0:800::2a2',
            subscription: const CascadeSubscription(
              entitled: true,
              planLabel: 'XIO Cascade',
            ),
            healthProbe: (bridge) async {
              probedBridge = bridge;
              return CascadeHealth(
                verdict: CascadeHealthVerdict.ok,
                checkedAt: DateTime(2026, 11, 4, 23, 40),
                latencyMs: 214,
                role: 'bridge',
                runtime: 'systemd',
                exitHost: '2a0c:b641:1a0:800::2a2',
                egressIpv6: '2a0c:b641:1a0:800::2a2',
                checks: const <CascadeHealthCheck>[
                  CascadeHealthCheck(
                    name: 'bridge.tunnel',
                    ok: true,
                    detail: 'awg0 up',
                  ),
                  CascadeHealthCheck(
                    name: 'exit.egress6',
                    ok: true,
                    detail: '2a0c:b641:1a0:800::2a2',
                  ),
                ],
              );
            },
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Проверить каскад'), findsOneWidget);
    expect(probedBridge, isEmpty);

    await tester.tap(find.text('Проверить каскад'));
    await tester.pumpAndSettle();

    expect(probedBridge, '81.177.142.37');
    expect(find.text('214 мс'), findsOneWidget);
    expect(find.textContaining('2a0c:b641:1a0:800::2a2'), findsWidgets);
    expect(find.text('Проверить каскад'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'cascade-health.png', pixelRatio: _phoneDpr);
  });

  testWidgets('cascade servers dialog: two fields and the install command', (
    tester,
  ) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: _theme(Brightness.dark),
          home: const CascadeScreen(
            bridgeAddress: '81.177.142.37',
            exitAddress: '2a0c:b641:1a0:800::2a2',
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Серверы каскада'));
    await tester.pumpAndSettle();

    expect(find.text('Серверы каскада'), findsOneWidget);
    expect(find.text('Bridge (IPv4 или домен)'), findsOneWidget);
    expect(find.text('Exit (только IPv6)'), findsOneWidget);
    expect(find.textContaining('--role bridge'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(
      tester,
      key,
      'cascade-servers-dialog.png',
      pixelRatio: _phoneDpr,
    );
  });

  testWidgets('dns resolver: presets, the saved pair and the custom fields', (
    tester,
  ) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(key: key, child: _page(DnsSettingsPage(store: store))),
    );
    await tester.pumpAndSettle();

    expect(find.text('DNS-резолвер'), findsOneWidget);
    for (final item in const <String>[
      'AdGuard DNS (IPv6)',
      'Quad9',
      'Cloudflare',
      'Google Public DNS',
      'Свои',
    ]) {
      expect(find.text(item).hitTestable(), findsOneWidget, reason: item);
    }
    // The saved pair is preselected, so its addresses are on the screen.
    expect(find.text('1.1.1.1, 2606:4700:4700::1111'), findsOneWidget);
    expect(find.text('Сохранить').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'settings-dns.png', pixelRatio: _phoneDpr);
  });

  testWidgets('mtproto proxy: instruction, saved link and status', (
    tester,
  ) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: _page(
          Scaffold(
            appBar: AppBar(title: const LText('Telegram-прокси (MTProto)')),
            body: SafeArea(
              // The screen has no Scaffold of its own: the settings page
              // supplies the title and the scroll view.
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: MtprotoProxyScreen(store: store),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Как включить прокси в Telegram'), findsOneWidget);
    expect(find.textContaining('Данные и память'), findsOneWidget);
    expect(find.text('Прокси настроен'), findsOneWidget);
    expect(find.text('Сохранить').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(tester, key, 'settings-mtproto.png', pixelRatio: _phoneDpr);
  });

  testWidgets('application settings: autostart, auto-connect, screenshots', (
    tester,
  ) async {
    tester.view.physicalSize = _phonePhysical;
    tester.view.devicePixelRatio = _phoneDpr;
    tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);

    final store = _ScreenshotStore();
    addTearDown(store.dispose);
    final key = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: key,
        child: _page(
          Scaffold(
            appBar: AppBar(title: const LText('Приложение')),
            body: SafeArea(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: AppBehaviorSettings(store: store),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    for (final item in const <String>[
      'Автозапуск при загрузке устройства',
      'Автоподключение после запуска',
      'Разрешить скриншоты',
    ]) {
      expect(find.text(item).hitTestable(), findsOneWidget, reason: item);
    }
    // The test host is Linux, so `Platform.isAndroid` is false and the
    // autostart row renders its non-Android fallback text: the frame is an
    // honest render of the widget, not a photograph of a phone.
    expect(find.textContaining('Доступно в сборке для Android'), findsOneWidget);
    expect(tester.takeException(), isNull);

    await _shoot(
      tester,
      key,
      'settings-behaviour.png',
      pixelRatio: _phoneDpr,
    );
  });
}
