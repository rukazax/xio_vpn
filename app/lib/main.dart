import 'desktop_engine.dart';
import 'help_legal_ui.dart';
import 'l10n.dart';

import 'dart:convert';
import 'dart:async';

import 'startup_statistics.dart';

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter/foundation.dart'
    show LicenseRegistry, LicenseEntryWithLineBreaks;
import 'package:flutter/services.dart';

import 'core.dart';
import 'workspace_ui.dart';

extension X1oColors on BuildContext {
  Color get ink => Theme.of(this).scaffoldBackgroundColor;
  Color get panel => Theme.of(this).colorScheme.surface;
  Color get lime => Theme.of(this).colorScheme.primary;
  Color get muted => Theme.of(this).colorScheme.onSurfaceVariant;
  Color get warning => Theme.of(this).colorScheme.error;
}

ThemeData x1oTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final background = Color(dark ? 0xff0c1119 : 0xfff2f5ef);
  final surface = Color(dark ? 0xff151e2a : 0xffffffff);
  final accent = Color(dark ? 0xffc0f57b : 0xff35620f);
  final scheme = ColorScheme.fromSeed(seedColor: accent, brightness: brightness)
      .copyWith(
        primary: accent,
        secondary: const Color(0xffc0f57b),
        onPrimary: const Color(0xff15220a),
        surface: surface,
        surfaceContainerLowest: background,
        surfaceContainerLow: surface,
        surfaceContainer: Color(dark ? 0xff192332 : 0xffffffff),
        surfaceContainerHigh: Color(dark ? 0xff192332 : 0xffffffff),
        surfaceContainerHighest: Color(dark ? 0xff27313e : 0xffe1e8db),
        onSurface: Color(dark ? 0xffe7efde : 0xff182117),
        onSurfaceVariant: Color(dark ? 0xff9baabc : 0xff53614f),
        outlineVariant: Color(dark ? 0xff27313e : 0xffd1dacd),
        error: Color(dark ? 0xffffba98 : 0xffa12f19),
      );
  return ThemeData(
    useMaterial3: true,
    dialogTheme: DialogThemeData(
      backgroundColor: Color(dark ? 0xff192332 : 0xffffffff),
      insetPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
      constraints: const BoxConstraints.tightFor(width: 880),
    ),
    cardTheme: CardThemeData(
      color: surface,
      surfaceTintColor: Colors.transparent,
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: surface,
      foregroundColor: scheme.onSurface,
      surfaceTintColor: Colors.transparent,
    ),
    brightness: brightness,
    scaffoldBackgroundColor: background,
    colorScheme: scheme,
    fontFamily: 'X1oSans', // Original XIO Noto Sans typography.
    fontFamilyFallback: const ['X1oArabic', 'X1oDevanagari', 'X1oCJK'],
    textTheme: const TextTheme(
      headlineLarge: TextStyle(
        fontSize: 36,
        fontWeight: FontWeight.w700,
        letterSpacing: -1.2,
      ),
      titleLarge: TextStyle(fontSize: 21, fontWeight: FontWeight.w600),
      bodyMedium: TextStyle(height: 1.5, fontSize: 14),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: background,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide.none,
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: const Color(0xffc0f57b),
        foregroundColor: const Color(0xff15220a),
        minimumSize: const Size(48, 48),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(48, 48),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    navigationBarTheme: NavigationBarThemeData(
      height: 64,
      backgroundColor: surface,
      surfaceTintColor: Colors.transparent,
      indicatorColor: accent.withValues(alpha: dark ? .16 : .12),
      labelTextStyle: WidgetStateProperty.resolveWith(
        (states) => TextStyle(
          fontSize: 10.5,
          fontWeight: states.contains(WidgetState.selected)
              ? FontWeight.w700
              : FontWeight.w500,
          height: 1.05,
          color: states.contains(WidgetState.selected)
              ? accent
              : scheme.onSurfaceVariant,
        ),
      ),
      iconTheme: WidgetStateProperty.resolveWith(
        (states) => IconThemeData(
          size: 22,
          color: states.contains(WidgetState.selected)
              ? accent
              : scheme.onSurfaceVariant,
        ),
      ),
    ),
  );
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (Platform.isLinux || Platform.isWindows) await DesktopEngine.initialise();
  LicenseRegistry.addLicense(() async* {
    for (final license in [
      ('WireGuard Android / AmneziaWG Android', 'Apache-2.0.txt'),
      ('AmneziaWG native and Go dependencies', 'AmneziaWG-native.txt'),
      ('RIVET transports and Go dependencies', 'RIVET-native.txt'),
      ('Xray core', 'Xray-MPL-2.0.txt'),
      ('Mozilla CA subset: GTS R1/R3/R4 and SSL.com ECC', 'Xray-MPL-2.0.txt'),
      ('Cloak', 'Cloak-GPL-3.0.txt'),
      ('XIO original code - GPL-3.0-only', 'XIO-GPL-3.0.txt'),
      ('Tailscale', 'Tailscale-BSD.txt'),
      ('OpenVPN 3 (MPL-2.0 alternative)', 'OpenVPN-MPL-2.0.txt'),
      ('MbedTLS', 'MbedTLS-license.txt'),
      ('Asio', 'Asio-license.txt'),
      ('fmt', 'Fmt-license.txt'),
      ('LZ4', 'LZ4-license.txt'),
      ('StrongSwan VICI Python', 'VICI-MIT.txt'),
      ('anet', 'Anet-license.txt'),
      ('WireGuard native', 'WireGuard-MIT.txt'),
      ('Noto Sans', 'Noto-fonts.txt'),
      ('Noto Sans CJK', 'Noto-CJK-OFL.txt'),
      ('Noto Sans Arabic / Devanagari', 'Noto-additional-OFL.txt'),
    ]) {
      yield LicenseEntryWithLineBreaks([
        license.$1,
      ], await rootBundle.loadString('assets/licenses/${license.$2}'));
    }
  });
  await AppLanguages.load();
  final store = AppStore()..enforceConsent = true;
  native.setMethodCallHandler((call) async {
    if (call.method == 'requestConnect' && store.ready) {
      if (await native.invokeMethod<bool>('consumeConnectRequest') == true) {
        await store.connect();
      }
    }
  });
  runApp(X1oApp(store: store, requireConsent: true));
  final statistics = StartupStatistics();
  void refreshAfterConsent() {
    if (store.ready && store.consentReady) unawaited(statistics.run(store));
  }

  store.addListener(refreshAfterConsent);
  unawaited(store.load().then((_) => refreshAfterConsent()));
}

class X1oApp extends StatelessWidget {
  final AppStore store;
  final bool requireConsent;
  const X1oApp({super.key, required this.store, this.requireConsent = false});
  @override
  Widget build(BuildContext context) => ValueListenableBuilder<int>(
    valueListenable: AppLanguages.revision,
    builder: (context, _, _) => MaterialApp(
      locale: AppLanguages.selected == null
          ? null
          : Locale(AppLanguages.selected!),
      supportedLocales: AppLanguages.locales,
      localizationsDelegates: GlobalMaterialLocalizations.delegates,
      localeListResolutionCallback: (locales, supported) =>
          Locale(AppLanguages.selected ?? AppLanguages.resolve(locales ?? [])),
      title: 'XIO · X in, 1 out',
      debugShowCheckedModeBanner: false,
      theme: x1oTheme(Brightness.light),
      darkTheme: x1oTheme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: requireConsent
          ? FirstRunGate(
              store: store,
              child: WorkspaceShell(store: store),
            )
          : WorkspaceShell(store: store),
    ),
  );
}

class BrandMark extends StatelessWidget {
  final double size;
  const BrandMark({super.key, this.size = 44});
  @override
  Widget build(BuildContext context) => SizedBox(
    width: size,
    height: size,
    child: CustomPaint(
      painter: _MarkPainter(
        context.lime,
        Theme.of(context).colorScheme.onSurface,
      ),
    ),
  );
}

class _MarkPainter extends CustomPainter {
  final Color accent, foreground;
  _MarkPainter(this.accent, this.foreground);
  @override
  void paint(Canvas canvas, Size size) {
    canvas.scale(size.width / 64, size.height / 64);
    final pen = Paint()
      ..color = accent
      ..strokeWidth = 5
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    canvas.drawPath(
      Path()
        ..moveTo(9, 12)
        ..lineTo(30, 32)
        ..lineTo(55, 32),
      pen,
    );
    canvas.drawPath(
      Path()
        ..moveTo(9, 52)
        ..lineTo(30, 32),
      pen,
    );
    canvas.drawPath(
      Path()
        ..moveTo(9, 32)
        ..lineTo(19, 32),
      pen..color = foreground,
    );
    canvas.drawPath(
      Path()
        ..moveTo(47, 24)
        ..lineTo(55, 32)
        ..lineTo(47, 40),
      pen..color = accent,
    );
  }

  @override
  bool shouldRepaint(_MarkPainter old) =>
      old.accent != accent || old.foreground != foreground;
}

class Surface extends StatelessWidget {
  final Widget child;
  const Surface({super.key, required this.child});
  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: EdgeInsets.all(MediaQuery.sizeOf(context).width < 600 ? 16 : 22),
    decoration: BoxDecoration(
      color: context.panel,
      borderRadius: BorderRadius.circular(22),
      border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
    ),
    child: child,
  );
}

void message(BuildContext context, String text) => ScaffoldMessenger.of(context)
    .showSnackBar(
      SnackBar(content: LText(text), duration: const Duration(seconds: 6)),
    );

class ImportDialog extends StatefulWidget {
  final AppStore store;
  const ImportDialog({super.key, required this.store});
  @override
  State<ImportDialog> createState() => _ImportDialogState();
}

class _ImportDialogState extends State<ImportDialog> {
  final name = TextEditingController(), config = TextEditingController();
  String? error;
  bool busy = false;
  @override
  void initState() {
    super.initState();
    if (Platform.isAndroid) {
      native.invokeMethod('secureScreen', {'enabled': true});
    }
  }

  @override
  void dispose() {
    name.dispose();
    config.dispose();
    if (Platform.isAndroid) {
      native.invokeMethod('secureScreen', {'enabled': false});
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    insetPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 24),
    constraints: const BoxConstraints.tightFor(width: 880),
    title: const LText('Новое подключение'),
    content: SizedBox(
      width: 800,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: name,
              decoration: InputDecoration(
                labelText: tr(context, 'Название'),
                hintText: tr(context, 'Мой сервер'),
              ),
            ),
            const SizedBox(height: 16),
            if (Platform.isAndroid) ...[
              const SizedBox(height: 12),
              TextButton.icon(
                onPressed: busy
                    ? null
                    : () async {
                        final data = await Clipboard.getData(
                          Clipboard.kTextPlain,
                        );
                        if (mounted && data?.text != null) {
                          config.text = data!.text!;
                        }
                      },
                icon: const Icon(Icons.paste),
                label: const LText('Вставить из буфера'),
              ),
              TextField(
                controller: config,
                minLines: 7,
                maxLines: 12,
                autocorrect: false,
                enableSuggestions: false,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                decoration: InputDecoration(
                  labelText: tr(context, 'Профиль XIO или конфигурация .conf'),
                  hintText: '[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …',
                ),
              ),
            ],
            if (!Platform.isAndroid)
              LText(
                'Этот профиль управляет уже установленным Tailscale. Сначала авторизуйте службу штатным клиентом. Установка Headscale-клиента: tailscale up --login-server=https://ваш-сервер.\n\nВ этой версии поддерживается одна локальная служба Tailscale; смена координатора выполняется штатным клиентом.',
                style: TextStyle(color: context.muted),
              ),
            if (error != null)
              Padding(
                padding: const EdgeInsets.only(top: 14),
                child: LText(error!, style: TextStyle(color: context.warning)),
              ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: busy ? null : () => Navigator.pop(context),
        child: const LText('Отмена'),
      ),
      FilledButton(
        onPressed: busy
            ? null
            : () async {
                setState(() => busy = true);
                try {
                  if (Platform.isAndroid) {
                    await widget.store.importConnection(
                      config.text,
                      name: name.text,
                    );
                  } else {
                    await widget.store.addTailscale(
                      name.text.trim().isEmpty
                          ? AppLanguages.text('Моя tailnet')
                          : name.text.trim(),
                    );
                  }
                  if (context.mounted) Navigator.pop(context);
                } catch (e) {
                  if (mounted) {
                    setState(
                      () => error = e is FormatException
                          ? e.message.toString()
                          : 'Не удалось сохранить профиль',
                    );
                  }
                } finally {
                  if (mounted) setState(() => busy = false);
                }
              },
        child: LText(busy ? 'Сохранение…' : 'Добавить'),
      ),
    ],
  );
}

class LabPage extends StatefulWidget {
  final AppStore store;
  const LabPage({super.key, required this.store});
  @override
  State<LabPage> createState() => _LabPageState();
}

class _LabPageState extends State<LabPage> {
  final host = TextEditingController(),
      port = TextEditingController(text: '443');
  List<Map<String, dynamic>> checks = [];
  bool busy = false;
  String? error;
  @override
  void dispose() {
    host.dispose();
    port.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Surface(
        child: Column(
          children: [
            TextField(
              controller: host,
              decoration: InputDecoration(
                labelText: tr(context, 'Адрес для проверки'),
                hintText: tr(context, 'Ваш домен или IP'),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: port,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(labelText: tr(context, 'TCP-порт')),
            ),
            const SizedBox(height: 18),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: busy
                    ? null
                    : () async {
                        setState(() {
                          busy = true;
                          error = null;
                        });
                        try {
                          final result = await NetworkChecks.run(
                            host.text.trim(),
                            int.tryParse(port.text) ?? 0,
                          );
                          if (mounted) setState(() => checks = result);
                        } catch (_) {
                          if (mounted) {
                            setState(() => error = 'Проверьте адрес и порт');
                          }
                        } finally {
                          if (mounted) setState(() => busy = false);
                        }
                      },
                icon: busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.play_arrow),
                label: LText(busy ? 'Проверяем…' : 'Запустить проверку'),
              ),
            ),
            if (error != null) LText(error!),
          ],
        ),
      ),
      for (final c in checks)
        Padding(
          padding: const EdgeInsets.only(top: 12),
          child: Surface(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  c['ok'] == true
                      ? Icons.check_circle_outline
                      : Icons.error_outline,
                  color: c['ok'] == true ? context.lime : context.warning,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '${c['test']}${c['ms'] == null ? '' : ' · ${c['ms']} ms'}',
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 6),
                      LText(
                        c['detail'],
                        style: TextStyle(color: context.muted),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      const SizedBox(height: 18),
      if (checks.isNotEmpty)
        OutlinedButton.icon(
          onPressed: () async {
            await Clipboard.setData(
              ClipboardData(
                text: const JsonEncoder.withIndent('  ')
                    .convert(widget.store.diagnosticReport(checks)),
              ),
            );
            if (context.mounted) {
              message(context, 'JSON-отчёт без ключей скопирован');
            }
          },
          icon: const Icon(Icons.copy),
          label: const LText('Скопировать отчёт'),
        ),
    ],
  );
}

class AndroidControls extends StatefulWidget {
  const AndroidControls({super.key});
  @override
  State<AndroidControls> createState() => _AndroidControlsState();
}

class _AndroidControlsState extends State<AndroidControls> {
  String? message;
  bool busy = false;
  Future<void> addTile() async {
    setState(() {
      busy = true;
      message = null;
    });
    try {
      final code = await native.invokeMethod<int>('addQuickTile');
      if (mounted) {
        setState(
          () => message = switch (code) {
            1 => 'Плитка уже добавлена в быстрые настройки.',
            2 => 'Плитка XIO добавлена.',
            0 => 'Добавление отменено. Можно повторить позже.',
            -1 => 'Разверните шторку → Изменить плитки → перетащите XIO VPN.',
            _ => 'Android не добавил плитку. Добавьте XIO VPN через редактирование быстрых настроек.',
          },
        );
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => message =
              'Разверните шторку → Изменить плитки → добавьте XIO VPN.',
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Surface(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const LText(
          'Шторка и уведомления',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 12),
        LText(
          'Подключение и отключение VPN из быстрых настроек.',
          style: TextStyle(color: context.muted),
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 12,
          runSpacing: 8,
          children: [
            FilledButton.icon(
              onPressed: busy ? null : addTile,
              icon: const Icon(Icons.dashboard_customize_outlined),
              label: LText(busy ? 'Ожидается Android…' : 'Добавить плитку XIO'),
            ),
            OutlinedButton(
              onPressed: () => native.invokeMethod('notificationSettings'),
              child: const LText('Настройки уведомлений'),
            ),
          ],
        ),
        if (message != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: LText(message!, style: TextStyle(color: context.muted)),
          ),
      ],
    ),
  );
}
