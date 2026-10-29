import 'dart:io';

import 'desktop_engine.dart';
import 'app_theme.dart';

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'client_policy.dart';
import 'core.dart';
import 'help_legal_ui.dart';
import 'l10n.dart';
import 'split_routing.dart';
import 'subclients_ui.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (!clientOnlyBuild) throw StateError('Build with XIO_CLIENT_ONLY=true');
  if (Platform.isLinux || Platform.isWindows) {
    await DesktopEngine.initialise();
  } else {
    await native.invokeMethod<void>('secureScreen', {'enabled': true});
  }
  await AppLanguages.load();
  for (final name in [
    'RIVET-native',
    'AmneziaWG-native',
    'Xray-MPL-2.0',
    'OpenVPN-MPL-2.0',
    'Cloak-GPL-3.0',
    'XIO-GPL-3.0',
  ]) {
    LicenseRegistry.addLicense(() async* {
      yield LicenseEntryWithLineBreaks([
        name,
      ], await rootBundle.loadString('assets/licenses/$name.txt'));
    });
  }
  final store = AppStore()..enforceConsent = true;
  native.setMethodCallHandler((call) async {
    if (call.method == 'requestConnect' && store.ready && store.consentReady) {
      if (await native.invokeMethod<bool>('consumeConnectRequest') == true) {
        await store.connect();
      }
    }
  });
  runApp(ClientApp(store: store));
  unawaited(store.load());
}

class ClientApp extends StatelessWidget {
  final AppStore store;
  const ClientApp({super.key, required this.store});
  @override
  Widget build(BuildContext context) => ValueListenableBuilder<int>(
    valueListenable: AppLanguages.revision,
    builder: (context, _, _) => MaterialApp(
      title: 'XIO Client',
      debugShowCheckedModeBanner: false,
      localizationsDelegates: GlobalMaterialLocalizations.delegates,
      supportedLocales: const [Locale('ru'), Locale('en')],
      locale: Locale(AppLanguages.effective == 'ru' ? 'ru' : 'en'),
      themeMode: ThemeMode.system,
      theme: xioTheme(Brightness.light, client: true),
      darkTheme: xioTheme(Brightness.dark, client: true),
      home: FirstRunGate(
        store: store,
        child: ClientHome(store: store),
      ),
    ),
  );
}

class ClientHome extends StatefulWidget {
  final AppStore store;
  const ClientHome({super.key, required this.store});
  @override
  State<ClientHome> createState() => _ClientHomeState();
}

class _ClientHomeState extends State<ClientHome> with WidgetsBindingObserver {
  AppStore get store => widget.store;
  bool working = false;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) =>
      store.setForeground(state == AppLifecycleState.resumed);

  Future<void> perform(Future<void> Function() action) async {
    if (working || store.busy) return;
    setState(() => working = true);
    try {
      await action();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: LText(
              e is FormatException
                  ? e.message
                  : e is StateError
                  ? e.message
                  : 'Операция не завершена. Проверьте профиль и разрешения.',
            ),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => working = false);
    }
  }

  Future<void> choose(Profile p) async {
    if (store.selectedId == p.id) return;
    if (store.status.active) {
      final agreed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const LText('Переключить сервер?'),
          content: const LText(
            'Текущий VPN отключится, затем начнётся подключение к выбранному профилю. Между подключениями VPN не защищает трафик. Для блокировки используйте системный режим «Блокировать соединения без VPN».',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const LText('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const LText('Переключить'),
            ),
          ],
        ),
      );
      if (agreed != true) return;
      await store.disconnect();
      await store.refresh(fresh: true);
      if (store.status.active || store.error != null) {
        throw StateError('Старый туннель не отключён; переключение отменено');
      }
      await store.select(p.id);
      await store.connect();
    } else {
      await store.select(p.id);
    }
  }

  Future<void> importProfile() async {
    final raw = await showDialog<String>(
      context: context,
      builder: (_) => const ClientImportDialog(),
    );
    if (raw == null) return;
    final bundle = ClientImport.parse(raw).bundle;
    if (bundle?.clientAccess != null && mounted) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const LText('Доступ аккаунта к субклиентам'),
          content: LText(
            'API: ${bundle!.clientAccess!['endpoint']}\n\nЭтот профиль содержит ограниченный токен аккаунта. Вы сможете создавать субклиентов в пределах квоты, подтверждённой сервером. SSH/root/admin-ключей в нём нет. Профили получателей не унаследуют этот токен.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const LText('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const LText('Добавить аккаунт'),
            ),
          ],
        ),
      );
      if (confirmed != true) return;
    }
    await store.importConnection(raw);
  }

  Future<void> settings() async {
    final site = TextEditingController(text: store.checkSite);
    var siteCheck = store.siteCheckEnabled;
    try {
      final value = await showDialog<String>(
        context: context,
        builder: (context) => StatefulBuilder(
          builder: (context, setDialogState) => AlertDialog(
            title: const LText('Проверка соединения'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const LText(
                    'Готовность туннеля проверяется его собственными признаками: сессия поднялась, рукопожатие состоялось, шлюз ответил эхом. Внешний сайт для этого не нужен.',
                  ),
                  const SizedBox(height: 8),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: siteCheck,
                    title: const LText('Проверять доступность сайта'),
                    subtitle: const LText(
                      'Дополнительная проверка через HTTPS-сайт. Выключена по умолчанию: сайт может быть заблокирован, даже когда туннель работает.',
                    ),
                    onChanged: (v) => setDialogState(() => siteCheck = v),
                  ),
                  if (siteCheck) ...[
                    const LText(
                      'Он видит адрес выхода. При раздельном туннелировании проверка приложения может идти напрямую; доступность сайта не доказывает защиту остальных приложений.',
                    ),
                    TextField(
                      controller: site,
                      keyboardType: TextInputType.url,
                      decoration: InputDecoration(labelText: 'HTTPS URL'),
                    ),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const LText('Отмена'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(
                  context,
                  '${siteCheck ? '1' : '0'}|${site.text}',
                ),
                child: const LText('Сохранить'),
              ),
            ],
          ),
        ),
      );
      if (value != null) {
        final parts = value.split('|');
        await store.saveConnectionSettings(
          parts.length > 1 ? parts[1] : store.checkSite,
          store.priorityProtocol,
          siteCheck: parts.first == '1',
        );
      }
    } finally {
      site.dispose();
    }
  }

  Future<void> pickServer() async {
    final selected = await showModalBottomSheet<Profile>(
      context: context,
      isScrollControlled: true,
      builder: (context) => SafeArea(
        child: SizedBox(
          height: MediaQuery.sizeOf(context).height * .65,
          child: ListView(
            children: [
              const ListTile(title: LText('Серверы и подключения')),
              for (final profile in store.profiles)
                ListTile(
                  selected: profile.id == store.selectedId,
                  title: Text(profile.name),
                  subtitle: LText('${profile.protocol} · ${profile.endpoint}'),
                  onTap: () => Navigator.pop(context, profile),
                  trailing: IconButton(
                    tooltip: tr(context, 'Удалить профиль'),
                    onPressed: store.status.active
                        ? null
                        : () async {
                            final yes = await showDialog<bool>(
                              context: context,
                              builder: (context) => AlertDialog(
                                title: const LText(
                                  'Удалить профиль с устройства?',
                                ),
                                actions: [
                                  TextButton(
                                    onPressed: () =>
                                        Navigator.pop(context, false),
                                    child: const LText('Отмена'),
                                  ),
                                  FilledButton(
                                    onPressed: () =>
                                        Navigator.pop(context, true),
                                    child: const LText('Удалить'),
                                  ),
                                ],
                              ),
                            );
                            if (yes == true) {
                              await store.remove(profile.id);
                              if (context.mounted) Navigator.pop(context);
                            }
                          },
                    icon: const Icon(Icons.delete_outline),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
    if (selected != null) await choose(selected);
  }

  Future<void> information() => showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      title: const LText('XIO Client · 0.22.3'),
      content: SingleChildScrollView(child: SelectableText(clientDisclosure)),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(
            context,
          ).push(MaterialPageRoute<void>(builder: (_) => const PrivacyPage())),
          child: const LText('Конфиденциальность'),
        ),
        TextButton(
          onPressed: () => showLicensePage(
            context: context,
            applicationName: 'XIO Client',
            applicationVersion: '0.22.3',
          ),
          child: const LText('Лицензии'),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const LText('Закрыть'),
        ),
      ],
    ),
  );
  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) {
      final locked = working || store.busy;
      final profile = store.activeProfile ?? store.selected;
      final account = store.users
          .where((u) => u.profileIds.values.contains(profile?.id))
          .firstOrNull;
      String traffic(int? value) => value == null
          ? '—'
          : value >= 1000000000
          ? '${(value / 1000000000).toStringAsFixed(2)} GB'
          : value >= 1000000
          ? '${(value / 1000000).toStringAsFixed(1)} MB'
          : '${(value / 1000).toStringAsFixed(1)} KB';
      return Scaffold(
        appBar: AppBar(
          title: const LText('XIO Client'),
          actions: [
            PopupMenuButton<String>(
              tooltip: 'Language / Язык',
              icon: const Icon(Icons.language),
              onSelected: store.setLanguage,
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'ru', child: Text('Русский')),
                PopupMenuItem(value: 'en', child: Text('English')),
              ],
            ),
            IconButton(
              tooltip: tr(context, 'Как работает VPN'),
              onPressed: information,
              icon: const Icon(Icons.info_outline),
            ),
          ],
        ),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 640),
            child: ListView(
              padding: const EdgeInsets.fromLTRB(20, 26, 20, 24),
              children: [
                Center(
                  child: SizedBox(
                    width: 230,
                    height: 230,
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        shape: const CircleBorder(),
                        side: BorderSide(
                          width: 2,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                      onPressed: locked
                          ? null
                          : store.profiles.isEmpty
                          ? () => perform(importProfile)
                          : () => perform(
                              store.status.active
                                  ? store.disconnect
                                  : store.connect,
                            ),
                      child: locked
                          ? const CircularProgressIndicator()
                          : LText(
                              store.profiles.isEmpty
                                  ? 'Добавить подключение'
                                  : store.status.active
                                  ? 'Отключиться'
                                  : 'Подключиться',
                              textAlign: TextAlign.center,
                              style: const TextStyle(
                                fontSize: 21,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                LText(store.status.state, textAlign: TextAlign.center),
                if (store.connectionCheck != null)
                  Padding(
                    padding: const EdgeInsets.all(8),
                    child: LText(
                      store.connectionCheck!,
                      textAlign: TextAlign.center,
                    ),
                  ),
                if (store.error != null)
                  Padding(
                    padding: const EdgeInsets.all(8),
                    child: LText(
                      store.error!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ),
                const SizedBox(height: 26),
                const SplitRoutingControl(compact: true),
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        TextButton.icon(
                          key: const ValueKey('client-server-picker'),
                          onPressed: locked || store.profiles.isEmpty
                              ? null
                              : () => perform(pickServer),
                          icon: const Icon(Icons.expand_more),
                          label: LText(
                            profile?.name ?? 'Выберите сервер',
                            style: const TextStyle(fontSize: 22),
                            textAlign: TextAlign.center,
                          ),
                        ),
                        if (account != null)
                          Text(account.name, textAlign: TextAlign.center),
                        LText(
                          profile?.protocol ?? 'Добавьте готовый профиль',
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          alignment: WrapAlignment.spaceAround,
                          spacing: 16,
                          children: [
                            LText('Получено: ${traffic(store.status.rx)}'),
                            LText('Передано: ${traffic(store.status.tx)}'),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: locked || store.status.active
                      ? null
                      : () => perform(importProfile),
                  icon: const Icon(Icons.add),
                  label: const LText('Добавить профиль'),
                ),
                if (account != null &&
                    account.statistics['clientAccount'] == true)
                  OutlinedButton.icon(
                    onPressed: locked
                        ? null
                        : () => Navigator.of(context).push(
                            MaterialPageRoute<void>(
                              builder: (_) => SubclientsPage(
                                store: store,
                                account: account,
                              ),
                            ),
                          ),
                    icon: const Icon(Icons.group_add_outlined),
                    label: const LText('Субклиенты'),
                  ),
                TextButton.icon(
                  onPressed: locked || store.status.active
                      ? null
                      : () => perform(settings),
                  icon: const Icon(Icons.network_check),
                  label: const LText('Проверка соединения'),
                ),
                Text(
                  Platform.isAndroid
                      ? 'Android 8.0+ · ARM32 / ARM64 / x86-64'
                      : Platform.isIOS
                      ? 'iOS · RIVET/H3 / RIVET/S1'
                      : '${Platform.isWindows ? 'Windows' : 'Ubuntu'} · x64',
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      );
    },
  );
}

class ClientImportDialog extends StatefulWidget {
  const ClientImportDialog({super.key});
  @override
  State<ClientImportDialog> createState() => _ClientImportDialogState();
}

class _ClientImportDialogState extends State<ClientImportDialog> {
  final input = TextEditingController();
  bool reading = false;
  @override
  void dispose() {
    input.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('Клиентский профиль'),
    content: SizedBox(
      width: 440,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const LText(
            'Вставьте ключ XIO/Amnezia или конфигурацию поддерживаемого протокола. Профиль содержит секреты; не публикуйте его.',
          ),
          TextField(
            controller: input,
            minLines: 3,
            maxLines: 7,
            maxLength: 200000,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(
              labelText: tr(context, 'Ключ или конфигурация'),
              counterText: '',
            ),
          ),
          TextButton.icon(
            onPressed: reading
                ? null
                : () async {
                    setState(() => reading = true);
                    try {
                      final raw = await native.invokeMethod<String>(
                        'pickBundle',
                      );
                      if (mounted && raw != null) input.text = raw;
                    } catch (_) {
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: LText('Не удалось прочитать файл профиля'),
                          ),
                        );
                      }
                    } finally {
                      if (mounted) setState(() => reading = false);
                    }
                  },
            icon: const Icon(Icons.file_open_outlined),
            label: const LText('Выбрать файл'),
          ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: reading ? null : () => Navigator.pop(context),
        child: const LText('Отмена'),
      ),
      FilledButton(
        onPressed: reading ? null : () => Navigator.pop(context, input.text),
        child: const LText('Добавить'),
      ),
    ],
  );
}
