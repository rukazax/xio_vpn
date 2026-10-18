import 'help_legal_ui.dart';
import 'credentials.dart';
import 'app_icons.dart';
import 'l10n.dart';

import 'dart:io';

import 'external_links.dart';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';
import 'managed_service.dart';
import 'main.dart' show BrandMark, ImportDialog, AndroidControls, LabPage;
import 'split_routing.dart';

String protocolName(String id) =>
    const {
      'wireguard': 'WireGuard',
      'awg': 'AmneziaWG 3.1',
      'rivet-h3': 'RIVET / H3',
      'rivet-s1': 'RIVET / S1',
      'xray': 'Xray / REALITY',
      'shadowsocks': 'Shadowsocks',
      'openvpn': 'OpenVPN',
      'cloak': 'OpenVPN / Cloak',
      'ikev2': 'IKEv2 / IPsec',
      'tailscale': 'Tailscale / Headscale',
    }[id] ??
    id;
String traffic(num bytes) => bytes < 1024
    ? '$bytes B'
    : bytes < 1048576
    ? '${(bytes / 1024).toStringAsFixed(1)} kB'
    : '${(bytes / 1048576).toStringAsFixed(1)} MB';
Future<void> actionGuard(
  BuildContext context,
  Future<void> Function() action,
) async {
  try {
    await action();
  } catch (e) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: LText(
            e is FormatException
                ? e.message.toString()
                : e is StateError
                ? e.message
                : 'Не удалось выполнить действие',
          ),
        ),
      );
    }
  }
}

Future<void> openAdmin(
  BuildContext context,
  AppStore store, {
  ManagedServer? server,
  String? action,
  ManagedUser? user,
  String? name,
  bool admin = false,
  int userLimit = 0,
}) async {
  FocusScope.of(context).unfocus();
  await showDialog(
    context: context,
    barrierDismissible: false,
    builder: (_) => ManagedAdminDialog(
      store: store,
      server: server,
      action: action,
      user: user,
      name: name,
      admin: admin,
      userLimit: userLimit,
    ),
  );
  if (context.mounted) {
    FocusScope.of(context).unfocus();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (context.mounted) {
        FocusScope.of(context).unfocus();
        SystemChannels.textInput.invokeMethod<void>('TextInput.hide');
      }
    });
  }
}

class WorkspaceShell extends StatefulWidget {
  final AppStore store;
  const WorkspaceShell({super.key, required this.store});
  @override
  State<WorkspaceShell> createState() => _WorkspaceShellState();
}

class _WorkspaceShellState extends State<WorkspaceShell>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    store.setForeground(state == AppLifecycleState.resumed);
  }

  final pager = PageController();
  int page = 0;
  static const titles = ['Главная', 'Настройки', 'Соединение'];
  static const icons = [
    Icons.home_outlined,
    Icons.settings_outlined,
    Icons.add,
  ];
  AppStore get store => widget.store;
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    pager.dispose();
    super.dispose();
  }

  void select(int value) {
    FocusScope.of(context).unfocus();
    pager.jumpToPage(value);
    setState(() => page = value);
  }

  void push(String title, Widget child) => Navigator.push(
    context,
    MaterialPageRoute(
      builder: (_) => Scaffold(
        appBar: AppBar(title: LText(title)),
        body: SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: child,
          ),
        ),
      ),
    ),
  );
  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) => Scaffold(
      appBar: AppBar(
        leading: const Padding(
          padding: EdgeInsets.all(12),
          child: BrandMark(size: 28),
        ),
        title: LText(titles[page]),
      ),
      body: SafeArea(
        child: PageView(
          controller: pager,
          onPageChanged: (v) {
            FocusScope.of(context).unfocus();
            setState(() => page = v);
          },
          children: [
            _CachedPage(active: page == 0, child: home()),
            _CachedPage(active: page == 1, child: settings()),
            _CachedPage(active: page == 2, child: connection()),
          ],
        ),
      ),
      bottomNavigationBar: SafeArea(
        top: false,
        child: MediaQuery.withClampedTextScaling(
          maxScaleFactor: 1,
          child: NavigationBar(
            height: 72,
            labelBehavior: NavigationDestinationLabelBehavior.alwaysHide,
            selectedIndex: page,
            onDestinationSelected: select,
            destinations: [
              for (var i = 0; i < 3; i++)
                NavigationDestination(
                  icon: Icon(icons[i], size: 32),
                  label: tr(context, titles[i]),
                ),
            ],
          ),
        ),
      ),
    ),
  );
  Widget home() {
    final p = store.activeProfile ?? store.selected;
    final currentUser = store.users
        .where((u) => u.profileIds.values.contains(p?.id))
        .firstOrNull;
    final choices = <String, Profile>{};
    for (final profile in store.profiles) {
      final user = store.users
          .where((u) => u.profileIds.values.contains(profile.id))
          .firstOrNull;
      if (user?.revoked == true) continue;
      final group = user?.serverId ?? profile.endpoint;
      if (!choices.containsKey(group) || profile.id == p?.id) {
        choices[group] = profile;
      }
    }
    String serverName(Profile profile) {
      final user = store.users
          .where((u) => u.profileIds.values.contains(profile.id))
          .firstOrNull;
      return store.servers
              .where((s) => s.id == user?.serverId)
              .firstOrNull
              ?.label ??
          '${store.serverFlagForProfile(profile)} ${user?.name ?? profile.name}';
    }

    return Column(
      children: [
        const SizedBox(height: 26),
        Semantics(
          button: true,
          label: tr(
            context,
            store.status.active ? 'Отключиться' : 'Подключиться',
          ),
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
              onPressed: store.busy
                  ? null
                  : store.profiles.isEmpty
                  ? () => select(2)
                  : () => actionGuard(
                      context,
                      store.status.active ? store.disconnect : store.connect,
                    ),
              child: store.busy
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
        LText(store.status.state),
        if (store.connectionCheck != null)
          Padding(
            padding: const EdgeInsets.all(8),
            child: LText(store.connectionCheck!, textAlign: TextAlign.center),
          ),
        if (store.error != null)
          Padding(
            padding: const EdgeInsets.all(8),
            child: LText(
              store.error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        const SizedBox(height: 26),
        if (Platform.isAndroid) const SplitRoutingControl(compact: true),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextButton.icon(
                  onPressed: store.busy || store.status.active
                      ? null
                      : () => showModalBottomSheet(
                          context: context,
                          isScrollControlled: true,
                          constraints: BoxConstraints.tightFor(
                            width: (MediaQuery.sizeOf(context).width - 24)
                                .clamp(0, 880)
                                .toDouble(),
                          ),
                          builder: (context) => SafeArea(
                            child: SizedBox(
                              height: MediaQuery.sizeOf(context).height * .6,
                              child: ListView(
                                children: [
                                  const ListTile(
                                    title: LText('Серверы и подключения'),
                                  ),
                                  for (final profile in choices.values)
                                    ListTile(
                                      selected: profile.id == store.selectedId,
                                      title: Text(serverName(profile)),
                                      subtitle: Text(
                                        '${store.serverFlagForProfile(profile)} ${profile.endpoint}',
                                      ),
                                      onTap: () {
                                        Navigator.pop(context);
                                        actionGuard(
                                          this.context,
                                          () => store.select(profile.id),
                                        );
                                      },
                                    ),
                                ],
                              ),
                            ),
                          ),
                        ),
                  icon: const Icon(Icons.expand_more),
                  label: p == null
                      ? const LText(
                          'Выберите сервер',
                          style: TextStyle(fontSize: 22),
                        )
                      : Text(
                          serverName(p),
                          style: const TextStyle(fontSize: 22),
                        ),
                ),
                if (currentUser != null)
                  Text(currentUser.name, textAlign: TextAlign.center),
                if (p != null)
                  LText(
                    'Автоматически · ${protocolName(store.status.active && nativeProtocols.contains(store.status.path) ? store.status.path : p.protocol)}',
                    textAlign: TextAlign.center,
                  ),
                const SizedBox(height: 12),
                if ((store.status.active ? store.status.path : p?.protocol) !=
                    'ikev2')
                  Wrap(
                    alignment: WrapAlignment.spaceAround,
                    spacing: 16,
                    children: [
                      LText('Получено: ${traffic(store.status.rx ?? 0)}'),
                      LText('Передано: ${traffic(store.status.tx ?? 0)}'),
                    ],
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget connection() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const LText(
        'Вставьте профиль XIO или конфигурацию VPN',
        style: TextStyle(fontSize: 20),
      ),
      const SizedBox(height: 20),
      ListTile(
        leading: const Icon(Icons.paste),
        title: const LText('Вставить ключ или конфигурацию'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => showDialog(
          context: context,
          builder: (_) => ImportDialog(store: store),
        ),
      ),
      ListTile(
        leading: const Icon(Icons.file_open_outlined),
        title: const LText('Файл с настройками подключения'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => actionGuard(context, () async {
          final raw = await native.invokeMethod<String>('pickBundle');
          if (raw != null) {
            await store.importConnection(raw);
          }
        }),
      ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.dns_outlined),
        title: const LText('VPN на своём сервере'),
        subtitle: const LText('Установить все протоколы XIO'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => openAdmin(context, store),
      ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.person_add_outlined),
        title: const LText('Добавить пользователя'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => push('Добавить пользователя', SharingPage(store: store)),
      ),
    ],
  );
  Widget serverSettings() => Column(
    children: [
      FilledButton.icon(
        onPressed: () => openAdmin(context, store),
        icon: const Icon(Icons.add),
        label: const LText('Добавить сервер'),
      ),
      for (final server in store.servers)
        Card(
          child: ListTile(
            title: Text(server.label),
            subtitle: const Text('RIVET · WireGuard · AmneziaWG'),
            trailing: PopupMenuButton<String>(
              constraints: BoxConstraints.tightFor(
                width: (MediaQuery.sizeOf(context).width - 24)
                    .clamp(0, 880)
                    .toDouble(),
              ),
              onSelected: (action) => actionGuard(context, () async {
                if (action == 'local') {
                  final yes = await showDialog<bool>(
                    context: context,
                    builder: (c) => AlertDialog(
                      title: const LText('Удалить сервер из приложения?'),
                      content: const LText(
                        'Локальные профили, пользователи и сохранённый SSH-доступ будут удалены. VPN на сервере продолжит работать.',
                      ),
                      actions: [
                        TextButton(
                          onPressed: () => Navigator.pop(c, false),
                          child: const LText('Отмена'),
                        ),
                        FilledButton(
                          onPressed: () => Navigator.pop(c, true),
                          child: const LText('Удалить'),
                        ),
                      ],
                    ),
                  );
                  if (yes == true) await store.forgetServer(server.id);
                } else {
                  await openAdmin(
                    context,
                    store,
                    server: server,
                    action: action == 'remote' ? 'uninstall' : null,
                  );
                }
              }),
              itemBuilder: (c) => [
                const PopupMenuItem(
                  value: 'settings',
                  child: LText('Настройки сервера'),
                ),
                const PopupMenuItem(
                  value: 'local',
                  child: LText('Удалить из приложения'),
                ),
                if (!server.delegated)
                  const PopupMenuItem(
                    value: 'remote',
                    child: LText('Удалить XIO VPN с сервера'),
                  ),
              ],
            ),
            onTap: () => openAdmin(context, store, server: server),
          ),
        ),
      for (final profile in store.profiles.where(
        (p) => !store.users.any((u) => u.profileIds.values.contains(p.id)),
      ))
        Card(
          child: ListTile(
            title: Text(profile.name),
            subtitle: Text(
              '${protocolName(profile.protocol)} · ${store.serverFlagForProfile(profile)} ${profile.endpoint}',
            ),
            trailing: IconButton(
              tooltip: tr(context, 'Удалить локальный профиль'),
              icon: const Icon(Icons.delete_outline),
              onPressed: () => actionGuard(context, () async {
                final yes = await showDialog<bool>(
                  context: context,
                  builder: (c) => AlertDialog(
                    title: const LText('Удалить локальный профиль?'),
                    content: const LText(
                      'Ключ будет удалён с этого устройства. Доступ на сервере не отзывается.',
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(c, false),
                        child: const LText('Отмена'),
                      ),
                      FilledButton(
                        onPressed: () => Navigator.pop(c, true),
                        child: const LText('Удалить'),
                      ),
                    ],
                  ),
                );
                if (yes == true) await store.remove(profile.id);
              }),
            ),
          ),
        ),
      if (store.servers.isEmpty)
        const Padding(
          padding: EdgeInsets.all(20),
          child: LText(
            'Управляемых серверов пока нет. Импортированный гостевой профиль не даёт SSH-доступ.',
          ),
        ),
    ],
  );
  Widget diagnostics() => Column(
    children: [
      LabPage(store: store),
      ExpansionTile(
        title: const LText('Журнал сеанса'),
        children: [
          ListenableBuilder(
            listenable: AppLanguages.revision,
            builder: (context, _) =>
                SelectableText(tr(context, store.events.join('\n'))),
          ),
        ],
      ),
    ],
  );
  Widget settings() => Column(
    children: [
      ListTile(
        leading: const Icon(Icons.dns_outlined),
        title: const LText('Серверы'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => push(
          'Серверы',
          ListenableBuilder(
            listenable: store,
            builder: (c, _) => serverSettings(),
          ),
        ),
      ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.wifi_tethering),
        title: const LText('Соединение'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => push(
          'Настройки соединения',
          ConnectionSettings(
            store: store,
            onDiagnostics: () => push('Диагностика', diagnostics()),
          ),
        ),
      ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.apps),
        title: const LText('Приложение'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => push(
          'Приложение',
          Column(
            children: [
              LanguageSetting(store: store),
              if (Platform.isAndroid) ...[
                ListTile(
                  leading: const Icon(Icons.palette_outlined),
                  title: const LText('Иконка приложения'),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () =>
                      push('Иконка приложения', AppIconPicker(store: store)),
                ),
                const SplitRoutingControl(),
                const SizedBox(height: 16),
                const AndroidControls(),
              ],
              const ListTile(
                title: LText('Оформление'),
                subtitle: LText(
                  'Автоматически, по системной светлой или тёмной теме',
                ),
              ),
            ],
          ),
        ),
      ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.file_copy_outlined),
        title: Row(
          children: [
            const Expanded(child: LText('Пользователи')),
            Text('${store.users.length}', key: const ValueKey('user-count')),
          ],
        ),
        trailing: const Icon(Icons.chevron_right),
        onTap: () =>
            push('Пользователи', SharingPage(store: store, initialTab: 1)),
      ),
      const Divider(),
      if (!const bool.fromEnvironment('XIO_PLAY_BUILD'))
        ListTile(
          leading: const Icon(Icons.favorite_border),
          title: const LText('Поддержать XIO'),
          trailing: const Icon(Icons.open_in_new),
          onTap: () => actionGuard(context, openSupportLink),
        ),
      const Divider(),
      ListTile(
        leading: const Icon(Icons.info_outline),
        title: const LText('О XIO'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => push(
          'О XIO',
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const LText('XIO · X in 1 out\nВерсия 0.20.0'),
              const SizedBox(height: 16),
              ListTile(
                leading: const Icon(Icons.route_outlined),
                title: const LText('Протоколы'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => push(
                  'Протоколы',
                  Column(
                    children: [
                      for (final p in protocols)
                        ListTile(
                          title: Text(p.name),
                          subtitle: LText(
                            p.available
                                ? 'Доступен в этой платформе'
                                : 'Движок ещё не интегрирован',
                          ),
                        ),
                    ],
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.help_outline),
                title: const LText('Справка и FAQ'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => push('Справка и FAQ', const HelpContent()),
              ),
              const Divider(),
              ListTile(
                leading: const Icon(Icons.gavel_outlined),
                title: const LText('Лицензия и ответственность'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => push(
                  'Лицензия и ответственность',
                  LegalDetails(store: store),
                ),
              ),
              const Divider(),
              TextButton(
                onPressed: () => showLicensePage(
                  context: context,
                  applicationName: 'XIO',
                  applicationVersion: '0.20.0',
                ),
                child: const LText('Лицензии компонентов'),
              ),
            ],
          ),
        ),
      ),
    ],
  );
}

class _CachedPage extends StatefulWidget {
  final Widget child;
  final bool active;
  const _CachedPage({required this.child, required this.active});
  @override
  State<_CachedPage> createState() => _CachedPageState();
}

class _CachedPageState extends State<_CachedPage>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  @override
  Widget build(BuildContext context) {
    super.build(context);
    return ExcludeFocus(
      excluding: !widget.active,
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: widget.child,
      ),
    );
  }
}

class ConnectionSettings extends StatefulWidget {
  final AppStore store;
  final VoidCallback? onDiagnostics;
  const ConnectionSettings({
    super.key,
    required this.store,
    this.onDiagnostics,
  });
  @override
  State<ConnectionSettings> createState() => _ConnectionSettingsState();
}

class _ConnectionSettingsState extends State<ConnectionSettings> {
  late final site = TextEditingController(text: widget.store.checkSite);
  late String priority = widget.store.priorityProtocol;
  late int timeoutSeconds = widget.store.protocolTimeoutSeconds;
  @override
  void dispose() {
    site.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      if (widget.onDiagnostics != null) ...[
        ListTile(
          leading: const Icon(Icons.science_outlined),
          title: const LText('Диагностика'),
          trailing: const Icon(Icons.chevron_right),
          onTap: widget.onDiagnostics,
        ),
        const Divider(),
      ],

      TextField(
        controller: site,
        keyboardType: TextInputType.url,
        autocorrect: false,
        decoration: InputDecoration(
          labelText: tr(context, 'Сайт для проверки'),
          hintText: 'https://youtube.com',
        ),
      ),
      const SizedBox(height: 16),
      DropdownButtonFormField<String>(
        initialValue: priority,
        decoration: InputDecoration(
          labelText: tr(context, 'Приоритетный протокол'),
        ),
        items: [
          for (final p in nativeProtocols.where(platformProtocols.contains))
            DropdownMenuItem(value: p, child: Text(protocolName(p))),
        ],
        onChanged: (v) {
          if (v != null) setState(() => priority = v);
        },
      ),
      const SizedBox(height: 16),
      DropdownButtonFormField<int>(
        initialValue: timeoutSeconds,
        decoration: InputDecoration(
          labelText: tr(context, 'Время попытки подключения'),
        ),
        items: [
          for (final v in ({
            5,
            10,
            15,
            20,
            30,
            45,
            60,
            timeoutSeconds,
          }.toList()..sort()))
            DropdownMenuItem(value: v, child: LText('$v с')),
        ],
        onChanged: (v) {
          if (v != null) setState(() => timeoutSeconds = v);
        },
      ),
      const SizedBox(height: 16),
      const LText(
        'Сайт проверяется после подключения. При раздельном туннелировании запрос следует правилам приложения; успешный ответ сам по себе не подтверждает маршрут всего трафика. Сначала проверяется приоритетный протокол; при неудаче — следующий из профиля пользователя.',
      ),
      const SizedBox(height: 20),
      FilledButton(
        onPressed: () => actionGuard(context, () async {
          await widget.store.saveConnectionSettings(
            site.text,
            priority,
            timeoutSeconds: timeoutSeconds,
          );
          if (context.mounted) Navigator.pop(context);
        }),
        child: const LText('Сохранить'),
      ),
    ],
  );
}

class SharingPage extends StatefulWidget {
  final AppStore store;
  final int initialTab;
  const SharingPage({super.key, required this.store, this.initialTab = 0});
  @override
  State<SharingPage> createState() => _SharingPageState();
}

class _SharingPageState extends State<SharingPage> {
  final name = TextEditingController(
    text: AppLanguages.text('Новый пользователь'),
  );
  String? serverId;
  void storeUpdated() {
    if (mounted) setState(() {});
  }

  int tab = 0;
  bool admin = false;
  final quota = TextEditingController(text: '5');
  @override
  void initState() {
    super.initState();
    tab = widget.initialTab;
    widget.store.addListener(storeUpdated);
  }

  @override
  void dispose() {
    widget.store.removeListener(storeUpdated);
    name.dispose();
    quota.dispose();
    super.dispose();
  }

  Future<void> share(ManagedUser user) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const LText('Поделиться доступом'),
        content: LText(
          user.admin
              ? 'Профиль администратора содержит VPN-ключи и ограниченный ключ управления пользователями. Root-пароль не передаётся.'
              : 'Профиль содержит личные VPN-ключи всех протоколов пользователя. Получатель сможет подключаться к VPN. SSH-доступ не передаётся.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const LText('Отмена'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const LText('Поделиться'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await actionGuard(context, () async {
      final bundle = await widget.store.exportUser(user);
      if (Platform.isAndroid) {
        await native.invokeMethod('shareBundle', {'bundle': bundle.encode()});
      } else {
        await Clipboard.setData(ClipboardData(text: bundle.encode()));
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final store = widget.store;
    if (!store.servers.any((s) => s.id == serverId)) {
      serverId = store.servers.firstOrNull?.id;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SegmentedButton<int>(
          showSelectedIcon: false,
          style: SegmentedButton.styleFrom(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 12),
          ),
          segments: [
            ButtonSegment(
              value: 0,
              label: FittedBox(
                fit: BoxFit.scaleDown,
                child: Text(
                  tr(context, 'Соединение'),
                  maxLines: 1,
                  softWrap: false,
                ),
              ),
            ),
            ButtonSegment(
              value: 1,
              label: FittedBox(
                fit: BoxFit.scaleDown,
                child: Text(
                  tr(context, 'Пользователи'),
                  maxLines: 1,
                  softWrap: false,
                ),
              ),
            ),
          ],
          selected: {tab},
          onSelectionChanged: (v) => setState(() => tab = v.first),
        ),
        const SizedBox(height: 20),
        if (tab == 0) ...[
          TextField(
            controller: name,
            decoration: InputDecoration(
              labelText: tr(context, 'Имя пользователя'),
            ),
          ),
          const SizedBox(height: 16),
          DropdownButtonFormField<String>(
            key: ValueKey(serverId),
            initialValue: serverId,
            isExpanded: true,
            decoration: InputDecoration(labelText: tr(context, 'Сервер')),
            items: [
              for (final s in store.servers)
                DropdownMenuItem(value: s.id, child: Text(s.label)),
            ],
            onChanged: (v) => setState(() => serverId = v),
          ),
          const SizedBox(height: 12),
          if (store.servers
                  .where((v) => v.id == serverId)
                  .firstOrNull
                  ?.delegated !=
              true) ...[
            CheckboxListTile(
              title: const LText('Админ'),
              value: admin,
              onChanged: (v) => setState(() => admin = v ?? false),
            ),
            if (admin)
              TextField(
                controller: quota,
                keyboardType: TextInputType.number,
                decoration: InputDecoration(
                  labelText: tr(context, 'Лимит действующих пользователей'),
                ),
              ),
          ],
          const ListTile(
            title: LText('Протоколы профиля'),
            subtitle: LText('Все установленные протоколы сервера'),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: serverId == null
                ? null
                : () => openAdmin(
                    context,
                    store,
                    server: store.servers.firstWhere((s) => s.id == serverId),
                    action: 'create',
                    name: name.text,
                    admin: admin,
                    userLimit: int.tryParse(quota.text) ?? -1,
                  ),
            child: const LText('Создать пользователя'),
          ),
        ] else ...[
          if (store.users.isEmpty) const LText('Пользователей пока нет.'),
          for (final u in store.users)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            u.name,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        if (u.admin) ...[
                          const SizedBox(width: 8),
                          Text(
                            'admin',
                            style: TextStyle(
                              color: Theme.of(context).colorScheme.primary,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ],
                        const SizedBox(width: 8),
                        Text(
                          !u.revoked && u.statistics['online'] == true
                              ? 'online'
                              : 'offline',
                        ),
                      ],
                    ),
                    LText(
                      'Трафик мес: ${u.statistics['monthBytes'] == null ? '—' : ((u.statistics['monthBytes'] as num) / 1000000000).toStringAsFixed(2)} GB',
                    ),
                    Row(
                      children: [
                        Expanded(
                          child: TextButton(
                            onPressed: !u.revoked && u.profileIds.isNotEmpty
                                ? () => share(u)
                                : null,
                            child: const LText(
                              'Поделиться',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ),
                        Expanded(
                          child: TextButton(
                            onPressed:
                                !u.revoked &&
                                    store.servers.any(
                                      (s) =>
                                          s.id == u.serverId &&
                                          s.actorId != u.id,
                                    )
                                ? () => openAdmin(
                                    context,
                                    store,
                                    server: store.servers.firstWhere(
                                      (s) => s.id == u.serverId,
                                    ),
                                    action: 'revoke',
                                    user: u,
                                  )
                                : null,
                            child: const LText(
                              'Отозвать',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
        ],
      ],
    );
  }
}

class ManagedAdminDialog extends StatefulWidget {
  final AppStore store;
  final bool admin;
  final int userLimit;
  final ManagedServer? server;
  final String? action, name;
  final ManagedUser? user;
  const ManagedAdminDialog({
    super.key,
    required this.store,
    this.server,
    this.action,
    this.name,
    this.user,
    this.admin = false,
    this.userLimit = 0,
  });
  @override
  State<ManagedAdminDialog> createState() => _ManagedAdminDialogState();
}

class _ManagedAdminDialogState extends State<ManagedAdminDialog> {
  late final host = TextEditingController(text: widget.server?.host ?? '');
  late final port = TextEditingController(text: '${widget.server?.port ?? 22}');
  late final username = TextEditingController(
    text: widget.server?.username ?? 'root',
  );
  late final serverName = TextEditingController(
    text: widget.server?.name ?? '',
  );
  final password = TextEditingController(),
      key = TextEditingController(),
      passphrase = TextEditingController();
  final ssh = VpsService();
  bool busy = false, authenticated = false, autoLoading = false;
  String? error, result;
  ManagedServer? server;
  ManagedService get service => ManagedService(ssh);
  @override
  void initState() {
    super.initState();
    server = widget.server;
    if (server != null && widget.store.ready) {
      autoLoading = true;
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        try {
          final credentials = await CredentialVault.read(
            widget.store.credentialId(server!),
          );
          if (!mounted) return;
          if (credentials != null) {
            password.text = credentials['password'] ?? '';
            key.text = credentials['key'] ?? '';
            passphrase.text = credentials['passphrase'] ?? '';
            await perform(login);
          }
        } catch (_) {
          if (mounted) {
            setState(
              () => error = 'Не удалось прочитать сохранённые данные SSH',
            );
          }
        } finally {
          if (mounted) setState(() => autoLoading = false);
        }
      });
    }
    if (Platform.isAndroid) {
      native.invokeMethod('secureScreen', {'enabled': true});
    }
  }

  @override
  void dispose() {
    ssh.close();
    for (final c in [
      host,
      port,
      username,
      password,
      key,
      passphrase,
      serverName,
    ]) {
      c.clear();
      c.dispose();
    }
    if (Platform.isAndroid) {
      native.invokeMethod('secureScreen', {'enabled': false});
    }
    super.dispose();
  }

  Future<void> perform(Future<void> Function() action) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await action();
    } catch (e) {
      if (mounted) {
        setState(
          () => error = e is FormatException
              ? e.message.toString()
              : e is StateError
              ? e.message
              : 'Не удалось выполнить операцию. Проверьте SSH-доступ и состояние сервера.',
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> login() async {
    await ssh.open(
      SshTarget(
        host.text.trim(),
        int.tryParse(port.text) ?? 0,
        username.text.trim(),
        server?.hostKey ?? '',
      ),
      password.text,
      key.text,
      passphrase.text,
    );
    await CredentialVault.write(
      CredentialVault.id(
        host.text.trim(),
        int.parse(port.text),
        username.text.trim(),
        scope: server?.actorId ?? '',
      ),
      {
        'password': password.text,
        'key': key.text,
        'passphrase': passphrase.text,
      },
    );
    if (server != null) {
      server!.hostKey = ssh.verifiedFingerprint;
      await widget.store.save();
    }
    password.clear();
    key.clear();
    passphrase.clear();
    setState(() => authenticated = true);
    if (server == null) {
      try {
        final known = await service.command({'action': 'inspect'});
        server = ManagedServer(
          id: known['server']['id'],
          host: host.text.trim(),
          port: int.parse(port.text),
          username: username.text.trim(),
          country: known['server']['country'] ?? '',
          hostKey: ssh.verifiedFingerprint,
        );
        if (!widget.store.servers.any((s) => s.id == server!.id)) {
          widget.store.servers.add(server!);
          await widget.store.save();
          widget.store.changed();
        }
      } catch (_) {
        /* A fresh server has no owned installation yet. */
      }
    }
    if (widget.action == 'create') await create();
    if (widget.action == 'uninstall') await uninstall();
    if (widget.action == 'stats') {
      await service.refresh(widget.store, server!);
      setState(() => result = 'Статистика пользователей обновлена.');
    }
  }

  Future<void> uninstall() async {
    if (!await confirm(
      'Удалить VPN с сервера?',
      'Будут удалены все пользователи, ключи, протоколы, службы, собственные сетевые правила и журнал установки XIO. Общие системные журналы и чужие установки сохранятся.',
    )) {
      return;
    }
    final removed = await service.uninstall(widget.store, server!);
    final retained = (removed['packagesRetained'] as List? ?? []).join(', ');
    setState(
      () => result = retained.isEmpty
          ? 'VPN удалён с сервера.'
          : 'VPN удалён. Общие пакеты сохранены: $retained',
    );
  }

  Future<void> create() async {
    await service.createUser(
      widget.store,
      server!,
      widget.name ?? AppLanguages.text('Владелец'),
      admin: widget.action == 'create' ? widget.admin : true,
      userLimit: widget.action == 'create' ? widget.userLimit : 250,
    );
    await service.refresh(widget.store, server!);
    setState(
      () => result = 'Пользователь создан. Профили сохранены. Поделиться можно во вкладке «Пользователи».',
    );
  }

  Future<bool> confirm(String title, String text) async =>
      await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: LText(title),
          content: LText(text),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(c, false),
              child: const LText('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(c, true),
              child: const LText('Подтвердить'),
            ),
          ],
        ),
      ) ??
      false;
  @override
  Widget build(BuildContext context) => PopScope(
    canPop: !busy,
    child: AlertDialog(
      title: LText(authenticated ? 'Управление сервером' : 'Подключение к VPS'),
      content: SizedBox(
        width: 800,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (!authenticated && !autoLoading) ...[
                TextField(
                  controller: host,
                  enabled: server == null,
                  decoration: InputDecoration(
                    labelText: tr(context, 'IP / домен VPS'),
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: port,
                        enabled: server == null,
                        keyboardType: TextInputType.number,
                        decoration: InputDecoration(
                          labelText: tr(context, 'SSH-порт'),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: TextField(
                        controller: username,
                        enabled: server == null,
                        decoration: InputDecoration(
                          labelText: tr(context, 'Пользователь'),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: password,
                  obscureText: true,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: InputDecoration(
                    labelText: tr(
                      context,
                      'SSH-пароль (сохраняется защищённо)',
                    ),
                  ),
                ),
                ExpansionTile(
                  title: const LText('Или SSH-ключ'),
                  children: [
                    TextField(
                      controller: key,
                      maxLines: 4,
                      autocorrect: false,
                      enableSuggestions: false,
                      decoration: InputDecoration(
                        labelText: tr(context, 'Закрытый ключ PEM / OpenSSH'),
                      ),
                    ),
                    TextField(
                      controller: passphrase,
                      obscureText: true,
                      decoration: InputDecoration(
                        labelText: tr(context, 'Пароль ключа'),
                      ),
                    ),
                  ],
                ),
              ] else if (authenticated && result == null) ...[
                Text(
                  server?.label ?? host.text,
                  style: const TextStyle(fontSize: 20),
                ),
                const SizedBox(height: 16),
                if (server == null) ...[
                  const LText(
                    'Установка всех доступных протоколов XIO на совместимый Linux VPS. Нужны x86_64, systemd, TUN и права администратора. Будут добавлены пакеты, сетевые службы и правила firewall. Создаётся отдельный профиль пользователя для подключения; чужие службы и общие журналы ОС не стираются.',
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: busy
                        ? null
                        : () => perform(() async {
                            server = await service.install(widget.store);
                            await create();
                          }),
                    child: const LText('Установить VPN'),
                  ),
                ] else ...[
                  TextField(
                    controller: serverName,
                    decoration: InputDecoration(
                      labelText: tr(context, 'Название сервера'),
                    ),
                  ),
                  TextButton(
                    onPressed: busy
                        ? null
                        : () => perform(() async {
                            final value = serverName.text.trim();
                            if (value.length > 80) {
                              throw const FormatException(
                                'Название: не более 80 символов',
                              );
                            }
                            server!.name = value;
                            await widget.store.save();
                            widget.store.changed();
                          }),
                    child: const LText('Переименовать'),
                  ),
                  OutlinedButton(
                    onPressed: busy
                        ? null
                        : () => perform(() async {
                            final value = await widget.store.exportServer(
                              server!,
                            );
                            if (!context.mounted) return;
                            final text = await showDialog<bool>(
                              context: context,
                              builder: (c) => AlertDialog(
                                title: const LText('Сохранить конфигурацию'),
                                content: const LText(
                                  'Конфигурация содержит данные доступа к серверу. Передавайте только доверенному получателю.',
                                ),
                                actions: [
                                  TextButton(
                                    onPressed: () => Navigator.pop(c, true),
                                    child: const LText('Текстом'),
                                  ),
                                  FilledButton(
                                    onPressed: () => Navigator.pop(c, false),
                                    child: const LText('Файлом'),
                                  ),
                                ],
                              ),
                            );
                            if (text == null) return;
                            if (Platform.isAndroid || Platform.isIOS) {
                              await native.invokeMethod('shareBundle', {
                                'bundle': value,
                                'asText': text,
                              });
                            } else if (text) {
                              await Clipboard.setData(
                                ClipboardData(text: value),
                              );
                            } else {
                              if (!context.mounted) return;
                              await showDialog<void>(
                                context: context,
                                builder: (_) => ServerFileDialog(raw: value),
                              );
                            }
                          }),
                    child: const LText('Сохранить конфигурацию'),
                  ),
                  FilledButton(
                    onPressed: busy
                        ? null
                        : () => perform(() async {
                            await service.refresh(widget.store, server!);
                            setState(() => result = 'Статистика обновлена.');
                          }),
                    child: const LText('Обновить статистику'),
                  ),
                  if (widget.action == 'revoke')
                    FilledButton(
                      onPressed: busy
                          ? null
                          : () => perform(() async {
                              if (await confirm(
                                'Отозвать доступ?',
                                'Все протоколы пользователя ${widget.user!.name} будут отключены.',
                              )) {
                                await service.revoke(
                                  widget.store,
                                  widget.user!,
                                );
                                setState(
                                  () => result = 'Доступ пользователя отозван.',
                                );
                              }
                            }),
                      child: const LText('Отозвать все протоколы'),
                    ),
                  const SizedBox(height: 20),
                  if (server?.delegated != true)
                    OutlinedButton(
                      onPressed: busy
                          ? null
                          : () => perform(() async {
                              await uninstall();
                            }),
                      child: const LText('Удалить VPN и данные установки'),
                    ),
                ],
              ],
              if (result != null) LText(result!),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: LText(
                    error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              if (busy || autoLoading)
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: LinearProgressIndicator(),
                ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: busy ? null : () => Navigator.pop(context),
          child: const LText('Закрыть'),
        ),
        if (!authenticated && !autoLoading)
          FilledButton(
            onPressed: busy ? null : () => perform(login),
            child: const LText('Подключиться по SSH'),
          ),
      ],
    ),
  );
}

class LanguageSetting extends StatelessWidget {
  final AppStore store;
  const LanguageSetting({super.key, required this.store});
  @override
  Widget build(BuildContext context) => ValueListenableBuilder<int>(
    valueListenable: AppLanguages.revision,
    builder: (context, _, _) => ListTile(
      leading: const Icon(Icons.language),
      title: const LText('Язык'),
      subtitle: LText(
        AppLanguages.selected == null
            ? tr(context, 'Системный')
            : '${AppLanguages.names[AppLanguages.selected]} · ${AppLanguages.selected}',
      ),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => showDialog<void>(
        context: context,
        builder: (c) => SimpleDialog(
          title: const LText('Язык приложения'),
          children: [
            for (final entry in <String, String>{
              '': tr(c, 'Системный'),
              ...AppLanguages.names,
            }.entries)
              SimpleDialogOption(
                onPressed: () async {
                  Navigator.pop(c);
                  await actionGuard(
                    context,
                    () =>
                        store.setLanguage(entry.key.isEmpty ? null : entry.key),
                  );
                },
                child: Row(
                  children: [
                    SizedBox(
                      width: 32,
                      child:
                          AppLanguages.selected ==
                              (entry.key.isEmpty ? null : entry.key)
                          ? const Icon(Icons.check)
                          : null,
                    ),
                    Expanded(
                      child: Text(
                        entry.value,
                        textDirection: entry.key == 'ar'
                            ? TextDirection.rtl
                            : TextDirection.ltr,
                      ),
                    ),
                    Text(entry.key, textDirection: TextDirection.ltr),
                  ],
                ),
              ),
          ],
        ),
      ),
    ),
  );
}

class ServerFileDialog extends StatefulWidget {
  final String raw;
  const ServerFileDialog({super.key, required this.raw});
  @override
  State<ServerFileDialog> createState() => _ServerFileDialogState();
}

class _ServerFileDialogState extends State<ServerFileDialog> {
  late final path = TextEditingController(
    text:
        '${Platform.environment[Platform.isWindows ? 'USERPROFILE' : 'HOME']}${Platform.pathSeparator}XIO-server-${DateTime.now().microsecondsSinceEpoch}.xio',
  );
  bool busy = false;
  String? error;
  @override
  void dispose() {
    path.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: !busy,
    child: AlertDialog(
      title: const LText('Сохранить конфигурацию'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: path,
            decoration: InputDecoration(
              labelText: tr(context, 'Файл с настройками подключения'),
            ),
          ),
          if (error != null) LText(error!),
        ],
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
                    final file = File(path.text.trim());
                    if (await file.exists()) {
                      throw const FormatException('Файл уже существует');
                    }
                    await file.create();
                    if (Platform.isLinux &&
                        (await Process.run('chmod', [
                              '600',
                              file.path,
                            ])).exitCode !=
                            0) {
                      throw StateError('Не удалось защитить хранилище');
                    }
                    await file.writeAsString(widget.raw, flush: true);
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
          child: const LText('Сохранить'),
        ),
      ],
    ),
  );
}
