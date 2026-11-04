import 'dart:io';

import 'package:flutter/material.dart';

import 'core.dart';
import 'l10n.dart';

/// Показывает ошибку сохранения настройки, не выходя из экрана.
Future<void> _saveGuard(
  BuildContext context,
  Future<void> Function() action,
) async {
  try {
    await action();
  } catch (e) {
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: LText(
          e is FormatException
              ? e.message.toString()
              : e is StateError
              ? e.message
              : 'Не удалось сохранить настройку',
        ),
      ),
    );
  }
}

/// Три переключателя экрана «Приложение»: автозапуск, автоподключение и
/// разрешение скриншотов. Каждый сохраняется сразу, отдельной кнопки нет.
class AppBehaviorSettings extends StatelessWidget {
  final AppStore store;
  const AppBehaviorSettings({super.key, required this.store});

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) => Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          value: store.autostart,
          onChanged: Platform.isAndroid
              ? (v) => _saveGuard(context, () => store.setAutostart(v))
              : null,
          title: const LText('Автозапуск при загрузке устройства'),
          subtitle: LText(
            Platform.isAndroid
                ? 'После перезагрузки устройства приложение запустится само. Разрешение на уведомления проверяется системой; без него подключение не поднимается.'
                : 'Доступно в сборке для Android: на этой платформе система не сообщает приложению о загрузке.',
          ),
        ),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          value: store.autoConnectOnStart,
          onChanged: (v) =>
              _saveGuard(context, () => store.setAutoConnectOnStart(v)),
          title: const LText('Автоподключение после запуска'),
          subtitle: const LText(
            'При открытии приложения выбранный профиль поднимается сразу, если туннель ещё не активен.',
          ),
        ),
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          value: store.allowScreenshots,
          onChanged: (v) =>
              _saveGuard(context, () => store.setAllowScreenshots(v)),
          title: const LText('Разрешить скриншоты'),
          subtitle: const LText(
            'По умолчанию выключено: экраны с ключами, профилями и SSH-доступом защищены от снятия скриншота и записи экрана. Включение снимает защиту со всего приложения.',
          ),
        ),
      ],
    ),
  );
}

/// Строка «DNS-резолвер» для настроек соединения и мастера установки.
class DnsServersTile extends StatelessWidget {
  final AppStore store;
  const DnsServersTile({super.key, required this.store});

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: store,
    builder: (context, _) => ListTile(
      contentPadding: EdgeInsets.zero,
      leading: const Icon(Icons.travel_explore),
      title: const LText('DNS-резолвер'),
      subtitle: LText(dnsServersLabel(store.dnsServers)),
      trailing: const Icon(Icons.chevron_right),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(builder: (_) => DnsSettingsPage(store: store)),
      ),
    ),
  );
}

/// Выбор резолвера из заложенного списка или ручной ввод двух адресов.
class DnsSettingsPage extends StatefulWidget {
  final AppStore store;
  const DnsSettingsPage({super.key, required this.store});
  @override
  State<DnsSettingsPage> createState() => _DnsSettingsPageState();
}

class _DnsSettingsPageState extends State<DnsSettingsPage> {
  late String preset = dnsPresetIdFor(widget.store.dnsServers);
  late final first = TextEditingController(
    text: preset == customDnsPreset && widget.store.dnsServers.isNotEmpty
        ? widget.store.dnsServers.first
        : '',
  );
  late final second = TextEditingController(
    text: preset == customDnsPreset && widget.store.dnsServers.length > 1
        ? widget.store.dnsServers[1]
        : '',
  );
  String? error;

  @override
  void dispose() {
    first.dispose();
    second.dispose();
    super.dispose();
  }

  List<String> get chosen => preset == customDnsPreset
      ? [first.text, second.text]
      : dnsPresets.firstWhere((item) => item.id == preset).servers;

  Future<void> save() async {
    List<String> servers;
    try {
      servers = validateDnsServers(chosen);
    } catch (e) {
      if (!mounted) return;
      setState(
        () => error = e is FormatException
            ? e.message.toString()
            : 'DNS: некорректный адрес',
      );
      return;
    }
    try {
      await widget.store.setDnsServers(servers);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(
          () => error = e is StateError
              ? e.message
              : 'Не удалось сохранить DNS-резолверы',
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final servers = chosen.where((v) => v.trim().isNotEmpty).toList();
    final ipv6Only = servers.isNotEmpty && servers.every(isIpv6Literal);
    return Scaffold(
      appBar: AppBar(title: const LText('DNS-резолвер')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const LText(
                'Сторонний резолвер записывается в новые AWG-профили и виден в мастере установки. Сервер не используется как DNS.',
              ),
              const SizedBox(height: 12),
              for (final item in dnsPresets)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    preset == item.id
                        ? Icons.radio_button_checked
                        : Icons.radio_button_off,
                  ),
                  title: LText(item.name),
                  subtitle: Text(item.servers.join(', ')),
                  onTap: () => setState(() {
                    preset = item.id;
                    error = null;
                  }),
                ),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  preset == customDnsPreset
                      ? Icons.radio_button_checked
                      : Icons.radio_button_off,
                ),
                title: const LText('Свои'),
                subtitle: const LText(
                  'До двух адресов: IPv4, IPv6 или домен. Без порта и схемы.',
                ),
                onTap: () => setState(() {
                  preset = customDnsPreset;
                  error = null;
                }),
              ),
              if (preset == customDnsPreset) ...[
                const SizedBox(height: 8),
                TextField(
                  controller: first,
                  autocorrect: false,
                  enableSuggestions: false,
                  keyboardType: TextInputType.url,
                  decoration: InputDecoration(
                    labelText: tr(context, 'Первый DNS'),
                    hintText: '1.1.1.1',
                  ),
                  onChanged: (_) => setState(() => error = null),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: second,
                  autocorrect: false,
                  enableSuggestions: false,
                  keyboardType: TextInputType.url,
                  decoration: InputDecoration(
                    labelText: tr(context, 'Второй DNS (необязательно)'),
                    hintText: '2606:4700:4700::1111',
                  ),
                  onChanged: (_) => setState(() => error = null),
                ),
              ],
              if (ipv6Only)
                const Padding(
                  padding: EdgeInsets.only(top: 12),
                  child: LText(
                    'Выбраны только IPv6-адреса. Если у сервера нет IPv6-выхода, имена не разрешатся: добавьте IPv4-адрес в «Свои».',
                  ),
                ),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              const SizedBox(height: 20),
              FilledButton(
                onPressed: () => _saveGuard(context, save),
                child: const LText('Сохранить'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
