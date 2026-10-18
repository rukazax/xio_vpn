import 'l10n.dart';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';

// Both cached tab entries must reflect a rule change immediately.
final _routingRevision = ValueNotifier<int>(0);

String routingLabel(String mode) => switch (mode) {
  'include' => 'Только выбранные приложения через VPN',
  'exclude' => 'Выбранные приложения в обход VPN',
  'ipInclude' => 'Только выбранные IP через VPN',
  'ipExclude' => 'Выбранные IP в обход VPN',
  _ => 'Все приложения через VPN',
};

/// Rules live in Android's private no-backup directory, outside exports/logs.
class SplitRoutingControl extends StatefulWidget {
  const SplitRoutingControl({super.key, this.compact = false});
  final bool compact;
  @override
  State<SplitRoutingControl> createState() => _SplitRoutingControlState();
}

class _SplitRoutingControlState extends State<SplitRoutingControl> {
  String summary = 'Загрузка правил…';
  @override
  void initState() {
    super.initState();
    _routingRevision.addListener(_reload);
    _reload();
  }

  @override
  void dispose() {
    _routingRevision.removeListener(_reload);
    super.dispose();
  }

  Future<void> _reload() async {
    try {
      final policy = await native.invokeMapMethod<String, dynamic>(
        'routingGet',
      );
      if (mounted) {
        setState(() {
          summary = routingLabel(policy!['mode'] as String);
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          summary = 'Правила недоступны — откройте настройки';
        });
      }
    }
  }

  Future<void> _open() async {
    await Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => const SplitRoutingPage()));
    await _reload();
  }

  @override
  Widget build(BuildContext context) => widget.compact
      ? TextButton.icon(
          onPressed: _open,
          icon: const Icon(Icons.call_split, size: 20),
          label: LText(summary, maxLines: 1, overflow: TextOverflow.ellipsis),
        )
      : Card(
          child: ListTile(
            leading: const Icon(Icons.call_split),
            title: const LText('Раздельное туннелирование'),
            subtitle: LText(summary),
            trailing: const Icon(Icons.chevron_right),
            onTap: _open,
          ),
        );
}

class SplitRoutingPage extends StatefulWidget {
  const SplitRoutingPage({super.key});
  @override
  State<SplitRoutingPage> createState() => _SplitRoutingPageState();
}

class _SplitRoutingPageState extends State<SplitRoutingPage> {
  String mode = 'all', query = '';
  final selected = <String>{};
  final networks = TextEditingController();
  bool get ipMode => mode.startsWith('ip');
  bool get appMode => mode == 'include' || mode == 'exclude';
  @override
  void dispose() {
    networks.dispose();
    super.dispose();
  }

  List<Map<String, dynamic>> apps = [];
  bool loading = true, saving = false;
  String? error;
  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final policy = await native.invokeMapMethod<String, dynamic>(
        'routingGet',
      );
      mode = policy!['mode'] as String;
      selected.addAll((policy['packages'] as List).cast<String>());
      networks.text = ((policy['networks'] as List?) ?? []).join('\n');
    } catch (_) {
      error = 'Не удалось прочитать правила. Можно выбрать и сохранить новые.';
    }
    try {
      final result = await native.invokeListMethod<dynamic>('routingApps');
      apps = result!.map((e) => Map<String, dynamic>.from(e as Map)).toList();
    } catch (_) {
      error = 'Не удалось получить приложения. Закройте и откройте этот экран.';
    }
    if (mounted) {
      setState(() {
        loading = false;
      });
    }
  }

  Future<void> _save() async {
    if (mode == 'include' && selected.isEmpty) {
      setState(() {
        error = 'Выберите хотя бы одно приложение для VPN';
      });
      return;
    }
    setState(() {
      saving = true;
      error = null;
    });
    try {
      await native.invokeMethod<dynamic>('routingSave', {
        'mode': mode,
        'packages': appMode ? (selected.toList()..sort()) : <String>[],
        'networks': ipMode
            ? networks.text
                  .split(RegExp(r'[\s,;]+'))
                  .where((v) => v.isNotEmpty)
                  .toList()
            : <String>[],
      });
      _routingRevision.value++;
      if (mounted) Navigator.of(context).pop();
    } on PlatformException catch (e) {
      if (mounted) {
        setState(() {
          error = e.message ?? 'Не удалось сохранить правила';
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          error = 'Не удалось сохранить правила';
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          saving = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final filtered = apps
        .where(
          (app) => '${app['label']} ${app['package']}'.toLowerCase().contains(
            query.toLowerCase(),
          ),
        )
        .toList();
    return Scaffold(
      appBar: AppBar(title: const LText('Маршрутизация')),
      body: SafeArea(
        child: loading
            ? const Center(child: CircularProgressIndicator())
            : Column(
                children: [
                  Expanded(
                    child: CustomScrollView(
                      slivers: [
                        SliverToBoxAdapter(
                          child: Padding(
                            padding: const EdgeInsets.all(16),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const LText(
                                  'WireGuard и AmneziaWG. Отключите VPN перед сохранением. Правила применяются при следующем подключении, включая плитку XIO.',
                                ),
                                const SizedBox(height: 12),
                                DropdownButtonFormField<String>(
                                  key: ValueKey(mode),
                                  initialValue: mode,
                                  isExpanded: true,
                                  isDense: false,
                                  itemHeight: 72,
                                  decoration: InputDecoration(
                                    labelText: tr(
                                      context,
                                      'Режим маршрутизации',
                                    ),
                                    border: OutlineInputBorder(),
                                  ),
                                  items:
                                      [
                                            'all',
                                            'include',
                                            'exclude',
                                            'ipInclude',
                                            'ipExclude',
                                          ]
                                          .map(
                                            (m) => DropdownMenuItem(
                                              value: m,
                                              child: Text(
                                                routingLabel(m),
                                                maxLines: 2,
                                              ),
                                            ),
                                          )
                                          .toList(),
                                  onChanged: saving
                                      ? null
                                      : (value) => setState(() {
                                          mode = value!;
                                          error = null;
                                        }),
                                ),
                                const SizedBox(height: 12),
                                LText(
                                  ipMode
                                      ? 'Правила IP действуют для всех приложений.'
                                      : mode == 'include'
                                      ? 'Остальные приложения выходят напрямую, вне VPN.'
                                      : mode == 'exclude'
                                      ? 'Выбранные приложения выходят напрямую, вне VPN. Остальные используют маршруты профиля.'
                                      : 'Все приложения используют маршруты профиля. Для полного туннеля профиль должен содержать 0.0.0.0/0 и ::/0.',
                                ),
                                if (ipMode) ...[
                                  const SizedBox(height: 12),
                                  LText(
                                    mode == 'ipInclude'
                                        ? 'Только указанные адреса в пределах AllowedIPs профиля идут через VPN. Остальные IPv4 и IPv6 идут напрямую.'
                                        : 'Указанные адреса исключаются из AllowedIPs профиля. Остальные маршруты профиля сохраняются.',
                                  ),
                                  const SizedBox(height: 12),
                                  const LText(
                                    'IP и подсети, по одному на строку (до 128). Домены не поддерживаются. DNS остаётся из профиля. Включите IP DNS-сервера в маршруты VPN, иначе разрешение имён может не работать. Приложения и IP выбираются раздельными режимами.',
                                  ),
                                  const SizedBox(height: 12),
                                  TextField(
                                    controller: networks,
                                    enabled: !saving,
                                    minLines: 3,
                                    maxLines: 7,
                                    maxLength: 8192,
                                    keyboardType: TextInputType.multiline,
                                    decoration: const InputDecoration(
                                      labelText: 'IPv4 / IPv6 / CIDR',
                                      hintText: '203.0.113.5\n192.168.0.0/16\n2001:db8::/32',
                                      border: OutlineInputBorder(),
                                    ),
                                  ),
                                ],
                                if (appMode) ...[
                                  const SizedBox(height: 12),
                                  LText('Выбрано: ${selected.length}'),
                                  const ExpansionTile(
                                    title: LText('Особенности Android'),
                                    tilePadding: EdgeInsets.zero,
                                    children: [
                                      LText(
                                        'Показаны приложения с ярлыком запуска. Приложения с общим UID могут разделять маршрут. Системная блокировка соединений без VPN может запретить обход. Правила не заменяют маршруты исходного профиля.',
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 12),
                                  TextField(
                                    decoration: InputDecoration(
                                      labelText: tr(
                                        context,
                                        'Поиск по имени или пакету',
                                      ),
                                      prefixIcon: Icon(Icons.search),
                                    ),
                                    onChanged: (v) => setState(() {
                                      query = v;
                                    }),
                                  ),
                                ],
                                if (error != null)
                                  Padding(
                                    padding: const EdgeInsets.only(top: 12),
                                    child: LText(
                                      error!,
                                      style: TextStyle(
                                        color: Theme.of(context)
                                            .colorScheme
                                            .error,
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ),
                        if (appMode)
                          SliverList.builder(
                            itemCount: filtered.length,
                            itemBuilder: (context, index) {
                              final app = filtered[index];
                              final package = app['package'] as String;
                              return CheckboxListTile(
                                value: selected.contains(package),
                                title: Text(app['label'] as String),
                                subtitle: Text(package),
                                onChanged: saving
                                    ? null
                                    : (value) => setState(() {
                                        value!
                                            ? selected.add(package)
                                            : selected.remove(package);
                                      }),
                              );
                            },
                          ),
                        if (appMode && filtered.isEmpty)
                          const SliverToBoxAdapter(
                            child: Padding(
                              padding: EdgeInsets.all(16),
                              child: LText('Приложения не найдены'),
                            ),
                          ),
                      ],
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: SizedBox(
                      width: double.infinity,
                      child: FilledButton(
                        onPressed: saving ? null : _save,
                        child: LText(
                          saving ? 'Сохранение…' : 'Сохранить правила',
                        ),
                      ),
                    ),
                  ),
                ],
              ),
      ),
    );
  }
}
