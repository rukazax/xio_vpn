import 'package:flutter/material.dart';

import 'core.dart';
import 'subclients.dart';

class SubclientsPage extends StatefulWidget {
  final AppStore store;
  final ManagedUser account;
  const SubclientsPage({super.key, required this.store, required this.account});
  @override
  State<SubclientsPage> createState() => _SubclientsPageState();
}

class _SubclientsPageState extends State<SubclientsPage> {
  late final service = Subclients(widget.store, widget.account);
  Map<String, dynamic>? snapshot;
  String? error;
  bool busy = false;
  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    setState(() => busy = true);
    try {
      final result = await service.status();
      if (mounted) {
        setState(() {
          snapshot = result;
          error = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(
          () => error = e is StateError
              ? e.message
              : 'Не удалось проверить права аккаунта',
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> share(UserBundle bundle) => native.invokeMethod<void>(
    'shareClientBundle',
    {'bundle': bundle.encode()},
  );
  Future<void> create() async {
    final input = TextEditingController(text: 'Новый субклиент');
    String? name;
    try {
      name = snapshot?['pending'] == true
          ? ''
          : await showDialog<String>(
              context: context,
              builder: (context) => AlertDialog(
                title: const Text('Добавить субклиента'),
                content: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    TextField(
                      controller: input,
                      maxLength: 80,
                      decoration: const InputDecoration(labelText: 'Имя'),
                    ),
                    const Text(
                      'Сервер проверит доступ и свободный лимит. Получатель получит только свои VPN-профили, без права создания других клиентов и без ключей сервера.',
                    ),
                  ],
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Отмена'),
                  ),
                  FilledButton(
                    onPressed: () => Navigator.pop(context, input.text),
                    child: const Text('Создать'),
                  ),
                ],
              ),
            );
    } finally {
      input.dispose();
    }
    if (name == null) return;
    setState(() => busy = true);
    try {
      final bundle = await service.create(name);
      if (!mounted) return;
      final send = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Субклиент создан'),
          content: const Text(
            'Передать его клиентский профиль? Он содержит личные ключи подключения этого субклиента.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Позже'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Поделиться'),
            ),
          ],
        ),
      );
      if (send == true) await share(bundle);
      await refresh();
    } catch (e) {
      if (mounted) {
        setState(
          () => error = e is StateError
              ? e.message
              : e is FormatException
              ? e.message
              : 'Ответ не получен. Проверьте незавершённую операцию; новая попытка не создана.',
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('Субклиенты'),
      actions: [
        IconButton(
          tooltip: 'Обновить права',
          onPressed: busy ? null : refresh,
          icon: const Icon(Icons.refresh),
        ),
      ],
    ),
    body: ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text(
          widget.account.name,
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const Text(
          'Права и число доступных субклиентов подтверждает сервер. Локальные настройки не увеличивают лимит.',
        ),
        if (busy) const LinearProgressIndicator(),
        if (error != null)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Text(
              error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        if (snapshot != null) ...[
          if (snapshot!['historyTruncated'] == true)
            const Text(
              'Показаны действующие и 20 последних отозванных субклиентов.',
            ),
          Text('API: ${snapshot!['apiEndpoint']}'),
          ListTile(
            title: Text(
              'Создано ${snapshot!['used']} из ${snapshot!['limit']}',
            ),
            subtitle: Text('Доступно: ${snapshot!['remaining']}'),
          ),
          FilledButton.icon(
            onPressed:
                busy ||
                    widget.store.status.active ||
                    snapshot!['remaining'] == 0 && snapshot!['pending'] != true
                ? null
                : create,
            icon: const Icon(Icons.person_add_alt),
            label: Text(
              snapshot!['pending'] == true
                  ? 'Проверить незавершённое создание'
                  : 'Добавить субклиента',
            ),
          ),
          if (widget.store.status.active)
            const Text('Перед созданием отключите VPN.'),
          for (final raw in snapshot!['children'] as List)
            Builder(
              builder: (context) {
                final child = Map<String, dynamic>.from(raw);
                final local = widget.store.users
                    .where(
                      (u) =>
                          u.serverId == widget.account.serverId &&
                          u.id == child['id'],
                    )
                    .firstOrNull;
                return Card(
                  child: ListTile(
                    title: Text(child['name'] as String),
                    subtitle: Text(
                      child['revoked'] == true ? 'Доступ отозван' : 'Действует',
                    ),
                    trailing: Wrap(
                      children: [
                        if (local != null &&
                            local.profileIds.isNotEmpty &&
                            child['revoked'] != true)
                          IconButton(
                            tooltip: 'Передать профиль',
                            onPressed: busy
                                ? null
                                : () async {
                                    try {
                                      await share(
                                        await widget.store.exportUser(local),
                                      );
                                    } catch (_) {
                                      if (mounted) {
                                        setState(
                                          () => error =
                                              'Не удалось передать профиль',
                                        );
                                      }
                                    }
                                  },
                            icon: const Icon(Icons.share_outlined),
                          ),
                        if (child['revoked'] != true)
                          IconButton(
                            tooltip: 'Отозвать доступ',
                            onPressed: busy
                                ? null
                                : () async {
                                    final agreed = await showDialog<bool>(
                                      context: context,
                                      builder: (context) => AlertDialog(
                                        title: const Text(
                                          'Отозвать доступ субклиента?',
                                        ),
                                        actions: [
                                          TextButton(
                                            onPressed: () =>
                                                Navigator.pop(context, false),
                                            child: const Text('Отмена'),
                                          ),
                                          FilledButton(
                                            onPressed: () =>
                                                Navigator.pop(context, true),
                                            child: const Text('Отозвать'),
                                          ),
                                        ],
                                      ),
                                    );
                                    if (agreed != true) return;
                                    setState(() => busy = true);
                                    try {
                                      await service.revoke(child['id']);
                                      await refresh();
                                    } catch (_) {
                                      if (mounted) {
                                        setState(
                                          () => error =
                                              'Сервер не подтвердил отзыв',
                                        );
                                      }
                                    } finally {
                                      if (mounted) setState(() => busy = false);
                                    }
                                  },
                            icon: const Icon(Icons.person_remove_outlined),
                          ),
                      ],
                    ),
                  ),
                );
              },
            ),
        ],
      ],
    ),
  );
}
