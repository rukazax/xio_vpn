import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';
import 'l10n.dart';

/// A control backed by real privileged routing, not a visual-only VPN toggle.
class VpnSharingControl extends StatefulWidget {
  const VpnSharingControl({super.key});
  @override
  State<VpnSharingControl> createState() => _VpnSharingControlState();
}

class _VpnSharingControlState extends State<VpnSharingControl> {
  bool enabled = false, busy = false;
  String selected = '', message = '';
  List<Map<String, dynamic>> candidates = [];
  bool get available => Platform.isAndroid || Platform.isWindows;
  @override
  void initState() {
    super.initState();
    if (available) load();
  }

  void apply(Map<String, dynamic> state) {
    enabled = state['enabled'] == true;
    selected = state['interface'] as String? ?? selected;
    candidates = (state['candidates'] as List? ?? [])
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList();
    message = state['message'] as String? ?? '';
    if (!candidates.any((e) => e['id'] == selected)) {
      selected = '';
    }
  }

  Future<void> load() async {
    try {
      final state = await native.invokeMapMethod<String, dynamic>(
        'sharingStatus',
      );
      if (mounted && state != null) setState(() => apply(state));
    } catch (_) {}
  }

  Future<void> toggle(bool value) async {
    setState(() => busy = true);
    try {
      final state = await native.invokeMapMethod<String, dynamic>(
        'sharingSet',
        {'enabled': value, 'interface': selected},
      );
      if (mounted && state != null) setState(() => apply(state));
    } catch (e) {
      final error = e is PlatformException
          ? e.message ?? 'Не удалось настроить раздачу через VPN'
          : 'Не удалось настроить раздачу через VPN';
      await load();
      if (mounted) {
        setState(() => message = error);
        await showDialog<void>(
          context: context,
          builder: (context) => AlertDialog(
            title: const LText('VPN при раздаче'),
            content: LText(error),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const LText('Понятно'),
              ),
            ],
          ),
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      SwitchListTile(
        title: const LText('VPN при раздаче'),
        value: enabled,
        onChanged: available && !busy ? toggle : null,
        subtitle: LText(
          !available
              ? 'Эта платформа не поддерживает VPN при раздаче в XIO'
              : Platform.isAndroid
              ? 'Необходим root. Сначала включите модем или точку доступа телефона.'
              : 'Необходимы права администратора. Сначала включите мобильный хот-спот Windows и VPN.',
        ),
      ),
      if (available && candidates.isNotEmpty)
        DropdownButtonFormField<String>(
          key: ValueKey('$enabled:$selected:${candidates.length}'),
          initialValue: selected.isEmpty ? null : selected,
          isExpanded: true,
          decoration: InputDecoration(
            labelText: tr(context, 'Интерфейс раздачи'),
          ),
          items: [
            for (final item in candidates)
              DropdownMenuItem(
                value: item['id'] as String,
                child: Text(
                  item['name'] as String,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: enabled || busy
              ? null
              : (value) => setState(() => selected = value ?? ''),
        ),
      if (available)
        Align(
          alignment: Alignment.centerRight,
          child: TextButton.icon(
            onPressed: busy ? null : load,
            icon: const Icon(Icons.refresh),
            label: const LText('Проверить интерфейсы'),
          ),
        ),
      if (message.isNotEmpty)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: LText(message),
        ),
      const Divider(),
    ],
  );
}
