import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'awg_export.dart';
import 'l10n.dart';

/// Shows one ready-to-import AmneziaWG profile: copy, save as `.conf`, and a
/// short explanation of which server the endpoint belongs to.
class AwgExportSheet extends StatefulWidget {
  const AwgExportSheet({
    super.key,
    required this.profile,
    required this.name,
    required this.cascadeLikely,
  });

  final AwgProfile profile;
  final String name;

  /// True when the issuing server is the bridge of a configured cascade; the
  /// wording then promises the second server instead of a direct exit.
  final bool cascadeLikely;

  @override
  State<AwgExportSheet> createState() => _AwgExportSheetState();
}

class _AwgExportSheetState extends State<AwgExportSheet> {
  static const _channel = MethodChannel('app.xio/engine');
  String? _status;

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: widget.profile.text));
    if (mounted) setState(() => _status = 'Профиль скопирован');
  }

  Future<void> _file() async {
    try {
      await _channel.invokeMethod<void>('shareTextFile', {
        'name': AwgProfile.fileName(widget.name),
        'text': widget.profile.text,
      });
      if (mounted) setState(() => _status = 'Файл передан системе');
    } catch (error) {
      if (mounted) setState(() => _status = 'Не удалось сохранить файл: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    final profile = widget.profile;
    return SafeArea(
      child: Padding(
        padding: EdgeInsets.fromLTRB(
          20,
          20,
          20,
          20 + MediaQuery.viewInsetsOf(context).bottom,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'AmneziaWG 3.1 · ${widget.name}',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            LText(
              widget.cascadeLikely
                  ? 'Endpoint ${profile.endpoint} — первый сервер каскада. Он сам направляет весь трафик через второй сервер; на клиенте ничего дополнительно настраивать не нужно.'
                  : 'Endpoint ${profile.endpoint} — конечный сервер. Профиль поднимает полный туннель: AllowedIPs 0.0.0.0/0, ::/0.',
            ),
            const SizedBox(height: 8),
            Text(
              'Импорт: Amnezia VPN → «+» → файл с настройками подключения, либо другой клиент AmneziaWG. Обфускация: ${profile.obfuscated ? 'параметры сервера сохранены' : 'профиль без обфускации'}.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            Container(
              constraints: const BoxConstraints(maxHeight: 260),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              padding: const EdgeInsets.all(10),
              child: SingleChildScrollView(
                child: SelectableText(
                  profile.text,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
            if (_status != null) ...[
              const SizedBox(height: 8),
              Text(_status!, style: Theme.of(context).textTheme.bodySmall),
            ],
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              alignment: WrapAlignment.end,
              children: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const LText('Закрыть'),
                ),
                OutlinedButton.icon(
                  onPressed: _copy,
                  icon: const Icon(Icons.copy),
                  label: const LText('Копировать'),
                ),
                FilledButton.icon(
                  onPressed: _file,
                  icon: const Icon(Icons.save_alt),
                  label: const LText('Файлом .conf'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
