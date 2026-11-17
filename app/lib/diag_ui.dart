import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'diag.dart';
import 'l10n.dart';

/// Test-build log viewer: read, copy, share and send the diagnostic bundle.
class DiagScreen extends StatefulWidget {
  const DiagScreen({super.key, this.initialUpload = false});

  /// Open from "send logs" and start the upload immediately.
  final bool initialUpload;

  @override
  State<DiagScreen> createState() => _DiagScreenState();
}

class _DiagScreenState extends State<DiagScreen> {
  String _text = 'Загрузка…';
  bool _busy = false;
  String? _status;

  static const _channel = MethodChannel('app.xio/engine');

  @override
  void initState() {
    super.initState();
    _refresh();
    if (widget.initialUpload) WidgetsBinding.instance.addPostFrameCallback((_) => _upload());
  }

  Future<void> _refresh() async {
    setState(() => _busy = true);
    try {
      final text = await XioDiag.snapshot(max: 400000);
      if (!mounted) return;
      setState(() => _text = text.isEmpty ? 'Журнал пуст' : text);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: _text));
    if (mounted) setState(() => _status = 'Скопировано в буфер');
  }

  Future<void> _share() async {
    final path = await XioDiag.bundlePath();
    if (!mounted) return;
    if (path == null) {
      setState(() => _status = 'Не удалось собрать архив');
      return;
    }
    try {
      await _channel.invokeMethod<void>('shareDiag', {'path': path});
      if (mounted) setState(() => _status = 'Архив передан системе');
    } catch (error) {
      if (mounted) setState(() => _status = 'Отправка архива не удалась: $error');
    }
  }

  Future<void> _upload() async {
    setState(() {
      _busy = true;
      _status = 'Отправка…';
    });
    try {
      final id = await XioDiag.upload();
      if (!mounted) return;
      setState(() => _status = id == null
          ? (XioDiag.canUpload ? 'Панель не приняла журнал' : 'Адрес панели не задан в сборке')
          : 'Отправлено: $id');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const LText('Диагностический журнал')),
        body: Column(
          children: [
            if (xioTestBuild)
              Container(
                width: double.infinity,
                color: Theme.of(context).colorScheme.errorContainer,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                child: const LText(
                  'Тестовая сборка: скриншоты разрешены, журнал пишется в файл и может отправляться в панель. Не используйте для постоянной работы.',
                ),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  OutlinedButton.icon(
                    onPressed: _busy ? null : _refresh,
                    icon: const Icon(Icons.refresh),
                    label: const LText('Обновить'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _copy,
                    icon: const Icon(Icons.copy),
                    label: const LText('Копировать'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _busy ? null : _share,
                    icon: const Icon(Icons.ios_share),
                    label: const LText('Файлом'),
                  ),
                  FilledButton.icon(
                    onPressed: _busy || !XioDiag.canUpload ? null : _upload,
                    icon: const Icon(Icons.cloud_upload_outlined),
                    label: const LText('Отправить'),
                  ),
                ],
              ),
            ),
            if (_status != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text(_status!, style: Theme.of(context).textTheme.bodySmall),
                ),
              ),
            if (_busy) const LinearProgressIndicator(minHeight: 2),
            const Divider(height: 20),
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                child: SelectableText(
                  _text,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
          ],
        ),
      );
}
