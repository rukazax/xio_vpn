/// Экран «Telegram-прокси (MTProto)».
///
/// Приложение ничего не подключает само: оно хранит ссылку `tg://proxy?…`,
/// отдаёт её в Telegram и позволяет скопировать. Так же, как в профилях VPN,
/// ссылка живёт в `AppStore` и переживает перезапуск; формат проверяется
/// в [parseMtprotoLink], чтобы в настройки не попал мусор.
///
/// Экран открывается из «Настроек» (`WorkspaceScreen.push`), поэтому у него
/// нет своего [Scaffold] и [AppBar] — заголовок и прокрутку даёт вызывающий.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';
import 'external_links.dart';
import 'l10n.dart';

class MtprotoProxyScreen extends StatefulWidget {
  const MtprotoProxyScreen({super.key, required this.store});

  final AppStore store;

  @override
  State<MtprotoProxyScreen> createState() => _MtprotoProxyScreenState();
}

class _MtprotoProxyScreenState extends State<MtprotoProxyScreen> {
  late final TextEditingController _link;
  String? _error;
  bool _busy = false;

  AppStore get store => widget.store;

  @override
  void initState() {
    super.initState();
    _link = TextEditingController(text: store.mtprotoLink);
  }

  @override
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  void _message(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(content: LText(text), behavior: SnackBarBehavior.floating),
      );
  }

  Future<void> _save() async {
    final text = _link.text;
    setState(() => _busy = true);
    try {
      final saved = await store.setMtprotoLink(text);
      if (!mounted) return;
      if (!saved) {
        setState(() => _error = validateMtprotoLink(text));
        _message(_error ?? 'Ссылка не сохранена');
        return;
      }
      setState(() => _error = null);
      // Показываем то, что реально легло в профиль: t.me-ссылка станет tg://.
      _link.text = store.mtprotoLink;
      _message(
        store.mtprotoLink.isEmpty ? 'Ссылка удалена' : 'Ссылка сохранена',
      );
    } catch (_) {
      if (mounted) _message('Не удалось сохранить ссылку');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _clear() async {
    _link.clear();
    setState(() => _error = null);
    await _save();
  }

  Future<void> _paste() async {
    try {
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      final text = data?.text?.trim() ?? '';
      if (text.isEmpty) {
        _message('Буфер обмена пуст');
        return;
      }
      if (!mounted) return;
      _link.text = text;
      setState(() => _error = null);
    } catch (_) {
      _message('Не удалось прочитать буфер обмена');
    }
  }

  Future<void> _copy() async {
    final parsed = parseMtprotoLink(_link.text);
    if (parsed == null) {
      setState(() => _error = validateMtprotoLink(_link.text));
      _message(_error ?? 'Ссылка некорректна');
      return;
    }
    try {
      await Clipboard.setData(ClipboardData(text: parsed.link));
      _message('Ссылка скопирована');
    } catch (_) {
      _message('Не удалось скопировать ссылку');
    }
  }

  Future<void> _open() async {
    final parsed = parseMtprotoLink(_link.text);
    if (parsed == null) {
      setState(() => _error = validateMtprotoLink(_link.text));
      _message(_error ?? 'Ссылка некорректна');
      return;
    }
    try {
      await openTelegramLink(parsed.link);
      _message('Открываю Telegram — подтвердите прокси в приложении');
    } catch (_) {
      _message('Telegram не установлен или ссылка не открылась');
    }
  }

  @override
  Widget build(BuildContext context) {
    final saved = store.mtprotoLink;
    final parsedSaved = parseMtprotoLink(saved);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: const [
                LText(
                  'Как включить прокси в Telegram',
                  style: TextStyle(fontWeight: FontWeight.w600),
                ),
                SizedBox(height: 8),
                _Step(1, 'Скопируйте ссылку ниже — в ней адрес прокси и секрет.'),
                _Step(2, 'Telegram: Настройки → Данные и память → Прокси.'),
                _Step(3, '«Добавить прокси» → MTProto → вставьте ссылку.'),
                _Step(4, 'Включите переключатель «Использовать прокси».'),
                SizedBox(height: 8),
                LText(
                  'Прокси работает только для Telegram: остальной трафик он не '
                  'видит. Ссылка не даёт доступа к аккаунту, но позволяет '
                  'пользоваться прокси — не публикуйте её.',
                  style: TextStyle(fontSize: 12),
                ),
              ],
            ),
          ),
        ),
        TextField(
          key: const ValueKey('mtproto-link-field'),
          controller: _link,
          keyboardType: TextInputType.url,
          autocorrect: false,
          minLines: 1,
          maxLines: 3,
          onChanged: (_) {
            if (_error != null) setState(() => _error = null);
          },
          decoration: InputDecoration(
            labelText: tr(context, 'Ссылка прокси'),
            hintText: 'tg://proxy?server=…&port=443&secret=ee…',
            errorText: _error == null ? null : tr(context, _error!),
            errorMaxLines: 3,
            helperText: parsedSaved == null
                ? null
                : tr(context, 'Сервер: ${parsedSaved.address}'),
            helperMaxLines: 2,
          ),
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton.icon(
              key: const ValueKey('mtproto-save'),
              onPressed: _busy ? null : _save,
              icon: const Icon(Icons.save_outlined),
              label: const LText('Сохранить'),
            ),
            OutlinedButton.icon(
              key: const ValueKey('mtproto-copy'),
              onPressed: _busy ? null : _copy,
              icon: const Icon(Icons.copy_all_outlined),
              label: const LText('Скопировать'),
            ),
            OutlinedButton.icon(
              key: const ValueKey('mtproto-open'),
              onPressed: _busy ? null : _open,
              icon: const Icon(Icons.send_outlined),
              label: const LText('Открыть в Telegram'),
            ),
            TextButton(
              key: const ValueKey('mtproto-paste'),
              onPressed: _busy ? null : _paste,
              child: const LText('Вставить'),
            ),
            if (saved.isNotEmpty)
              TextButton(
                key: const ValueKey('mtproto-clear'),
                onPressed: _busy ? null : _clear,
                child: const LText('Очистить'),
              ),
          ],
        ),
        const SizedBox(height: 16),
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: Icon(
            saved.isEmpty ? Icons.info_outline : Icons.check_circle_outline,
          ),
          title: LText(saved.isEmpty ? 'Прокси не настроен' : 'Прокси настроен'),
          subtitle: LText(
            saved.isEmpty
                ? 'Вставьте ссылку от оператора прокси или из инструкции и нажмите «Сохранить».'
                : 'Сервер: ${parsedSaved?.address ?? saved} · секрет задан',
          ),
        ),
      ],
    );
  }
}

class _Step extends StatelessWidget {
  const _Step(this.number, this.text);

  final int number;
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(top: 6),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 20,
          child: Text('$number.', style: const TextStyle(height: 1.3)),
        ),
        Expanded(child: LText(text)),
      ],
    ),
  );
}
