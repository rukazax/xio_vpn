/// Экран «Telegram-прокси (MTProto)».
///
/// Приложение ничего не подключает само: оно хранит ссылку `tg://proxy?…`,
/// отдаёт её в Telegram и позволяет скопировать. Так же, как в профилях VPN,
/// ссылка живёт в `AppStore` и переживает перезапуск; формат проверяется
/// в [parseMtprotoLink], чтобы в настройки не попал мусор.
///
/// Владельцу сервера ссылку вводить не нужно: если сервер сохранён, экран сам
/// спрашивает её по SSH ([MtprotoRemote]) и показывает. Если прокси ещё не
/// установлен, здесь же есть кнопка установки — установщик лежит в репозитории
/// и запускается по SSH.
///
/// Экран открывается из «Настроек» (`WorkspaceScreen.push`), поэтому у него
/// нет своего [Scaffold] и [AppBar] — заголовок и прокрутку даёт вызывающий.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';
import 'external_links.dart';
import 'l10n.dart';
import 'mtproto_remote.dart';

class MtprotoProxyScreen extends StatefulWidget {
  const MtprotoProxyScreen({super.key, required this.store, this.remote});

  final AppStore store;

  /// Источник ссылки. `null` — настоящий SSH к сохранённому серверу.
  final MtprotoRemote? remote;

  @override
  State<MtprotoProxyScreen> createState() => _MtprotoProxyScreenState();
}

class _MtprotoProxyScreenState extends State<MtprotoProxyScreen> {
  late final TextEditingController _link;
  late final MtprotoRemote _remote;
  String? _error;
  bool _busy = false;

  /// Запрос ссылки с сервера идёт: индикатор заменяет кнопки.
  bool _loading = false;

  /// Установка прокси по SSH: она длиннее запроса, поэтому отдельный флаг.
  bool _installing = false;

  /// Есть ли на сервере прокси. `null` — сервер ещё не ответил.
  bool? _serverInstalled;

  /// Отдельная строка про автоподстановку: ошибка запроса не мешает ручному
  /// вводу, поэтому она живёт рядом с кнопками, а не в поле «Ссылка прокси».
  String? _remoteError;
  String? _remoteNote;

  AppStore get store => widget.store;

  bool get _hasServer => store.servers.isNotEmpty;

  @override
  void initState() {
    super.initState();
    _link = TextEditingController(text: store.mtprotoLink);
    _remote = widget.remote ?? SshMtprotoRemote(store: store);
    if (_hasServer) {
      // Первый кадр должен показать экран, а не ждать SSH.
      WidgetsBinding.instance.addPostFrameCallback((_) => _fetchLink());
    }
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

  /// Спрашивает ссылку у сервера и сохраняет её в профиль.
  ///
  /// Это удобство, а не часть подключения: любая ошибка оставляет ручной ввод
  /// рабочим и показывается отдельной строкой.
  Future<void> _fetchLink() async {
    if (!_hasServer) return;
    setState(() {
      _loading = true;
      _remoteError = null;
      _remoteNote = null;
    });
    try {
      final state = await _remote.fetch();
      if (!mounted) return;
      final link = state.link;
      if (link == null) {
        setState(() {
          _serverInstalled = false;
          _remoteError =
              'На сервере не установлен MTProto-прокси — установите кнопкой';
        });
        return;
      }
      final saved = await store.setMtprotoLink(link.link);
      if (!mounted) return;
      if (!saved) {
        setState(
          () => _remoteError = 'Сервер вернул ссылку, которую нельзя сохранить',
        );
        return;
      }
      _link.text = store.mtprotoLink;
      setState(() {
        _serverInstalled = true;
        _remoteNote = 'Ссылка получена с сервера автоматически';
        _error = null;
      });
    } on TimeoutException {
      _failFetch('Сервер не ответил за 10 с');
    } on StateError catch (error) {
      _failFetch(error.message);
    } on FormatException catch (error) {
      _failFetch(error.message);
    } catch (_) {
      _failFetch('Не удалось получить ссылку с сервера');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _failFetch(String text) {
    if (!mounted) return;
    setState(() => _remoteError = text);
  }

  /// Ставит прокси установщиком из репозитория и повторяет запрос ссылки.
  Future<void> _install() async {
    setState(() {
      _installing = true;
      _remoteError = null;
      _remoteNote = null;
    });
    try {
      await _remote.install();
    } on TimeoutException {
      return _failInstall(
        'Установка не завершилась за 10 мин. Проверьте сервер и повторите',
      );
    } on StateError catch (error) {
      return _failInstall(error.message);
    } on FormatException catch (error) {
      return _failInstall(error.message);
    } catch (_) {
      return _failInstall('Не удалось установить MTProto-прокси');
    } finally {
      if (mounted) setState(() => _installing = false);
    }
    if (!mounted) return;
    _message('Установщик завершил работу — проверяю ссылку');
    await _fetchLink();
  }

  void _failInstall(String text) {
    if (!mounted) return;
    setState(() {
      _installing = false;
      _remoteError = text;
    });
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
      setState(() {
        _error = null;
        // Ручное сохранение — тоже повод не показывать «получена с сервера».
        _remoteNote = null;
      });
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

  /// Индикатор и всё, что относится к автоматическому получению ссылки.
  List<Widget> _serverRows() {
    if (!_hasServer) return const [];
    return [
      if (_loading || _installing)
        Padding(
          key: const ValueKey('mtproto-progress'),
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(
            children: [
              const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: LText(
                  _installing
                      ? 'Устанавливаю MTProto-прокси на сервер…'
                      : 'Запрашиваю ссылку с сервера…',
                ),
              ),
            ],
          ),
        ),
      if (_remoteError != null)
        Padding(
          key: const ValueKey('mtproto-auto-error'),
          padding: const EdgeInsets.only(top: 8),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.error_outline, size: 20),
              const SizedBox(width: 8),
              Expanded(child: LText(_remoteError!)),
            ],
          ),
        ),
      if (_remoteNote != null)
        Padding(
          key: const ValueKey('mtproto-auto-note'),
          padding: const EdgeInsets.only(top: 8),
          child: Row(
            children: [
              const Icon(Icons.cloud_done_outlined, size: 20),
              const SizedBox(width: 8),
              Expanded(child: LText(_remoteNote!)),
            ],
          ),
        ),
      const SizedBox(height: 8),
      Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          if (_serverInstalled == false)
            FilledButton.tonalIcon(
              key: const ValueKey('mtproto-install'),
              onPressed: _busy || _loading || _installing ? null : _install,
              icon: const Icon(Icons.download_outlined),
              label: const LText('Установить MTProto на сервер'),
            ),
          if (_serverInstalled != false)
            TextButton.icon(
              key: const ValueKey('mtproto-refresh'),
              onPressed: _busy || _loading || _installing ? null : _fetchLink,
              icon: const Icon(Icons.refresh),
              label: const LText('Обновить с сервера'),
            ),
        ],
      ),
    ];
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
        ..._serverRows(),
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
