import 'core.dart' show native;

// SPDX-License-Identifier: GPL-3.0-only
import 'dart:io';

import 'package:flutter/material.dart';

import 'external_links.dart';
import 'update_service.dart';
import 'update_installer.dart';
import 'l10n.dart';

Future<void>? _updateInteraction;
Future<void> checkForUpdates(BuildContext context, {bool manual = true}) =>
    _updateInteraction ??= _checkForUpdates(
      context,
      manual: manual,
    ).whenComplete(() => _updateInteraction = null);

Future<void> _checkForUpdates(
  BuildContext context, {
  bool manual = true,
}) async {
  final updater = UpdateService.instance;
  if (playDistribution) {
    await openExternalLink(
      'https://play.google.com/store/apps/details?id=app.x1o.x1o',
    );
    return;
  }
  try {
    final release = await updater.check(manual: manual);
    if (!context.mounted) return;
    if (release == null) {
      if (manual) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: LText('Установлена последняя версия')),
        );
      }
      return;
    }
    final key = await updater.platformKey();
    final asset = release.forPlatform(key);
    if (!context.mounted) return;
    var permissionChecking = false;
    final choice = await showDialog<String>(
      context: context,
      builder: (c) => AlertDialog(
        title: LText(
          'Доступно обновление {0}'.replaceFirst('{0}', release.version),
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(release.notes),
              const SizedBox(height: 16),
              LText(
                Platform.isIOS || asset == null
                    ? 'Для этой платформы откроется страница релиза'
                    : Platform.isAndroid
                    ? 'Android запросит разрешение на установку. После установки пакет будет удалён.'
                    : 'Приложение перезапустится после установки. Настройки сохранятся.',
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(c, 'later'),
            child: const LText('Позже'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(c, 'skip'),
            child: const LText('Пропустить релиз'),
          ),
          FilledButton(
            onPressed: () async {
              if (permissionChecking) return;
              permissionChecking = true;
              try {
                if (Platform.isAndroid &&
                    asset != null &&
                    !await nativeUpdatePermission()) {
                  if (c.mounted) {
                    ScaffoldMessenger.of(c).showSnackBar(
                      const SnackBar(
                        content: LText(
                          'Разрешите установку приложений из XIO и нажмите «Обновить» ещё раз.',
                        ),
                      ),
                    );
                  }
                  return;
                }
                if (c.mounted) Navigator.pop(c, 'update');
              } catch (_) {
                if (c.mounted) {
                  ScaffoldMessenger.of(c).showSnackBar(
                    const SnackBar(
                      content: LText('Установка обновления не завершена'),
                    ),
                  );
                }
              } finally {
                permissionChecking = false;
              }
            },
            child: const LText('Обновить'),
          ),
        ],
      ),
    );
    if (choice == 'skip') {
      await updater.skip(release);
      return;
    }
    if (choice != 'update' || !context.mounted) return;
    if (Platform.isIOS || asset == null) {
      await openExternalLink(release.page);
      return;
    }
    if (!context.mounted) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => UpdateDownloadDialog(release: release, asset: asset),
    );
  } catch (_) {
    if (context.mounted && manual) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: LText('Не удалось проверить обновления. Повторите позже.'),
        ),
      );
    }
  }
}

class UpdateDownloadDialog extends StatefulWidget {
  final XioRelease release;
  final UpdateAsset asset;
  const UpdateDownloadDialog({
    super.key,
    required this.release,
    required this.asset,
  });
  @override
  State<UpdateDownloadDialog> createState() => _UpdateDownloadDialogState();
}

class _UpdateDownloadDialogState extends State<UpdateDownloadDialog> {
  double progress = 0;
  bool failed = false, cancelled = false, installing = false;
  @override
  void initState() {
    super.initState();
    run();
  }

  Future<void> run() async {
    try {
      final file = await UpdateService.instance.download(
        widget.release,
        widget.asset,
        (p) {
          if (mounted) setState(() => progress = p);
        },
      );
      if (cancelled) {
        if (await file.exists()) await file.delete();
        return;
      }
      if (mounted) setState(() => installing = true);
      await installUpdate(file, widget.release);
      if (mounted) Navigator.pop(context);
    } catch (_) {
      if (mounted) setState(() => failed = true);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: failed,
    child: AlertDialog(
      title: const LText('Обновление XIO'),
      content: failed
          ? const LText('Установка обновления не завершена')
          : Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                LinearProgressIndicator(value: progress),
                const SizedBox(height: 12),
                Text('${(progress * 100).floor()}%'),
              ],
            ),
      actions: [
        TextButton(
          onPressed: installing && !failed
              ? null
              : () {
                  cancelled = true;
                  UpdateService.instance.cancelDownload();
                  Navigator.pop(context);
                },
          child: LText(failed ? 'Закрыть' : 'Отмена'),
        ),
      ],
    ),
  );
}

class UpdateSettingsTile extends StatefulWidget {
  const UpdateSettingsTile({super.key});
  @override
  State<UpdateSettingsTile> createState() => _UpdateSettingsTileState();
}

class _UpdateSettingsTileState extends State<UpdateSettingsTile> {
  bool busy = false;
  @override
  Widget build(BuildContext context) => ListTile(
    leading: busy
        ? const SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        : const Icon(Icons.system_update_outlined),
    title: const LText('Проверить обновления'),
    subtitle: const LText('Автоматически раз в неделю, в случайное время'),
    onTap: busy
        ? null
        : () async {
            setState(() => busy = true);
            await checkForUpdates(context);
            if (mounted) setState(() => busy = false);
          },
  );
}

Future<bool> nativeUpdatePermission() async =>
    await native.invokeMethod<bool>('prepareUpdateInstall') ?? false;
