import 'dart:io';

import 'package:flutter/services.dart';

import 'core.dart';
import 'update_service.dart';

const supportUrl = 'https://xio.org/pay';
Future<void> openSupportLink() => openExternalLink(supportUrl);
Future<void> openExternalLink(String url) async {
  final uri = Uri.parse(url);
  if (uri.scheme != 'https' || uri.userInfo.isNotEmpty) {
    throw StateError('Не удалось открыть ссылку');
  }
  if (Platform.isAndroid || Platform.isIOS) {
    await native.invokeMethod<void>('openExternalLink', {'url': url});
    return;
  }
  final result = Platform.isWindows
      ? await Process.run('rundll32.exe', ['url.dll,FileProtocolHandler', url])
      : await Process.run('xdg-open', [url]);
  if (result.exitCode != 0) throw StateError('Не удалось открыть ссылку');
}

/// Открывает ссылку MTProto-прокси в Telegram.
///
/// Через [openExternalLink] это нельзя: там разрешена только схема `https`.
/// Здесь наоборот — только `tg`, чтобы приложение не запускало по чужому
/// вводу произвольный обработчик протокола.
Future<void> openTelegramLink(String url) async {
  final uri = Uri.parse(url);
  if (uri.scheme != 'tg' || uri.userInfo.isNotEmpty) {
    throw StateError('Не удалось открыть Telegram');
  }
  if (Platform.isAndroid || Platform.isIOS) {
    await native.invokeMethod<void>('openTelegramLink', {'url': url});
    return;
  }
  final result = Platform.isWindows
      ? await Process.run('rundll32.exe', ['url.dll,FileProtocolHandler', url])
      : await Process.run('xdg-open', [url]);
  if (result.exitCode != 0) throw StateError('Не удалось открыть Telegram');
}

Future<void> shareApplication() async {
  final url = '$releasesUrl/tag/v$xioVersion';
  if (Platform.isAndroid || Platform.isIOS) {
    await native.invokeMethod<void>('shareApplication', {
      'text': 'XIO VPN\n$url',
    });
  } else {
    await Clipboard.setData(ClipboardData(text: 'XIO VPN\n$url'));
  }
}
