import 'dart:io';

import 'core.dart';

const supportUrl = 'https://x1o.org/pay';
Future<void> openSupportLink() async {
  if (Platform.isAndroid) {
    await native.invokeMethod<void>('openSupportLink');
    return;
  }
  final result = Platform.isWindows
      ? await Process.run('rundll32.exe', [
          'url.dll,FileProtocolHandler',
          supportUrl,
        ])
      : await Process.run('xdg-open', [supportUrl]);
  if (result.exitCode != 0) throw StateError('Не удалось открыть ссылку');
}
