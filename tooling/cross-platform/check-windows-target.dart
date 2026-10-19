// SPDX-License-Identifier: GPL-3.0-only
import 'dart:convert';
import 'dart:io';

import 'package:flutter/widgets.dart';
import 'package:x1o/desktop_engine.dart';
import 'package:x1o/update_installer.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final output = Platform.environment['XIO_KERNEL_CHECK_OUTPUT'];
  final result = <String, dynamic>{
    'operatingSystem': Platform.operatingSystem,
    'isWindows': Platform.isWindows,
    'scope': 'Windows runtime under Wine, not a native Windows driver/UAC test',
  };
  try {
    if (!Platform.isWindows)
      throw StateError('Kernel compiled for the wrong operating system');
    await DesktopEngine.initialise();
    result['engines'] = DesktopEngine.supported.toList()..sort();
    if (DesktopEngine.supported.length != 4)
      throw StateError('Desktop helper capabilities unavailable');
    final package = Platform.environment['XIO_KERNEL_CHECK_ARCHIVE'];
    if (package != null) {
      final temporary = await Directory.systemTemp.createTemp(
        'xio-archive-check',
      );
      try {
        extractWindowsUpdate(package, temporary.path);
        result['archiveExtractionPassed'] =
            File('${temporary.path}/XIO/XIO.exe').existsSync() &&
            File('${temporary.path}/XIO/data/app.so').existsSync();
      } finally {
        await temporary.delete(recursive: true);
      }
    }
    result['passed'] = true;
  } catch (e) {
    result['passed'] = false;
    result['error'] = e.toString();
  }
  if (output != null) await File(output).writeAsString(jsonEncode(result));
  exit(result['passed'] == true ? 0 : 1);
}
