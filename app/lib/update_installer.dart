// SPDX-License-Identifier: GPL-3.0-only
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:archive/archive_io.dart';

import 'core.dart';
import 'update_service.dart';

/// Extract regular files only, never trusting archive paths, links or mode bits.
void extractWindowsUpdate(String source, String destination) {
  final input = InputFileStream(source);
  try {
    final decoder = ZipDecoder();
    final archive = decoder.decodeStream(input, verify: true);
    final rawNames = <String>{};
    for (final header in decoder.directory.fileHeaders) {
      if (!rawNames.add(header.filename.toLowerCase())) {
        throw const FormatException('Duplicate ZIP entry');
      }
    }
    var total = 0;
    final seen = <String>{};
    for (final entry in archive) {
      final parts = entry.name.split('/');
      total += entry.size;
      if (archive.length > 15000 ||
          total > 2 * 1024 * 1024 * 1024 ||
          entry.size > 800 * 1024 * 1024 ||
          entry.isSymbolicLink ||
          !{0, 0x8000, 0x4000}.contains(entry.mode & 0xf000) ||
          parts.first != 'XIO' ||
          parts.any(
            (s) =>
                s == '..' ||
                s.endsWith('.') ||
                s.endsWith(' ') ||
                RegExp(
                  r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)',
                  caseSensitive: false,
                ).hasMatch(s) ||
                s.contains('\\') ||
                s.contains(':') ||
                RegExp(r'[\x00-\x1f]').hasMatch(s),
          ) ||
          !seen.add(entry.name.toLowerCase())) {
        throw const FormatException('Unsafe update archive');
      }
    }
    if (!archive.any((e) => e.name == 'XIO/XIO.exe' && e.isFile)) {
      throw const FormatException('Missing XIO executable');
    }
    for (final entry in archive) {
      if (!entry.isFile) continue;
      final file = File('$destination/${entry.name}');
      file.parent.createSync(recursive: true);
      final output = OutputFileStream(file.path);
      try {
        entry.writeContent(output);
      } finally {
        output.closeSync();
      }
    }
  } finally {
    input.closeSync();
  }
}

String psLiteral(String value) => "'${value.replaceAll("'", "''")}'";
Future<void> installUpdate(File file, XioRelease release) async {
  if (playDistribution || Platform.isIOS) {
    throw StateError('Откройте страницу релиза');
  }
  if (Platform.isAndroid) {
    await native.invokeMethod<void>('installUpdate', {
      'path': file.path,
      'build': release.build,
    });
    return;
  }
  if (Platform.isLinux) {
    // APT maintains package ownership and resolves newly required dependencies.
    if (!File('/var/lib/dpkg/status').existsSync() ||
        !file.path.endsWith('.deb')) {
      throw StateError('Откройте страницу релиза');
    }
    final result = await Process.run('pkexec', [
      '/usr/bin/apt-get',
      '--yes',
      '--no-remove',
      'install',
      file.path,
    ]);
    if (result.exitCode != 0) {
      throw StateError('Установка обновления не завершена');
    }
    await file.delete();
    // The current process remains usable until the OS completed installation.
    await Process.start(
      '/opt/xio/XIO',
      [],
      mode: ProcessStartMode.detached,
      workingDirectory: file.parent.path,
    );
    exit(0);
  }
  if (Platform.isWindows) {
    final target = File(Platform.resolvedExecutable).parent.path;
    // Never replace an unrelated directory or a system root.
    if (!File('$target/data/app.so').existsSync() ||
        target.length < 10 ||
        !File('$target/XIO.exe').existsSync()) {
      throw StateError('Откройте страницу релиза');
    }
    final stage = Directory('${file.parent.path}/unpacked');
    if (await stage.exists()) await stage.delete(recursive: true);
    await stage.create();
    await Isolate.run(() => extractWindowsUpdate(file.path, stage.path));
    final script = File('${file.parent.path}/install.ps1');
    final backup = '$target.xio-backup-${release.build}';
    final ack = '${file.parent.path}/installed-${release.build}';
    final text =
        '''
\$ErrorActionPreference = 'Stop'
\$target = ${psLiteral(target)}
\$source = ${psLiteral('${stage.path}/XIO')}
\$backup = ${psLiteral(backup)}
\$ack = ${psLiteral(ack)}
try {
  Wait-Process -Id $pid -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath \$backup) { throw 'Backup exists' }
  Move-Item -LiteralPath \$target -Destination \$backup
  try { Copy-Item -LiteralPath \$source -Destination \$target -Recurse }
  catch { Remove-Item -LiteralPath \$target -Recurse -Force -ErrorAction SilentlyContinue; Move-Item -LiteralPath \$backup -Destination \$target; throw }
  Start-Process -FilePath (Join-Path \$target 'XIO.exe')
  for (\$i=0; \$i -lt 90 -and !(Test-Path -LiteralPath \$ack); \$i++) { Start-Sleep -Seconds 1 }
  if (!(Test-Path -LiteralPath \$ack)) { throw 'New version did not confirm startup; backup retained' }
  Remove-Item -LiteralPath \$backup -Recurse -Force
  Remove-Item -LiteralPath ${psLiteral(file.path)} -Force
  Remove-Item -LiteralPath ${psLiteral(stage.path)} -Recurse -Force
  Remove-Item -LiteralPath \$ack -Force
  Remove-Item -LiteralPath \$PSCommandPath -Force
} catch { \$_ | Out-String | Set-Content -LiteralPath ${psLiteral('${file.parent.path}/install-error.txt')} }
''';
    await script.writeAsString('\ufeff$text', encoding: utf8, flush: true);
    // Encoded command avoids cmd.exe expansion and argument quoting pitfalls.
    final command = "& ${psLiteral(script.path)}";
    final encoded = base64Encode(
      command.codeUnits.expand((v) => [v & 255, v >> 8]).toList(),
    );
    await Process.start(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        encoded,
      ],
      mode: ProcessStartMode.detached,
      workingDirectory: file.parent.path,
    );
    exit(0);
  }
}
