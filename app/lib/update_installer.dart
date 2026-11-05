// SPDX-License-Identifier: GPL-3.0-only
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:archive/archive_io.dart';

import 'core.dart';
import 'update_service.dart';

/// Accept the published flat ZIP and the legacy XIO/ layout, normalizing both
/// into destination/XIO. Validate the complete namespace before writing a byte.
void extractWindowsUpdate(String source, String destination) {
  final input = InputFileStream(source);
  try {
    final decoder = ZipDecoder();
    final archive = decoder.decodeStream(input, verify: true);
    final rawNames = <String>{};
    for (final header in decoder.directory.fileHeaders) {
      // ArchiveFile normalizes backslashes; inspect the original headers too.
      if (header.filename.contains('\\') ||
          !rawNames.add(header.filename.toLowerCase())) {
        throw const FormatException('Unsafe or duplicate ZIP entry');
      }
    }
    final flat = archive.any((e) => e.name == 'XIO.exe' && e.isFile);
    final nested = archive.any((e) => e.name == 'XIO/XIO.exe' && e.isFile);
    if (flat == nested) {
      throw const FormatException('Missing or ambiguous XIO executable');
    }
    var total = 0;
    final seen = <String>{};
    final files = <String>{};
    final entries = <({ArchiveFile entry, String name})>[];
    for (final entry in archive) {
      final parts = entry.name.split('/');
      // A final slash denotes a directory, never an alias for a regular file.
      if (!entry.isFile && parts.last.isEmpty) parts.removeLast();
      total += entry.size;
      if (archive.length > 15000 ||
          total > 2 * 1024 * 1024 * 1024 ||
          entry.size > 800 * 1024 * 1024 ||
          entry.isSymbolicLink ||
          !{0, 0x8000, 0x4000}.contains(entry.mode & 0xf000) ||
          parts.isEmpty ||
          (nested
              ? parts.first != 'XIO'
              : parts.first.toLowerCase() == 'xio') ||
          parts.any(
            (s) =>
                s.isEmpty ||
                s == '..' ||
                s.endsWith('.') ||
                s.endsWith(' ') ||
                RegExp(
                  r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)',
                  caseSensitive: false,
                ).hasMatch(s) ||
                RegExp(r'[<>:"\\|?*\x00-\x1f\x7f]').hasMatch(s),
          )) {
        throw const FormatException('Unsafe update archive');
      }
      final name = flat ? 'XIO/${parts.join('/')}' : parts.join('/');
      final canonical = name.toLowerCase();
      if (!seen.add(canonical)) {
        throw const FormatException('Duplicate update path');
      }
      if (entry.isFile) files.add(canonical);
      entries.add((entry: entry, name: name));
    }
    for (final name in seen) {
      final parts = name.split('/');
      for (var i = 1; i < parts.length; i++) {
        if (files.contains(parts.take(i).join('/'))) {
          throw const FormatException('File/directory update conflict');
        }
      }
    }
    for (final required in [
      'xio/xio.exe',
      'xio/flutter_windows.dll',
      'xio/data/app.so',
    ]) {
      if (!files.contains(required)) {
        throw const FormatException('Incomplete Windows update');
      }
    }
    for (final item in entries) {
      if (!item.entry.isFile) continue;
      final file = File('$destination/${item.name}');
      file.parent.createSync(recursive: true);
      final output = OutputFileStream(file.path);
      try {
        item.entry.writeContent(output);
      } finally {
        output.closeSync();
      }
    }
  } finally {
    input.closeSync();
  }
}

String psLiteral(String value) => "'${value.replaceAll("'", "''")}'";

/// Pure generator so rollback can be exercised with mocked launches and real
/// temporary filesystem operations, without executing an unsigned application.
String windowsUpdateScript({
  required String target,
  required String stage,
  required String package,
  required String version,
  required int build,
  required int parentPid,
  int startupTimeoutSeconds = 90,
}) {
  if (startupTimeoutSeconds < 1 || startupTimeoutSeconds > 300) {
    throw ArgumentError.value(startupTimeoutSeconds, 'startupTimeoutSeconds');
  }
  final parent = File(package).parent.path;
  return '''
\$ErrorActionPreference = 'Stop'
\$target = ${psLiteral(target)}
\$source = ${psLiteral('$stage/XIO')}
\$backup = ${psLiteral('$target.xio-backup-$build')}
\$ack = ${psLiteral('$parent/installed-$build')}
\$archive = ${psLiteral(package)}
\$stage = ${psLiteral(stage)}
\$version = ${psLiteral(version)}
\$errorFile = ${psLiteral('$parent/install-error.txt')}
\$parentProcessId = $parentPid
\$startupTimeoutSeconds = $startupTimeoutSeconds
'''
      r'''
$moved = $false
$targetCreated = $false
$committed = $false
$newProcess = $null
try {
  Wait-Process -Id $parentProcessId -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $backup) { throw 'Backup exists' }
  foreach ($relative in @('XIO.exe', 'data/app.so', 'flutter_windows.dll')) {
    if (!(Test-Path -LiteralPath (Join-Path $source $relative) -PathType Leaf)) { throw 'Incomplete update source' }
  }
  if (!(Test-Path -LiteralPath (Join-Path $target 'XIO.exe') -PathType Leaf) -or
      !(Test-Path -LiteralPath (Join-Path $target 'data/app.so') -PathType Leaf)) { throw 'Installed application changed' }
  # An acknowledgement from an earlier attempt must never commit this attempt.
  if (Test-Path -LiteralPath $ack) { Remove-Item -LiteralPath $ack -Force -ErrorAction Stop }
  [IO.Directory]::Move($target, $backup)
  $moved = $true
  # Own the replacement directory before copying; never erase a raced-in path.
  New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
  $targetCreated = $true
  Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $target -Recurse -Force
  }
  $newProcess = Start-Process -FilePath (Join-Path $target 'XIO.exe') -WorkingDirectory $target -PassThru
  if ($null -eq $newProcess) { throw 'New application did not start' }
  $confirmed = $false
  for ($i = 0; $i -lt $startupTimeoutSeconds; $i++) {
    if (Test-Path -LiteralPath $ack -PathType Leaf) {
      try { $confirmed = ([IO.File]::ReadAllText($ack) -ceq $version) } catch { $confirmed = $false }
    }
    if ($confirmed) { break }
    $newProcess.Refresh()
    if ($newProcess.HasExited) { throw 'New application exited before startup acknowledgement' }
    Start-Sleep -Seconds 1
  }
  if (!$confirmed) { throw 'New application did not confirm startup' }
  $committed = $true
  Remove-Item -LiteralPath $archive -Force
  Remove-Item -LiteralPath $stage -Recurse -Force
  Remove-Item -LiteralPath $ack -Force
  Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
  # An old VPN helper may keep files mapped; retain that backup rather than
  # affecting another process. It must not invalidate a confirmed installation.
  Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $PSCommandPath -Force
} catch {
  $failure = $_ | Out-String
  if ($moved -and !$committed) {
    try {
      if ($null -ne $newProcess -and !$newProcess.HasExited) {
        Stop-Process -Id $newProcess.Id -Force -ErrorAction Stop
        if (!$newProcess.WaitForExit(5000)) { throw 'Replacement process did not stop' }
      }
      if ($targetCreated) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop }
      [IO.Directory]::Move($backup, $target)
      $moved = $false
      Start-Process -FilePath (Join-Path $target 'XIO.exe') -WorkingDirectory $target | Out-Null
    } catch {
      # Never delete the original backup when rollback itself cannot complete.
      $failure += "`nRollback failed; original files retained: " + ($_ | Out-String)
    }
  }
  $failure | Set-Content -LiteralPath $errorFile -Encoding UTF8
}
''';
}

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
    final text = windowsUpdateScript(
      target: target,
      stage: stage.path,
      package: file.path,
      version: release.version,
      build: release.build,
      parentPid: pid,
    );
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
