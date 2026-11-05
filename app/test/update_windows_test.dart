import 'dart:convert';
import 'dart:io';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/update_installer.dart';

Archive bundle(String prefix) => Archive()
  ..add(ArchiveFile.string('${prefix}XIO.exe', 'exe'))
  ..add(ArchiveFile.string('${prefix}flutter_windows.dll', 'engine'))
  ..add(ArchiveFile.string('${prefix}data/app.so', 'aot'));

void main() {
  for (final prefix in ['', 'XIO/']) {
    test(
      'normalizes a complete ${prefix.isEmpty ? 'flat' : 'nested'} bundle',
      () async {
        final dir = await Directory.systemTemp.createTemp('xio-layout-');
        addTearDown(() => dir.delete(recursive: true));
        final archive = bundle(prefix)
          ..add(ArchiveFile.directory('${prefix}data/'));
        if (prefix.isNotEmpty) archive.add(ArchiveFile.directory(prefix));
        final source = File('${dir.path}/input.zip')
          ..writeAsBytesSync(ZipEncoder().encode(archive));
        extractWindowsUpdate(source.path, '${dir.path}/out');
        expect(File('${dir.path}/out/XIO/XIO.exe').readAsStringSync(), 'exe');
        expect(
          File('${dir.path}/out/XIO/data/app.so').readAsStringSync(),
          'aot',
        );
        expect(
          File('${dir.path}/out/XIO/flutter_windows.dll').readAsStringSync(),
          'engine',
        );
      },
    );

    for (final bad in [
      '../escape',
      'data//alias',
      '/absolute',
      'data/./alias',
      'data/aux.txt',
      'data/com1.bin',
      'data/name.',
      'data/name ',
      'data/bad?name',
      'data/bad|name',
      'data/bad<name',
      'data/a:stream',
      'data\\escape',
    ]) {
      test(
        'rejects ${prefix.isEmpty ? 'flat' : 'nested'} path $bad before writing',
        () async {
          final dir = await Directory.systemTemp.createTemp('xio-invalid-');
          addTearDown(() => dir.delete(recursive: true));
          final rawName = '$prefix$bad';
          // ArchiveFile itself normalizes backslashes. Change equal-length ZIP
          // header names after encoding, leaving compressed content/CRC intact.
          final encodedName = rawName.replaceAll('\\', '~');
          final archive = bundle(prefix)
            ..add(ArchiveFile.string(encodedName, 'bad'));
          final bytes = ZipEncoder().encode(archive);
          if (encodedName != rawName) {
            final from = utf8.encode(encodedName), to = utf8.encode(rawName);
            var replaced = 0;
            for (var i = 0; i <= bytes.length - from.length; i++) {
              if (List.generate(from.length, (j) => bytes[i + j]).join(',') ==
                  from.join(',')) {
                bytes.setRange(i, i + to.length, to);
                replaced++;
              }
            }
            expect(replaced, 2, reason: 'local and central ZIP name headers');
          }
          final source = File('${dir.path}/input.zip')..writeAsBytesSync(bytes);
          expect(
            () => extractWindowsUpdate(source.path, '${dir.path}/out'),
            throwsFormatException,
          );
          expect(Directory('${dir.path}/out').existsSync(), isFalse);
        },
      );
    }
  }

  for (final conflict in [
    'mixed',
    'file-parent',
    'directory-alias',
    'case-alias',
    'symlink',
    'incomplete',
  ]) {
    test('rejects $conflict before writing', () async {
      final dir = await Directory.systemTemp.createTemp('xio-conflict-');
      addTearDown(() => dir.delete(recursive: true));
      final archive = bundle('');
      switch (conflict) {
        case 'mixed':
          archive.add(ArchiveFile.string('XIO/XIO.exe', 'other'));
        case 'file-parent':
          archive.add(ArchiveFile.string('data', 'file'));
        case 'directory-alias':
          archive.add(ArchiveFile.directory('data'));
          archive.add(ArchiveFile.directory('data/'));
        case 'case-alias':
          archive.add(ArchiveFile.string('DATA/APP.SO', 'other'));
        case 'symlink':
          archive.add(
            ArchiveFile.string('link', '/tmp')
              ..symbolicLink = '/tmp'
              ..mode = 0xa1ff,
          );
        case 'incomplete':
          archive.removeFile(archive.findFile('flutter_windows.dll')!);
      }
      final source = File('${dir.path}/input.zip')
        ..writeAsBytesSync(ZipEncoder().encode(archive));
      expect(
        () => extractWindowsUpdate(source.path, '${dir.path}/out'),
        throwsFormatException,
      );
      expect(Directory('${dir.path}/out').existsSync(), isFalse);
    });
  }

  test('Windows transaction script quotes paths and requires a fresh version ACK', () async {
    final script = windowsUpdateScript(
      target: "C:/Тест [x]/XIO's",
      stage: 'C:/staging/unpacked',
      package: 'C:/staging/release.zip',
      version: '0.24.3',
      build: 5020,
      parentPid: 123,
    );
    expect(script, contains("\$target = 'C:/Тест [x]/XIO''s'"));
    expect(script, contains('[IO.Directory]::Move(\$backup, \$target)'));
    expect(script, contains('[IO.File]::ReadAllText(\$ack) -ceq \$version'));
    expect(
      script.indexOf('Remove-Item -LiteralPath \$ack'),
      lessThan(script.indexOf('[IO.Directory]::Move(\$target')),
    );
    expect(script, contains('Stop-Process -Id \$newProcess.Id'));
    expect(script, contains('if (\$moved -and !\$committed)'));
    expect(
      () => windowsUpdateScript(
        target: 'x',
        stage: 'x',
        package: 'x',
        version: 'x',
        build: 1,
        parentPid: 1,
        startupTimeoutSeconds: 0,
      ),
      throwsArgumentError,
    );

    // Export the exact production generator output for the Windows PowerShell
    // transaction harness. Launches are mocked there; no unsigned app is run.
    final export = Platform.environment['XIO_WINDOWS_SCRIPT_EXPORT'];
    final root = Platform.environment['XIO_WINDOWS_TEST_ROOT'];
    if (export != null && root != null) {
      await File(export).writeAsString(
        '\ufeff${windowsUpdateScript(target: '$root/target', stage: '$root/stage', package: '$root/release.zip', version: '0.24.3', build: 5020, parentPid: 424242, startupTimeoutSeconds: 1)}',
      );
    }
  });

  final releaseDir = Platform.environment['XIO_RELEASE_DIR'];
  test(
    'extracts the real published flat Windows ZIP',
    () async {
      final dir = await Directory.systemTemp.createTemp('xio-real-windows-');
      addTearDown(() => dir.delete(recursive: true));
      extractWindowsUpdate(
        '$releaseDir/XIO-Full-0.24.2-windows-x64.zip',
        dir.path,
      );
      expect(File('${dir.path}/XIO/XIO.exe').lengthSync(), greaterThan(0));
      expect(File('${dir.path}/XIO/data/app.so').lengthSync(), greaterThan(0));
    },
    skip: releaseDir == null
        ? 'set XIO_RELEASE_DIR to the release assets'
        : false,
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
