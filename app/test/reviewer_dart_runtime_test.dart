import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/store_writer_owner.dart';

import 'support/reviewer_cross_process_owner.dart' show child;
import 'support/reviewer_dart_runtime.dart'
    show ReviewerDartRuntime, diagnosticForProcess, isSupportedLockContention;

String _markExecutable(File file) {
  if (!Platform.isWindows) {
    final chmod = Process.runSync('chmod', ['755', file.path]);
    if (chmod.exitCode != 0) throw StateError('chmod failed: ${chmod.stderr}');
  }
  return file.resolveSymbolicLinksSync();
}

({String root, String native}) _actualRuntime() {
  final root = Platform.environment['FLUTTER_ROOT'];
  if (root == null || root.isEmpty) {
    throw StateError('FLUTTER_ROOT is required for the focused runtime tests');
  }
  final name = Platform.isWindows ? 'dart.exe' : 'dart';
  return (
    root: root,
    native: '$root/bin/cache/dart-sdk/bin/$name',
  );
}

void main() {
  test('explicit owned native Dart executable is accepted', () {
    final actual = _actualRuntime();
    final runtime = ReviewerDartRuntime.resolve(
      environment: {
        ReviewerDartRuntime.executableVariable: actual.native,
        ReviewerDartRuntime.rootVariable: actual.root,
      },
    );
    expect(runtime.executable, File(actual.native).resolveSymbolicLinksSync());
  });

  test('explicit Flutter root resolves its native Dart under the root', () {
    final root = Directory.systemTemp.createTempSync('reviewer-runtime-');
    addTearDown(() => root.deleteSync(recursive: true));
    final nativeName = Platform.isWindows ? 'dart.exe' : 'dart';
    final native = File('${root.path}/bin/cache/dart-sdk/bin/$nativeName')
      ..createSync(recursive: true)
      ..writeAsStringSync('#!/bin/sh\nexit 0\n');
    _markExecutable(native);
    final runtime = ReviewerDartRuntime.resolve(
      environment: {ReviewerDartRuntime.rootVariable: root.path},
    );
    expect(runtime.executable, native.resolveSymbolicLinksSync());
  });

  test('empty, missing and no-selector configurations fail closed', () {
    final actual = _actualRuntime();
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable: '',
          'FLUTTER_ROOT': actual.root,
        },
      ),
      throwsStateError,
    );
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable: actual.native,
          ReviewerDartRuntime.rootVariable: '',
        },
      ),
      throwsStateError,
    );
    expect(
      () => ReviewerDartRuntime.resolve(environment: const {}),
      throwsStateError,
    );
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {'FLUTTER_ROOT': ''},
      ),
      throwsStateError,
    );
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {ReviewerDartRuntime.executableVariable: 'dart'},
      ),
      throwsStateError,
    );
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable:
              '${Directory.current.path}/missing-dart',
        },
      ),
      throwsStateError,
    );
  });

  test('conflicting explicit/selected roots fail', () {
    final actual = _actualRuntime();
    final other = Directory.systemTemp.createTempSync('reviewer-root-other-');
    addTearDown(() => other.deleteSync(recursive: true));
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.rootVariable: actual.root,
          'FLUTTER_ROOT': other.path,
        },
      ),
      throwsStateError,
    );
  });

  test('explicit runtime outside selected root is rejected', () {
    final actual = _actualRuntime();
    final root = Directory.systemTemp.createTempSync('reviewer-runtime-own-');
    addTearDown(() => root.deleteSync(recursive: true));
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable: actual.native,
          ReviewerDartRuntime.rootVariable: root.path,
        },
      ),
      throwsStateError,
    );
  });

  test('bootstrap wrapper and non-executable text are not native Dart', () {
    final actual = _actualRuntime();
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable:
              '${actual.root}/bin/dart',
          ReviewerDartRuntime.rootVariable: actual.root,
        },
      ),
      throwsStateError,
    );
    final root = Directory.systemTemp.createTempSync('reviewer-runtime-text-');
    addTearDown(() => root.deleteSync(recursive: true));
    final text = File('${root.path}/not-executable')
      ..writeAsStringSync('ordinary text');
    expect(
      () => ReviewerDartRuntime.resolve(
        environment: {
          ReviewerDartRuntime.executableVariable: text.path,
          ReviewerDartRuntime.rootVariable: root.path,
        },
      ),
      throwsStateError,
    );
  });

  test('lock contention is narrow and diagnostics include stderr', () {
    expect(isSupportedLockContention(99), isFalse);
    final result = ProcessResult(1, 73, 'BUSY\n', 'lock detail\n');
    expect(diagnosticForProcess(result), contains('stderr="lock detail"'));
  });

  test('unexpected open failure is surfaced, not BUSY', () async {
    final directory = Directory.systemTemp.createTempSync('reviewer-probe-bad-');
    addTearDown(() => directory.deleteSync(recursive: true));
    Directory('${directory.path}/.document-writer.lock').createSync();
    final result = await child(directory);
    expect(result.exitCode, 74);
    expect(result.stdout.toString(), isNot(contains('BUSY')));
    expect(result.stderr.toString(), contains('OPEN_ERROR'));
    expect(diagnosticForProcess(result), contains('exit=74'));
  });

  test('timeout kills and reaps only the owned child', () async {
    final actual = _actualRuntime();
    final directory = Directory.systemTemp.createTempSync('reviewer-timeout-');
    addTearDown(() => directory.deleteSync(recursive: true));
    final script = File('${directory.path}/sleep.dart')
      ..writeAsStringSync(
        'import "dart:io"; void main() { sleep(Duration(seconds: 10)); }',
      );
    final runtime = ReviewerDartRuntime.resolve(
      environment: {
        ReviewerDartRuntime.executableVariable: actual.native,
        ReviewerDartRuntime.rootVariable: actual.root,
      },
    );
    await expectLater(
      runtime.run(
        [script.path],
        timeout: const Duration(milliseconds: 100),
      ),
      throwsA(isA<TimeoutException>()),
    );
  });

  test('pending BUSY is suppressed when cleanup fails', () async {
    final directory = Directory.systemTemp.createTempSync('reviewer-busy-cleanup-');
    final owner = await ProductStoreWriterOwner.acquire(directory);
    try {
      final result = await child(directory, syntheticCloseFailure: true);
      expect(result.exitCode, 74);
      expect(result.stdout.toString(), isNot(contains('BUSY')));
      expect(result.stderr.toString(), contains('CLEANUP_ERROR'));
      expect(result.stderr.toString(), contains('SYNTHETIC'));
    } finally {
      await owner.closeWhenSettled();
      if (directory.existsSync()) directory.deleteSync(recursive: true);
    }
  });

  test('pending ACQUIRED is suppressed when cleanup fails', () async {
    final directory = Directory.systemTemp.createTempSync('reviewer-acquired-cleanup-');
    addTearDown(() {
      if (directory.existsSync()) directory.deleteSync(recursive: true);
    });
    final result = await child(directory, syntheticCloseFailure: true);
    expect(result.exitCode, 74);
    expect(result.stdout.toString(), isNot(contains('ACQUIRED')));
    expect(result.stderr.toString(), contains('CLEANUP_ERROR'));
    expect(result.stderr.toString(), contains('SYNTHETIC'));
  });}
