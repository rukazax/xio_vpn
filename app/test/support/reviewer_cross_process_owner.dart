import 'dart:io';

import 'reviewer_dart_runtime.dart';

/// Cross-process lock probe used by the reviewer config-owner fixture.
///
/// A real child Dart process attempts `.document-writer.lock`. Exit 73 means
/// the OS lock is held (BUSY); 0 means it acquired it. Only the supported OS
/// lock-contention errors are mapped to BUSY. Status/stdout are emitted only
/// after all owned file resources have been cleaned up; any open, unlock or
/// close failure is 74 with stderr regardless of a pending BUSY/ACQUIRED.
Future<ProcessResult> child(
  Directory directory, {
  bool syntheticCloseFailure = false,
}) async {
  final script = File('${directory.path}/reviewer_lock_child.dart');
  await script.writeAsString(r'''
import 'dart:io';

bool busyCode(int? code) {
  if (Platform.isLinux) return code == 11 || code == 13;
  if (Platform.isMacOS) return code == 35 || code == 13;
  if (Platform.isWindows) return code == 32 || code == 33;
  return false;
}

void main(List<String> args) {
  final syntheticCloseFailure = args.contains('--synthetic-close-failure');
  RandomAccessFile? owned;
  String? cleanupError;
  String? pendingError;
  var pendingBusy = false;
  var acquired = false;

  // Detach ownership before the one close attempt: never retry a released
  // handle. The synthetic seam only induces a cleanup failure; it cannot
  // choose BUSY/ACQUIRED or bypass the real lock result.
  void closeOnce() {
    final file = owned;
    if (file == null) return;
    owned = null;
    try {
      file.closeSync();
      if (syntheticCloseFailure) {
        throw StateError('SYNTHETIC_AFTER_REAL_CLOSE_FAILURE');
      }
    } catch (error) {
      cleanupError = '$error';
    }
  }

  try {
    try {
      owned = File(args[0] + '/.document-writer.lock')
          .openSync(mode: FileMode.append);
    } catch (error) {
      stderr.writeln('OPEN_ERROR: $error');
      exitCode = 74;
      return;
    }
    try {
      owned!.lockSync(FileLock.exclusive);
      acquired = true;
    } on FileSystemException catch (error) {
      if (busyCode(error.osError?.errorCode)) {
        pendingBusy = true;
      } else {
        pendingError = 'LOCK_ERROR: $error';
      }
    } catch (error) {
      pendingError = 'LOCK_ERROR: $error';
    }
    if (acquired) {
      try {
        owned!.unlockSync();
      } catch (error) {
        cleanupError = '$error';
      }
    }
    closeOnce();
    if (cleanupError != null) {
      stderr.writeln('CLEANUP_ERROR: $cleanupError');
      exitCode = 74;
      return;
    }
    if (pendingError != null) {
      stderr.writeln(pendingError);
      exitCode = 74;
      return;
    }
    if (pendingBusy) {
      stdout.writeln('BUSY');
      exitCode = 73;
      return;
    }
    stdout.writeln('ACQUIRED');
  } catch (error) {
    closeOnce();
    if (cleanupError != null) {
      stderr.writeln('CLEANUP_ERROR: $cleanupError');
    } else {
      stderr.writeln('PROBE_ERROR: $error');
    }
    exitCode = 74;
  }
}
''');
  return ReviewerDartRuntime.resolve().run([
    script.path,
    directory.path,
    if (syntheticCloseFailure) '--synthetic-close-failure',
  ]);
}
