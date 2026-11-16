import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/store_writer_owner.dart';

/// Corrected physical-ownership oracle (supersedes the legacy reviewer F2
/// sequencing: that fixture awaited closeWhenSettled before releasing a gated
/// native commit, which cannot be satisfied by a correct OS-lock invariant).
///
/// A real child Dart process attempts the same file lock, so this is a genuine
/// cross-process check, not only the in-process cooperating claim.
import 'support/reviewer_cross_process_owner.dart' show child;
import 'support/reviewer_dart_runtime.dart' show diagnosticForProcess;

Future<String> externalLockProbe(Directory directory) async {
  final result = await child(directory);
  final out = result.stdout.toString().trim();
  if (result.exitCode == 0 && out == 'ACQUIRED') return 'ACQUIRED';
  if (result.exitCode == 73 && out == 'BUSY') return 'BUSY';
  throw StateError('Lock probe failed: ${diagnosticForProcess(result)}');
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('cross-process lock is held until native publication settles', () async {
    final directory = await Directory.systemTemp.createTemp('writer-owner-');
    addTearDown(() async {
      if (directory.existsSync()) await directory.delete(recursive: true);
    });
    final owner = await ProductStoreWriterOwner.acquire(directory);
    final entered = Completer<void>();
    final gate = Completer<void>();
    var released = false;
    final hold = owner.native(() async {
      if (!entered.isCompleted) entered.complete();
      await gate.future;
    });
    await entered.future;
    final release = owner.closeWhenSettled();
    unawaited(release.whenComplete(() => released = true));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    try {
      // Dispose is logical/non-blocking, but the physical settlement is pending.
      expect(released, isFalse);
      // Another real process cannot take the OS lock while native IO is out.
      expect(await externalLockProbe(directory), 'BUSY');
      // A second controller in this process is refused for the same span.
      await expectLater(
        ProductStoreWriterOwner.acquire(directory),
        throwsA(isA<StateError>()),
      );
      // New native admissions after closing are rejected, outstanding drains.
      await expectLater(owner.native(() async {}), throwsA(isA<StateError>()));
    } finally {
      if (!gate.isCompleted) gate.complete();
      try {
        await hold;
      } catch (_) {}
      try {
        await release;
      } catch (_) {}
    }
    // Only after file+native settlement does the lock admit a successor.
    expect(await externalLockProbe(directory), 'ACQUIRED');
    final successor = await ProductStoreWriterOwner.acquire(directory);
    await successor.closeWhenSettled();
  });

  test('file IO alone keeps the lock; file and native must both settle',
      () async {
    final directory = await Directory.systemTemp.createTemp('writer-owner-');
    addTearDown(() async {
      if (directory.existsSync()) await directory.delete(recursive: true);
    });
    final owner = await ProductStoreWriterOwner.acquire(directory);
    final ioGate = Completer<void>();
    final ioEntered = Completer<void>();
    unawaited(owner.io(() async {
      if (!ioEntered.isCompleted) ioEntered.complete();
      await ioGate.future;
    }));
    await ioEntered.future;
    final release = owner.closeWhenSettled();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    try {
      expect(await externalLockProbe(directory), 'BUSY');
    } finally {
      if (!ioGate.isCompleted) ioGate.complete();
      try {
        await release;
      } catch (_) {}
    }
    expect(await externalLockProbe(directory), 'ACQUIRED');
  });
}
