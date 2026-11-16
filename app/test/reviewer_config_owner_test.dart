import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/store_writer_owner.dart';

import 'support/reviewer_cross_process_owner.dart' show child;
import 'support/reviewer_dart_runtime.dart' show diagnosticForProcess;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('real Store admitted deleteConfig retains OS owner until native mutation settles', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    final dir = await Directory.systemTemp.createTemp('review-config-owner-');
    final entered = Completer<void>();
    final gate = Completer<void>();
    final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(native, (call) async {
      if (call.method == 'deleteConfig') {
        if (!entered.isCompleted) entered.complete();
        await gate.future;
      }
      return null;
    });
    final store = AppStore(nativeTunnelOverride: true)..directory = dir;
    ProductStoreWriterOwner? owner;
    Future<void>? release;
    Future<void>? pending;
    Object? error;
    var released = false;
    ProcessResult? before;
    ProcessResult? after;
    try {
      store.profiles.add(const Profile(
        id: 'p1',
        name: 'one',
        protocol: 'awg',
        endpoint: '192.0.2.1:51820',
      ));
      store.selectedId = 'p1';
      owner = await ProductStoreWriterOwner.acquire(dir);
      store.attachProductWriter(owner);
      pending = store.remove('p1').catchError((Object e) {
        error = e;
      });
      await entered.future;
      expect(store.documentMutationPending, true);
      store.dispose();
      release = owner.closeWhenSettled().then((_) {
        released = true;
      });
      before = await child(dir);
      if (before.exitCode != 73) {
        throw StateError(
          'Expected BUSY before settlement: ${diagnosticForProcess(before)}',
        );
      }
      final premature = released;
      gate.complete();
      await pending;
      await release;
      after = await child(dir);
      if (after.exitCode != 0) {
        throw StateError(
          'Expected ACQUIRED after settlement: ${diagnosticForProcess(after)}',
        );
      }
      print(
        'deleteConfig releaseBeforeGate=$premature '
        'childBefore=${before.exitCode}:${before.stdout} '
        'childAfter=${after.exitCode}:${after.stdout} '
        'completion=${error.runtimeType}',
      );
      expect(premature, false);
    } finally {
      if (!gate.isCompleted) gate.complete();
      try {
        await pending;
      } catch (_) {}
      try {
        await release;
      } catch (_) {}
      if (release == null && owner != null) {
        try {
          await owner.closeWhenSettled();
        } catch (_) {}
      }
      messenger.setMockMethodCallHandler(native, null);
      debugDefaultTargetPlatformOverride = null;
      if (dir.existsSync()) await dir.delete(recursive: true);
    }
  });
}
