import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

class ScreenGateStore extends AppStore {
  final firstSave = Completer<void>();
  final secondSave = Completer<void>();
  int writes = 0;
  @override
  Future<void> save() async {
    writes++;
    if (writes == 1) await firstSave.future;
    if (writes == 2) await secondSave.future;
  }
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(native, (_) async => null);
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(native, null);
  });
  test('actual Store counts both queued screen intents before bodies run', () async {
    final store = ScreenGateStore();
    final first = store.setAllowScreenshots(true);
    final second = store.setAllowScreenshots(false);
    expect(store.documentMutationPending, isTrue);
    await Future<void>.delayed(Duration.zero);
    expect(store.writes, 1);
    store.firstSave.complete();
    await first;
    expect(store.documentMutationPending, isTrue);
    store.secondSave.complete();
    await second;
    expect(store.documentMutationPending, isFalse);
    expect(store.allowScreenshots, isFalse);
    store.dispose();
  });
  test('dispose revokes logical admission without releasing physical queue early', () async {
    final store = ScreenGateStore();
    final first = store.setAllowScreenshots(true);
    await Future<void>.delayed(Duration.zero);
    store.dispose();
    expect(store.documentMutationPending, isTrue);
    store.firstSave.complete();
    await first;
    expect(store.documentMutationPending, isFalse);
    await expectLater(store.withDocumentMutation(() async {}), throwsStateError);
  });
}
