import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';

class CountingStore extends AppStore {
  int reads = 0;
  @override
  Future<void> refresh({bool fresh = false}) async {
    reads++;
  }
}

void main() {
  testWidgets(
    'UI lifecycle stops status polling in background and refreshes on resume',
    (tester) async {
      final store = CountingStore()..ready = true;
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump(const Duration(seconds: 9));
      expect(store.reads, greaterThanOrEqualTo(3));
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      final before = store.reads;
      await tester.pump(const Duration(seconds: 30));
      expect(store.reads, before);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(store.reads, before + 1);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
}
