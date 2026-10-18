import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';

void main() {
  test('read-only inspection of the installed Tailscale service', () async {
    final dir = await Directory.systemTemp.createTemp('x1o-adapter-');
    final store = AppStore()..directory = dir;
    try {
      // addTailscale writes only x1o metadata and invokes `status --json`.
      // Never invoke connect/disconnect/setExitNode in this host-level test.
      await store.addTailscale('Local verification');
      await store.refresh();
      expect(store.status.active, isTrue);
      expect(store.status.state, contains('Mesh'));
      expect(store.selected?.protocol, 'tailscale');
    } finally {
      store.dispose();
      await dir.delete(recursive: true);
    }
  }, skip: !const bool.fromEnvironment('X1O_LIVE_TAILSCALE'));
}
