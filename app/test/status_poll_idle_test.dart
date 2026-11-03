import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';

/// The workspace rebuilds on every [AppStore] notification, so a status poll
/// that reports an unchanged tunnel must stay silent. Before this guard the
/// 3 s poll rebuilt the whole shell 20 times a minute while idle.
void main() {
  testWidgets('an idle status poll does not notify listeners', (tester) async {
    final store = AppStore();
    store.ready = true;
    var notifications = 0;
    store.addListener(() => notifications++);

    store.setForeground(true);
    await tester.pump();
    expect(notifications, 0, reason: 'the first read changed nothing');

    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(seconds: 3));
    }
    expect(notifications, 0, reason: '15 s of idle polling must not repaint');

    store.dispose();
  });

  test('equal tunnel states compare equal', () {
    const a = TunnelStatus(active: true, state: 's', path: 'p', rx: 1, tx: 2);
    const b = TunnelStatus(active: true, state: 's', path: 'p', rx: 1, tx: 2);
    const c = TunnelStatus(active: true, state: 's', path: 'p', rx: 1, tx: 3);
    expect(a, b);
    expect(a.hashCode, b.hashCode);
    expect(a, isNot(c));
    expect(const TunnelStatus(), const TunnelStatus());
  });
}
