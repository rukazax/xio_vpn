import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';

class _Store extends AppStore {
  String? forgotten;
  @override
  Future<void> forgetServer(String id) async {
    forgotten = id;
    servers.removeWhere((s) => s.id == id);
    notifyListeners();
  }
}

void main() {
  testWidgets(
    'local deletion needs confirmation, no SSH and preserves remote choice',
    (tester) async {
      final store = _Store()
        ..servers.add(
          ManagedServer(id: 's', host: 'vpn.example', name: 'Test VPS'),
        );
      await tester.pumpWidget(X1oApp(store: store));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(NavigationDestination).at(1));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Серверы'));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();
      expect(find.text('Удалить XIO VPN с сервера'), findsOneWidget);
      await tester.tap(find.text('Удалить из приложения'));
      await tester.pumpAndSettle();
      expect(store.forgotten, isNull);
      expect(find.text('Удалить сервер из приложения?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Удалить'));
      await tester.pumpAndSettle();
      expect(store.forgotten, 's');
      expect(find.textContaining('Test VPS'), findsNothing);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
}
