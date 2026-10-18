import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/main.dart';

void main() {
  testWidgets(
    'tile addition reports cancellation, success and legacy manual flow',
    (tester) async {
      var result = 0;
      final calls = <String>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(native, (MethodCall call) async {
            calls.add(call.method);
            return result;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(native, null),
      );
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: SingleChildScrollView(child: AndroidControls())),
        ),
      );
      await tester.tap(find.text('Добавить плитку XIO'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Добавление отменено'), findsOneWidget);
      result = 2;
      await tester.tap(find.text('Добавить плитку XIO'));
      await tester.pumpAndSettle();
      expect(find.text('Плитка XIO добавлена.'), findsOneWidget);
      result = -1;
      await tester.tap(find.text('Добавить плитку XIO'));
      await tester.pumpAndSettle();
      expect(find.textContaining('перетащите XIO VPN'), findsOneWidget);
      await tester.tap(find.text('Настройки уведомлений'));
      await tester.pumpAndSettle();
      expect(calls, [
        'addQuickTile',
        'addQuickTile',
        'addQuickTile',
        'notificationSettings',
      ]);
      expect(tester.takeException(), isNull);
    },
  );
}
