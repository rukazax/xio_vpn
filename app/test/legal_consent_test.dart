import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/legal_record.dart';
import 'package:x1o/main.dart';

class MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

void main() {
  test('acknowledgement is versioned, timestamped and invalid records require review', () {
    final record = LegalRecord.acknowledge('displayed terms', 'ru');
    expect(record.current, isTrue);
    expect(
      LegalRecord.parse(jsonDecode(jsonEncode(record.toJson())))!.textSha256,
      record.textSha256,
    );
    for (final field in ['revision', 'timestamp', 'textSha256']) {
      final invalid = record.toJson()..[field] = 'invalid';
      expect(LegalRecord.parse(invalid), isNull);
    }
  });
  testWidgets(
    'first run needs two separate unchecked acknowledgements and persists receipt',
    (tester) async {
      final store = MemoryStore()
        ..ready = true
        ..enforceConsent = true;
      try {
        await tester.pumpWidget(X1oApp(store: store, requireConsent: true));
        await tester.pumpAndSettle();
        await tester.scrollUntilVisible(
          find.byKey(const ValueKey('legal-ack')),
          350,
          scrollable: find.byType(Scrollable).first,
        );
        final button = find.byKey(const ValueKey('ack-continue'));
        expect(tester.widget<FilledButton>(button).onPressed, isNull);
        await tester.tap(find.byKey(const ValueKey('legal-ack')));
        await tester.pump();
        await tester.ensureVisible(button);
        await tester.tap(button);
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 80)),
        );
        await tester.pumpAndSettle();
        expect(store.legalRecord?.current, isTrue);
        expect(store.consentReady, isFalse);
        await tester.scrollUntilVisible(
          find.byKey(const ValueKey('vpn-ack')),
          300,
          scrollable: find.byType(Scrollable).first,
        );
        expect(tester.widget<FilledButton>(button).onPressed, isNull);
        await tester.tap(find.byKey(const ValueKey('vpn-ack')));
        await tester.pump();
        await tester.ensureVisible(button);
        await tester.tap(button);
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 80)),
        );
        await tester.pumpAndSettle();
        expect(store.consentReady, isTrue);
        expect(find.byType(NavigationBar), findsOneWidget);
        final saved = jsonDecode(
          jsonEncode({
            'legalRecord': store.legalRecord!.toJson(),
            'vpnDisclosure': store.vpnDisclosure,
          }),
        ) as Map;
        expect(LegalRecord.parse(saved['legalRecord'])!.current, isTrue);
        expect(saved['vpnDisclosure'], vpnDisclosureRevision);
        expect(tester.takeException(), isNull);
      } finally {
        await tester.pumpWidget(const SizedBox());
        store.dispose();
      }
    },
  );
  test(
    'receipt persists in the ordinary app storage without changing GPL rights',
    () async {
      final dir = await Directory.systemTemp.createTemp('xio-legal-test-');
      final store = AppStore()..directory = dir;
      try {
        await store.acknowledgeLegal('displayed terms', 'ru');
        await store.acknowledgeVpn();
        final saved = jsonDecode(
          await File('${dir.path}/profiles.json').readAsString(),
        ) as Map;
        expect(LegalRecord.parse(saved['legalRecord'])!.current, isTrue);
        expect(saved['vpnDisclosure'], vpnDisclosureRevision);
      } finally {
        store.dispose();
        await dir.delete(recursive: true);
      }
    },
  );
  test('failed storage cannot acknowledge or unlock connection', () async {
    final store = AppStore()..enforceConsent = true;
    await expectLater(store.acknowledgeLegal('terms', 'ru'), throwsStateError);
    expect(store.legalRecord, isNull);
    expect(store.consentReady, isFalse);
    await expectLater(store.connect(), throwsStateError);
    store.dispose();
  });
}
