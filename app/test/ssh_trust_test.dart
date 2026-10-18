import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/core.dart';
import 'package:x1o/workspace_ui.dart';

void main() {
  late Directory directory;
  late File file;
  final first = 'SHA256:${'a' * 43}';
  final changed = 'SHA256:${'b' * 43}';
  const target = SshTarget('HOST.example', 22, 'root');
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('x1o-ssh-trust-');
    file = File('${directory.path}/known.json');
  });
  tearDown(() async => directory.delete(recursive: true));

  test(
    'first key persists and reconnect works across instances and users',
    () async {
      await SshHostKeyStore(file).verify(target, first);
      expect(jsonDecode(await file.readAsString()), {
        '[host.example]:22': first,
      });
      await SshHostKeyStore(file)
          .verify(const SshTarget('host.example', 22, 'admin'), first);
      await expectLater(
        SshHostKeyStore(file).verify(target, changed),
        throwsFormatException,
      );
      expect(jsonDecode(await file.readAsString()), {
        '[host.example]:22': first,
      });
      await SshHostKeyStore(file)
          .verify(const SshTarget('host.example', 2222, 'root'), changed);
      expect((jsonDecode(await file.readAsString()) as Map).length, 2);
    },
  );
  test('concurrent first contacts never overwrite each other', () async {
    final results = await Future.wait([
      SshHostKeyStore(file).verify(target, first).then((_) => true),
      SshHostKeyStore(file)
          .verify(target, changed)
          .then((_) => true, onError: (_) => false),
    ]);
    expect(results, [true, false]);
    expect(jsonDecode(await file.readAsString()), {'[host.example]:22': first});
  });
  test('corrupt trust store fails closed and is not overwritten', () async {
    for (final bad in ['{', '[]', '{"host":42}', '{"host":"bad"}']) {
      await file.writeAsString(bad);
      await expectLater(
        SshHostKeyStore(file).verify(target, first),
        throwsFormatException,
      );
      expect(await file.readAsString(), bad);
    }
  });
  test(
    'write failure refuses trust and does not poison later attempts',
    () async {
      await Directory('${file.path}.tmp').create();
      await expectLater(
        SshHostKeyStore(file).verify(target, first),
        throwsFormatException,
      );
      expect(await file.exists(), isFalse);
      await Directory('${file.path}.tmp').delete();
      await SshHostKeyStore(file).verify(target, first);
    },
  );
  testWidgets(
    'VPS setup needs address and credentials without fingerprint field',
    (tester) async {
      final store = AppStore();
      await tester.pumpWidget(
        MaterialApp(home: ManagedAdminDialog(store: store)),
      );
      await tester.pumpAndSettle();
      expect(find.text('IP / домен VPS'), findsOneWidget);
      expect(find.text('SSH-пароль (сохраняется защищённо)'), findsOneWidget);
      expect(find.text('Доверенный SSH-отпечаток'), findsNothing);
      expect(find.textContaining('ssh-keygen'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      store.dispose();
    },
  );
}
