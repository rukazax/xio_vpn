import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/build_identity.dart';
import 'package:xio/client_main.dart';
import 'package:xio/connection_attempt.dart';
import 'package:xio/connection_mode_ui.dart';
import 'package:xio/core.dart';
import 'package:xio/l10n.dart';
import 'package:xio/legal_record.dart';
import 'package:xio/main.dart';
import 'package:xio/store_mode_source.dart';
import 'package:xio/store_writer_owner.dart';

/// Real-Store integration of the mode control: actual `AppStore`, actual
/// document bytes on disk, actual blocker codes and the actual
/// `saveConnectionSettings(..., policy:)` publication through
/// [StoreConnectionModeSource].
///
/// Nothing here replaces a Store guard or synthesises an ACK. On a Linux test
/// host there is no native capability, so the Store's own authoritative
/// confirmation is `document` — never `native` — and the UI must show a stored
/// setting. Every confirmation assertion reads the Store getter, not a local
/// inference.
///
/// Real file IO and the cooperating product-store lock are started **inside**
/// `tester.runAsync`: the widget-test fake clock never advances real IO. The
/// lock is never bypassed — every store owns a real `ProductStoreWriterOwner`
/// acquired through the production path for its own temporary product directory.
///
/// Client surfaces exist only in the Client build:
///   flutter test --dart-define=XIO_CLIENT_ONLY=true test/policy_mode_ui_store_test.dart
class Harness {
  Harness._(this.directory, this.store, this.source, this.writer);

  final Directory directory;
  final AppStore store;
  final StoreConnectionModeSource source;
  final ProductStoreWriterOwner writer;

  static Future<Harness> create({String? policyJson}) async {
    final directory = await Directory.systemTemp.createTemp('xio-mode-store-');
    if (policyJson != null) {
      await File('${directory.path}/profiles.json')
          .writeAsString(policyJson, flush: true);
    }
    final writer = await ProductStoreWriterOwner.acquire(directory);
    final store = AppStore(nativeTunnelOverride: false)..directory = directory;
    store.attachProductWriter(writer);
    await store.load();
    // The 3-second status poll is a UI concern, not a test one.
    store.setForeground(false);
    // `load()` adopts the document language; keep the assertions in Russian.
    AppLanguages.set('ru');
    store
      ..ready = true
      ..legalRecord = LegalRecord.acknowledge('fixture terms', 'ru')
      ..vpnDisclosure = vpnDisclosureRevision;
    if (!store.profiles.any((p) => p.id == 'sel')) {
      store.profiles.add(
        const Profile(
          id: 'sel',
          name: 'fixture',
          protocol: 'awg',
          endpoint: '192.0.2.1:1',
        ),
      );
    }
    store.selectedId ??= 'sel';
    return Harness._(
      directory,
      store,
      StoreConnectionModeSource(store),
      writer,
    );
  }

  Future<Map<String, dynamic>> readDurable() async {
    final text = await File('${directory.path}/profiles.json').readAsString();
    return Map<String, dynamic>.from(jsonDecode(text) as Map);
  }

  Future<void> dispose() async {
    store.dispose();
    source.dispose();
    // A physical close may legitimately stay pending while admitted IO drains;
    // the harness must not hang on it.
    await writer
        .closeWhenSettled()
        .timeout(const Duration(seconds: 2), onTimeout: () {})
        .catchError((_) {});
    await directory.delete(recursive: true).catchError((_) => directory);
  }
}

/// A real-IO call whose outcome (value or error) is captured explicitly.
class RealCall<T> {
  T? value;
  Object? error;
}

/// Runs [body] on the real event loop. Real file IO started under the widget
/// test's fake clock never completes, so every Store publication, recovery call
/// and document read must start here.
Future<RealCall<T>> real<T>(
  WidgetTester tester,
  Future<T> Function() body,
) async {
  final result = RealCall<T>();
  await tester.runAsync(() async {
    try {
      result.value = await body();
    } catch (error) {
      result.error = error;
    }
  });
  return result;
}

String t(String value) => AppLanguages.text(value);

const draftKey = ValueKey('connection-mode-draft');
const saveKey = ValueKey('connection-settings-save');
const repairKey = ValueKey('connection-mode-repair');
const retryKey = ValueKey('connection-mode-retry');

Future<void> openFull(WidgetTester tester, Harness harness) async {
  await tester.pumpWidget(
    XioApp(store: harness.store, modeSource: harness.source),
  );
  await tester.pumpAndSettle();
  await tester.tap(find.byType(NavigationDestination).at(1));
  await tester.pumpAndSettle();
  final tile = find
      .descendant(
        of: find.byType(ListTile),
        matching: find.text(t('Настройка соединений')),
      )
      .hitTestable();
  await tester.ensureVisible(tile);
  await tester.tap(tile);
  await tester.pumpAndSettle();
}

Future<void> openClient(WidgetTester tester, Harness harness) async {
  await tester.pumpWidget(
    ClientApp(store: harness.store, modeSource: harness.source),
  );
  await tester.pumpAndSettle();
  final button = find.text(t('Проверка соединения'));
  await tester.scrollUntilVisible(
    button,
    120,
    scrollable: find.byType(Scrollable).first,
  );
  await tester.pumpAndSettle();
  await tester.tap(button);
  await tester.pumpAndSettle();
}

Future<void> draftMode(WidgetTester tester, ConnectionPolicy policy) async {
  final picker = find.byKey(draftKey);
  await tester.ensureVisible(picker);
  await tester.tap(picker);
  await tester.pumpAndSettle();
  await tester.tap(find.text(t(ConnectionModeText.label(policy))).last);
  await tester.pumpAndSettle();
}

bool draftEnabled(WidgetTester tester) =>
    tester
        .widget<DropdownButtonFormField<ConnectionPolicy>>(find.byKey(draftKey))
        .onChanged !=
    null;

bool saveEnabled(WidgetTester tester) =>
    tester.widget<FilledButton>(find.byKey(saveKey)).onPressed != null;

void sizeSurface(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

/// Closes the harness on the real event loop and removes its temp directory.
Future<void> closeHarness(WidgetTester tester, Harness harness) async {
  await tester.pumpWidget(const SizedBox());
  await real(tester, harness.dispose);
}

void scenariosFor({
  required String product,
  required Future<void> Function(WidgetTester, Harness) open,
}) {
  testWidgets('$product: real Store shows a stored setting, not a receipt', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    // The authoritative Store getters are the only confirmation oracle here.
    expect(harness.store.connectionModeConfirmed, isFalse);
    expect(
      harness.store.connectionModeConfirmation,
      anyOf(
        ConnectionModeConfirmation.document,
        ConnectionModeConfirmation.legacyAutomatic,
      ),
    );
    await open(tester, harness);
    expect(find.byType(ConnectionModeControl), findsOneWidget);
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    expect(
      find.text(t(ConnectionModeText.storedSettingNotice)),
      findsOneWidget,
    );
    await closeHarness(tester, harness);
  });

  testWidgets('$product: adapter publishes the real durable mode', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    await open(tester, harness);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    expect(harness.store.connectionPolicy, ConnectionPolicy.automatic);
    // One real owned publication through the production adapter.
    final saved = await real(
      tester,
      () => harness.source.saveConnectionSettings(
        harness.store.checkSite,
        harness.store.priorityProtocol,
        policy: ConnectionPolicy.selectedOnly,
      ),
    );
    expect(saved.error, isNull);
    expect(harness.store.connectionPolicy, ConnectionPolicy.selectedOnly);
    final durable = await real(tester, harness.readDurable);
    final policy = durable.value!['connectionPolicy'] as Map<String, dynamic>;
    expect(policy['mode'], 'selectedOnly');
    expect(policy['roundMillis'], 30000);
    // No native capability on this host: the Store says document, not native.
    expect(harness.store.connectionModeConfirmed, isFalse);
    expect(
      harness.store.connectionModeConfirmation,
      ConnectionModeConfirmation.document,
    );
    await tester.pumpAndSettle();
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    await closeHarness(tester, harness);
  });

  testWidgets('$product: publication notifies at acquisition', (tester) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    await open(tester, harness);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    // The Store notifies when the publication acquires its owner, not only on
    // success: a listener must observe pending before the write settles.
    var sawPending = false;
    void watch() {
      if (harness.store.connectionModePending) sawPending = true;
    }

    harness.store.addListener(watch);
    final saved = await real(
      tester,
      () => harness.source.saveConnectionSettings(
        harness.store.checkSite,
        harness.store.priorityProtocol,
        policy: ConnectionPolicy.selectedOnly,
      ),
    );
    harness.store.removeListener(watch);
    expect(saved.error, isNull);
    expect(sawPending, isTrue);
    // After settlement the stored setting is shown, never a native badge.
    await tester.pumpAndSettle();
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    await closeHarness(tester, harness);
  });

  testWidgets('$product: active connection blocks with the Store code', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    await open(tester, harness);
    harness.store
      ..status = const TunnelStatus(active: true)
      ..changed();
    await tester.pumpAndSettle();
    expect(harness.store.canChangeConnectionMode, isFalse);
    // A live tunnel is `connected`, not `busy`: the remedy is disconnecting,
    // and the sentence must say so instead of naming an operation that ran.
    expect(harness.store.connectionPolicyError, 'connected');
    expect(
      find.text(t(ConnectionModeText.blocker('connected'))),
      findsOneWidget,
    );
    expect(find.text(t(ConnectionModeText.blocker('busy'))), findsNothing);
    expect(draftEnabled(tester), isFalse);
    expect(saveEnabled(tester), isFalse);
    // The Store refuses the same attempt with its own code.
    final refused = await real(
      tester,
      () => harness.source.saveConnectionSettings(
        harness.store.checkSite,
        harness.store.priorityProtocol,
        policy: ConnectionPolicy.selectedOnly,
      ),
    );
    expect(refused.error, isA<PolicyFailure>());
    expect((refused.error! as PolicyFailure).code, 'POLICY_BUSY');
    expect(harness.store.connectionPolicy, ConnectionPolicy.automatic);
    // Controller-local preflight code is localized, never the English text.
    final oversize = ConnectionModeText.saveFailure(
      const PolicyFailure(
        'POLICY_OVERSIZE',
        'Document bytes are empty or exceed the validation bound',
      ),
    );
    expect(oversize, isNot(contains('exceed')));
    expect(oversize, contains('объём'));
    await closeHarness(tester, harness);
  });

  testWidgets('$product: an owned write blocks with persistence', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    await open(tester, harness);
    // An explicit owner ticket stands in for a queued ordinary write; the real
    // admission gate reports the blocker and nothing is bypassed.
    final ticket = harness.store.beginOwnedDocumentMutation();
    harness.store.changed();
    await tester.pumpAndSettle();
    expect(harness.store.connectionPolicyError, 'persistence');
    expect(
      find.text(t(ConnectionModeText.blocker('persistence'))),
      findsOneWidget,
    );
    expect(saveEnabled(tester), isFalse);
    harness.store.releaseOwnedDocumentMutation(ticket);
    harness.store.changed();
    await tester.pumpAndSettle();
    expect(harness.store.connectionPolicyError, isNull);
    expect(saveEnabled(tester), isTrue);
    await closeHarness(tester, harness);
  });

  testWidgets('$product: corrupt durable policy needs explicit repair', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(
      tester,
      () => Harness.create(
        policyJson: jsonEncode({
          'schema': 2,
          'connectionPolicy': {'mode': 'broken'},
          'profiles': [
            {
              'id': 'sel',
              'name': 'fixture',
              'protocol': 'awg',
              'endpoint': '192.0.2.1:1',
            },
          ],
          'selected': 'sel',
        }),
      ),
    );
    final harness = created.value!;
    // Malformed bytes are preserved and block admission.
    expect(harness.store.connectionPolicyError, 'corrupt');
    expect(harness.store.connectionModeConfirmed, isFalse);
    expect(
      harness.store.connectionModeConfirmation,
      ConnectionModeConfirmation.none,
    );
    await open(tester, harness);
    expect(find.text(t(ConnectionModeText.blocker('corrupt'))), findsOneWidget);
    expect(find.byKey(repairKey), findsOneWidget);
    // The explicit repair takes the drafted replacement mode, so the draft is
    // editable while publishing stays blocked.
    expect(draftEnabled(tester), isTrue);
    expect(saveEnabled(tester), isFalse);
    // Explicit recovery through the real Store, with an explicit choice.
    final repaired = await real(
      tester,
      () =>
          harness.source.repairConnectionPolicy(ConnectionPolicy.selectedOnly),
    );
    expect(repaired.error, isNull);
    expect(harness.store.connectionPolicy, ConnectionPolicy.selectedOnly);
    expect(harness.store.connectionPolicyError, isNull);
    final durable = await real(tester, harness.readDurable);
    expect(
      (durable.value!['connectionPolicy'] as Map<String, dynamic>)['mode'],
      'selectedOnly',
    );
    // Repaired document is still not a native ACK.
    expect(harness.store.connectionModeConfirmed, isFalse);
    await tester.pumpAndSettle();
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    await closeHarness(tester, harness);
  });

  testWidgets('$product: reconciliation retry refuses a missing document', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final created = await real(tester, Harness.create);
    final harness = created.value!;
    await open(tester, harness);
    // The retry action is offered only for the blockers it can settle.
    expect(find.byKey(retryKey), findsNothing);
    final empty = await real(
      tester,
      () => Directory.systemTemp.createTemp('xio-mode-empty-'),
    );
    final directory = empty.value!;
    final opened = await real(tester, () async {
      final writer = await ProductStoreWriterOwner.acquire(directory);
      final store = AppStore(nativeTunnelOverride: false)
        ..directory = directory;
      store.attachProductWriter(writer);
      await store.load();
      store.setForeground(false);
      return store;
    });
    final store = opened.value!;
    final retried = await real(tester, store.retryPolicyReconciliation);
    expect(retried.error, isA<PolicyFailure>());
    final failure = retried.error! as PolicyFailure;
    expect(failure.code, 'POLICY_UNKNOWN');
    // The UI maps the code, never the Store's English diagnostic.
    expect(
      ConnectionModeText.saveFailure(failure),
      t(ConnectionModeText.blocker('reconcileRequired')),
    );
    expect(failure.message, isNot(t(ConnectionModeText.saveFailure(failure))));
    await real(tester, () async {
      store.dispose();
      await directory.delete(recursive: true).catchError((_) => directory);
    });
    await closeHarness(tester, harness);
  });

  // Core F2 sequencing, exactly as the lock contract requires: a logical
  // dispose never blocks, a physical close stays pending while admitted IO
  // drains, a second controller (child) is refused until release, and only then
  // is the lock acquired. Never await the close before the admitted IO settles.
  testWidgets('$product: controller lock release follows admitted IO', (
    tester,
  ) async {
    final directory = (await real(
      tester,
      () => Directory.systemTemp.createTemp('xio-mode-lock-'),
    )).value!;
    final first = await real(
      tester,
      () => ProductStoreWriterOwner.acquire(directory),
    );
    final writer = first.value!;
    final opened = await real(tester, () async {
      final store = AppStore(nativeTunnelOverride: false)
        ..directory = directory;
      store.attachProductWriter(writer);
      await store.load();
      store.setForeground(false);
      return store;
    });
    final store = opened.value!;
    expect(store.productWriter, isNotNull);

    // One admitted physical IO that drains later (the "native publication").
    // It must be admitted on the real event loop: its completion callbacks (and
    // the writer's release chain) inherit the zone that admitted it.
    final gate = Completer<void>();
    late Future<void> admitted;
    await real(tester, () async {
      admitted = writer.io(() => gate.future);
    });

    // Logical dispose must return immediately: the physical lock is still held
    // because admitted IO has not settled.
    store.dispose();
    expect(writer.acceptsWrites, isFalse);
    var closed = false;
    final close = writer.closeWhenSettled()..whenComplete(() => closed = true);
    await real(
      tester,
      () => Future<void>.delayed(const Duration(milliseconds: 60)),
    );
    expect(closed, isFalse);

    // Child BUSY: a second controller cannot acquire while the lock is held.
    final busy = await real(
      tester,
      () => ProductStoreWriterOwner.acquire(directory),
    );
    expect(busy.error, isA<StateError>());

    // Release the admitted IO ON the real event loop: completing it under the
    // fake clock would strand the release chain's file IO.
    await real(tester, () async {
      gate.complete();
      await admitted;
    });
    await real(tester, () => close);
    expect(closed, isTrue);

    // Child ACQUIRED: the successor owns the same store.
    final successor = await real(
      tester,
      () => ProductStoreWriterOwner.acquire(directory),
    );
    expect(successor.error, isNull);
    await real(tester, () async {
      await successor.value!.closeWhenSettled();
      await directory.delete(recursive: true).catchError((_) => directory);
    });
    await tester.pumpWidget(const SizedBox());
  });

  test('$product: each product owns a distinct canonical store directory', () {
    // Full and Client must not contend for one lock: the identity is the
    // compile-time product, and the lock key is that directory.
    final name = desktopProductDirectory(windows: Platform.isWindows);
    expect(name, clientOnlyBuild ? 'app.xio.client' : 'app.xio.xio');
  });
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(AppLanguages.load);
  setUp(() => AppLanguages.set('ru'));
  tearDown(() => AppLanguages.set(null));

  if (clientOnlyBuild) {
    scenariosFor(product: 'Client', open: openClient);
  } else {
    scenariosFor(product: 'Full', open: openFull);
  }
}
