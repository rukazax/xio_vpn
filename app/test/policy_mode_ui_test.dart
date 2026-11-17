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
import 'package:xio/policy_publication.dart';

/// UI-contract coverage of the durable connection-mode control with a
/// test-local source. Real-Store navigation, guards, ACKs and recovery are
/// covered separately by `policy_mode_ui_store_test.dart`; this file never
/// replaces a Store guard or synthesises an ACK.
///
/// The fake uses the **real** `PolicyFailure` / `PublicationFailure` types, so
/// the UI's type matching is exercised, not a duck-typed imitation.
///
/// Client surfaces exist only in the Client build (`XIO_CLIENT_ONLY=true`):
///   flutter test --dart-define=XIO_CLIENT_ONLY=true test/policy_mode_ui_test.dart
class FakeModeSource extends ChangeNotifier implements ConnectionModeSource {
  FakeModeSource();

  ConnectionPolicy committed = ConnectionPolicy.automatic;
  ConnectionModeConfirmation confirmation = ConnectionModeConfirmation.native;
  bool pending = false;
  bool canChange = true;
  String? blocker;
  bool usable = true;

  /// Exact failure the Store would throw after the document write.
  Object? failAfterWrite;

  /// Exact failure the Store would throw before anything is renamed.
  Object? failBeforeWrite;

  /// When set, the save future waits for it before acknowledging.
  Completer<void>? gate;

  /// Every policy the widget asked to persist, in order.
  final List<ConnectionPolicy> saved = [];
  int repairs = 0;
  int retries = 0;
  Object? actionFailure;

  /// When set, a recovery action stays in flight until it completes.
  Completer<void>? actionGate;

  @override
  ConnectionPolicy get connectionPolicy => committed;

  @override
  ConnectionModeConfirmation get connectionModeConfirmation => confirmation;

  @override
  bool get connectionModeConfirmed =>
      confirmation == ConnectionModeConfirmation.native;

  @override
  bool get connectionModePending => pending;

  @override
  bool get canChangeConnectionMode => canChange && blocker == null && !pending;

  @override
  String? get connectionPolicyError => blocker;

  @override
  bool get selectedProfileUsable => usable;

  @override
  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    required ConnectionPolicy policy,
  }) async {
    if (!canChangeConnectionMode) {
      throw const PolicyFailure('POLICY_BUSY', 'fixture: guard refused');
    }
    saved.add(policy);
    if (failBeforeWrite != null) {
      // `begin` may already have fenced READY even if the rename never happened.
      if (failBeforeWrite is PublicationFailure) {
        confirmation = ConnectionModeConfirmation.none;
      }
      notifyListeners();
      throw failBeforeWrite!;
    }
    pending = true;
    notifyListeners();
    await (gate?.future ?? Future<void>.value());
    if (failAfterWrite != null) {
      pending = false;
      confirmation = ConnectionModeConfirmation.none;
      notifyListeners();
      throw failAfterWrite!;
    }
    committed = policy;
    confirmation = ConnectionModeConfirmation.native;
    pending = false;
    notifyListeners();
  }

  @override
  Future<void> repairConnectionPolicy(ConnectionPolicy policy) async {
    repairs++;
    await actionGate?.future;
    if (actionFailure != null) throw actionFailure!;
    blocker = null;
    pending = false;
    committed = policy;
    confirmation = ConnectionModeConfirmation.document;
    notifyListeners();
  }

  @override
  Future<void> retryPolicyReconciliation() async {
    retries++;
    await actionGate?.future;
    if (actionFailure != null) throw actionFailure!;
    blocker = null;
    // The real Store clears the unconfirmed/reconcile flags when the retry has
    // actually settled; the fixture mirrors that.
    pending = false;
    confirmation = ConnectionModeConfirmation.native;
    notifyListeners();
  }
}

AppStore fixtureStore({String? selectedId = 'sel'}) {
  final store = AppStore(nativeTunnelOverride: false)
    ..ready = true
    ..selectedId = selectedId;
  store.profiles.add(
    const Profile(
      id: 'sel',
      name: 'fixture',
      protocol: 'awg',
      endpoint: '192.0.2.1:1',
    ),
  );
  store.legalRecord = LegalRecord.acknowledge('fixture terms', 'ru');
  store.vpnDisclosure = vpnDisclosureRevision;
  return store;
}

String t(String value) => AppLanguages.text(value);

const draftKey = ValueKey('connection-mode-draft');
const saveKey = ValueKey('connection-settings-save');
const repairKey = ValueKey('connection-mode-repair');
const retryKey = ValueKey('connection-mode-retry');

Finder listTileWith(String text) => find
    .descendant(of: find.byType(ListTile), matching: find.text(t(text)))
    .hitTestable();

Future<void> openFullSettings(
  WidgetTester tester,
  AppStore store,
  FakeModeSource? source,
) async {
  await tester.pumpWidget(XioApp(store: store, modeSource: source));
  await tester.pumpAndSettle();
  await tester.tap(find.byType(NavigationDestination).at(1));
  await tester.pumpAndSettle();
  final tile = listTileWith('Настройка соединений');
  await tester.ensureVisible(tile);
  await tester.tap(tile);
  await tester.pumpAndSettle();
}

Future<void> openClientSettings(
  WidgetTester tester,
  AppStore store,
  FakeModeSource? source,
) async {
  await tester.pumpWidget(ClientApp(store: store, modeSource: source));
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

/// Picks a mode in the draft dropdown. The menu shows a second copy of the
/// label, so the last match is the menu entry.
Future<void> draftMode(WidgetTester tester, ConnectionPolicy policy) async {
  final picker = find.byKey(draftKey);
  await tester.ensureVisible(picker);
  await tester.tap(picker);
  await tester.pumpAndSettle();
  await tester.tap(find.text(t(ConnectionModeText.label(policy))).last);
  await tester.pumpAndSettle();
}

Future<void> tapKey(WidgetTester tester, Key key) async {
  final button = find.byKey(key);
  await tester.ensureVisible(button);
  await tester.tap(button);
  await tester.pump();
}

bool enabledKey(WidgetTester tester, Key key) {
  final widget = tester.widget(find.byKey(key));
  if (widget is FilledButton) return widget.onPressed != null;
  if (widget is OutlinedButton) return widget.onPressed != null;
  throw StateError('unexpected widget for $key');
}

bool draftEnabled(WidgetTester tester) =>
    tester
        .widget<DropdownButtonFormField<ConnectionPolicy>>(find.byKey(draftKey))
        .onChanged !=
    null;

void sizeSurface(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

/// Shared scenarios for one product surface.
void scenariosFor({
  required String product,
  required bool client,
  required Future<void> Function(WidgetTester, AppStore, FakeModeSource?) open,
}) {
  testWidgets('$product: native confirmation renders the badge', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource();
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    expect(find.byType(ConnectionModeControl), findsOneWidget);
    expect(find.text(t('Подтверждённый режим')), findsOneWidget);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsNothing);
    expect(
      find.text(t(ConnectionModeText.explanation(ConnectionPolicy.automatic))),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox());
  });

  for (final confirmation in [
    ConnectionModeConfirmation.document,
    ConnectionModeConfirmation.legacyAutomatic,
    ConnectionModeConfirmation.none,
  ]) {
    testWidgets('$product: ${confirmation.name} is a stored setting', (
      tester,
    ) async {
      sizeSurface(tester, const Size(1400, 2000));
      final store = fixtureStore();
      final source = FakeModeSource()..confirmation = confirmation;
      addTearDown(store.dispose);
      addTearDown(source.dispose);
      await open(tester, store, source);
      expect(find.text(t('Подтверждённый режим')), findsNothing);
      expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
      expect(
        find.text(t(ConnectionModeText.storedSettingNotice)),
        findsOneWidget,
      );
      // Still editable, and nothing claims an applied tunnel.
      expect(draftEnabled(tester), isTrue);
      expect(find.textContaining('применено к туннелю'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    });
  }

  testWidgets('$product: a draft choice is not a committed mode', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource();
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    expect(source.saved, isEmpty);
    expect(source.committed, ConnectionPolicy.automatic);
    expect(
      find.text(
        t(ConnectionModeText.explanation(ConnectionPolicy.selectedOnly)),
      ),
      findsOneWidget,
    );
    expect(find.text(t('Подтверждённый режим')), findsOneWidget);
    if (client) {
      await tester.tap(find.text(t('Отмена')));
    } else {
      await tester.tap(find.byType(BackButton));
    }
    await tester.pumpAndSettle();
    expect(source.saved, isEmpty);
    expect(source.committed, ConnectionPolicy.automatic);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: mode-aware fallback wording follows the draft', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource();
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    expect(
      find.text(t(ConnectionModeText.reconnect(ConnectionPolicy.automatic))),
      findsOneWidget,
    );
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    expect(
      find.text(t(ConnectionModeText.reconnect(ConnectionPolicy.selectedOnly))),
      findsOneWidget,
    );
    expect(
      find.text(t(ConnectionModeText.reconnect(ConnectionPolicy.automatic))),
      findsNothing,
    );
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: save waits for the exact ACK', (tester) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()..gate = Completer<void>();
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    await tapKey(tester, saveKey);
    expect(source.saved, [ConnectionPolicy.selectedOnly]);
    expect(source.committed, ConnectionPolicy.automatic);
    // Persisted intent is not an applied mode and not a confirmation.
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsNothing);
    expect(
      find.text(
        t(
          'Сохранение или согласование режима не завершено. Подтверждение ещё не получено.',
        ),
      ),
      findsOneWidget,
    );
    expect(draftEnabled(tester), isFalse);
    expect(enabledKey(tester, saveKey), isFalse);
    source.gate!.complete();
    await tester.pumpAndSettle();
    expect(source.committed, ConnectionPolicy.selectedOnly);
    expect(find.byType(ConnectionModeControl), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: lost ACK keeps the draft and claims nothing', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()
      ..failAfterWrite = PublicationFailure(
        PublicationPhase.renamedNativeUnconfirmed,
        PolicyFailure('POLICY_UNKNOWN', 'lost ack'),
      );
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    await tapKey(tester, saveKey);
    await tester.pumpAndSettle();
    expect(source.committed, ConnectionPolicy.automatic);
    expect(source.connectionModePending, isFalse);
    expect(find.byType(ConnectionModeControl), findsOneWidget);
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(
      find.text(
        t(
          'Настройки сохранены; движок не подтвердил режим. Требуется согласование.',
        ),
      ),
      findsOneWidget,
    );
    // A lost ACK may hide a successful native commit.
    expect(find.textContaining('не применён'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: unknown outcome asserts neither file nor engine', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()
      ..failAfterWrite = PublicationFailure(
        PublicationPhase.pendingUnknown,
        PolicyFailure('POLICY_UNKNOWN', 'unknown'),
      );
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    await tapKey(tester, saveKey);
    await tester.pumpAndSettle();
    expect(
      find.text(
        t(
          'Результат неизвестен: не подтверждены ни файл, ни режим в движке. Требуется согласование.',
        ),
      ),
      findsOneWidget,
    );
    expect(find.textContaining('Настройки сохранены'), findsNothing);
    expect(find.textContaining('Файл не изменён'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: beforeRename never restores a confirmed badge', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()
      ..failBeforeWrite = PublicationFailure(
        PublicationPhase.beforeRename,
        StateError('rename failed'),
      );
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    await tapKey(tester, saveKey);
    await tester.pumpAndSettle();
    expect(
      find.text(
        t(
          'Файл не изменён: переименование не произошло. Движок режим не подтвердил, требуется согласование.',
        ),
      ),
      findsOneWidget,
    );
    // A begin may already have fenced READY: no confirmed row.
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  for (final code in [
    'loading',
    'persistence',
    'busy',
    'connected',
    'publishPending',
    'reconcileRequired',
    'corrupt',
    'disposed',
  ]) {
    testWidgets('$product: blocker "$code" is localized not raw', (
      tester,
    ) async {
      sizeSurface(tester, const Size(1400, 2000));
      final store = fixtureStore();
      final source = FakeModeSource()..blocker = code;
      addTearDown(store.dispose);
      addTearDown(source.dispose);
      await open(tester, store, source);
      expect(find.text(t(ConnectionModeText.blocker(code))), findsOneWidget);
      expect(find.text(code), findsNothing);
      // The corrupt repair path still takes a chosen replacement mode, so the
      // draft stays editable there; every other blocker freezes the draft.
      expect(draftEnabled(tester), code == 'corrupt' ? isTrue : isFalse);
      expect(enabledKey(tester, saveKey), isFalse);
      expect(source.saved, isEmpty);
      // Confirmation is independent of the blocker: the fixture is native.
      expect(find.text(t('Подтверждённый режим')), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    });
  }

  testWidgets('$product: corrupt policy offers explicit repair', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()
      ..blocker = 'corrupt'
      ..confirmation = ConnectionModeConfirmation.none;
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    expect(find.byKey(repairKey), findsOneWidget);
    expect(find.byKey(retryKey), findsNothing);
    await draftMode(tester, ConnectionPolicy.selectedOnly);
    await tapKey(tester, repairKey);
    await tester.pumpAndSettle();
    expect(source.repairs, 1);
    expect(source.blocker, isNull);
    expect(source.committed, ConnectionPolicy.selectedOnly);
    // Recovered through the document, not a native ACK: still a stored setting.
    expect(find.text(t('Подтверждённый режим')), findsNothing);
    expect(find.text(t(ConnectionModeText.storedSetting)), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  for (final code in ['publishPending', 'reconcileRequired']) {
    // Persisted uncertainty is exactly when retry is needed: it must not be
    // hidden by the same "busy" flag that disables the mode picker.
    testWidgets('$product: $code offers retry while still pending', (
      tester,
    ) async {
      sizeSurface(tester, const Size(1400, 2000));
      final store = fixtureStore();
      final source = FakeModeSource()
        ..blocker = code
        ..pending = true;
      addTearDown(store.dispose);
      addTearDown(source.dispose);
      await open(tester, store, source);
      expect(find.byKey(repairKey), findsNothing);
      // Mode changing stays disabled while pending/error.
      expect(draftEnabled(tester), isFalse);
      expect(enabledKey(tester, saveKey), isFalse);
      // Recovery is reachable and enabled.
      expect(find.byKey(retryKey), findsOneWidget);
      expect(enabledKey(tester, retryKey), isTrue);
      await tapKey(tester, retryKey);
      await tester.pumpAndSettle();
      expect(source.retries, 1);
      expect(source.blocker, isNull);
      expect(find.text(t('Подтверждённый режим')), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('$product: rapid taps start a single $code recovery', (
      tester,
    ) async {
      sizeSurface(tester, const Size(1400, 2000));
      final store = fixtureStore();
      final source = FakeModeSource()
        ..blocker = code
        ..pending = true
        ..actionGate = Completer<void>();
      addTearDown(store.dispose);
      addTearDown(source.dispose);
      await open(tester, store, source);
      final retry = find.byKey(retryKey);
      expect(retry, findsOneWidget);
      // Two taps before the first settles must not duplicate physical recovery.
      await tester.tap(retry);
      await tester.tap(retry, warnIfMissed: false);
      await tester.pump();
      expect(source.retries, 1);
      // A recovery in flight hides the action until it settles.
      expect(find.byKey(retryKey), findsNothing);
      source.actionGate!.complete();
      await tester.pumpAndSettle();
      expect(source.retries, 1);
      await tester.pumpWidget(const SizedBox());
    });
  }

  testWidgets('$product: rapid taps start a single repair', (tester) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    final source = FakeModeSource()
      ..blocker = 'corrupt'
      ..confirmation = ConnectionModeConfirmation.none
      ..actionGate = Completer<void>();
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    // The draft stays editable for the repair path even while publishing is off.
    expect(draftEnabled(tester), isTrue);
    expect(enabledKey(tester, saveKey), isFalse);
    final repair = find.byKey(repairKey);
    await tester.tap(repair);
    await tester.tap(repair, warnIfMissed: false);
    await tester.pump();
    expect(source.repairs, 1);
    expect(find.byKey(repairKey), findsNothing);
    source.actionGate!.complete();
    await tester.pumpAndSettle();
    expect(source.repairs, 1);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    '$product: a failed recovery is localized and keeps the blocker',
    (tester) async {
      sizeSurface(tester, const Size(1400, 2000));
      final store = fixtureStore();
      final source = FakeModeSource()
        ..blocker = 'corrupt'
        ..confirmation = ConnectionModeConfirmation.none
        ..actionFailure = const PolicyFailure(
          'POLICY_INVALID',
          'still corrupt',
        );
      addTearDown(store.dispose);
      addTearDown(source.dispose);
      await open(tester, store, source);
      await tapKey(tester, repairKey);
      await tester.pumpAndSettle();
      expect(source.repairs, 1);
      expect(source.blocker, 'corrupt');
      expect(find.text(t(ConnectionModeText.recoveryFailed)), findsOneWidget);
      expect(find.textContaining('PolicyFailure'), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('$product: manual without a usable profile never repairs it', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore(selectedId: 'missing');
    final source = FakeModeSource()
      ..committed = ConnectionPolicy.selectedOnly
      ..usable = false;
    addTearDown(store.dispose);
    addTearDown(source.dispose);
    await open(tester, store, source);
    expect(
      find.text(
        t(
          'Выберите доступный профиль в списке подключений. Ручной режим не выбирает замену автоматически.',
        ),
      ),
      findsOneWidget,
    );
    expect(store.selectedId, 'missing');
    expect(source.saved, isEmpty);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: no mode control when the seam is absent', (
    tester,
  ) async {
    sizeSurface(tester, const Size(1400, 2000));
    final store = fixtureStore();
    addTearDown(store.dispose);
    await open(tester, store, null);
    expect(find.byType(ConnectionModeControl), findsNothing);
    expect(
      find.text(t(ConnectionModeText.reconnect(ConnectionPolicy.automatic))),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('$product: every language keeps the control laid out at 360 dp', (
    tester,
  ) async {
    sizeSurface(tester, const Size(360, 640));
    for (final code in AppLanguages.names.keys) {
      AppLanguages.set(code);
      final store = fixtureStore();
      final source = FakeModeSource();
      await open(tester, store, source);
      await draftMode(tester, ConnectionPolicy.selectedOnly);
      expect(find.byType(ConnectionModeControl), findsOneWidget, reason: code);
      expect(find.text(t('Режим подключения')), findsOneWidget, reason: code);
      expect(tester.takeException(), isNull, reason: code);
      await tester.pumpWidget(const SizedBox());
      await tester.pumpAndSettle();
      source.dispose();
      store.dispose();
    }
    AppLanguages.set('ru');
  });
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(AppLanguages.load);
  setUp(() => AppLanguages.set('ru'));
  tearDown(() => AppLanguages.set(null));

  if (clientOnlyBuild) {
    scenariosFor(product: 'Client', client: true, open: openClientSettings);
  } else {
    scenariosFor(product: 'Full', client: false, open: openFullSettings);
  }

  test('all 13 catalogues carry the mode cells and keep them mode-aware', () {
    final files = Directory('assets/l10n')
        .listSync()
        .whereType<File>()
        .where((file) => file.path.endsWith('.json'))
        .toList();
    expect(files, hasLength(13));
    final catalogs = <String, Map<String, String>>{};
    for (final file in files) {
      final code = file.uri.pathSegments.last.replaceAll('.json', '');
      catalogs[code] = Map<String, String>.from(
        jsonDecode(file.readAsStringSync()) as Map,
      );
    }
    final keys = <String>{
      'Режим подключения',
      'Черновик режима',
      'Подтверждённый режим',
      ConnectionModeText.storedSetting,
      ConnectionModeText.storedSettingNotice,
      ConnectionModeText.modeUnavailable,
      ConnectionModeText.repairAction,
      ConnectionModeText.retryAction,
      ConnectionModeText.recoveryFailed,
      'Выберите доступный профиль в списке подключений. Ручной режим не выбирает замену автоматически.',
      for (final policy in ConnectionPolicy.values) ...[
        ConnectionModeText.label(policy),
        ConnectionModeText.explanation(policy),
        ConnectionModeText.reconnect(policy),
        for (final enabled in [true, false])
          ConnectionModeText.siteCheck(enabled: enabled, policy: policy),
      ],
      for (final code in [
        'loading',
        'persistence',
        'busy',
        'publishPending',
        'reconcileRequired',
        'corrupt',
        'disposed',
        'unknown-code',
      ])
        ConnectionModeText.blocker(code),
      for (final error in <Object>[
        const PolicyFailure('POLICY_BUSY', 'x'),
        const PolicyFailure('POLICY_INVALID', 'x'),
        const PolicyFailure('POLICY_UNKNOWN', 'x'),
        const PolicyFailure('POLICY_UNSUPPORTED', 'x'),
        const PolicyFailure('POLICY_PENDING', 'x'),
        const PolicyFailure('POLICY_OTHER', 'x'),
        const PolicyFailure('POLICY_OVERSIZE', 'x'),
        PublicationFailure(PublicationPhase.beforeRename, StateError('x')),
        PublicationFailure(
          PublicationPhase.renamedNativeUnconfirmed,
          StateError('x'),
        ),
        PublicationFailure(PublicationPhase.pendingUnknown, StateError('x')),
      ])
        ConnectionModeText.saveFailure(error),
    };
    final english = catalogs['en']!;
    for (final entry in catalogs.entries) {
      for (final key in keys) {
        final value = entry.value[key];
        expect(value, isNotNull, reason: '${entry.key} has no cell for «$key»');
        expect(value!.trim(), isNotEmpty, reason: '${entry.key}: $key');
        if (entry.key != 'ru') {
          expect(value, isNot(key), reason: '${entry.key} keeps the source');
        }
        if (entry.key != 'ru' && entry.key != 'en') {
          expect(
            value,
            isNot(english[key]),
            reason: '${entry.key} reuses the English cell for «$key»',
          );
        }
      }
      // The two modes must never share one explanation in any language.
      expect(
        entry.value[ConnectionModeText.explanation(ConnectionPolicy.automatic)],
        isNot(
          entry.value[ConnectionModeText.explanation(
            ConnectionPolicy.selectedOnly,
          )],
        ),
        reason: '${entry.key} explanation is not mode-aware',
      );
      // Blocker codes must stay distinguishable in every language.
      expect(
        entry.value[ConnectionModeText.blocker('corrupt')],
        isNot(entry.value[ConnectionModeText.blocker('busy')]),
        reason: '${entry.key} reuses one text for different blockers',
      );
    }
    // Reverse check: no dead catalogue entries.
    final lib = Directory('lib')
        .listSync()
        .whereType<File>()
        .where((file) => file.path.endsWith('.dart'))
        .map((file) => file.readAsStringSync())
        .join('\n');
    for (final key in keys) {
      expect(lib.contains(key), isTrue, reason: 'no widget uses «$key»');
    }
  });
}
