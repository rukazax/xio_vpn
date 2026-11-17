import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_wizard.dart';
import 'package:xio/core.dart';

/// A store that never touches the filesystem: the dialog only needs the saved
/// addresses and a save that accepts the new ones.
class _MemoryStore extends AppStore {
  @override
  Future<void> save() async {}
}

/// One SSH host. Answers by the first response whose key appears in the command,
/// which is enough to fake both cascade units and a failing step.
class _FakeSsh extends VpsService {
  _FakeSsh();

  final responses = <String, String>{};
  final commands = <String>[];
  final uploaded = <String, String>{};

  @override
  Future<void> upload(String path, List<int> bytes) async {
    uploaded[path] = utf8.decode(bytes);
  }

  @override
  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    commands.add(command);
    if (command.contains('cat /root/.ssh/xio_cascade.pub')) {
      return utf8.encode(
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY xio-cascade\n',
      );
    }
    for (final entry in responses.entries) {
      if (command.contains(entry.key)) return utf8.encode(entry.value);
    }
    return const <int>[];
  }
}

const String _exitHost = '203.0.113.9';
const String _bridgeHost = '198.51.100.7';

_FakeSsh _exitServer() => _FakeSsh()
  ..responses['XIO_CASCADE_EXIT_READY'] =
      'XIO_CASCADE_EXIT_READY addr=10.250.0.2/30 forward=1 v6=1\n';

_FakeSsh _bridgeServer() => _FakeSsh()
  ..responses['XIO_CASCADE_TUNNEL_READY'] =
      'XIO_CASCADE_TUNNEL_READY tun=10.250.0.1/30\n'
  ..responses['XIO_CASCADE_BRIDGE_READY'] =
      'XIO_CASCADE_BRIDGE_READY ssh=ok ping=ok\n';

Widget _host(
  AppStore store, {
  required CascadeSshOpener openSsh,
  Future<void> Function(VpsService ssh)? cleanServer,
  String? bridgeHint,
}) => MaterialApp(
  home: Scaffold(
    body: CascadeWizardDialog(
      store: store,
      bridgeHint: bridgeHint,
      openSsh: openSsh,
      cleanServer: cleanServer,
    ),
  ),
);

Future<void> _tap(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pump();
  await tester.tap(finder);
  await tester.pump();
}

/// Pumps until [done] appears; the run itself is a chain of immediate futures,
/// so a bounded number of frames settles it without waiting on a timer.
Future<void> _runUntil(WidgetTester tester, Finder done) async {
  for (var i = 0; i < 200; i++) {
    await tester.pump(const Duration(milliseconds: 5));
    if (done.evaluate().isNotEmpty) {
      // The result card scrolls into view; let that animation finish so the
      // test does not end with a running ticker.
      await tester.pump(const Duration(milliseconds: 400));
      return;
    }
  }
  fail('the wizard did not reach the expected state');
}

Future<void> _fill(WidgetTester tester, String stage) async {
  await tester.enterText(
    find.byKey(ValueKey('cascade-$stage-password')),
    'secret',
  );
}

void main() {
  testWidgets('one button installs the exit and then the bridge', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(900, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore()
      ..cascadeExit = _exitHost
      ..cascadeBridge = _bridgeHost;
    final exit = _exitServer();
    final bridge = _bridgeServer();
    final opened = <String>[];

    await tester.pumpWidget(
      _host(
        store,
        openSsh: (target, password, key, passphrase) async {
          opened.add(target.host);
          return target.host == _exitHost ? exit : bridge;
        },
      ),
    );
    await tester.pump();

    // One action, and no per-stage buttons left.
    expect(find.text('Установить каскад'), findsOneWidget);
    expect(find.text('Этап 1 · установить exit'), findsNothing);
    expect(find.text('Этап 2 · поднять bridge'), findsNothing);

    await _fill(tester, 'exit');
    await _fill(tester, 'bridge');
    await _tap(tester, find.text('Установить каскад'));
    await _runUntil(tester, find.text('Каскад поднят'));

    expect(opened, <String>[_exitHost, _bridgeHost]);
    expect(
      exit.uploaded.keys,
      contains('/usr/local/sbin/xio-cascade-exit-up.sh'),
    );
    expect(
      bridge.uploaded.keys,
      contains('/etc/systemd/system/xio-cascade-bridge.service'),
    );
    expect(store.cascadeExit, _exitHost);
    expect(store.cascadeBridge, _bridgeHost);

    // The plan of both servers is on screen with the lines that proved it.
    expect(find.text('prerequisites'), findsNWidgets(2));
    expect(find.text('NAT for client networks'), findsOneWidget);
    expect(find.text('SSH TUN and addresses'), findsOneWidget);
    expect(find.textContaining('10.250.0.2/30'), findsWidgets);
    expect(find.textContaining('SSH TUN to 203.0.113.9'), findsWidgets);
  });

  testWidgets('a failed step shows its reason and the host logs', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(900, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String?;
        }
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );

    final store = _MemoryStore()
      ..cascadeExit = _exitHost
      ..cascadeBridge = _bridgeHost;
    final exit = _exitServer();
    final bridge = _FakeSsh()
      ..responses['systemctl restart xio-cascade-bridge.service'] =
          'bridge did not come up\n'
          'xio-cascade-bridge-up.sh: line 48: iptables: command not found\n'
      ..responses['journalctl -u xio-cascade-bridge.service -n 40'] =
          'xio-cascade-bridge.service: status=127/INVALIDARGUMENT\n';

    await tester.pumpWidget(
      _host(
        store,
        openSsh: (target, password, key, passphrase) async =>
            target.host == _exitHost ? exit : bridge,
      ),
    );
    await tester.pump();

    await _fill(tester, 'exit');
    await _fill(tester, 'bridge');
    await _tap(tester, find.text('Установить каскад'));
    await _runUntil(tester, find.text('Логи'));

    // The description names the server and the step, the message carries the
    // host's own words, and the logs hold both the output and the journal.
    expect(find.text('bridge · SSH TUN and addresses'), findsOneWidget);
    expect(find.textContaining('iptables: command not found'), findsWidgets);
    expect(
      find.textContaining('--- journalctl -u xio-cascade-bridge.service'),
      findsOneWidget,
    );
    expect(find.text('Каскад поднят'), findsNothing);
    expect(
      store.cascadeBridge,
      _bridgeHost,
      reason: 'адрес уже сохранён до запуска',
    );

    await _tap(tester, find.text('Копировать'));
    await tester.pump();
    expect(copied, isNotNull);
    expect(copied!, contains('bridge · SSH TUN and addresses'));
    expect(copied!, contains('iptables: command not found'));
    expect(copied!, contains('status=127'));
    expect(find.text('Логи скопированы'), findsOneWidget);
  });

  testWidgets('a 360×640 viewport shows the failure without overflow', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore()
      ..cascadeExit = _exitHost
      ..cascadeBridge = _bridgeHost;
    final exit = _exitServer();
    final bridge = _FakeSsh()
      ..responses['systemctl restart xio-cascade-bridge.service'] =
          'bridge did not come up\n';

    await tester.pumpWidget(
      _host(
        store,
        openSsh: (target, password, key, passphrase) async =>
            target.host == _exitHost ? exit : bridge,
      ),
    );
    await tester.pump();

    await _fill(tester, 'exit');
    await _fill(tester, 'bridge');
    await _tap(tester, find.text('Установить каскад'));
    await _runUntil(tester, find.text('Логи'));

    expect(tester.takeException(), isNull);
    expect(find.text('Установить каскад'), findsOneWidget);
  });

  testWidgets('the cleanup checkbox adds a visible first step', (tester) async {
    tester.view.physicalSize = const Size(900, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final store = _MemoryStore()
      ..cascadeExit = _exitHost
      ..cascadeBridge = _bridgeHost;
    final exit = _exitServer();
    final bridge = _bridgeServer();
    final cleaned = <VpsService>[];

    await tester.pumpWidget(
      _host(
        store,
        openSsh: (target, password, key, passphrase) async =>
            target.host == _exitHost ? exit : bridge,
        cleanServer: (ssh) async => cleaned.add(ssh),
      ),
    );
    await tester.pump();

    final purge = find.text('Очистить сервер перед установкой');
    expect(purge, findsNWidgets(2));
    await _tap(tester, purge.first);
    await _tap(tester, purge.last);
    await _fill(tester, 'exit');
    await _fill(tester, 'bridge');
    await _tap(tester, find.text('Установить каскад'));
    await _runUntil(tester, find.text('Каскад поднят'));

    expect(cleaned, <VpsService>[exit, bridge]);
    expect(find.text('remove the previous XIO install'), findsNWidgets(2));
  });
}
