// Plain-Dart isolate lease test: two Dart isolates in one process must not
// share the journal lease (flock is per open file description on POSIX; the
// Windows lease is handle-based). The child isolate opens the vault, reports
// HELD, and waits; the parent must get Busy; after stop the parent acquires.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:xio/issuance_vault.dart';
import 'package:xio/issuance_vault_posix.dart';
import 'package:xio/issuance_vault_windows.dart';

var pass = 0;
var fail = 0;

void check(String name, bool ok, [String detail = '']) {
  if (ok) {
    pass++;
  } else {
    fail++;
    print('FAIL  $name  [$detail]');
  }
}

Future<IssuanceJournalVault> openVault(String store, Directory root) {
  if (Platform.isWindows) return openWindowsJournalVault(store);
  return openPosixJournalVault(directory: root, storeIdentity: store);
}

Future<void> _child(List<Object> args) async {
  final store = args[0] as String;
  final rootPath = args[1] as String;
  final port = args[2] as SendPort;
  final commands = ReceivePort();
  port.send(commands.sendPort);
  final vault = await openVault(store, Directory(rootPath));
  port.send('HELD');
  await commands.first;
  await vault.close();
  commands.close();
  port.send('DONE');
}

Future<void> main() async {
  final root = Platform.isWindows
      ? Directory(windowsLocalAppData())
      : Directory.systemTemp.createTempSync('xio-issuance-iso-');
  final store = issuanceVaultRandomHex(32);
  final messages = ReceivePort();
  final commands = ReceivePort();
  Isolate? isolate;
  try {
    isolate = await Isolate.spawn(_child, [store, root.path, messages.sendPort]);
    SendPort? childCommands;
    final ready = Completer<void>();
    messages.listen((message) {
      if (message is SendPort) {
        childCommands = message;
      } else if (message == 'HELD' && !ready.isCompleted) {
        ready.complete();
      }
    });
    await ready.future.timeout(const Duration(seconds: 20));
    final commandPort = childCommands!;
    check(
      'second isolate is busy while the child isolate holds the lease',
      await _throwsBusy(() => openVault(store, root)),
    );
    commandPort.send('stop');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    isolate.kill(priority: Isolate.immediate);
    isolate = null;

    var opened = false;
    for (var i = 0; i < 100 && !opened; i++) {
      try {
        final vault = await openVault(store, root);
        await vault.close();
        opened = true;
      } on IssuanceVaultBusy {
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
    }
    check('lease is reacquirable after the isolate exits', opened);
    print('RESULT pass=$pass fail=$fail');
  } finally {
    isolate?.kill(priority: Isolate.immediate);
    messages.close();
    commands.close();
    if (!Platform.isWindows) {
      try {
        await root.delete(recursive: true);
      } catch (_) {}
    }
  }
  if (fail != 0) exitCode = 1;
}

Future<bool> _throwsBusy(Future<IssuanceJournalVault> Function() action) async {
  try {
    final vault = await action();
    await vault.close();
    return false;
  } on IssuanceVaultBusy {
    return true;
  } catch (error) {
    print('unexpected: $error');
    return false;
  }
}
