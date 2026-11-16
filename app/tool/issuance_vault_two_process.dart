// Plain-Dart two-process lease test for Slice B.
// Child opens the journal and holds the session lease; parent must get Busy;
// after SIGKILL the OS releases the lease and the parent can acquire it.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

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

Future<void> child(String store, Directory root) async {
  final vault = await openVault(store, root);
  stdout.writeln('HELD');
  await stdin.first;
  await vault.close();
}

Future<void> main(List<String> args) async {
  if (args.length >= 3 && args[0] == '--child') {
    await child(args[1], Directory(args[2]));
    return;
  }
  final root = Platform.isWindows
      ? Directory(windowsLocalAppData())
      : Directory.systemTemp.createTempSync('xio-issuance-proc-');
  final store = issuanceVaultRandomHex(32);
  final children = <Process>[];
  try {
    final childProcess = await Process.start(
      Platform.resolvedExecutable,
      [Platform.script.toFilePath(), '--child', store, root.path],
      workingDirectory: Directory.current.path,
    );
    children.add(childProcess);
    final held = Completer<void>();
    childProcess.stdout
        .transform(utf8.decoder)
        .listen((text) {
          if (text.contains('HELD') && !held.isCompleted) held.complete();
        });
    await held.future.timeout(const Duration(seconds: 20));
    check(
      'second process is busy while the child holds the lease',
      await _throwsBusy(() => openVault(store, root)),
    );
    childProcess.kill(ProcessSignal.sigkill);
    await childProcess.exitCode.timeout(const Duration(seconds: 20));

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
    check('lease is reacquirable after the holder is killed', opened);
    print('RESULT pass=$pass fail=$fail');
  } finally {
    for (final process in children) {
      try {
        process.kill(ProcessSignal.sigkill);
      } catch (_) {}
    }
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
