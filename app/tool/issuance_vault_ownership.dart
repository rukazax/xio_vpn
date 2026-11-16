// Ownership-copy probe: a lease/provider with a native handle must not be
// sendable to another isolate, and a copied object (if the VM allowed it) must
// refuse to act on the handle. Also checks same-owner repeated close.
import 'dart:async';
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

Future<void> _child(List<Object> args) async {
  final lease = args[0] as IssuanceJournalLease;
  final port = args[1] as SendPort;
  try {
    await lease.closeWhenSettled();
    port.send('CLOSED');
  } catch (error) {
    port.send('REFUSED:${error.runtimeType}');
  }
}

Future<IssuanceJournalVault> openVault(String store, Directory root) {
  if (Platform.isWindows) return openWindowsJournalVault(store);
  return openPosixJournalVault(directory: root, storeIdentity: store);
}

Future<void> main() async {
  final root = Platform.isWindows
      ? Directory(windowsLocalAppData())
      : Directory.systemTemp.createTempSync('xio-ownership-');
  final store = issuanceVaultRandomHex(32);
  IssuanceJournalVault? vault;
  try {
    print("STEP open");
    vault = await openVault(store, root);
    print("STEP opened");
    print("STEP owner=${vault.lease.ownedByCurrentIsolate}");
    check('provider is owned by current isolate', vault.lease.ownedByCurrentIsolate);

    final reply = ReceivePort();
    var sent = false;
    try {
      await Isolate.spawn(_child, [vault.lease, reply.sendPort]);
      sent = true;
    } catch (_) {
      sent = false;
    }
    print("STEP sent=$sent");
    if (sent) {
      final outcome = await reply.first.timeout(const Duration(seconds: 5));
      check('copied lease refuses native close', '$outcome'.startsWith('REFUSED'),
          '$outcome');
    } else {
      check('lease is unsendable', true);
    }
    print("STEP reply close");
    reply.close();

    // Provider object itself is also an ownership object.
    var providerSent = false;
    final providerReply = ReceivePort();
    try {
      await Isolate.spawn(_child, [vault, providerReply.sendPort]);
      providerSent = true;
    } catch (_) {
      providerSent = false;
    } finally {
      providerReply.close();
    }
    print("STEP provider sent=$providerSent");
    check('provider is unsendable', !providerSent);

    await vault.close();
    vault = null;

    // Same-owner repeated close is idempotent and does not touch a reused fd.
    final lease = Platform.isWindows
        ? WindowsJournalLease.acquire(
            '${root.path}\\xio-issuance-${IssuanceVaultContext.vaultIdFor(store)}-lease',
          )
        : PosixJournalLease.acquire('${root.path}/xio-issuance-lease');
    await lease.closeWhenSettled();
    await lease.closeWhenSettled();
    check('repeated close is idempotent', true);
    print('RESULT pass=$pass fail=$fail');
  } finally {
    if (vault != null) await vault.close();
    if (!Platform.isWindows) {
      try {
        await root.delete(recursive: true);
      } catch (_) {}
    }
  }
  if (fail != 0) exitCode = 1;
}
