// Plain-Dart Windows self-test for the Slice B provider. Not a Flutter test:
// it exercises the real system winsqlite3/DPAPI/LockFileEx path with
// synthetic contexts and unique opaque names under LocalAppData.
import 'dart:io';
import 'dart:typed_data';

import 'package:xio/issuance_vault.dart';
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

Future<bool> throws<T>(Future<void> Function() action) async {
  try {
    await action();
    return false;
  } catch (error) {
    return error is T;
  }
}

Future<void> main() async {
  final root = Directory(windowsLocalAppData());
  final store = issuanceVaultRandomHex(32);
  final context = IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(store),
    storeIdentity: store,
  );
  final dbPath = '${root.path}\\xio-issuance-${context.digestHex}-journal.db';
  final leasePath = '${root.path}\\xio-issuance-${context.digestHex}-lease';
  final id = context.vaultId;
  final otherStore = issuanceVaultRandomHex(32);
  final other = IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(otherStore),
    storeIdentity: otherStore,
  );

  Future<void> cleanup() async {
    for (final path in [
      dbPath,
      leasePath,
      '$dbPath-wal',
      '$dbPath-shm',
      '$dbPath-journal',
    ]) {
      final file = File(path);
      if (await file.exists()) {
        try {
          await file.delete();
        } catch (_) {}
      }
    }
  }

  await cleanup();

  // Fresh empty session must be idempotent: open→null→close→reopen.
  final emptyStore = issuanceVaultRandomHex(32);
  final emptyCtx = IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(emptyStore),
    storeIdentity: emptyStore,
  );
  final emptyDb = '${root.path}\\xio-issuance-${emptyCtx.digestHex}-journal.db';
  final emptyLease = '${root.path}\\xio-issuance-${emptyCtx.digestHex}-lease';
  try {
    final empty = await openWindowsJournalVault(emptyStore);
    check('fresh empty read is null', await empty.read(emptyCtx.vaultId) == null);
    await empty.close();
    final reopenedEmpty = await openWindowsJournalVault(emptyStore);
    check('empty reopen is not corruption',
        await reopenedEmpty.read(emptyCtx.vaultId) == null);
    await reopenedEmpty.close();
  } finally {
    for (final path in [emptyDb, '$emptyDb-wal', '$emptyDb-shm', emptyLease]) {
      final file = File(path);
      if (await file.exists()) await file.delete();
    }
  }

  IssuanceJournalVault? vault;
  try {
    vault = await openWindowsJournalVault(store);
    check('vault opens', vault.vaultId == id);
    check('absent read is null', await vault.read(id) == null);
    final record = <String, String>{
      'schema': '1',
      'revision': '0',
      'uid': 'a' * 32,
      'phase': 'prepared',
      'payload': 'synthetic',
    };
    await vault.write(id, record);
    final read = await vault.read(id);
    check('round trip', read?['payload'] == 'synthetic');
    check('revision preserved', read?['revision'] == '0');
    check('wrong id rejected',
        await throws<IssuanceVaultContextMismatch>(() => vault!.read('state${'0' * 64}')));
    check('oversized rejected',
        await throws<FormatException>(() => vault!.write(id, {'revision': '1', 'x': 'a' * 600000})));
    await vault.close();
    vault = null;

    final reopened = await openWindowsJournalVault(store);
    final after = await reopened.read(id);
    check('reopen keeps record', after?['payload'] == 'synthetic');
    await reopened.close();

    // Two leases on the same identity must not overlap.
    final leaseA = WindowsJournalLease.acquire(leasePath);
    check('second lease is busy',
        await throws<IssuanceVaultBusy>(() async => WindowsJournalLease.acquire(leasePath)));
    await leaseA.closeWhenSettled();
    final leaseB = WindowsJournalLease.acquire(leasePath);
    check('lease reacquires after release', leaseB.held);
    await leaseB.closeWhenSettled();

    // Unsupported root: temp is rejected.
    final tempBackend = WindowsSqliteBackend(
      root: Directory.systemTemp,
      context: context,
    );
    check('temp root rejected',
        await throws<IssuanceVaultUnsupported>(() => tempBackend.open()));

    // Existing zero-length DB is corrupt, not a fresh journal.
    final zeroStore = issuanceVaultRandomHex(32);
    final zeroCtx = IssuanceVaultContext(
      version: issuanceVaultVersion,
      vaultId: IssuanceVaultContext.vaultIdFor(zeroStore),
      storeIdentity: zeroStore,
    );
    final zeroDb = '${root.path}\\xio-issuance-${zeroCtx.digestHex}-journal.db';
    await File(zeroDb).writeAsBytes(<int>[], flush: true);
    check('zero-length db is corrupt',
        await throws<IssuanceVaultCorrupt>(
            () => openWindowsJournalVault(zeroStore)));
    await File(zeroDb).delete();

    // Corrupt database is not absent.
    final raw = await File(dbPath).readAsBytes();
    await File(dbPath).writeAsBytes(Uint8List.fromList([0, 0, 0, 0]), flush: true);
    check('corrupt db maps to corrupt/unsupported',
        await throws<IssuanceVaultException>(() async {
      final corrupt = await openWindowsJournalVault(store);
      await corrupt.close();
    }));
    await File(dbPath).writeAsBytes(raw, flush: true);

    // Identity swap: copy an A record under a B context path.
    final aBackend = WindowsSqliteBackend(root: root, context: context);
    await aBackend.open();
    final sealedA = await aBackend.readSealed(id);
    await aBackend.close();
    final bBackend = WindowsSqliteBackend(root: root, context: other);
    await bBackend.open();
    await bBackend.writeSealed(other.vaultId, sealedA!);
    await bBackend.close();
    check('swapped ciphertext fails the bootstrap fence',
        await throws<IssuanceVaultCorrupt>(
            () => openWindowsJournalVault(otherStore)));

    // Whole foreign DB under this identity's path must not read as absence.
    final otherDb =
        '${root.path}\\xio-issuance-${other.digestHex}-journal.db';
    await File(otherDb).copy(dbPath);
    check('foreign single-row db is corrupt, not null',
        await throws<IssuanceVaultCorrupt>(
            () => openWindowsJournalVault(store)));
    await File(dbPath).writeAsBytes(raw, flush: true);
  } finally {
    if (vault != null) await vault.close();
    await cleanup();
    for (final path in [
      '${root.path}\\xio-issuance-${other.digestHex}-journal.db',
      '${root.path}\\xio-issuance-${other.digestHex}-journal.db-wal',
      '${root.path}\\xio-issuance-${other.digestHex}-journal.db-shm',
      '${root.path}\\xio-issuance-${other.digestHex}-lease',
    ]) {
      final file = File(path);
      if (await file.exists()) await file.delete();
    }
  }

  print('RESULT pass=$pass fail=$fail');
  if (fail != 0) exitCode = 1;
}
