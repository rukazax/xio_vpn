// Plain-Dart Linux self-test for the POSIX Slice B provider. Synthetic
// temp-root, synthetic context; exercises flock, key creation, AES-GCM AAD,
// rename + directory fsync, corrupt-vs-absent and missing-key behavior.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:xio/issuance_vault.dart';
import 'package:xio/issuance_vault_posix.dart';

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

String recordPath(Directory dir, String id) =>
    '${dir.path}/xio-issuance-${sha256.convert(utf8.encode(id))}.bin';

Future<void> main() async {
  final root = Directory.systemTemp.createTempSync('xio-issuance-linux-');
  final store = issuanceVaultRandomHex(32);
  final context = IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(store),
    storeIdentity: store,
  );
  final id = context.vaultId;
  try {
    final vault = await openPosixJournalVault(
      directory: root,
      storeIdentity: store,
    );
    check('vault opens', vault.vaultId == id);
    check('absent read is null', await vault.read(id) == null);
    await vault.write(id, {
      'schema': '1',
      'revision': '0',
      'uid': 'a' * 32,
      'phase': 'prepared',
    });
    final read = await vault.read(id);
    check('round trip', read?['phase'] == 'prepared');

    final record = File(recordPath(root, id));
    check('record exists', await record.exists());
    final key = File('${root.path}/issuance.key');
    check('key exists', await key.exists());

    // The provider holds the session lease; a second fd/open in this process
    // must not overlap (flock is per open file description).
    check('second lease is busy while vault holds it',
        await throws<IssuanceVaultBusy>(() async =>
            PosixJournalLease.acquire('${root.path}/xio-issuance-lease')));

    await vault.close();

    final leaseAfterClose =
        PosixJournalLease.acquire('${root.path}/xio-issuance-lease');
    check('lease reacquires after close', leaseAfterClose.held);
    await leaseAfterClose.closeWhenSettled();

    // Reopen keeps the record.
    final reopened = await openPosixJournalVault(
      directory: root,
      storeIdentity: store,
    );
    check('reopen keeps record',
        (await reopened.read(id))?['phase'] == 'prepared');

    await reopened.close();

    // Identity swap: put A's ciphertext under B's record path/context.
    final otherStore = issuanceVaultRandomHex(32);
    final other = IssuanceVaultContext(
      version: issuanceVaultVersion,
      vaultId: IssuanceVaultContext.vaultIdFor(otherStore),
      storeIdentity: otherStore,
    );
    final sealedA = await File(recordPath(root, id)).readAsBytes();
    final bFile = File(recordPath(root, other.vaultId));
    await bFile.writeAsBytes(sealedA, flush: true);
    check('swapped ciphertext fails the bootstrap fence',
        await throws<IssuanceVaultCorrupt>(() => openPosixJournalVault(
              directory: root,
              storeIdentity: otherStore,
            )));
    await bFile.delete();

    // Corrupt record is not absent.
    await record.writeAsBytes(Uint8List.fromList([1, 2, 3, 4]), flush: true);
    check('corrupt record fails the bootstrap fence',
        await throws<IssuanceVaultCorrupt>(() => openPosixJournalVault(
              directory: root,
              storeIdentity: store,
            )));

    // Missing key with an existing record fails closed and does not regenerate.
    await key.delete();
    check('missing key fails closed',
        await throws<IssuanceVaultKeyUnavailable>(() => openPosixJournalVault(
              directory: root,
              storeIdentity: store,
            )));
    check('key was not regenerated', !await key.exists());

    // Pre-existing immutable key: load under the key lock and fence it.
    final keyRoot = Directory.systemTemp.createTempSync('xio-issuance-key-');
    try {
      final preKey = File('${keyRoot.path}/issuance.key');
      final bytes = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      await preKey.writeAsBytes(bytes, flush: true);
      final chmod = await Process.run('/bin/chmod', ['600', preKey.path]);
      check('pre-key chmod', chmod.exitCode == 0);
      final kv = await openPosixJournalVault(
        directory: keyRoot,
        storeIdentity: issuanceVaultRandomHex(32),
      );
      await kv.write(kv.vaultId, {
        'schema': '1',
        'revision': '0',
        'uid': 'a' * 32,
      });
      check('pre-existing key decrypts a fresh record',
          (await kv.read(kv.vaultId))?['revision'] == '0');
      check('key bytes unchanged after load/fence',
          (await preKey.readAsBytes()).join(',') == bytes.join(','));
      await kv.close();
    } finally {
      try {
        await keyRoot.delete(recursive: true);
      } catch (_) {}
    }

    final badRoot = Directory.systemTemp.createTempSync('xio-issuance-badkey-');
    try {
      await File('${badRoot.path}/issuance.key')
          .writeAsBytes(Uint8List.fromList([1, 2, 3]), flush: true);
      check('short key fails closed',
          await throws<IssuanceVaultKeyUnavailable>(() =>
              openPosixJournalVault(
                directory: badRoot,
                storeIdentity: issuanceVaultRandomHex(32),
              )));
    } finally {
      try {
        await badRoot.delete(recursive: true);
      } catch (_) {}
    }

    // Fresh empty open→null→close→reopen must be idempotent.
    final emptyRoot = Directory.systemTemp.createTempSync('xio-issuance-empty-');
    try {
      final emptyStore = issuanceVaultRandomHex(32);
      final firstEmpty = await openPosixJournalVault(
        directory: emptyRoot,
        storeIdentity: emptyStore,
      );
      check('fresh empty read is null',
          await firstEmpty.read(firstEmpty.vaultId) == null);
      await firstEmpty.close();
      final secondEmpty = await openPosixJournalVault(
        directory: emptyRoot,
        storeIdentity: emptyStore,
      );
      check('empty reopen is not corruption',
          await secondEmpty.read(secondEmpty.vaultId) == null);
      await secondEmpty.close();
    } finally {
      try {
        await emptyRoot.delete(recursive: true);
      } catch (_) {}
    }

    print('RESULT pass=$pass fail=$fail');
    if (fail != 0) exitCode = 1;
  } finally {
    try {
      await root.delete(recursive: true);
    } catch (_) {}
  }
}
