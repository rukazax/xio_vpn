import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_vault.dart';
import 'package:xio/issuance_vault_posix.dart';

final class FakeLease extends SettlingJournalLease {
  int releases = 0;
  FakeLease() {
    markHeld();
  }

  @override
  Future<void> release() async {
    releases++;
  }
}

class FakeBackend implements IssuanceVaultBackend {
  Map<String, Uint8List> records = {};
  Map<String, Uint8List> durable = {};
  bool failWrite = false;
  bool failFlush = false;
  bool mismatchReadback = false;
  int writes = 0;
  int closeCalls = 0;
  Completer<void>? gate;
  Completer<void>? entered;
  Completer<void>? openGate;
  Completer<void>? writeGate;
  Completer<void>? writeEntered;

  @override
  Future<void> open() async {
    final pending = openGate;
    if (pending != null) await pending.future;
  }

  @override
  Future<Uint8List?> readSealed(String id) async {
    final value = records[id];
    return value == null ? null : Uint8List.fromList(value);
  }

  @override
  Future<void> writeSealed(String id, Uint8List sealed) async {
    writes++;
    entered?.complete();
    writeEntered?.complete();
    final pending = gate ?? writeGate;
    if (pending != null) await pending.future;
    if (failWrite) throw StateError('synthetic physical failure');
    records[id] = mismatchReadback
        ? Uint8List.fromList([0, ...sealed])
        : Uint8List.fromList(sealed);
    if (failFlush) throw StateError('synthetic visible/durable split');
    durable[id] = Uint8List.fromList(records[id]!);
  }

  void crash() {
    records = {
      for (final entry in durable.entries)
        entry.key: Uint8List.fromList(entry.value),
    };
  }

  @override
  Future<Uint8List> sealSealed(
    IssuanceVaultContext context,
    Uint8List plaintext,
  ) async {
    return Uint8List.fromList([0xA5, ...plaintext]);
  }

  @override
  Future<Uint8List> openSealed(
    IssuanceVaultContext context,
    Uint8List sealed,
  ) async {
    if (sealed.isEmpty || sealed[0] != 0xA5) {
      throw const IssuanceVaultCorrupt('synthetic authentication failure');
    }
    return Uint8List.fromList(sealed.sublist(1));
  }

  @override
  Future<void> close() async {
    closeCalls++;
  }
}

const String storeA =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const String storeB =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

Map<String, String> record(String revision) => {
  'schema': '1',
  'revision': revision,
  'uid': 'a' * 32,
  'phase': 'prepared',
};


final class HeldRealBackend implements IssuanceVaultBackend {
  HeldRealBackend(this.inner);
  final PosixFileVaultBackend inner;
  final Completer<void> entered = Completer<void>();
  final Completer<void> gate = Completer<void>();

  @override
  Future<void> open() => inner.open();

  @override
  Future<Uint8List?> readSealed(String id) => inner.readSealed(id);

  @override
  Future<Uint8List> sealSealed(IssuanceVaultContext c, Uint8List b) =>
      inner.sealSealed(c, b);

  @override
  Future<Uint8List> openSealed(IssuanceVaultContext c, Uint8List b) =>
      inner.openSealed(c, b);

  @override
  Future<void> writeSealed(String id, Uint8List b) async {
    if (!entered.isCompleted) entered.complete();
    await gate.future;
    await inner.writeSealed(id, b);
  }

  @override
  Future<void> close() => inner.close();
}
void main() {
  late FakeBackend backend;
  late FakeLease lease;
  late IssuanceJournalVault vault;
  late IssuanceVaultContext context;

  setUp(() async {
    backend = FakeBackend();
    lease = FakeLease();
    vault = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: lease,
    );
    context = vault.context;
    await vault.open();
  });

  test('absent record is null and wrong id is a context error', () async {
    expect(await vault.read(vault.vaultId), isNull);
    await expectLater(
      vault.read('state${'0' * 64}'),
      throwsA(isA<IssuanceVaultContextMismatch>()),
    );
  });

  test('round trip preserves the record', () async {
    await vault.write(vault.vaultId, record('0'));
    final read = await vault.read(vault.vaultId);
    expect(read, isNotNull);
    expect(read!['revision'], '0');
    expect(read['phase'], 'prepared');
  });

  test('record disappearing after ready is corruption, not null', () async {
    await vault.write(vault.vaultId, record('0'));
    backend.records.remove(vault.vaultId);
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultCorrupt>()),
    );
  });

  test('oversized record is rejected before the backend', () async {
    final writesBefore = backend.writes;
    await expectLater(
      vault.write(vault.vaultId, {'revision': '0', 'x': 'a' * 600000}),
      throwsA(isA<FormatException>()),
    );
    expect(backend.writes, writesBefore);
  });

  test('context mismatch inside the envelope is rejected', () async {
    final plain = utf8.encode(
      jsonEncode({
        'v': 1,
        'id': context.vaultId,
        'store': storeB,
        'rev': 0,
        'data': record('0'),
      }),
    );
    backend.records[vault.vaultId] = Uint8List.fromList([0xA5, ...plain]);
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultContextMismatch>()),
    );
  });

  test('float version 1.0 is not accepted as integer version 1', () async {
    final backend = FakeBackend();
    final vault = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    final plain = utf8.encode(
      jsonEncode({
        'v': 1.0,
        'id': vault.vaultId,
        'store': storeA,
        'rev': 0,
        'data': record('0'),
      }),
    );
    backend.records[vault.vaultId] = Uint8List.fromList([0xA5, ...plain]);
    await expectLater(
      vault.open(),
      throwsA(isA<IssuanceVaultContextMismatch>()),
    );
  });

  test('negative or non-canonical revision is corruption', () async {
    for (final variant in <Map<String, String>>[
      {'revision': '-1'},
      {'revision': '09'},
    ]) {
      final backend = FakeBackend();
      final vault = IssuanceJournalVault(
        storeIdentity: storeA,
        backend: backend,
        lease: FakeLease(),
      );
      final raw = int.tryParse(variant['revision']!) ?? 0;
      final plain = utf8.encode(
        jsonEncode({
          'v': 1,
          'id': vault.vaultId,
          'store': storeA,
          'rev': raw,
          'data': variant,
        }),
      );
      backend.records[vault.vaultId] = Uint8List.fromList([0xA5, ...plain]);
      await expectLater(
        vault.open(),
        throwsA(isA<IssuanceVaultCorrupt>()),
      );
    }
  });

  test('revision mismatch between header and payload is corruption', () async {
    final plain = utf8.encode(
      jsonEncode({
        'v': 1,
        'id': context.vaultId,
        'store': storeA,
        'rev': 0,
        'data': record('1'),
      }),
    );
    backend.records[vault.vaultId] = Uint8List.fromList([0xA5, ...plain]);
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultCorrupt>()),
    );
  });

  test('write failure propagates as an unknown outcome', () async {
    backend.failWrite = true;
    await expectLater(
      vault.write(vault.vaultId, record('0')),
      throwsA(isA<StateError>()),
    );
    expect(await vault.read(vault.vaultId), isNull);
  });

  test('readback mismatch is durability-unknown', () async {
    backend.mismatchReadback = true;
    await expectLater(
      vault.write(vault.vaultId, record('0')),
      throwsA(isA<IssuanceVaultDurabilityUnknown>()),
    );
  });

  test('close waits for admitted physical I/O and stops new admissions', () async {
    backend.entered = Completer<void>();
    backend.gate = Completer<void>();
    final write = vault.write(vault.vaultId, record('0'));
    await backend.entered!.future;
    var closed = false;
    final closing = vault.close().then((_) => closed = true);
    await Future<void>.delayed(Duration.zero);
    expect(closed, isFalse);
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultClosed>()),
    );
    backend.gate!.complete();
    await write;
    await closing;
    expect(closed, isTrue);
    expect(lease.releases, 1);
  });

  test('real POSIX backend: key, corruption and missing-key behavior', () async {
    if (!Platform.isLinux) return;
    final root = Directory.systemTemp.createTempSync('xio-issuance-unit-');
    try {
      final v = await openPosixJournalVault(
        directory: root,
        storeIdentity: storeA,
      );
      await v.write(v.vaultId, record('0'));
      expect((await v.read(v.vaultId))!['phase'], 'prepared');
      await v.close();

      final key = File('${root.path}/issuance.key');
      expect(await key.exists(), isTrue);

      // The backend file name is derived from the id, not the context digest.
      final actual = await root
          .list()
          .where((e) => e is File && e.path.endsWith('.bin'))
          .cast<File>()
          .toList();
      expect(actual.length, 1);
      await actual.single.writeAsBytes(Uint8List.fromList([1, 2, 3]));
      await expectLater(
        openPosixJournalVault(directory: root, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultCorrupt>()),
      );

      await key.delete();
      await expectLater(
        openPosixJournalVault(directory: root, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultKeyUnavailable>()),
      );
      expect(await key.exists(), isFalse);

    } finally {
      await root.delete(recursive: true);
    }
  });

  test('fresh open → absent → clean close → reopen is idempotent', () async {
    final backend = FakeBackend();
    final first = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await first.open();
    expect(await first.read(first.vaultId), isNull);
    await first.close();
    final second = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await second.open();
    expect(await second.read(second.vaultId), isNull);
    await second.close();
  });

  test('read before bootstrap is ready is refused', () async {
    final backend = FakeBackend()..openGate = Completer<void>();
    final vault = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    final opening = vault.open();
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultClosed>()),
    );
    backend.openGate!.complete();
    await opening;
    await vault.close();
  });

  test('read is refused while the bootstrap fence is still physical', () async {
    final backend = FakeBackend();
    final seed = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await seed.open();
    await seed.write(seed.vaultId, record('1'));
    await seed.close();

    backend.writeEntered = Completer<void>();
    backend.writeGate = Completer<void>();
    final vault = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    final opening = vault.open();
    await backend.writeEntered!.future;
    await expectLater(
      vault.read(vault.vaultId),
      throwsA(isA<IssuanceVaultClosed>()),
    );
    backend.writeGate!.complete();
    await opening;
    await vault.close();
  });

  test('authenticated missing payload is corruption, not absence', () async {
    final backend = FakeBackend();
    final vault = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    final plain = utf8.encode(
      jsonEncode({
        'v': 1,
        'id': vault.vaultId,
        'store': storeA,
        'rev': 0,
      }),
    );
    backend.records[vault.vaultId] = Uint8List.fromList([0xA5, ...plain]);
    await expectLater(
      vault.open(),
      throwsA(isA<IssuanceVaultCorrupt>()),
    );
  });

  test('bootstrap fence makes a recovered visible record durable before exposure', () async {
    final backend = FakeBackend();
    final lease = FakeLease();
    final first = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: lease,
    );
    await first.open();
    backend.failFlush = true;
    await expectLater(
      first.write(first.vaultId, record('0')),
      throwsA(isA<StateError>()),
    );
    // Visible new intent, durable state still empty; A's latch is process-local.
    expect(backend.records, isNotEmpty);

    backend.failFlush = false;
    final restarted = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await restarted.open();
    expect(backend.durable, isNotEmpty);
    final read = await restarted.read(restarted.vaultId);
    expect(read?['revision'], '0');

    // A later power-loss model keeps the fenced record.
    backend.crash();
    final afterCrash = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await afterCrash.open();
    expect((await afterCrash.read(afterCrash.vaultId))?['revision'], '0');
  });

  test('bootstrap fence failure is DurabilityUnknown and exposes nothing', () async {
    final backend = FakeBackend();
    final first = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await first.open();
    backend.failFlush = true;
    await expectLater(
      first.write(first.vaultId, record('0')),
      throwsA(isA<StateError>()),
    );

    final restarted = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await expectLater(
      restarted.open(),
      throwsA(isA<IssuanceVaultDurabilityUnknown>()),
    );
    // The volatile intent is not authorized: a later power loss loses it.
    backend.crash();
    backend.failFlush = false;
    final afterCrash = IssuanceJournalVault(
      storeIdentity: storeA,
      backend: backend,
      lease: FakeLease(),
    );
    await afterCrash.open();
    expect(await afterCrash.read(afterCrash.vaultId), isNull);
  });

  test('POSIX key fence loads an immutable key and rejects a short key', () async {
    if (!Platform.isLinux) return;
    final root = Directory.systemTemp.createTempSync('xio-issuance-key-unit-');
    final badRoot = Directory.systemTemp.createTempSync('xio-issuance-badkey-unit-');
    try {
      final key = File('${root.path}/issuance.key');
      final bytes = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      await key.writeAsBytes(bytes, flush: true);
      final chmod = await Process.run('/bin/chmod', ['600', key.path]);
      expect(chmod.exitCode, 0);
      final v = await openPosixJournalVault(
        directory: root,
        storeIdentity: storeA,
      );
      await v.write(v.vaultId, record('0'));
      expect((await v.read(v.vaultId))!['revision'], '0');
      expect(await key.readAsBytes(), bytes);
      await v.close();

      await File('${badRoot.path}/issuance.key')
          .writeAsBytes(Uint8List.fromList([1, 2, 3]), flush: true);
      await expectLater(
        openPosixJournalVault(directory: badRoot, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultKeyUnavailable>()),
      );
    } finally {
      await root.delete(recursive: true);
      await badRoot.delete(recursive: true);
    }
  });

  test('real POSIX close waits for the held bootstrap and retains the lease', () async {
    if (!Platform.isLinux) return;
    final root = Directory.systemTemp.createTempSync('xio-issuance-close-');
    try {
      final seed = await openPosixJournalVault(
        directory: root,
        storeIdentity: storeA,
      );
      await seed.write(seed.vaultId, {
        'revision': '1',
        'phase': 'dispatchIntent',
      });
      await seed.close();

      final backend = HeldRealBackend(PosixFileVaultBackend(directory: root));
      final lease = PosixJournalLease.acquire('${root.path}/xio-issuance-lease');
      final old = IssuanceJournalVault(
        storeIdentity: storeA,
        backend: backend,
        lease: lease,
      );
      final opening = old.open();
      await backend.entered.future;
      var closeDone = false;
      final closing = old.close().then((_) => closeDone = true);
      await Future<void>.delayed(Duration.zero);
      expect(closeDone, isFalse);
      await expectLater(
        openPosixJournalVault(directory: root, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultBusy>()),
      );
      backend.gate.complete();
      await opening;
      await closing;
      final finalOwner = await openPosixJournalVault(
        directory: root,
        storeIdentity: storeA,
      );
      expect((await finalOwner.read(finalOwner.vaultId))?['revision'], '1');
      await finalOwner.close();
    } finally {
      await root.delete(recursive: true);
    }
  });

  test('POSIX record symlink or non-regular node is corrupt at bootstrap', () async {
    if (!Platform.isLinux) return;
    final root = Directory.systemTemp.createTempSync('xio-issuance-link-');
    try {
      final v = await openPosixJournalVault(
        directory: root,
        storeIdentity: storeA,
      );
      await v.write(v.vaultId, record('0'));
      await v.close();
      final recordFile = (await root
              .list()
              .where((e) => e is File && e.path.endsWith('.bin'))
              .cast<File>()
              .toList())
          .single;
      final recordPath = recordFile.path;
      final target = File('${root.path}/decoy-target');
      await target.writeAsBytes([1, 2, 3], flush: true);
      await recordFile.delete();
      await Link(recordPath).create(target.path);
      await expectLater(
        openPosixJournalVault(directory: root, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultCorrupt>()),
      );
      await Link(recordPath).delete();
      await Directory(recordPath).create();
      await expectLater(
        openPosixJournalVault(directory: root, storeIdentity: storeA),
        throwsA(isA<IssuanceVaultCorrupt>()),
      );
    } finally {
      await root.delete(recursive: true);
    }
  });
}