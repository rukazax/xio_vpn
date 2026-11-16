import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/issuance_canonical.dart';
import 'package:xio/issuance_journal.dart';

const String _uid1 = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const String _uid2 = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf';

final Uint8List _privateA = decodeCanonicalHex(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  length: 32,
);
final String _privateAB64 = canonicalBase64(_privateA);
final String _publicAB64 = base64Encode(
  Uint8List.fromList(List<int>.generate(32, (i) => i)),
);

String _storeId([int seed = 0]) {
  final random = Random.secure();
  final bytes = Uint8List(32);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = random.nextInt(256) ^ seed;
  }
  return canonicalHex(bytes);
}

Map<String, Object?> _requestFor(String uid) => {
  'action': 'issuance',
  'schema': 1,
  'uid': uid,
  'nameSha256': issuanceNameSha256('alice'),
  'publicKeys': {'awg': _publicAB64, 'wireguard': _publicAB64},
  'protocols': ['awg', 'rivet'],
};

Map<String, String> _material() => {
  'capsuleRecipientPrivateKey': _privateAB64,
  'entryToken': base64Encode(List<int>.generate(32, (i) => i + 1)),
  'deviceSecret': base64Encode(List<int>.generate(32, (i) => i + 2)),
};

// Logical decrypted views of a hypothetical encrypted provider. Success writes
// are durable; a failed flush leaves the new bytes VISIBLE while the durable
// view remains the previous record. This is a storage-failure model, not an
// encrypted backend or a measured fsync test.
class MemoryVault {
  final Map<String, Map<String, String>> data = {};
  final Map<String, Map<String, String>> durable = {};
  int writes = 0;
  int activeWrites = 0;
  int maxActiveWrites = 0;
  bool failBeforeWrite = false;
  bool failFlush = false;
  bool failBeforeOnce = false;
  bool corruptReadBack = false;
  Completer<void>? gate;
  Completer<void> entered = Completer<void>();

  Future<void> write(String id, Map<String, String> value) async {
    activeWrites++;
    if (activeWrites > maxActiveWrites) maxActiveWrites = activeWrites;
    try {
      writes++;
      if (!entered.isCompleted) entered.complete();
      final pending = gate;
      if (pending != null) await pending.future;
      if (failBeforeOnce) {
        failBeforeOnce = false;
        throw StateError('unclassified storage failure');
      }
      if (failBeforeWrite) throw StateError('disk full');
      data[id] = Map<String, String>.of(value);
      if (corruptReadBack) {
        final corrupted = Map<String, String>.of(value);
        corrupted['revision'] = '999';
        data[id] = corrupted;
      }
      if (failFlush) {
        throw StateError('rename visible; directory fsync failed');
      }
      durable[id] = Map<String, String>.of(value);
    } finally {
      activeWrites--;
    }
  }

  Future<Map<String, String>?> read(String id) async =>
      data[id] == null ? null : Map<String, String>.of(data[id]!);

  /// Simulated power loss: the visible view reverts to the durable one.
  void crash() {
    data
      ..clear()
      ..addAll(
        durable.map(
          (key, value) => MapEntry(key, Map<String, String>.of(value)),
        ),
      );
  }

  IssuanceJournalStore store() =>
      IssuanceJournalStore(read: read, write: write);
}

Future<IssuanceRecord> _prepare(
  IssuanceJournalStore store,
  String storeIdentity,
  String uid, {
  Map<String, String>? material,
}) => store.prepare(
  storeIdentity: storeIdentity,
  uid: uid,
  serverId: 'srv-test-1',
  sshFingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  actor: 'owner',
  request: _requestFor(uid),
  material: material ?? _material(),
  capsuleRecipientPublicKey: Uint8List.fromList(_privateA),
);

void main() {
  test('prepare persists an encrypted record that survives a restart', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final record = await _prepare(vault.store(), identity, _uid1);
    expect(record.revision, 0);
    expect(record.phase, IssuancePhase.prepared);
    expect(record.dispatchIntent, isFalse);
    expect(record.isUnresolved, isTrue);
    expect(vault.data.length, 1);

    final restarted = MemoryVault()..data.addAll({
      IssuanceJournalStore.vaultId(identity):
          Map<String, String>.of(vault.data.values.single),
    });
    final loaded = await restarted.store().load(identity);
    expect(loaded, isNotNull);
    expect(loaded!.uid, _uid1);
    expect(loaded.operationId, record.operationId);
    expect(loaded.requestDigest, issuanceRequestDigest(_requestFor(_uid1)));
    expect(loaded.request, _requestFor(_uid1));
    expect(loaded.materialSha256('entryToken'), record.materialSha256('entryToken'));
    expect(loaded.capsuleRecipientPublicKey, _privateA);
  });

  test('a second prepare is refused while one issuance is unresolved', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    await _prepare(store, identity, _uid1);
    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalConflict>()),
    );
    expect(vault.data.length, 1);
  });

  test('two store instances interleaved: exactly one prepare survives', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final first = vault.store();
    final second = vault.store();

    Future<String> attempt(IssuanceJournalStore store, String uid) async {
      try {
        await _prepare(store, identity, uid);
        return 'ok';
      } on IssuanceJournalConflict {
        return 'conflict';
      } catch (error) {
        return 'other:$error';
      }
    }

    final results = await Future.wait([
      attempt(first, _uid1),
      attempt(second, _uid2),
    ]);
    expect(results.where((value) => value == 'ok').length, 1);
    expect(results.where((value) => value == 'conflict').length, 1);
    expect(vault.data.length, 1);
    final loaded = await first.load(identity);
    expect(loaded, isNotNull);
    expect(loaded!.isUnresolved, isTrue);
  });

  test('dispatch intent precedes the remote call and cannot be skipped', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final dispatched = await store.markDispatchIntent(prepared);
    expect(dispatched.phase, IssuancePhase.dispatchIntent);
    expect(dispatched.dispatchIntent, isTrue);
    expect(dispatched.revision, 1);

    final loaded = await store.load(identity);
    expect(loaded!.dispatchIntent, isTrue);
    await expectLater(
      store.markDispatchIntent(dispatched),
      throwsA(isA<IssuanceJournalConflict>()),
    );
    await expectLater(
      store.abandonPrepared(dispatched),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('prepared abandonment releases the slot without deleting bytes', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final abandoned = await store.abandonPrepared(prepared);
    expect(abandoned.flags, contains('cancelledConfirmed'));
    expect(abandoned.isUnresolved, isFalse);
    expect(vault.data.length, 1);
    final replacement = await _prepare(store, identity, _uid2);
    expect(replacement.uid, _uid2);
    expect(replacement.revision, 0);
  });

  test('stale revision is a conflict, never a blind overwrite', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final dispatched = await store.markDispatchIntent(prepared);
    expect(dispatched.revision, 1);
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('a pending physical write blocks prepare, abandon and dispatch', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);

    vault.entered = Completer<void>();
    vault.gate = Completer<void>();
    final inFlight = store.markDispatchIntent(prepared);
    await vault.entered.future;

    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalBusy>()),
    );
    await expectLater(
      store.abandonPrepared(prepared),
      throwsA(isA<IssuanceJournalBusy>()),
    );
    await expectLater(
      store.load(identity),
      completes,
    );

    vault.gate!.complete();
    vault.gate = null;
    final dispatched = await inFlight;
    expect(dispatched.dispatchIntent, isTrue);
    expect(vault.data.length, 1);
  });

  test('write failing before persistence stays unlatched after resolve', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    vault.failBeforeWrite = true;
    await expectLater(
      _prepare(store, identity, _uid1),
      throwsA(isA<StateError>()),
    );
    expect(vault.data, isEmpty);
    expect(await store.resolveUncertain(identity), isNull);
    vault.failBeforeWrite = false;
    final prepared = await _prepare(store, identity, _uid1);
    expect(prepared.uid, _uid1);
  });

  test('write persisted then threw: resolve returns the intended record', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    vault.failFlush = true;
    await expectLater(
      _prepare(store, identity, _uid1),
      throwsA(isA<StateError>()),
    );
    vault.failFlush = false;
    final resolved = await store.resolveUncertain(identity);
    expect(resolved, isNotNull);
    expect(resolved!.uid, _uid1);
    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('read-back mismatch latches as unknown and stays fail-closed', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    vault.corruptReadBack = true;
    await expectLater(
      _prepare(store, identity, _uid1),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
    vault.corruptReadBack = false;
    await expectLater(
      store.resolveUncertain(identity),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
  });

  test('remote result is idempotent and the first capsule digest cannot rotate', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final dispatched = await store.markDispatchIntent(prepared);
    final receipt = <String, Object?>{
      'user': {'id': _uid1, 'slot': 2},
      'phase': 'complete',
    };
    final digest = 'a'.padRight(64, 'a');
    final complete = await store.remoteResult(
      dispatched,
      receipt: receipt,
      capsuleDigest: digest,
    );
    expect(complete.phase, IssuancePhase.remoteComplete);
    expect(complete.capsuleDigest, digest);

    final replay = await store.remoteResult(
      complete,
      receipt: receipt,
      capsuleDigest: digest,
    );
    expect(replay.revision, complete.revision);

    await expectLater(
      store.remoteResult(
        complete,
        receipt: receipt,
        capsuleDigest: 'b'.padRight(64, 'b'),
      ),
      throwsA(isA<IssuanceJournalConflict>()),
    );
    await expectLater(
      store.remoteResult(
        complete,
        receipt: {'phase': 'other'},
        capsuleDigest: digest,
      ),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('failure retains the dispatched phase and only safe codes', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final dispatched = await store.markDispatchIntent(prepared);
    final failed = await store.fail(dispatched, 'TIMEOUT');
    expect(failed.phase, IssuancePhase.dispatchIntent);
    expect(failed.errorCode, 'TIMEOUT');
    expect(failed.dispatchIntent, isTrue);
    await expectLater(
      store.fail(failed, 'NOT_A_CODE'),
      throwsFormatException,
    );
    await expectLater(
      store.fail(prepared, 'TIMEOUT'),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('local commit phases are monotonic and typed', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    await expectLater(
      store.commitLocal(prepared, 'c'.padRight(64, 'c')),
      throwsA(isA<IssuanceJournalConflict>()),
    );
    final dispatched = await store.markDispatchIntent(prepared);
    final complete = await store.remoteResult(
      dispatched,
      receipt: {'phase': 'complete'},
    );
    await expectLater(
      store.markCommitted(complete),
      throwsA(isA<IssuanceJournalConflict>()),
    );
    final staged = await store.commitLocal(complete, 'c'.padRight(64, 'c'));
    expect(staged.phase, IssuancePhase.localStaged);
    expect(staged.localSnapshotDigest, 'c'.padRight(64, 'c'));
    final unconfirmed = await store.markLocalUnconfirmed(staged);
    expect(unconfirmed.phase, IssuancePhase.localDurableNativeUnconfirmed);
    final committed = await store.markCommitted(unconfirmed);
    expect(committed.phase, IssuancePhase.committed);
    expect(committed.isUnresolved, isFalse);
  });

  test('receipt and material are deep-copied and redacted', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final material = _material();
    final prepared = await _prepare(
      store,
      identity,
      _uid1,
      material: material,
    );
    final tokenPrint = prepared.materialSha256('entryToken');
    material['entryToken'] = base64Encode(List<int>.filled(32, 9));
    final dispatched = await store.markDispatchIntent(prepared);
    final receipt = <String, Object?>{
      'user': {'id': _uid1},
    };
    final complete = await store.remoteResult(dispatched, receipt: receipt);
    expect(complete.phase, IssuancePhase.remoteComplete);
    receipt['user'] = {'id': 'tampered'};

    final loaded = await store.load(identity);
    expect(loaded!.materialSha256('entryToken'), tokenPrint);
    expect(
      (loaded.receipt!['user'] as Map)['id'],
      _uid1,
    );
    expect(loaded.toString(), isNot(contains(_material()['entryToken']!)));
    expect(loaded.toString(), 'IssuanceRecord([redacted])');
  });

  test('corrupt vault bytes fail closed without rewriting them', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    await _prepare(store, identity, _uid1);
    final key = IssuanceJournalStore.vaultId(identity);
    final raw = Map<String, String>.of(vault.data.values.single);
    raw.remove('uid');
    vault.data[key] = raw;
    await expectLater(store.load(identity), throwsFormatException);
    expect(vault.data[key], raw);
  });

  test('vault ids match the desktop credential namespace exactly', () {
    final identity = _storeId();
    final id = IssuanceJournalStore.vaultId(identity);
    expect(id.length, 69);
    expect(id.startsWith('state'), isTrue);
    expect(
      RegExp(r'^(?:ssh|vpn|state)[a-f0-9]{64}$').hasMatch(id),
      isTrue,
    );
    expect(() => IssuanceJournalStore.vaultId('short'), throwsFormatException);
  });

  test('durability failure on prepare stays unknown until recommitted', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    vault.failFlush = true;
    await expectLater(
      _prepare(store, identity, _uid1),
      throwsA(isA<StateError>()),
    );
    expect(vault.data.length, 1);
    expect(vault.durable, isEmpty);
    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
    vault.failFlush = false;
    final writesBefore = vault.writes;
    final resolved = await vault.store().resolveUncertain(identity);
    expect(resolved, isNotNull);
    expect(resolved!.phase, IssuancePhase.prepared);
    expect(vault.writes, writesBefore + 1);
    expect(vault.durable.length, 1);
  });

  test('durability failure on abandon stays unknown until recommitted', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.abandonPrepared(prepared),
      throwsA(isA<StateError>()),
    );
    await expectLater(
      _prepare(store, identity, _uid2),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
    vault.failFlush = false;
    final resolved = await store.resolveUncertain(identity);
    expect(resolved!.flags, contains('cancelledConfirmed'));
    expect(vault.durable.length, 1);
  });

  test('visible dispatch never survives a crash unless recommitted durably', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<StateError>()),
    );
    // A crash loses the volatile dispatch record; the durable view is PREPARED.
    vault.crash();
    vault.failFlush = false;
    final restarted = vault.store();
    final resolved = await restarted.resolveUncertain(identity);
    expect(resolved!.phase, IssuancePhase.prepared);
    expect(resolved.dispatchIntent, isFalse);
    final abandoned = await restarted.abandonPrepared(resolved);
    expect(abandoned.flags, contains('cancelledConfirmed'));
  });

  test('recommitted dispatch survives a crash and blocks abandonment', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<StateError>()),
    );
    vault.failFlush = false;
    final resolved = await store.resolveUncertain(identity);
    expect(resolved!.phase, IssuancePhase.dispatchIntent);
    expect(resolved.dispatchIntent, isTrue);
    // The recommit made the dispatch durable, so a power loss keeps it.
    vault.crash();
    final restarted = vault.store();
    final recovered = await restarted.load(identity);
    expect(recovered!.phase, IssuancePhase.dispatchIntent);
    await expectLater(
      restarted.abandonPrepared(recovered),
      throwsA(isA<IssuanceJournalConflict>()),
    );
  });

  test('queued prepare cannot cross an unknown boundary', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final writesBefore = vault.writes;
    vault.failBeforeOnce = true;
    final first = store.markDispatchIntent(prepared);
    final queued = _prepare(store, identity, _uid2);
    final outcomes = await Future.wait<Object>([
      first.then<Object>((value) => value).catchError((Object error) => error),
      queued.then<Object>((value) => value).catchError((Object error) => error),
    ]);
    expect(outcomes[0], isA<StateError>());
    expect(outcomes[1], isA<IssuanceJournalUnknown>());
    expect(vault.writes, writesBefore + 1);
  });

  test('queued dispatch cannot cross an unknown boundary', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final writesBefore = vault.writes;
    vault.failBeforeOnce = true;
    final first = store.abandonPrepared(prepared);
    final queued = store.markDispatchIntent(prepared);
    final outcomes = await Future.wait<Object>([
      first.then<Object>((value) => value).catchError((Object error) => error),
      queued.then<Object>((value) => value).catchError((Object error) => error),
    ]);
    expect(outcomes[0], isA<StateError>());
    expect(outcomes[1], isA<IssuanceJournalUnknown>());
    expect(vault.writes, writesBefore + 1);
  });

  test('queued abandon cannot cross an unknown boundary', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    final writesBefore = vault.writes;
    vault.failBeforeOnce = true;
    final first = store.markDispatchIntent(prepared);
    final queued = store.abandonPrepared(prepared);
    final outcomes = await Future.wait<Object>([
      first.then<Object>((value) => value).catchError((Object error) => error),
      queued.then<Object>((value) => value).catchError((Object error) => error),
    ]);
    expect(outcomes[0], isA<StateError>());
    expect(outcomes[1], isA<IssuanceJournalUnknown>());
    expect(vault.writes, writesBefore + 1);
  });

  test('concurrent resolvers share one barrier and cannot rewind a receipt', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<StateError>()),
    );
    vault.failFlush = false;
    final visible = (await store.load(identity))!; // dispatchIntent, revision 1
    final writesBefore = vault.writes;
    vault.entered = Completer<void>();
    vault.gate = Completer<void>();
    final one = store.resolveUncertain(identity);
    await vault.entered.future;
    final two = vault.store().resolveUncertain(identity);
    vault.gate!.complete();
    vault.gate = null;
    final first = await one;
    final second = await two;
    expect(first!.phase, IssuancePhase.dispatchIntent);
    expect(second, isA<IssuanceRecord>());
    expect(vault.maxActiveWrites, 1);
    expect(vault.writes, writesBefore + 1);
    final receipt = await store.remoteResult(
      visible,
      receipt: {'synthetic': 'complete'},
    );
    expect(receipt.phase, IssuancePhase.remoteComplete);
    final finalRecord = (await store.load(identity))!;
    expect(finalRecord.phase, IssuancePhase.remoteComplete);
    expect(finalRecord.revision, 2);
    expect(finalRecord.receipt, isNotNull);
  });

  test('failed recovery releases the lane and a second instance can settle', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<StateError>()),
    );
    final first = vault.store().resolveUncertain(identity);
    final second = vault.store().resolveUncertain(identity);
    await expectLater(first, throwsA(isA<IssuanceJournalUnknown>()));
    await expectLater(second, throwsA(isA<IssuanceJournalUnknown>()));
    await expectLater(
      _prepare(vault.store(), identity, _uid2),
      throwsA(isA<IssuanceJournalUnknown>()),
    );
    vault.failFlush = false;
    final resolved = await vault.store().resolveUncertain(identity);
    expect(resolved!.phase, IssuancePhase.dispatchIntent);
    expect(vault.maxActiveWrites, 1);
  });

  test('resolver queued behind a newer receipt returns the current record', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final prepared = await _prepare(store, identity, _uid1);
    vault.failFlush = true;
    await expectLater(
      store.markDispatchIntent(prepared),
      throwsA(isA<StateError>()),
    );
    vault.failFlush = false;
    final visible = (await store.load(identity))!;

    // Negative: while the recovery barrier is held, a mutation must fast-reject
    // instead of joining the lane. This is the contract the earlier fixture
    // violated by calling remoteResult under the held recovery write.
    vault.entered = Completer<void>();
    vault.gate = Completer<void>();
    final recovery = store.resolveUncertain(identity);
    await vault.entered.future;
    await expectLater(
      store.remoteResult(visible, receipt: {'early': 'must-not-write'}),
      throwsA(isA<IssuanceJournalBusy>()),
    );
    vault.gate!.complete();
    vault.gate = null;
    final resolved = (await recovery)!;
    expect(resolved.phase, IssuancePhase.dispatchIntent);

    // Finish recovery first. Then hold the NEW receipt write and queue a
    // resolver behind that write; the resolver must read CURRENT rev2 and
    // perform no write or stale barrier.
    final writesBefore = vault.writes;
    vault.entered = Completer<void>();
    vault.gate = Completer<void>();
    final physical = store.remoteResult(
      resolved,
      receipt: {'synthetic': 'complete'},
    );
    await vault.entered.future;
    final resolver = vault.store().resolveUncertain(identity);
    vault.gate!.complete();
    vault.gate = null;
    final acked = await physical;
    final current = (await resolver)!;
    expect(acked.phase, IssuancePhase.remoteComplete);
    expect(current.phase, IssuancePhase.remoteComplete);
    expect(current.revision, 2);
    expect(current.receipt!['synthetic'], 'complete');
    // Only the receipt write happened; the resolver performed zero writes.
    expect(vault.writes, writesBefore + 1);
  });

  test('oversized or unknown material is rejected before any write', () async {
    final vault = MemoryVault();
    final identity = _storeId();
    final store = vault.store();
    final oversized = _material()
      ..['managementPrivate'] = 'a'.padRight(5000, 'a');
    await expectLater(
      _prepare(store, identity, _uid1, material: oversized),
      throwsFormatException,
    );
    final unknown = _material()..['evilKey'] = _privateAB64;
    await expectLater(
      _prepare(store, identity, _uid1, material: unknown),
      throwsFormatException,
    );
    final missing = _material()..remove('capsuleRecipientPrivateKey');
    await expectLater(
      _prepare(store, identity, _uid1, material: missing),
      throwsFormatException,
    );
    expect(vault.data, isEmpty);
  });
}
