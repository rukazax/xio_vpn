import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/native_cascade_journal.dart';
import 'package:xio/native_cascade_plan.dart';

NativeCascadePlan plan([String host = '2001:db8::20']) {
  final pin = 'SHA256:${'A' * 43}';
  return NativeCascadePlan(
    bridge: NativeCascadeTarget(
      serverId: 'bridge',
      hostKey: pin,
      publicHost: '198.51.100.10',
      exit: false,
    ),
    exit: NativeCascadeTarget(
      serverId: 'exit',
      hostKey: pin,
      publicHost: host,
      exit: true,
    ),
    families: {NativeCascadeFamily.ipv6},
    exitInterfaces: {NativeCascadeFamily.ipv6: 'eth0'},
  );
}

class MemoryVault {
  final data = <String, Map<String, String>>{};
  int writes = 0;
  Future<void> write(String id, Map<String, String> value) async {
    writes++;
    data[id] = Map.of(value);
  }

  Future<Map<String, String>?> read(String id) async =>
      data[id] == null ? null : Map.of(data[id]!);
  NativeCascadeJournalStore store() =>
      NativeCascadeJournalStore(read: read, write: write);
}

void main() {
  test('keys persist before open returns and restart reuses exactly the same intent', () async {
    final vault = MemoryVault();
    final first = await vault.store().open(plan());
    final second = await vault.store().open(plan());
    expect(second.operationId, first.operationId);
    expect(second.keys.toVault(), first.keys.toVault());
    expect(second.step, NativeCascadeSetupStep.prepared);
    expect(vault.writes, 1);
    expect(jsonEncode(vault.data.values.single).length, lessThan(32768));
  });
  test(
    'parallel instances cannot overwrite each others first key material',
    () async {
      final vault = MemoryVault();
      final results = await Future.wait(
        List.generate(5, (_) => vault.store().open(plan())),
      );
      expect(results.map((v) => v.operationId).toSet(), hasLength(1));
      expect(
        results.map((v) => jsonEncode(v.keys.toVault())).toSet(),
        hasLength(1),
      );
      expect(vault.writes, 1);
    },
  );
  test(
    'write is awaited and failed persistence never admits a returned intent',
    () async {
      final vault = MemoryVault(),
          gate = Completer<void>(),
          started = Completer<void>();
      final store = NativeCascadeJournalStore(
        read: vault.read,
        write: (id, value) async {
          started.complete();
          await gate.future;
          await vault.write(id, value);
        },
      );
      var completed = false;
      final pending = store.open(plan()).then((v) {
        completed = true;
        return v;
      });
      await started.future;
      expect(completed, isFalse);
      expect(vault.data, isEmpty);
      gate.complete();
      await pending;
      expect(completed, isTrue);
      final failing = NativeCascadeJournalStore(
        read: (id) async => null,
        write: (id, data) async => throw StateError('disk unavailable'),
      );
      await expectLater(failing.open(plan('203.0.113.20')), throwsStateError);
    },
  );
  test(
    'missing write readback fails and reordered maps remain valid',
    () async {
      final noReadback = NativeCascadeJournalStore(
        read: (id) async => null,
        write: (id, value) async {},
      );
      await expectLater(noReadback.open(plan()), throwsStateError);
      final vault = MemoryVault();
      final store = NativeCascadeJournalStore(
        write: vault.write,
        read: (id) async {
          final raw = await vault.read(id);
          return raw == null
              ? null
              : Map.fromEntries(raw.entries.toList().reversed);
        },
      );
      expect((await store.open(plan())).revision, 0);
    },
  );
  test('unknown remote outcomes preserve operation identity keys and pending action', () async {
    final vault = MemoryVault(), store = vault.store();
    final opened = await store.open(plan());
    final pending = await store.begin(
      opened,
      NativeCascadeRole.exit,
      NativeCascadeOperation.configure,
    );
    final uncertain = await store.uncertain(pending, 'TIMEOUT');
    final resumed = await vault.store().open(plan());
    expect(resumed.operationId, opened.operationId);
    expect(resumed.keys.toVault(), opened.keys.toVault());
    expect(resumed.pendingNode, NativeCascadeRole.exit);
    expect(resumed.pendingOperation, NativeCascadeOperation.configure);
    expect(resumed.errorCode, 'TIMEOUT');
    expect(
      () => store.begin(
        uncertain,
        NativeCascadeRole.bridge,
        NativeCascadeOperation.configure,
      ),
      throwsStateError,
    );
    final confirmed = await store.confirm(
      resumed,
      NativeCascadeSetupStep.exitConfigured,
    );
    expect(confirmed.pendingOperation, isNull);
    expect(confirmed.errorCode, isNull);
    expect(confirmed.keys.toVault(), opened.keys.toVault());
  });
  test(
    'stale caller cannot roll journal backwards or replace newer state',
    () async {
      final vault = MemoryVault(), store = vault.store();
      final opened = await store.open(plan());
      final pending = await store.begin(
        opened,
        NativeCascadeRole.exit,
        NativeCascadeOperation.configure,
      );
      await expectLater(
        store.confirm(opened, NativeCascadeSetupStep.exitConfigured),
        throwsStateError,
      );
      expect((await store.open(plan())).revision, pending.revision);
      expect(
        () => store.confirm(pending, NativeCascadeSetupStep.complete),
        throwsStateError,
      );
    },
  );
  test(
    'corrupt private record never regenerates or prints private contents',
    () async {
      final vault = MemoryVault(), store = vault.store();
      final opened = await store.open(plan());
      final id = NativeCascadeJournalStore.vaultId(plan().identity);
      vault.data[id]!['keys'] = 'PRIVATE_SENTINEL';
      try {
        await store.open(plan());
        fail('accepted corruption');
      } on FormatException catch (error) {
        expect(error.toString(), isNot(contains('PRIVATE_SENTINEL')));
      }
      expect(vault.writes, 1);
      expect(
        opened.toString(),
        isNot(contains(opened.keys.toVault()['bridgePrivate']!)),
      );
      expect(
        () => jsonEncode(opened),
        throwsA(isA<JsonUnsupportedObjectError>()),
      );
    },
  );
  test(
    'different target/configuration cannot be resumed under the old identity',
    () async {
      final vault = MemoryVault(), store = vault.store();
      await store.open(plan());
      final id = NativeCascadeJournalStore.vaultId(plan().identity);
      vault.data[id]!['plan'] = jsonEncode(plan('203.0.113.20').toJson());
      await expectLater(store.open(plan()), throwsFormatException);
      expect(vault.writes, 1);
      expect(
        () => NativeCascadeJournalStore.vaultId('../secret'),
        throwsFormatException,
      );
    },
  );
}
