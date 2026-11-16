import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/policy_publication.dart';

class ControlledIO implements PublicationIO {
  final calls = <String>[];
  final gates = <String, Completer<void>>{};
  final entered = <String, Completer<void>>{};
  String? fail;
  String nativeCache = 'old-ready', nativeDisk = 'old-ready';
  String documentDisk = 'old-document';
  String? falseCommitDisk;
  Directory? directory;
  Completer<void> hold(String step) {
    entered[step] = Completer<void>();
    return gates[step] = Completer<void>();
  }
  Future<void> step(String name) async {
    calls.add(name);
    final entry = entered[name];
    if (entry != null && !entry.isCompleted) entry.complete();
    final gate = gates.remove(name);
    if (gate != null) await gate.future;
    if (fail == name) throw StateError('fixture $name');
  }
  @override
  Future<void> begin(PublicationSnapshot snapshot) async {
    await step('begin');
    nativeCache = nativeDisk = 'pending:${snapshot.transactionId}';
  }
  @override
  Future<void> writeDocument(PublicationSnapshot snapshot, void Function() renamed) async {
    await step('write');
    if (directory != null) {
      final tmp = File('${directory!.path}/profiles.tmp');
      await tmp.writeAsString(snapshot.documentBytes, flush: true);
      await tmp.rename('${directory!.path}/profiles.json');
    }
    documentDisk = snapshot.documentBytes;
    renamed();
    await step('postRename');
  }
  @override
  Future<void> commit(PublicationSnapshot snapshot) async {
    await step('commit');
    nativeCache = 'ready:${snapshot.generation}';
    if (falseCommitDisk != null) {
      nativeDisk = falseCommitDisk!;
      throw StateError('commit false');
    }
    nativeDisk = nativeCache;
  }
  @override
  Future<void> block(PublicationSnapshot snapshot) async {
    await step('block');
    nativeCache = nativeDisk = 'blocked';
  }
}

PublicationSnapshot snapshot(int id) => PublicationSnapshot(
  transactionId: id.toRadixString(16).padLeft(32, '0'),
  generation: (id + 100).toRadixString(16).padLeft(32, '0'),
  document: {'connectionPolicy': {'mode': 'selectedOnly', 'roundMillis': 30000}, 'selected': 'awg$id'},
  plan: {'ids': ['awg$id']},
);

void main() {
  test('deep immutable paired snapshot cannot be changed through aliases', () {
    final document = <String, dynamic>{'nested': [{'selected': 'a'}]};
    final plan = <String, dynamic>{'ids': ['a']};
    final value = PublicationSnapshot(transactionId: 'a' * 32, generation: 'b' * 32, document: document, plan: plan);
    (document['nested'] as List).clear();
    (plan['ids'] as List).add('other');
    (value.plan['ids'] as List).clear();
    expect(value.document['nested'], [{'selected': 'a'}]);
    expect(value.plan['ids'], ['a']);
  });
  test('actual writer happy path ACKs only after commit', () async {
    final io = ControlledIO();
    final writer = PolicyPublicationWriter(io);
    final gate = io.hold('commit');
    final value = snapshot(1);
    final future = writer.publish(value);
    await io.entered['commit']!.future;
    expect(writer.writing, isTrue);
    expect(writer.committed, isNull);
    expect(io.nativeDisk, startsWith('pending:'));
    gate.complete();
    expect(await future, same(value));
    expect(writer.publicationReady, isTrue);
    expect(io.calls, ['begin', 'write', 'postRename', 'commit']);
  });
  for (final event in ['down', 'dispose', 'timeout']) {
    test('physical late IO remains owned after $event until block settles', () async {
      final io = ControlledIO();
      final writer = PolicyPublicationWriter(io);
      final oldIO = io.hold('commit');
      final blockedIO = io.hold('block');
      final a = writer.publish(snapshot(1), wait: event == 'timeout' ? const Duration(milliseconds: 20) : const Duration(seconds: 5));
      final failed = expectLater(a, throwsA(isA<PublicationFailure>()));
      await io.entered['commit']!.future;
      if (event == 'down') writer.revoke();
      if (event == 'dispose') writer.dispose();
      if (event == 'timeout') await failed;
      expect(writer.writing, isTrue);
      await expectLater(writer.publish(snapshot(2)), throwsA(isA<PublicationFailure>()));
      oldIO.complete();
      await io.entered['block']!.future;
      expect(io.nativeDisk, startsWith('ready:')); // Late physical write DID happen.
      expect(writer.writing, isTrue);
      await expectLater(writer.publish(snapshot(3), reconcile: true), throwsA(isA<PublicationFailure>()));
      blockedIO.complete();
      await writer.settled;
      await failed;
      expect(writer.blocked, isTrue);
      expect(io.nativeDisk, 'blocked');
      expect(writer.committed, isNull);
      if (event != 'dispose') {
        await writer.publish(snapshot(4), reconcile: true);
        expect(io.nativeDisk, 'ready:${snapshot(4).generation}');
      }
    });
  }
  for (final cut in ['begin', 'write', 'postRename', 'commit']) {
    test('physical failure at $cut retains exact rename outcome', () async {
      final io = ControlledIO()..fail = cut;
      final writer = PolicyPublicationWriter(io);
      final expected = ['postRename', 'commit'].contains(cut)
          ? PublicationPhase.renamedNativeUnconfirmed : PublicationPhase.beforeRename;
      await expectLater(writer.publish(snapshot(1)), throwsA(isA<PublicationFailure>().having((e) => e.phase, 'phase', expected)));
      expect(writer.blocked, isTrue);
      expect(io.nativeDisk, 'blocked');
      if (expected == PublicationPhase.renamedNativeUnconfirmed) {
        expect(jsonDecode(io.documentDisk)['selected'], 'awg1');
      } else { expect(io.documentDisk, 'old-document'); }
    });
  }
  for (final disk in ['old-ready', 'pending', 'new-ready']) {
    test('false commit with independent $disk durable state is never ACK', () async {
      final io = ControlledIO()..falseCommitDisk = disk;
      final block = io.hold('block');
      final writer = PolicyPublicationWriter(io);
      final failed = expectLater(writer.publish(snapshot(1)), throwsA(isA<PublicationFailure>()));
      await io.entered['block']!.future;
      expect(io.nativeCache, startsWith('ready:'));
      expect(io.nativeDisk, disk);
      expect(writer.writing, isTrue);
      expect(writer.committed, isNull);
      block.complete();
      await failed;
      expect(io.nativeDisk, 'blocked');
    });
  }
  test('failed blocked reconciliation never releases admission readiness', () async {
    final io = ControlledIO()..falseCommitDisk = 'old-ready'..fail = 'block';
    final writer = PolicyPublicationWriter(io);
    await expectLater(writer.publish(snapshot(1)), throwsA(isA<PublicationFailure>()));
    expect(writer.writing, isFalse);
    expect(writer.publicationReady, isFalse);
    await expectLater(writer.publish(snapshot(2)), throwsA(isA<PublicationFailure>()));
    io.fail = null;
    io.falseCommitDisk = null;
    await writer.publish(snapshot(3), reconcile: true);
    expect(writer.publicationReady, isTrue);
  });
  test('real owned file rename is not undone by postwrite failure', () async {
    final directory = await Directory.systemTemp.createTemp('policy-publication-');
    addTearDown(() => directory.delete(recursive: true));
    final io = ControlledIO()..directory = directory..fail = 'postRename';
    final writer = PolicyPublicationWriter(io);
    await expectLater(writer.publish(snapshot(1)), throwsA(isA<PublicationFailure>().having((e) => e.phase, 'phase', PublicationPhase.renamedNativeUnconfirmed)));
    expect(jsonDecode(await File('${directory.path}/profiles.json').readAsString())['selected'], 'awg1');
    expect(writer.committed, isNull);
  });
  test('timeout before rename is pendingUnknown, not compensation proof', () async {
    final io = ControlledIO();
    final write = io.hold('write');
    final writer = PolicyPublicationWriter(io);
    final failed = expectLater(
      writer.publish(snapshot(1), wait: const Duration(milliseconds: 20)),
      throwsA(isA<PublicationFailure>().having(
        (e) => e.phase, 'phase', PublicationPhase.pendingUnknown,
      )),
    );
    await io.entered['write']!.future;
    await failed;
    expect(io.documentDisk, 'old-document');
    expect(writer.writing, isTrue);
    write.complete();
    await writer.settled;
    expect(jsonDecode(io.documentDisk)['selected'], 'awg1');
    expect(io.calls, isNot(contains('commit')));
    expect(io.nativeDisk, 'blocked');
  });
  test('transaction replay with different content rejects without any IO', () async {
    final io = ControlledIO();
    final writer = PolicyPublicationWriter(io);
    final a = snapshot(1);
    await writer.publish(a);
    final before = io.calls.length;
    expect(await writer.publish(a), same(a));
    final changed = PublicationSnapshot(transactionId: a.transactionId, generation: a.generation, document: {}, plan: {});
    await expectLater(writer.publish(changed), throwsA(isA<PublicationFailure>()));
    expect(io.calls.length, before);
  });
  test('queued screenshot intents count before body and remain serializable', () {
    final gate = StoreMutationAdmission();
    final first = gate.ordinary(), second = gate.ordinary();
    expect(gate.policy, throwsStateError);
    first.release();
    expect(gate.policy, throwsStateError);
    second.release();
    final mode = gate.policy();
    expect(gate.ordinary, throwsStateError);
    mode.revoke();
    expect(gate.policy, throwsStateError); // Logical revoke is not release.
    mode.release();
    final third = gate.ordinary();
    gate.dispose();
    expect(third.current, isFalse);
    expect(gate.busy, isTrue);
    third.release();
    expect(gate.busy, isFalse);
  });
}
