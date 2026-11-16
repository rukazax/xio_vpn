import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'credentials.dart';
import 'native_cascade_plan.dart';

enum NativeCascadeSetupStep {
  prepared,
  exitConfigured,
  bridgeConfigured,
  verified,
  profileBound,
  complete,
}

enum NativeCascadeOperation { configure, reconcile, verify, remove }

/// Private resumable intent. No toJson: ordinary state/exports must contain only
/// the public plan identity, never this object or its encrypted-vault payload.
class NativeCascadeJournal {
  NativeCascadeJournal._({
    required this.plan,
    required this.keys,
    required this.operationId,
    required this.revision,
    required this.step,
    this.pendingNode,
    this.pendingOperation,
    this.errorCode,
  });
  final NativeCascadePlan plan;
  final NativeCascadeKeys keys;
  final String operationId;
  final int revision;
  final NativeCascadeSetupStep step;
  final NativeCascadeRole? pendingNode;
  final NativeCascadeOperation? pendingOperation;
  final String? errorCode;

  Map<String, String> toVault() => {
    'schema': '1',
    'plan': jsonEncode(plan.toJson()),
    'keys': jsonEncode(keys.toVault()),
    'operationId': operationId,
    'revision': '$revision',
    'step': step.name,
    'pendingNode': pendingNode?.name ?? '',
    'pendingOperation': pendingOperation?.name ?? '',
    'errorCode': errorCode ?? '',
  };

  static const safeErrorCodes = {
    'OWNER_REQUIRED',
    'SERVER_IDENTITY',
    'INVALID_REQUEST',
    'MODULE_UNAVAILABLE',
    'PREFLIGHT_FAILED',
    'INVALID_RESULT',
    'TIMEOUT',
    'IO_FAILURE',
    'OPERATION_FAILED',
    'LOCAL_TIMEOUT',
    'CANCELLED',
    'JOURNAL_FAILURE',
  };

  static Future<NativeCascadeJournal> _parse(Map<String, String> data) async {
    const fields = {
      'schema',
      'plan',
      'keys',
      'operationId',
      'revision',
      'step',
      'pendingNode',
      'pendingOperation',
      'errorCode',
    };
    try {
      if (data['schema'] != '1' ||
          data.length != fields.length ||
          !data.keys.every(fields.contains)) {
        throw const FormatException();
      }
      final plan = NativeCascadePlan.fromJson(jsonDecode(data['plan']!));
      final keys = await NativeCascadeKeys.fromVault(
        Map<String, String>.from(jsonDecode(data['keys']!)),
      );
      final operationId = data['operationId']!;
      if (operationId.length != 32 ||
          !RegExp(r'^[a-f0-9]{32}$').hasMatch(operationId)) {
        throw const FormatException();
      }
      final revision = int.tryParse(data['revision']!);
      if (revision == null || revision < 0 || '$revision' != data['revision']) {
        throw const FormatException();
      }
      final step = NativeCascadeSetupStep.values.singleWhere(
        (x) => x.name == data['step'],
      );
      final node = data['pendingNode'] == ''
          ? null
          : NativeCascadeRole.values.singleWhere(
              (x) => x.name == data['pendingNode'],
            );
      final operation = data['pendingOperation'] == ''
          ? null
          : NativeCascadeOperation.values.singleWhere(
              (x) => x.name == data['pendingOperation'],
            );
      if ((node == null) != (operation == null)) {
        throw const FormatException();
      }
      final error = data['errorCode']!;
      if (error.isNotEmpty && !safeErrorCodes.contains(error)) {
        throw const FormatException();
      }
      return NativeCascadeJournal._(
        plan: plan,
        keys: keys,
        operationId: operationId,
        revision: revision,
        step: step,
        pendingNode: node,
        pendingOperation: operation,
        errorCode: error.isEmpty ? null : error,
      );
    } catch (_) {
      // Never regenerate keys after corruption, nor echo a decoded private map.
      throw const FormatException('Invalid encrypted cascade setup journal');
    }
  }

  @override
  String toString() =>
      'NativeCascadeJournal(${plan.identity}, ${step.name}, [redacted])';
}

typedef NativeJournalRead = Future<Map<String, String>?> Function(String id);
typedef NativeJournalWrite = Future<void> Function(
  String id,
  Map<String, String> data,
);

/// Serializes all instances for the same plan within this app process. Vault
/// writes are awaited before callers may send mutations; stale writers cannot
/// replace newer private material. Multiple OS processes are not supported.
class NativeCascadeJournalStore {
  NativeCascadeJournalStore({
    NativeJournalRead? read,
    NativeJournalWrite? write,
  }) : _read = read ?? CredentialVault.read,
       _write = write ?? CredentialVault.write;
  final NativeJournalRead _read;
  final NativeJournalWrite _write;
  static final Map<String, Future<void>> _tails = {};

  static String vaultId(String identity) {
    if (identity.length != 64 ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(identity)) {
      throw const FormatException('Invalid cascade plan identity');
    }
    return CredentialVault.id('native-cascade', 0, 'setup', scope: identity);
  }

  Future<T> _exclusive<T>(String identity, Future<T> Function() body) async {
    final previous = _tails[identity] ?? Future<void>.value();
    final done = Completer<void>();
    final tail = done.future;
    _tails[identity] = tail;
    try {
      await previous;
      return await body();
    } finally {
      done.complete();
      if (identical(_tails[identity], tail)) _tails.remove(identity);
    }
  }

  Future<NativeCascadeJournal?> _load(String identity) async {
    final data = await _read(vaultId(identity));
    if (data == null) return null;
    final result = await NativeCascadeJournal._parse(data);
    if (result.plan.identity != identity) {
      throw const FormatException('Cascade journal identity mismatch');
    }
    return result;
  }

  Future<void> _persist(NativeCascadeJournal value) async {
    final id = vaultId(value.plan.identity);
    final expected = value.toVault();
    await _write(id, expected);
    final actual = await _read(id);
    if (actual == null ||
        actual.length != expected.length ||
        !expected.entries.every((entry) => actual[entry.key] == entry.value)) {
      throw StateError('Encrypted cascade journal write was not confirmed');
    }
  }

  Future<NativeCascadeJournal> open(NativeCascadePlan plan) =>
      _exclusive(plan.identity, () async {
        final existing = await _load(plan.identity);
        if (existing != null) return existing;
        final random = Random.secure();
        final id = List.generate(
          16,
          (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
        ).join();
        final result = NativeCascadeJournal._(
          plan: plan,
          keys: await NativeCascadeKeys.generate(),
          operationId: id,
          revision: 0,
          step: NativeCascadeSetupStep.prepared,
        );
        await _persist(result);
        return result;
      });

  Future<NativeCascadeJournal> _change(
    NativeCascadeJournal previous, {
    NativeCascadeSetupStep? step,
    NativeCascadeRole? pendingNode,
    NativeCascadeOperation? pendingOperation,
    String? errorCode,
  }) => _exclusive(previous.plan.identity, () async {
    final current = await _load(previous.plan.identity);
    if (current == null ||
        current.revision != previous.revision ||
        current.operationId != previous.operationId) {
      throw StateError(
        'Cascade journal changed; inspect and resume its latest intent',
      );
    }
    final next = NativeCascadeJournal._(
      plan: current.plan,
      keys: current.keys,
      operationId: current.operationId,
      revision: current.revision + 1,
      step: step ?? current.step,
      pendingNode: pendingNode,
      pendingOperation: pendingOperation,
      errorCode: errorCode,
    );
    // Reuse the strict reader to reject accidental inconsistent/error payloads.
    await NativeCascadeJournal._parse(next.toVault());
    await _persist(next);
    return next;
  });

  /// Must complete BEFORE the corresponding remote mutating call is admitted.
  Future<NativeCascadeJournal> begin(
    NativeCascadeJournal value,
    NativeCascadeRole node,
    NativeCascadeOperation operation,
  ) {
    if (value.pendingOperation != null) {
      throw StateError(
        'Inspect the unknown remote outcome before another mutation',
      );
    }
    return _change(value, pendingNode: node, pendingOperation: operation);
  }

  /// Keeps pending identity+keys on timeout/error. No delete or direct rollback.
  Future<NativeCascadeJournal> uncertain(
    NativeCascadeJournal value,
    String safeCode,
  ) {
    if (value.pendingOperation == null) {
      throw StateError('No pending cascade operation');
    }
    return _change(
      value,
      pendingNode: value.pendingNode,
      pendingOperation: value.pendingOperation,
      errorCode: safeCode,
    );
  }

  /// Caller must bind an authenticated inspection/proof to BOTH plan identities
  /// and exact public configuration before using this method after uncertainty.
  Future<NativeCascadeJournal> confirm(
    NativeCascadeJournal value,
    NativeCascadeSetupStep step,
  ) {
    if (step.index < value.step.index || step.index > value.step.index + 1) {
      throw StateError('Invalid cascade setup transition');
    }
    return _change(value, step: step);
  }
}
