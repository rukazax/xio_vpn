// G5 Slice B — bounded issuance vault provider.
//
// This is the storage/encryption/lease layer behind Slice A's two callbacks
// (`read`, `write`). A's API is unchanged: a successful `write` is a durable
// commit, and any throw means the durable outcome is unknown.
//
// Design constraints (see work/G5-SLICE-B-PLAN-20261106.md and the Windows
// durability review):
// * Entire record is encrypted and authenticated as one bounded snapshot.
// * The encrypted envelope binds version + vaultId + storeIdentity; the header
//   is validated after decrypt before any map is exposed. A filename/row id is
//   routing only, never authentication.
// * One journal-specific session lease spans all A callbacks; it is acquired
//   before any read and released only after physical I/O settles.
// * Missing key with existing ciphertext fails closed; no generic crypto
//   create-on-read and no plaintext fallback.
import 'dart:async';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

const int issuanceVaultVersion = 1;
const int issuanceVaultMaxPlaintext = 512 * 1024;
const int issuanceVaultMaxCiphertext = 1024 * 1024;
const String issuanceVaultIdPrefix = 'xio-issuance/v1/';

/// Authenticated context for one journal in one product Store.
final class IssuanceVaultContext {
  IssuanceVaultContext({
    required this.version,
    required this.vaultId,
    required this.storeIdentity,
  }) {
    if (version != issuanceVaultVersion) {
      throw const FormatException('Unsupported issuance vault version');
    }
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(storeIdentity)) {
      throw const FormatException('Invalid store identity');
    }
    if (!RegExp(r'^state[a-f0-9]{64}$').hasMatch(vaultId)) {
      throw const FormatException('Invalid vault id');
    }
  }

  final int version;
  final String vaultId;
  final String storeIdentity;

  /// Canonical bytes used as AES-GCM AAD / DPAPI optional entropy.
  Uint8List get aad => Uint8List.fromList(
    utf8.encode('$version|$vaultId|$storeIdentity'),
  );

  String get digestHex => sha256.convert(aad).toString();

  static String vaultIdFor(String storeIdentity) =>
      'state${sha256.convert(utf8.encode('$issuanceVaultIdPrefix$storeIdentity'))}';
}

sealed class IssuanceVaultException implements Exception {
  const IssuanceVaultException(this.message);
  final String message;
  @override
  String toString() => '$runtimeType: $message';
}

final class IssuanceVaultBusy extends IssuanceVaultException {
  const IssuanceVaultBusy(super.message);
}

final class IssuanceVaultClosed extends IssuanceVaultException {
  const IssuanceVaultClosed(super.message);
}

class IssuanceVaultCorrupt extends IssuanceVaultException {
  const IssuanceVaultCorrupt(super.message);
}

final class IssuanceVaultDurabilityUnknown extends IssuanceVaultException {
  const IssuanceVaultDurabilityUnknown(super.message);
}

final class IssuanceVaultKeyUnavailable extends IssuanceVaultException {
  const IssuanceVaultKeyUnavailable(super.message);
}

final class IssuanceVaultContextMismatch extends IssuanceVaultCorrupt {
  const IssuanceVaultContextMismatch(super.message);
}

final class IssuanceVaultUnsupported extends IssuanceVaultException {
  const IssuanceVaultUnsupported(super.message);
}

/// Storage + crypto boundary. Implementations MUST encrypt before persisting
/// and MUST treat every write error as an unknown durable outcome, never as
/// "no effect".
abstract interface class IssuanceVaultBackend {
  /// Opens/qualifies the backend. Must not create a new parent hierarchy.
  Future<void> open();

  /// Returns the sealed ciphertext for [id], or null only when the record is
  /// genuinely absent. Corruption/unsupported storage throws.
  Future<Uint8List?> readSealed(String id);

  /// Durable write of one whole sealed record. Returns only after the platform
  /// barrier succeeds; throws when the outcome is unknown.
  Future<void> writeSealed(String id, Uint8List sealed);

  /// Authenticated encryption with the context as AAD/entropy.
  Future<Uint8List> sealSealed(IssuanceVaultContext context, Uint8List plaintext);

  /// Authenticated decryption; throws Corrupt on any authentication failure.
  Future<Uint8List> openSealed(IssuanceVaultContext context, Uint8List sealed);

  /// Releases physical resources after all admitted I/O has settled.
  Future<void> close();
}

/// One journal-specific physical lease. Never the Store document writer and
/// never a native policy claim.
abstract interface class IssuanceJournalLease {
  bool get held;

  /// True only in the isolate that acquired this lease. Native handles must
  /// never be acted on by another isolate.
  bool get ownedByCurrentIsolate;

  /// Runs [io] while holding the lease and counts it as outstanding physical
  /// work. New admissions are refused once close starts; release waits.
  Future<T> admit<T>(Future<T> Function() io);

  /// Stops new admissions, waits for outstanding I/O, then releases the OS
  /// lease. A timeout in a caller does not cancel this.
  Future<void> closeWhenSettled();
}

/// Shared settlement logic for platform leases.
@pragma('vm:isolate-unsendable')
abstract base class SettlingJournalLease implements IssuanceJournalLease {
  int _pending = 0;
  bool _closing = false;
  bool _held = false;
  SendPort? _ownerPort;
  Completer<void>? _drained;

  @override
  bool get held => _held;

  void markHeld() {
    _held = true;
    _ownerPort = Isolate.current.controlPort;
  }

  /// A copied object (if the VM ever allowed it) or a different isolate must
  /// never act on the native handle.
  @override
  bool get ownedByCurrentIsolate =>
      _ownerPort != null && _ownerPort == Isolate.current.controlPort;

  @override
  Future<T> admit<T>(Future<T> Function() io) async {
    if (!ownedByCurrentIsolate) {
      throw const IssuanceVaultUnsupported(
        'Issuance journal lease is not owned by this isolate',
      );
    }
    if (_closing || !_held) {
      throw const IssuanceVaultClosed('Issuance journal lease is closed');
    }
    _pending++;
    try {
      return await io();
    } finally {
      _pending--;
      if (_closing && _pending == 0) {
        _drained?.complete();
      }
    }
  }

  @override
  Future<void> closeWhenSettled() async {
    if (!ownedByCurrentIsolate) {
      throw const IssuanceVaultUnsupported(
        'Issuance journal lease is not owned by this isolate',
      );
    }
    if (_closing) return;
    _closing = true;
    if (_pending > 0) {
      _drained = Completer<void>();
      await _drained!.future;
    }
    try {
      await release();
    } finally {
      _held = false;
    }
  }

  Future<void> release();
}

enum _VaultState { initial, opening, ready, closing, closed, failed }

/// Bounded provider implementing A's `read`/`write`.
final class IssuanceJournalVault {
  IssuanceJournalVault({
    required this.storeIdentity,
    required this.backend,
    required this.lease,
  }) : context = IssuanceVaultContext(
         version: issuanceVaultVersion,
         vaultId: IssuanceVaultContext.vaultIdFor(storeIdentity),
         storeIdentity: storeIdentity,
       ) {
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(storeIdentity)) {
      throw const FormatException('Invalid store identity');
    }
  }

  final String storeIdentity;
  final IssuanceVaultContext context;
  final IssuanceVaultBackend backend;
  final IssuanceJournalLease lease;

  _VaultState _state = _VaultState.initial;
  bool _closeRequested = false;
  bool _cleanupTried = false;
  bool _cleaned = false;
  Future<void> _tail = Future<void>.value();
  Future<void>? _closeFuture;
  int _inFlight = 0;
  Completer<void>? _idle;

  String get vaultId => context.vaultId;

  Future<T> _enqueue<T>(Future<T> Function() body) {
    final run = _tail.then((_) => body());
    _tail = run.then<void>((_) {}, onError: (Object error, StackTrace stack) {});
    return run;
  }

  Future<T> _admitted<T>(Future<T> Function() io) async {
    _inFlight++;
    try {
      return await lease.admit(io);
    } finally {
      _inFlight--;
      if (_inFlight == 0) _idle?.complete();
    }
  }

  Future<void> _waitIdle() async {
    if (_inFlight == 0) return;
    _idle = Completer<void>();
    await _idle!.future;
  }

  Future<void> open() {
    if (_state != _VaultState.initial) {
      return Future<void>.error(
        const IssuanceVaultClosed('Issuance vault is not openable'),
      );
    }
    _state = _VaultState.opening;
    return _enqueue(() async {
      try {
        // Qualification, key/DB open and the bootstrap fence are all admitted
        // physical work; a concurrent close waits for this future.
        await _admitted(() async {
          await backend.open();
          await _bootstrapFence();
        });
        _state = _closeRequested
            ? _VaultState.closing
            : _VaultState.ready;
      } catch (_) {
        _state = _VaultState.failed;
        await _cleanupFailedOpen();
        rethrow;
      }
    });
  }

  Future<bool> _cleanupFailedOpen() async {
    if (_cleaned) return true;
    if (_cleanupTried) return false;
    _cleanupTried = true;
    try {
      // Backend destruction first, while the lease is still held; release only
      // after the backend's physical close returns.
      await backend.close();
      await lease.closeWhenSettled();
      _cleaned = true;
      return true;
    } catch (_) {
      // Keep authority (lease held) rather than pretending the release was
      // confirmed.
      return false;
    }
  }

  Future<void> _bootstrapFence() async {
    final sealed = await backend.readSealed(context.vaultId);
    if (sealed == null) {
      // A missing record on a new/empty backend is initialized as an
      // authenticated ABSENT tombstone, committed through the same durable
      // write path before the provider becomes ready. This makes a fresh
      // open→read-null→close→reopen idempotent instead of rejecting the
      // schema-less file the backend just created.
      final plain = _encodeAbsentEnvelope();
      final fresh = await backend.sealSealed(context, plain);
      try {
        await backend.writeSealed(context.vaultId, fresh);
      } on IssuanceVaultDurabilityUnknown {
        rethrow;
      } catch (_) {
        throw const IssuanceVaultDurabilityUnknown(
          'Initial absent tombstone could not be committed durably',
        );
      }
      return;
    }
    if (sealed.length > issuanceVaultMaxCiphertext) {
      throw const IssuanceVaultCorrupt('Bootstrap record exceeds the cap');
    }
    final plain = await backend.openSealed(context, sealed);
    // Validates version/id/store/revision and payload shape. A null payload is
    // the authenticated absent tombstone; it is re-committed too.
    _decodeEnvelope(plain);
    final fresh = await backend.sealSealed(context, plain);
    try {
      await backend.writeSealed(context.vaultId, fresh);
    } on IssuanceVaultDurabilityUnknown {
      rethrow;
    } catch (_) {
      throw const IssuanceVaultDurabilityUnknown(
        'Bootstrap durability fence failed; recovered record is not durable',
      );
    }
  }

  Future<void> close() {
    if (_state == _VaultState.closed) return Future<void>.value();
    final existing = _closeFuture;
    if (existing != null) return existing;
    _closeRequested = true;
    if (_state == _VaultState.initial) {
      _state = _VaultState.closed;
      final future = _enqueue(() async {
        await lease.closeWhenSettled();
      });
      _closeFuture = future;
      return future;
    }
    final future = _enqueue(() async {
      if (_state == _VaultState.closed) return;
      if (_state == _VaultState.failed) {
        final cleaned = await _cleanupFailedOpen();
        if (!cleaned) {
          throw const IssuanceVaultDurabilityUnknown(
            'Opening cleanup could not confirm physical release; lease retained',
          );
        }
        _state = _VaultState.closed;
        return;
      }
      _state = _VaultState.closing;
      // All admitted read/write/open physical work must settle before the
      // backend is destroyed. The lease is still held here.
      await _waitIdle();
      try {
        await backend.close();
      } catch (_) {
        // Retain authority; the lease is not released on an unconfirmed close.
        _state = _VaultState.failed;
        rethrow;
      }
      await lease.closeWhenSettled();
      _state = _VaultState.closed;
    });
    _closeFuture = future;
    return future;
  }

  Future<Map<String, String>?> read(String id) {
    if (_state != _VaultState.ready || _closeRequested) {
      return Future<Map<String, String>?>.error(
        const IssuanceVaultClosed('Issuance vault is not ready'),
      );
    }
    if (id != context.vaultId) {
      return Future<Map<String, String>?>.error(
        const IssuanceVaultContextMismatch('Vault id does not match the context'),
      );
    }
    return _enqueue(() async {
      if (_state != _VaultState.ready || _closeRequested) {
        throw const IssuanceVaultClosed('Issuance vault is not ready');
      }
      return _admitted(() async {
        final sealed = await backend.readSealed(id);
        if (sealed == null) {
          // Bootstrap always commits an authenticated ABSENT tombstone before
          // ready. A null after ready means the bound row disappeared: that is
          // corruption/loss, never fresh absence.
          throw const IssuanceVaultCorrupt(
            'Journal record disappeared after the bootstrap was ready',
          );
        }
        if (sealed.length > issuanceVaultMaxCiphertext) {
          throw const IssuanceVaultCorrupt(
            'Ciphertext exceeds the bounded size',
          );
        }
        final plain = await backend.openSealed(context, sealed);
        return _decodeEnvelope(plain);
      });
    });
  }

  Future<void> write(String id, Map<String, String> data) {
    if (_state != _VaultState.ready || _closeRequested) {
      return Future<void>.error(
        const IssuanceVaultClosed('Issuance vault is not ready'),
      );
    }
    if (id != context.vaultId) {
      return Future<void>.error(
        const IssuanceVaultContextMismatch('Vault id does not match the context'),
      );
    }
    return _enqueue(() async {
      if (_state != _VaultState.ready || _closeRequested) {
        throw const IssuanceVaultClosed('Issuance vault is not ready');
      }
      await _admitted(() async {
        final plain = _encodeEnvelope(Map<String, String>.of(data));
        if (plain.length > issuanceVaultMaxPlaintext) {
          throw const FormatException('Issuance record too large');
        }
        final sealed = await backend.sealSealed(context, plain);
        if (sealed.length > issuanceVaultMaxCiphertext) {
          throw const FormatException('Sealed issuance record too large');
        }
        await backend.writeSealed(id, sealed);
        final readback = await backend.readSealed(id);
        if (readback == null || !_sameBytes(readback, sealed)) {
          throw const IssuanceVaultDurabilityUnknown(
            'Sealed record readback does not match the committed bytes',
          );
        }
      });
    });
  }
  Uint8List _encodeAbsentEnvelope() {
    final envelope = <String, Object?>{
      'v': context.version,
      'id': context.vaultId,
      'store': context.storeIdentity,
      'rev': 0,
      'data': null,
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(envelope)));
  }

  Uint8List _encodeEnvelope(Map<String, String> data) {
    final rawRevision = data['revision'];
    final revision = rawRevision == null ? null : int.tryParse(rawRevision);
    if (revision == null ||
        revision < 0 ||
        rawRevision != revision.toString()) {
      throw const IssuanceVaultCorrupt(
        'Record revision must be a canonical non-negative integer',
      );
    }
    final envelope = <String, Object?>{
      'v': context.version,
      'id': context.vaultId,
      'store': context.storeIdentity,
      'rev': revision,
      'data': data,
    };
    final encoded = utf8.encode(jsonEncode(envelope));
    return Uint8List.fromList(encoded);
  }

  Map<String, String>? _decodeEnvelope(Uint8List plain) {
    if (plain.isEmpty || plain.length > issuanceVaultMaxPlaintext) {
      throw const IssuanceVaultCorrupt('Plaintext exceeds the bounded size');
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(plain));
    } on FormatException {
      throw const IssuanceVaultCorrupt('Envelope is not valid JSON');
    }
    if (decoded is! Map) {
      throw const IssuanceVaultCorrupt('Envelope is not an object');
    }
    final envelope = decoded.cast<String, Object?>();
    const expectedKeys = {'v', 'id', 'store', 'rev', 'data'};
    if (envelope.length != expectedKeys.length ||
        !envelope.keys.every(expectedKeys.contains)) {
      throw const IssuanceVaultCorrupt('Envelope has an invalid field set');
    }
    if (!envelope.containsKey('data')) {
      throw const IssuanceVaultCorrupt('Envelope data field is missing');
    }
    final version = envelope['v'];
    if (version is! int ||
        version != context.version ||
        envelope['id'] != context.vaultId ||
        envelope['store'] != context.storeIdentity) {
      throw const IssuanceVaultContextMismatch(
        'Envelope context does not match the requested journal',
      );
    }
    final revision = envelope['rev'];
    if (revision is! int || revision < 0) {
      throw const IssuanceVaultCorrupt(
        'Envelope revision is not a non-negative integer',
      );
    }
    // `data: null` is the explicit authenticated absent tombstone; a missing
    // field was rejected above and is corruption, not absence.
    final data = envelope['data'];
    if (data == null) return null;
    if (data is! Map) {
      throw const IssuanceVaultCorrupt('Envelope payload is not an object');
    }
    final record = <String, String>{};
    for (final entry in data.entries) {
      final key = entry.key;
      final value = entry.value;
      if (key is! String || value is! String) {
        throw const IssuanceVaultCorrupt('Envelope payload is not string-valued');
      }
      record[key] = value;
    }
    final rawRecordRevision = record['revision'];
    final recordRevision = rawRecordRevision == null
        ? null
        : int.tryParse(rawRecordRevision);
    if (recordRevision == null ||
        recordRevision < 0 ||
        recordRevision != revision ||
        rawRecordRevision != revision.toString()) {
      throw const IssuanceVaultCorrupt(
        'Envelope revision and canonical payload revision disagree',
      );
    }
    return record;
  }

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}

String issuanceVaultRandomHex(int bytes) {
  final random = Random.secure();
  final buffer = StringBuffer();
  for (var i = 0; i < bytes; i++) {
    buffer.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
