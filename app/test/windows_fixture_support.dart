// Pure-Dart Windows fixture scenarios, shared by the Flutter wrapper and the
// plain-Dart runner. No Flutter dependency: the same body can execute in the
// allowed plain-Dart Windows mode without the blocked Flutter frontend.
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:xio/issuance_vault.dart';
import 'package:xio/issuance_vault_windows.dart';

class RawSqlite {
  RawSqlite() {
    final kernel = DynamicLibrary.open('kernel32.dll');
    final getDir = kernel.lookupFunction<
      Uint32 Function(Pointer<Utf16>, Uint32),
      int Function(Pointer<Utf16>, int)
    >('GetSystemDirectoryW');
    final buffer = calloc<Uint16>(260);
    final length = getDir(buffer.cast<Utf16>(), 260);
    if (length == 0 || length >= 260) {
      calloc.free(buffer);
      throw StateError('System directory unavailable');
    }
    final system = buffer.cast<Utf16>().toDartString();
    calloc.free(buffer);
    final lib = DynamicLibrary.open('$system\\winsqlite3.dll');
    _open = lib.lookupFunction<_OpenC, _OpenD>('sqlite3_open_v2');
    _close = lib.lookupFunction<_CloseC, _CloseD>('sqlite3_close_v2');
    _exec = lib.lookupFunction<_ExecC, _ExecD>('sqlite3_exec');
    _prepare = lib.lookupFunction<_PrepC, _PrepD>('sqlite3_prepare_v2');
    _step = lib.lookupFunction<_StepC, _StepD>('sqlite3_step');
    _finalize = lib.lookupFunction<_FinC, _FinD>('sqlite3_finalize');
    _columnCount = lib.lookupFunction<_CountC, _CountD>('sqlite3_column_count');
    _columnInt = lib.lookupFunction<_IntC, _IntD>('sqlite3_column_int64');
  }

  late final _OpenD _open;
  late final _CloseD _close;
  late final _ExecD _exec;
  late final _PrepD _prepare;
  late final _StepD _step;
  late final _FinD _finalize;
  late final _CountD _columnCount;
  late final _IntD _columnInt;

  Pointer<Void> _connect(String dbPath) {
    final path = dbPath.toNativeUtf8(allocator: calloc);
    final out = calloc<Pointer<Void>>();
    try {
      final rc = _open(path, out, 2 | 0x10000, nullptr);
      if (rc != 0 || out.value == nullptr) {
        if (out.value != nullptr) _close(out.value);
        throw StateError('raw open failed: $rc');
      }
      return out.value;
    } finally {
      calloc.free(path);
      calloc.free(out);
    }
  }

  void run(String dbPath, String sql) {
    final db = _connect(dbPath);
    final script = sql.toNativeUtf8(allocator: calloc);
    try {
      final result = _exec(db, script, nullptr, nullptr, nullptr);
      if (result != 0) throw StateError('raw exec failed: $result');
    } finally {
      calloc.free(script);
      final rc = _close(db);
      if (rc != 0) throw StateError('raw close failed: $rc');
    }
  }

  List<int> singleIntRow(String dbPath, String sql) {
    final db = _connect(dbPath);
    final script = sql.toNativeUtf8(allocator: calloc);
    final stmt = calloc<Pointer<Void>>();
    try {
      final prep = _prepare(db, script, -1, stmt, nullptr);
      if (prep != 0 || stmt.value == nullptr) {
        throw StateError('raw prepare failed: $prep');
      }
      try {
        final step = _step(stmt.value);
        if (step != 100) throw StateError('raw step failed: $step');
        final columns = _columnCount(stmt.value);
        final values = <int>[];
        for (var i = 0; i < columns; i++) {
          values.add(_columnInt(stmt.value, i));
        }
        return values;
      } finally {
        final rc = _finalize(stmt.value);
        if (rc != 0) throw StateError('raw finalize failed: $rc');
      }
    } finally {
      calloc.free(script);
      calloc.free(stmt);
      final rc = _close(db);
      if (rc != 0) throw StateError('raw close failed: $rc');
    }
  }

  int columnCount(String dbPath, String sql) {
    final db = _connect(dbPath);
    final script = sql.toNativeUtf8(allocator: calloc);
    final stmt = calloc<Pointer<Void>>();
    try {
      final prep = _prepare(db, script, -1, stmt, nullptr);
      if (prep != 0 || stmt.value == nullptr) {
        throw StateError('raw prepare failed: $prep');
      }
      try {
        final step = _step(stmt.value);
        if (step != 100) throw StateError('raw step failed: $step');
        return _columnCount(stmt.value);
      } finally {
        final rc = _finalize(stmt.value);
        if (rc != 0) throw StateError('raw finalize failed: $rc');
      }
    } finally {
      calloc.free(script);
      calloc.free(stmt);
      final rc = _close(db);
      if (rc != 0) throw StateError('raw close failed: $rc');
    }
  }
}

final class SentinelOwner {
  SentinelOwner._(this.path, this.bytes);
  final String path;
  final List<int> bytes;
  bool _owned = true;

  static SentinelOwner createExclusive(String path, List<int> bytes) {
    final file = File(path);
    file.createSync(exclusive: true);
    RandomAccessFile? handle;
    try {
      handle = file.openSync(mode: FileMode.write);
      handle.writeFromSync(bytes);
      handle.flushSync();
      handle.closeSync();
      handle = null;
      return SentinelOwner._(path, List<int>.from(bytes));
    } catch (_) {
      try {
        handle?.closeSync();
      } catch (_) {}
      try {
        if (FileSystemEntity.typeSync(path, followLinks: false) ==
            FileSystemEntityType.file) {
          file.deleteSync();
        }
      } catch (_) {}
      rethrow;
    }
  }

  bool matches() {
    if (FileSystemEntity.typeSync(path, followLinks: false) !=
        FileSystemEntityType.file) {
      return false;
    }
    final current = File(path).readAsBytesSync();
    if (current.length != bytes.length) return false;
    for (var i = 0; i < bytes.length; i++) {
      if (current[i] != bytes[i]) return false;
    }
    return true;
  }

  void cleanup() {
    if (!_owned) return;
    final type = FileSystemEntity.typeSync(path, followLinks: false);
    if (type == FileSystemEntityType.notFound) {
      _owned = false;
      return;
    }
    if (type != FileSystemEntityType.file) {
      throw StateError('Refusing sentinel cleanup on a non-regular path');
    }
    File(path).deleteSync();
    _owned = false;
  }
}
final class OwnedFixture {
  OwnedFixture(this.root) : store = issuanceVaultRandomHex(32) {
    context = IssuanceVaultContext(
      version: issuanceVaultVersion,
      vaultId: IssuanceVaultContext.vaultIdFor(store),
      storeIdentity: store,
    );
  }

  final Directory root;
  final String store;
  late final IssuanceVaultContext context;
  final List<String> _owned = [];
  bool _authorized = false;

  String get dbPath =>
      '${root.path}\\xio-issuance-${context.digestHex}-journal.db';
  String get leasePath =>
      '${root.path}\\xio-issuance-${context.digestHex}-lease';

  List<String> get candidates => [
    dbPath,
    '$dbPath-wal',
    '$dbPath-shm',
    '$dbPath-journal',
    leasePath,
  ];

  void requireAbsent() {
    for (final path in candidates) {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type != FileSystemEntityType.notFound) {
        throw StateError(
          'Fixture path exists or is not absent ($type); refusing reuse: $path',
        );
      }
    }
  }

  /// Explicit preflight-success gate. Ownership recording/cleanup is authorized
  /// only after this returns without throwing.
  void preflight() {
    requireAbsent();
    _authorized = true;
  }

  void recordOwned() {
    if (!_authorized) return;
    for (final path in candidates) {
      if (FileSystemEntity.typeSync(path, followLinks: false) !=
          FileSystemEntityType.file) {
        continue;
      }
      if (!path.startsWith('${root.path}\\xio-issuance-')) continue;
      if (Directory(path).parent.absolute.path.toLowerCase() !=
          root.absolute.path.toLowerCase()) {
        continue;
      }
      if (!_owned.contains(path)) _owned.add(path);
    }
  }

  void cleanup() {
    if (!_authorized) return;
    for (final path in _owned) {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type == FileSystemEntityType.notFound) continue;
      if (type != FileSystemEntityType.file) {
        throw StateError('Refusing cleanup of a non-regular owned path: $path');
      }
      final file = File(path);
      if (Directory(path).parent.absolute.path.toLowerCase() !=
          root.absolute.path.toLowerCase()) {
        throw StateError('Refusing cleanup outside the owned root: $path');
      }
      file.deleteSync();
    }
    _owned.clear();
  }
}

void _require(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Future<void> expectThrows<T>(Future<void> Function() action, String label) async {
  try {
    await action();
  } catch (error) {
    _require(error is T, '$label: expected $T, got ${error.runtimeType}');
    return;
  }
  throw StateError('$label: expected $T, but no error was thrown');
}

Future<void> expectOpenThrows<T>(String store, String label) async {
  IssuanceJournalVault? opened;
  try {
    opened = await openWindowsJournalVault(store);
  } catch (error) {
    _require(error is T, '$label: expected $T, got ${error.runtimeType}');
    return;
  }
  await opened.close();
  throw StateError('$label: expected $T, but the provider opened');
}
Future<void> scenarioEraseBeforeOpen() async {
  final fixture = OwnedFixture(Directory(windowsLocalAppData()));
  final raw = RawSqlite();
  IssuanceJournalVault? vault;
  fixture.preflight();
  try {
    vault = await openWindowsJournalVault(fixture.store);
    await vault.write(vault.vaultId, {
      'revision': '9',
      'payload': 'synthetic',
    });
    await vault.close();
    vault = null;
    fixture.recordOwned();
    raw.run(fixture.dbPath, 'DELETE FROM journal;');
    _require(
      raw.singleIntRow(fixture.dbPath, 'SELECT COUNT(*) FROM journal;').single == 0,
      'pre-open erased row count',
    );
    await expectOpenThrows<IssuanceVaultCorrupt>(
      fixture.store,
      'erased-before-open',
    );
    _require(
      raw.singleIntRow(fixture.dbPath, 'SELECT COUNT(*) FROM journal;').single == 0,
      'no tombstone regenerated',
    );
    _require(
      raw.singleIntRow(fixture.dbPath, 'PRAGMA user_version;').single == 1,
      'user_version preserved',
    );
    _require(
      raw.columnCount(fixture.dbPath, 'PRAGMA table_info(journal);') == 6,
      'table_info arity',
    );
    _require(raw.columnCount(fixture.dbPath, 'SELECT 1,2,3;') == 3, 'query arity');
  } finally {
    if (vault != null) await vault.close();
    fixture.recordOwned();
    fixture.cleanup();
  }
}

Future<void> scenarioEraseAfterOpen() async {
  final fixture = OwnedFixture(Directory(windowsLocalAppData()));
  final raw = RawSqlite();
  IssuanceJournalVault? vault;
  fixture.preflight();
  try {
    vault = await openWindowsJournalVault(fixture.store);
    final active = vault;
    await active.write(active.vaultId, {
      'revision': '9',
      'payload': 'synthetic',
    });
    fixture.recordOwned();
    raw.run(fixture.dbPath, 'DELETE FROM journal;');
    await expectThrows<IssuanceVaultCorrupt>(
      () => active.read(active.vaultId),
      'post-open read',
    );
    await expectThrows<IssuanceVaultCorrupt>(
      () => active.write(active.vaultId, {'revision': '10'}),
      'post-open write',
    );
    await active.close();
    vault = null;
    _require(
      raw.singleIntRow(fixture.dbPath, 'SELECT COUNT(*) FROM journal;').single == 0,
      'post-open zero row',
    );
    _require(
      raw.singleIntRow(fixture.dbPath, 'PRAGMA user_version;').single == 1,
      'post-open version',
    );
  } finally {
    if (vault != null) await vault.close();
    fixture.recordOwned();
    fixture.cleanup();
  }
}

Future<void> scenarioFreshEmptyReopen() async {
  final fixture = OwnedFixture(Directory(windowsLocalAppData()));
  final raw = RawSqlite();
  IssuanceJournalVault? first;
  IssuanceJournalVault? second;
  fixture.preflight();
  try {
    first = await openWindowsJournalVault(fixture.store);
    _require(await first.read(first.vaultId) == null, 'fresh read null');
    await first.close();
    first = null;
    second = await openWindowsJournalVault(fixture.store);
    _require(await second.read(second.vaultId) == null, 'reopen read null');
    await second.close();
    second = null;
    fixture.recordOwned();
    _require(
      raw.singleIntRow(fixture.dbPath, 'SELECT COUNT(*) FROM journal;').single == 1,
      'exactly one tombstone row',
    );
    _require(
      raw.singleIntRow(fixture.dbPath, 'PRAGMA user_version;').single == 1,
      'fresh version',
    );
    _require(
      raw.singleIntRow(fixture.dbPath, 'PRAGMA application_id;').single == 0x58494F4A,
      'fresh application id',
    );
  } finally {
    if (first != null) await first.close();
    if (second != null) await second.close();
    fixture.recordOwned();
    fixture.cleanup();
  }
}

Future<void> scenarioPreflightCollision() async {
  final fixture = OwnedFixture(Directory(windowsLocalAppData()));
  final bytes = [0x53, 0x45, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x4c];
  SentinelOwner? sentinel;
  try {
    sentinel = SentinelOwner.createExclusive(fixture.leasePath, bytes);
    var threw = false;
    try {
      fixture.preflight();
    } on StateError {
      threw = true;
    }
    _require(threw, 'preflight collision must throw');
    // The old unsafe cleanup would have claimed/deleted the sentinel here.
    fixture.recordOwned();
    fixture.cleanup();
    _require(sentinel.matches(), 'preflight sentinel was deleted or changed');
  } finally {
    sentinel?.cleanup();
  }
}
typedef _OpenC = Int32 Function(
  Pointer<Utf8>,
  Pointer<Pointer<Void>>,
  Int32,
  Pointer<Utf8>,
);
typedef _OpenD = int Function(
  Pointer<Utf8>,
  Pointer<Pointer<Void>>,
  int,
  Pointer<Utf8>,
);
typedef _CloseC = Int32 Function(Pointer<Void>);
typedef _CloseD = int Function(Pointer<Void>);
typedef _ExecC = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Void>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
);
typedef _ExecD = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Void>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
);
typedef _PrepC = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Int32,
  Pointer<Pointer<Void>>,
  Pointer<Pointer<Utf8>>,
);
typedef _PrepD = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  int,
  Pointer<Pointer<Void>>,
  Pointer<Pointer<Utf8>>,
);
typedef _StepC = Int32 Function(Pointer<Void>);
typedef _StepD = int Function(Pointer<Void>);
typedef _FinC = Int32 Function(Pointer<Void>);
typedef _FinD = int Function(Pointer<Void>);
typedef _CountC = Int32 Function(Pointer<Void>);
typedef _CountD = int Function(Pointer<Void>);
typedef _IntC = Int64 Function(Pointer<Void>, Int32);
typedef _IntD = int Function(Pointer<Void>, int);
