// Windows Slice B backend: system winsqlite3 (WAL + synchronous=FULL) with
// DPAPI-bound, whole-record encrypted BLOBs, plus a handle-based file lease.
//
// No helper, no unsigned binary, no WDAC bypass. The root is the OS-provisioned
// LocalAppData known folder; no parent hierarchy is created and unsupported
// roots (temp/network/removable/reparse/non-NTFS) are rejected.
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ffi/ffi.dart';

import 'issuance_vault.dart';
import 'issuance_windows_crypto.dart';

final class _Guid extends Struct {
  @Uint32()
  external int data1;
  @Uint16()
  external int data2;
  @Uint16()
  external int data3;
  @Array(8)
  external Array<Uint8> data4;
}


final class _Overlapped extends Struct {
  @UintPtr()
  external int internal;
  @UintPtr()
  external int internalHigh;
  @Uint32()
  external int offset;
  @Uint32()
  external int offsetHigh;
  external Pointer<Void> event;
}

typedef _ShGetKnownFolderPathC = Int32 Function(
  Pointer<_Guid>,
  Uint32,
  Pointer<Void>,
  Pointer<Pointer<Utf16>>,
);
typedef _ShGetKnownFolderPathD = int Function(
  Pointer<_Guid>,
  int,
  Pointer<Void>,
  Pointer<Pointer<Utf16>>,
);
typedef _CoTaskMemFreeC = Void Function(Pointer<Void>);
typedef _GetFileAttributesC = Uint32 Function(Pointer<Utf16>);
typedef _GetFileAttributesD = int Function(Pointer<Utf16>);
typedef _GetDriveTypeC = Uint32 Function(Pointer<Utf16>);
typedef _GetDriveTypeD = int Function(Pointer<Utf16>);
typedef _GetVolumeInformationC = Int32 Function(
  Pointer<Utf16>,
  Pointer<Utf16>,
  Uint32,
  Pointer<Uint32>,
  Pointer<Uint32>,
  Pointer<Uint32>,
  Pointer<Utf16>,
  Uint32,
);
typedef _GetVolumeInformationD = int Function(
  Pointer<Utf16>,
  Pointer<Utf16>,
  int,
  Pointer<Uint32>,
  Pointer<Uint32>,
  Pointer<Uint32>,
  Pointer<Utf16>,
  int,
);
typedef _GetTempPathC = Uint32 Function(Uint32, Pointer<Utf16>);
typedef _GetTempPathD = int Function(int, Pointer<Utf16>);
typedef _GetSystemDirectoryC = Uint32 Function(Pointer<Utf16>, Uint32);
typedef _GetSystemDirectoryD = int Function(Pointer<Utf16>, int);

typedef _CreateFileC = Pointer<Void> Function(
  Pointer<Utf16>,
  Uint32,
  Uint32,
  Pointer<Void>,
  Uint32,
  Uint32,
  Pointer<Void>,
);
typedef _CreateFileD = Pointer<Void> Function(
  Pointer<Utf16>,
  int,
  int,
  Pointer<Void>,
  int,
  int,
  Pointer<Void>,
);
typedef _LockFileExC = Int32 Function(
  Pointer<Void>,
  Uint32,
  Uint32,
  Uint32,
  Uint32,
  Pointer<_Overlapped>,
);
typedef _LockFileExD = int Function(
  Pointer<Void>,
  int,
  int,
  int,
  int,
  Pointer<_Overlapped>,
);
typedef _CloseHandleC = Int32 Function(Pointer<Void>);
typedef _CloseHandleD = int Function(Pointer<Void>);

typedef _SqliteOpenC = Int32 Function(
  Pointer<Utf8>,
  Pointer<Pointer<Void>>,
  Int32,
  Pointer<Utf8>,
);
typedef _SqliteOpenD = int Function(
  Pointer<Utf8>,
  Pointer<Pointer<Void>>,
  int,
  Pointer<Utf8>,
);
typedef _SqliteCloseC = Int32 Function(Pointer<Void>);
typedef _SqliteCloseD = int Function(Pointer<Void>);
typedef _SqliteExecC = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Void>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
);
typedef _SqliteExecD = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Void>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
);
typedef _SqlitePrepareC = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Int32,
  Pointer<Pointer<Void>>,
  Pointer<Pointer<Utf8>>,
);
typedef _SqlitePrepareD = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  int,
  Pointer<Pointer<Void>>,
  Pointer<Pointer<Utf8>>,
);
typedef _SqliteBindTextC = Int32 Function(
  Pointer<Void>,
  Int32,
  Pointer<Utf8>,
  Int32,
  Pointer<Void>,
);
typedef _SqliteBindTextD = int Function(
  Pointer<Void>,
  int,
  Pointer<Utf8>,
  int,
  Pointer<Void>,
);
typedef _SqliteBindBlobC = Int32 Function(
  Pointer<Void>,
  Int32,
  Pointer<Uint8>,
  Int32,
  Pointer<Void>,
);
typedef _SqliteBindBlobD = int Function(
  Pointer<Void>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Void>,
);
typedef _SqliteStepC = Int32 Function(Pointer<Void>);
typedef _SqliteStepD = int Function(Pointer<Void>);
typedef _SqliteColumnBlobC = Pointer<Uint8> Function(Pointer<Void>, Int32);
typedef _SqliteColumnTextC = Pointer<Utf8> Function(Pointer<Void>, Int32);
typedef _SqliteColumnBytesC = Int32 Function(Pointer<Void>, Int32);
typedef _SqliteFinalizeC = Int32 Function(Pointer<Void>);
typedef _SqliteFinalizeD = int Function(Pointer<Void>);
typedef _SqliteErrmsgC = Pointer<Utf8> Function(Pointer<Void>);
typedef _SqliteErrcodeC = Int32 Function(Pointer<Void>);
typedef _SqliteBusyTimeoutC = Int32 Function(Pointer<Void>, Int32);
typedef _SqliteLibversionC = Pointer<Utf8> Function();
typedef _SqliteThreadsafeC = Int32 Function();
typedef _SqliteCompileOptionUsedC = Int32 Function(Pointer<Utf8>);
typedef _SqliteLimitC = Int32 Function(Pointer<Void>, Int32, Int32);
typedef _SqliteColumnInt64C = Int64 Function(Pointer<Void>, Int32);
typedef _SqliteColumnCountC = Int32 Function(Pointer<Void>);

const int _sqliteOk = 0;
const int _sqliteRow = 100;
const int _sqliteDone = 101;
const int _sqliteCorrupt = 11;
const int _sqliteNotadb = 26;
const int _sqliteReadwrite = 2;
const int _sqliteReadonly = 1;
const int _sqliteCreate = 4;
const int _sqliteFullmutex = 0x10000;
const int _sqliteLimitLength = 0;
const int _issuanceSchemaVersion = 1;
const int _issuanceApplicationId = 0x58494F4A; // 'XIOJ'
const int _issuanceMaxStoredBytes = issuanceVaultMaxCiphertext + 16384;

final Pointer<Void> _sqliteTransient = Pointer<Void>.fromAddress(-1);

final class _Sqlite {
  _Sqlite._(this._lib) {
    open2 = _lib.lookupFunction<_SqliteOpenC, _SqliteOpenD>('sqlite3_open_v2');
    close2 = _lib.lookupFunction<_SqliteCloseC, _SqliteCloseD>(
      'sqlite3_close_v2',
    );
    exec = _lib.lookupFunction<_SqliteExecC, _SqliteExecD>('sqlite3_exec');
    prepare = _lib.lookupFunction<_SqlitePrepareC, _SqlitePrepareD>(
      'sqlite3_prepare_v2',
    );
    bindText = _lib.lookupFunction<_SqliteBindTextC, _SqliteBindTextD>(
      'sqlite3_bind_text',
    );
    bindBlob = _lib.lookupFunction<_SqliteBindBlobC, _SqliteBindBlobD>(
      'sqlite3_bind_blob',
    );
    step = _lib.lookupFunction<_SqliteStepC, _SqliteStepD>('sqlite3_step');
    columnBlob = _lib.lookupFunction<_SqliteColumnBlobC, Pointer<Uint8> Function(Pointer<Void>, int)>(
      'sqlite3_column_blob',
    );
    columnText = _lib.lookupFunction<_SqliteColumnTextC, Pointer<Utf8> Function(Pointer<Void>, int)>(
      'sqlite3_column_text',
    );
    columnBytes = _lib.lookupFunction<_SqliteColumnBytesC, int Function(Pointer<Void>, int)>(
      'sqlite3_column_bytes',
    );
    finalize = _lib.lookupFunction<_SqliteFinalizeC, _SqliteFinalizeD>(
      'sqlite3_finalize',
    );
    errmsg = _lib.lookupFunction<_SqliteErrmsgC, Pointer<Utf8> Function(Pointer<Void>)>(
      'sqlite3_errmsg',
    );
    errcode = _lib.lookupFunction<_SqliteErrcodeC, int Function(Pointer<Void>)>(
      'sqlite3_errcode',
    );
    busyTimeout = _lib.lookupFunction<_SqliteBusyTimeoutC, int Function(Pointer<Void>, int)>(
      'sqlite3_busy_timeout',
    );
    libversion = _lib.lookupFunction<_SqliteLibversionC, Pointer<Utf8> Function()>(
      'sqlite3_libversion',
    );
    threadsafe = _lib.lookupFunction<_SqliteThreadsafeC, int Function()>(
      'sqlite3_threadsafe',
    );
    compileoptionUsed = _lib.lookupFunction<_SqliteCompileOptionUsedC, int Function(Pointer<Utf8>)>(
      'sqlite3_compileoption_used',
    );
    limit = _lib.lookupFunction<_SqliteLimitC, int Function(Pointer<Void>, int, int)>(
      'sqlite3_limit',
    );
    columnInt64 = _lib.lookupFunction<_SqliteColumnInt64C, int Function(Pointer<Void>, int)>(
      'sqlite3_column_int64',
    );
    columnCount = _lib.lookupFunction<_SqliteColumnCountC, int Function(Pointer<Void>)>(
      'sqlite3_column_count',
    );
  }

  final DynamicLibrary _lib;
  late final _SqliteOpenD open2;
  late final _SqliteCloseD close2;
  late final _SqliteExecD exec;
  late final _SqlitePrepareD prepare;
  late final _SqliteBindTextD bindText;
  late final _SqliteBindBlobD bindBlob;
  late final _SqliteStepD step;
  late final Pointer<Uint8> Function(Pointer<Void>, int) columnBlob;
  late final Pointer<Utf8> Function(Pointer<Void>, int) columnText;
  late final int Function(Pointer<Void>, int) columnBytes;
  late final _SqliteFinalizeD finalize;
  late final Pointer<Utf8> Function(Pointer<Void>) errmsg;
  late final int Function(Pointer<Void>) errcode;
  late final int Function(Pointer<Void>, int) busyTimeout;
  late final Pointer<Utf8> Function() libversion;
  late final int Function() threadsafe;
  late final int Function(Pointer<Utf8>) compileoptionUsed;
  late final int Function(Pointer<Void>, int, int) limit;
  late final int Function(Pointer<Void>, int) columnInt64;
  late final int Function(Pointer<Void>) columnCount;

  static _Sqlite loadSystem() {
    final kernel = DynamicLibrary.open('kernel32.dll');
    final getSystemDirectory = kernel.lookupFunction<
      _GetSystemDirectoryC,
      _GetSystemDirectoryD
    >('GetSystemDirectoryW');
    final buffer = calloc<Uint16>(260);
    final length = getSystemDirectory(buffer.cast<Utf16>(), 260);
    if (length == 0 || length >= 260) {
      calloc.free(buffer);
      throw const IssuanceVaultUnsupported('Cannot resolve System32');
    }
    final systemDir = buffer.cast<Utf16>().toDartString();
    calloc.free(buffer);
    final path = '$systemDir\\winsqlite3.dll';
    if (!File(path).existsSync()) {
      throw const IssuanceVaultUnsupported(
        'System winsqlite3.dll is not present',
      );
    }
    return _Sqlite._(DynamicLibrary.open(path));
  }
}

/// Returns the OS-provisioned LocalAppData path.
String windowsLocalAppData() {
  final shell = DynamicLibrary.open('shell32.dll');
  final ole = DynamicLibrary.open('ole32.dll');
  final getPath = shell.lookupFunction<
    _ShGetKnownFolderPathC,
    _ShGetKnownFolderPathD
  >('SHGetKnownFolderPath');
  final free = ole.lookupFunction<_CoTaskMemFreeC, void Function(Pointer<Void>)>(
    'CoTaskMemFree',
  );
  final guid = calloc<_Guid>();
  // FOLDERID_LocalAppData {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
  guid.ref
    ..data1 = 0xF1B32785
    ..data2 = 0x6FBA
    ..data3 = 0x4FCF;
  final tail = [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91];
  for (var i = 0; i < 8; i++) {
    guid.ref.data4[i] = tail[i];
  }
  final out = calloc<Pointer<Utf16>>();
  try {
    final hr = getPath(guid, 0, nullptr, out);
    if (hr != 0 || out.value == nullptr) {
      throw const IssuanceVaultUnsupported(
        'Cannot resolve the LocalAppData known folder',
      );
    }
    return out.value.toDartString();
  } finally {
    if (out.value != nullptr) free(out.value.cast<Void>());
    calloc.free(out);
    calloc.free(guid);
  }
}

void _requireSupportedRoot(String path) {
  final kernel = DynamicLibrary.open('kernel32.dll');
  final attrs = kernel.lookupFunction<_GetFileAttributesC, _GetFileAttributesD>(
    'GetFileAttributesW',
  );
  final driveType = kernel.lookupFunction<_GetDriveTypeC, _GetDriveTypeD>(
    'GetDriveTypeW',
  );
  final volumeInfo = kernel.lookupFunction<
    _GetVolumeInformationC,
    _GetVolumeInformationD
  >('GetVolumeInformationW');
  final getTempPath = kernel.lookupFunction<_GetTempPathC, _GetTempPathD>(
    'GetTempPathW',
  );
  if (!Directory(path).existsSync()) {
    throw const IssuanceVaultUnsupported(
      'The journal root does not exist; no parent hierarchy is created',
    );
  }
  final nativePath = path.toNativeUtf16(allocator: calloc);
  try {
    final attr = attrs(nativePath);
    if (attr == 0xFFFFFFFF) {
      throw const IssuanceVaultUnsupported('Cannot stat the journal root');
    }
    if ((attr & 0x400) != 0) {
      throw const IssuanceVaultUnsupported(
        'The journal root is a reparse point; refusing redirection',
      );
    }
    // Every ancestor must be a real directory, not a reparse point. A
    // local-looking path with a redirected ancestor can target another volume.
    var ancestor = Directory(path).absolute;
    while (true) {
      final parent = ancestor.parent;
      if (parent.path == ancestor.path) break;
      final nativeParent = parent.path.toNativeUtf16(allocator: calloc);
      try {
        final parentAttr = attrs(nativeParent);
        if (parentAttr == 0xFFFFFFFF || (parentAttr & 0x400) != 0) {
          throw const IssuanceVaultUnsupported(
            'A journal root ancestor is missing or a reparse point',
          );
        }
      } finally {
        calloc.free(nativeParent);
      }
      ancestor = parent;
    }
    final volumeRoot = path.startsWith(r'\\') ? path : '${path[0]}:\\';
    final nativeRoot = volumeRoot.toNativeUtf16(allocator: calloc);
    final fs = calloc<Uint16>(64);
    try {
      if (driveType(nativeRoot) != 3) {
        throw const IssuanceVaultUnsupported(
          'The journal root is not a fixed local drive',
        );
      }
      final ok = volumeInfo(
        nativeRoot,
        nullptr,
        0,
        nullptr,
        nullptr,
        nullptr,
        fs.cast<Utf16>(),
        64,
      );
      if (ok == 0 || fs.cast<Utf16>().toDartString().toUpperCase() != 'NTFS') {
        throw const IssuanceVaultUnsupported('The journal root is not NTFS');
      }
    } finally {
      calloc.free(fs);
      calloc.free(nativeRoot);
    }
  } finally {
    calloc.free(nativePath);
  }
  final temp = calloc<Uint16>(260);
  try {
    final len = getTempPath(260, temp.cast<Utf16>());
    if (len > 0) {
      final tempPath = temp.cast<Utf16>().toDartString();
      final a = Directory(path).resolveSymbolicLinksSync().toLowerCase();
      final b = Directory(tempPath).resolveSymbolicLinksSync().toLowerCase();
      if (a == b || a.startsWith(b.endsWith('\\') ? b : '$b\\')) {
        throw const IssuanceVaultUnsupported(
          'The journal root is under the temporary directory',
        );
      }
    }
  } finally {
    calloc.free(temp);
  }
}

@pragma('vm:isolate-unsendable')
final class WindowsJournalLease extends SettlingJournalLease {
  WindowsJournalLease._(this._handle, this._overlapped);
  final Pointer<Void> _handle;
  final Pointer<_Overlapped> _overlapped;
  bool _released = false;

  static WindowsJournalLease acquire(String path) {
    final kernel = DynamicLibrary.open('kernel32.dll');
    final createFile = kernel.lookupFunction<_CreateFileC, _CreateFileD>(
      'CreateFileW',
    );
    final lockFile = kernel.lookupFunction<_LockFileExC, _LockFileExD>(
      'LockFileEx',
    );
    final native = path.toNativeUtf16(allocator: calloc);
    final handle = createFile(
      native,
      0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
      0x1 | 0x2, // FILE_SHARE_READ | FILE_SHARE_WRITE
      nullptr,
      4, // OPEN_ALWAYS
      0x80, // FILE_ATTRIBUTE_NORMAL
      nullptr,
    );
    calloc.free(native);
    if (handle == nullptr || handle.address == 0xFFFFFFFFFFFFFFFF) {
      throw const IssuanceVaultUnsupported(
        'Cannot open the journal lease file in the existing root',
      );
    }
    final overlapped = calloc<_Overlapped>();
    final ok = lockFile(handle, 0x2 | 0x1, 0, 1, 0, overlapped);
    if (ok == 0) {
      kernel.lookupFunction<_CloseHandleC, _CloseHandleD>('CloseHandle')(handle);
      calloc.free(overlapped);
      throw const IssuanceVaultBusy('Journal lease is held by another owner');
    }
    return WindowsJournalLease._(handle, overlapped)..markHeld();
  }

  @override
  Future<void> release() async {
    if (_released) return;
    final kernel = DynamicLibrary.open('kernel32.dll');
    final ok = kernel.lookupFunction<_CloseHandleC, _CloseHandleD>(
      'CloseHandle',
    )(_handle);
    if (ok == 0) {
      throw const IssuanceVaultDurabilityUnknown(
        'Journal lease handle close was not confirmed',
      );
    }
    _released = true;
    calloc.free(_overlapped);
  }
}

@pragma('vm:isolate-unsendable')
final class WindowsSqliteBackend implements IssuanceVaultBackend {
  WindowsSqliteBackend({
    required this.root,
    required this.context,
  }) : dbPath = '${root.path}\\xio-issuance-${context.digestHex}-journal.db',
       leasePath = '${root.path}\\xio-issuance-${context.digestHex}-lease';

  final Directory root;
  final IssuanceVaultContext context;
  final String dbPath;
  final String leasePath;

  _Sqlite? _sqlite;
  Pointer<Void>? _db;
  bool _newDatabase = false;

  static void qualifyRoot(String path) => _requireSupportedRoot(path);

  @override
  Future<void> open() async {
    // Root and ancestors are qualified before the factory creates any lease
    // file; this second call is a defence for direct backend construction.
    _requireSupportedRoot(root.path);
    final sqlite = _Sqlite.loadSystem();
    _sqlite = sqlite;
    final exists = File(dbPath).existsSync();
    if (exists && File(dbPath).lengthSync() == 0) {
      throw const IssuanceVaultCorrupt(
        'Existing zero-length journal database is not valid',
      );
    }

    // Qualify the engine and its supported feature set before inspecting any
    // database content.
    final version = sqlite.libversion().toDartString();
    final parts = version.split('.');
    final major = parts.isEmpty ? 0 : int.tryParse(parts[0]) ?? 0;
    final minor = parts.length < 2 ? 0 : int.tryParse(parts[1]) ?? 0;
    if (major != 3 || minor < 35) {
      throw IssuanceVaultUnsupported(
        'Unsupported SQLite version $version; at least 3.35 is required',
      );
    }
    if (sqlite.threadsafe() != 1) {
      throw const IssuanceVaultUnsupported(
        'System SQLite is not built thread-safe',
      );
    }
    final option = 'THREADSAFE=1'.toNativeUtf8(allocator: calloc);
    try {
      if (sqlite.compileoptionUsed(option) == 0) {
        throw const IssuanceVaultUnsupported(
          'System SQLite does not report THREADSAFE=1',
        );
      }
    } finally {
      calloc.free(option);
    }

    if (exists) {
      // Validate over a READ-ONLY connection before opening for write. This
      // avoids claiming that validation SQL on a readwrite connection has no
      // physical effects (hot-journal recovery/checkpoint may write).
      final readOnly = _openConnection(
        sqlite,
        _sqliteReadonly | _sqliteFullmutex,
      );
      final previous = _db;
      _db = readOnly;
      try {
        sqlite.limit(readOnly, _sqliteLimitLength, _issuanceMaxStoredBytes);
        _validateExisting();
      } finally {
        _db = previous;
        final rc = sqlite.close2(readOnly);
        if (rc != _sqliteOk) {
          throw const IssuanceVaultCorrupt(
            'Read-only validation connection did not close cleanly',
          );
        }
      }
    }

    _db = _openConnection(
      sqlite,
      _sqliteReadwrite |
          _sqliteFullmutex |
          (exists ? 0 : _sqliteCreate),
    );
    _newDatabase = !exists;
    if (sqlite.busyTimeout(_db!, 2000) != _sqliteOk) {
      throw const IssuanceVaultCorrupt('Cannot set the SQLite busy timeout');
    }
    sqlite.limit(_db!, _sqliteLimitLength, _issuanceMaxStoredBytes);
    _exec('PRAGMA journal_mode=WAL;');
    final mode = _queryText('PRAGMA journal_mode;');
    if (mode.toLowerCase() != 'wal') {
      throw const IssuanceVaultUnsupported(
        'WAL journal mode is not effective on this system SQLite',
      );
    }
    _exec('PRAGMA synchronous=FULL;');
    final sync = _queryText('PRAGMA synchronous;').toLowerCase();
    if (sync != '2' && sync != 'full') {
      throw const IssuanceVaultUnsupported(
        'synchronous=FULL is not effective on this system SQLite',
      );
    }
  }

  Pointer<Void> _openConnection(_Sqlite sqlite, int flags) {
    final nativePath = dbPath.toNativeUtf8(allocator: calloc);
    final out = calloc<Pointer<Void>>();
    try {
      final rc = sqlite.open2(nativePath, out, flags, nullptr);
      if (rc != _sqliteOk || out.value == nullptr) {
        if (out.value != nullptr) sqlite.close2(out.value);
        throw const IssuanceVaultCorrupt(
          'Cannot open the journal database; it is not valid SQLite',
        );
      }
      return out.value;
    } finally {
      calloc.free(nativePath);
      calloc.free(out);
    }
  }

  void _validateExisting() {
    if (_queryText('PRAGMA user_version;') != '$_issuanceSchemaVersion') {
      throw const IssuanceVaultCorrupt(
        'Existing journal database has an unknown schema version',
      );
    }
    if (_queryInt('PRAGMA application_id;') != _issuanceApplicationId) {
      throw const IssuanceVaultCorrupt(
        'Existing journal database has a foreign application id',
      );
    }
    _validateSchema();
    if (_queryText('PRAGMA quick_check;').toLowerCase() != 'ok') {
      throw const IssuanceVaultCorrupt(
        'Existing journal database failed quick_check',
      );
    }
    final count = _queryInt('SELECT COUNT(*) FROM journal;');
    if (count != 1) {
      throw IssuanceVaultCorrupt(
        'Existing journal database must contain exactly one bound row, '
        'found $count',
      );
    }
  }
  void _validateSchema() {
    final tables = _queryStrings(
      "SELECT name FROM sqlite_master WHERE type='table' "
      "AND name NOT LIKE 'sqlite_%';",
    );
    if (tables.length != 1 || tables.single != 'journal') {
      throw const IssuanceVaultCorrupt(
        'Journal database has an unexpected table set',
      );
    }
    final info = _queryRows('PRAGMA table_info(journal);');
    if (info.length != 2) {
      throw const IssuanceVaultCorrupt('Journal table has an invalid shape');
    }
    final id = info[0];
    final envelope = info[1];
    if (id.length < 6 ||
        id[1] != 'id' ||
        id[2].toUpperCase() != 'TEXT' ||
        id[5] != '1') {
      throw const IssuanceVaultCorrupt('Journal id column is invalid');
    }
    if (envelope.length < 6 ||
        envelope[1] != 'envelope' ||
        envelope[2].toUpperCase() != 'BLOB' ||
        envelope[3] != '1') {
      throw const IssuanceVaultCorrupt('Journal envelope column is invalid');
    }
  }

  int _queryInt(String sql) {
    final text = _queryText(sql);
    final value = int.tryParse(text);
    if (value == null) {
      throw const IssuanceVaultCorrupt('SQLite numeric query returned non-int');
    }
    return value;
  }

  List<String> _queryStrings(String sql) {
    final rows = _queryRows(sql);
    return [for (final row in rows) row.isEmpty ? '' : row.first];
  }

  List<List<String>> _queryRows(String sql) {
    final sqlite = _sqlite!;
    final db = _db!;
    final nativeSql = sql.toNativeUtf8(allocator: calloc);
    final stmt = calloc<Pointer<Void>>();
    try {
      final rc = sqlite.prepare(db, nativeSql, -1, stmt, nullptr);
      if (rc != _sqliteOk) {
        throw _corruptOrUnknown(sqlite, db, 'prepare query');
      }
      final rows = <List<String>>[];
      try {
        while (true) {
          final step = sqlite.step(stmt.value);
          if (step == _sqliteDone) break;
          if (step != _sqliteRow) {
            throw _corruptOrUnknown(sqlite, db, 'query step');
          }
          final columns = sqlite.columnCount(stmt.value);
          if (columns <= 0 || columns > 16) {
            throw const IssuanceVaultCorrupt(
              'SQLite query returned an invalid column count',
            );
          }
          rows.add([
            for (var i = 0; i < columns; i++)
              sqlite.columnText(stmt.value, i) == nullptr
                  ? ''
                  : sqlite.columnText(stmt.value, i).toDartString(),
          ]);
        }
      } finally {
        final fin = sqlite.finalize(stmt.value);
        if (fin != _sqliteOk) {
          throw const IssuanceVaultCorrupt('SQLite finalize failed');
        }
      }
      return rows;
    } finally {
      calloc.free(nativeSql);
      calloc.free(stmt);
    }
  }
  void _exec(String sql) {
    final sqlite = _sqlite!;
    final db = _db!;
    final native = sql.toNativeUtf8(allocator: calloc);
    try {
      final rc = sqlite.exec(db, native, nullptr, nullptr, nullptr);
      if (rc != _sqliteOk) {
        throw IssuanceVaultCorrupt(
          'SQLite exec failed: ${sqlite.errmsg(db).toDartString()}',
        );
      }
    } finally {
      calloc.free(native);
    }
  }

  String _queryText(String sql) {
    final sqlite = _sqlite!;
    final db = _db!;
    final nativeSql = sql.toNativeUtf8(allocator: calloc);
    final stmt = calloc<Pointer<Void>>();
    try {
      final rc = sqlite.prepare(db, nativeSql, -1, stmt, nullptr);
      if (rc != _sqliteOk) {
        throw IssuanceVaultCorrupt(
          'SQLite prepare failed: ${sqlite.errmsg(db).toDartString()}',
        );
      }
      late final String text;
      var finalizeRc = _sqliteOk;
      try {
        final step = sqlite.step(stmt.value);
        if (step != _sqliteRow) {
          throw const IssuanceVaultCorrupt('SQLite pragma returned no row');
        }
        text = sqlite.columnText(stmt.value, 0).toDartString();
      } finally {
        finalizeRc = sqlite.finalize(stmt.value);
      }
      if (finalizeRc != _sqliteOk) {
        throw const IssuanceVaultCorrupt('SQLite finalize failed');
      }
      return text;
    } finally {
      calloc.free(nativeSql);
      calloc.free(stmt);
    }
  }

  @override
  Future<Uint8List?> readSealed(String id) async {
    final sqlite = _sqlite!;
    final db = _db!;
    if (_newDatabase) return null;
    final count = _queryInt('SELECT COUNT(*) FROM journal;');
    if (count != 1) {
      throw IssuanceVaultCorrupt(
        'Open journal must contain exactly one bound row, found $count',
      );
    }
    final metaRows = _queryRows(
      'SELECT id, typeof(envelope), length(envelope) FROM journal LIMIT 1;',
    );
    if (metaRows.length != 1) {
      throw const IssuanceVaultCorrupt(
        'Journal record metadata is inconsistent',
      );
    }
    final meta = metaRows.single;
    if (meta[0] != id) {
      throw const IssuanceVaultCorrupt(
        'Journal database belongs to a different journal identity',
      );
    }
    if (meta[1] != 'blob') {
      throw const IssuanceVaultCorrupt('Journal envelope is not a BLOB');
    }
    final storedLength = int.tryParse(meta[2]);
    if (storedLength == null ||
        storedLength < 0 ||
        storedLength > issuanceVaultMaxCiphertext) {
      throw const IssuanceVaultCorrupt(
        'Stored journal BLOB exceeds the bounded size',
      );
    }
    final nativeSql = 'SELECT envelope FROM journal WHERE id=?1;'
        .toNativeUtf8(allocator: calloc);
    final stmt = calloc<Pointer<Void>>();
    final nativeId = id.toNativeUtf8(allocator: calloc);
    try {
      final rc = sqlite.prepare(db, nativeSql, -1, stmt, nullptr);
      if (rc != _sqliteOk) {
        throw _corruptOrUnknown(sqlite, db, 'prepare read');
      }
      try {
        final bound = sqlite.bindText(
          stmt.value,
          1,
          nativeId,
          -1,
          _sqliteTransient,
        );
        if (bound != _sqliteOk) {
          throw _corruptOrUnknown(sqlite, db, 'bind read id');
        }
        final step = sqlite.step(stmt.value);
        if (step != _sqliteRow) {
          throw const IssuanceVaultCorrupt(
            'Preflight record disappeared; read is not absence',
          );
        }
        final length = sqlite.columnBytes(stmt.value, 0);
        if (length != storedLength ||
            length < 0 ||
            length > issuanceVaultMaxCiphertext) {
          throw const IssuanceVaultCorrupt(
            'Stored journal BLOB length changed or exceeds the cap',
          );
        }
        final pointer = sqlite.columnBlob(stmt.value, 0);
        if (pointer == nullptr) {
          throw const IssuanceVaultCorrupt('Sealed record BLOB is null');
        }
        return Uint8List.fromList(pointer.asTypedList(length));
      } finally {
        final fin = sqlite.finalize(stmt.value);
        if (fin != _sqliteOk) {
          throw const IssuanceVaultCorrupt('SQLite finalize failed');
        }
      }
    } finally {
      calloc.free(nativeSql);
      calloc.free(nativeId);
      calloc.free(stmt);
    }
  }
  @override
  Future<void> writeSealed(String id, Uint8List sealed) async {
    if (sealed.length > issuanceVaultMaxCiphertext) {
      throw const IssuanceVaultDurabilityUnknown('Sealed record too large');
    }
    final sqlite = _sqlite!;
    final db = _db!;
    if (!_newDatabase) {
      final count = _queryInt('SELECT COUNT(*) FROM journal;');
      if (count != 1) {
        throw IssuanceVaultCorrupt(
          'Existing journal must contain exactly one bound row, found $count',
        );
      }
      final existing = _queryRows('SELECT id FROM journal LIMIT 1;').single;
      if (existing[0] != id) {
        throw const IssuanceVaultCorrupt(
          'Journal database belongs to a different journal identity',
        );
      }
    }
    _exec('BEGIN IMMEDIATE;');
    try {
      if (_newDatabase) {
        _exec(
          'CREATE TABLE journal('
          'id TEXT PRIMARY KEY, envelope BLOB NOT NULL);',
        );
        _exec('PRAGMA application_id=$_issuanceApplicationId;');
        _exec('PRAGMA user_version=$_issuanceSchemaVersion;');
      }
      final nativeSql = (_newDatabase
              ? 'INSERT INTO journal(id,envelope) VALUES(?1,?2);'
              : 'INSERT INTO journal(id,envelope) VALUES(?1,?2) '
                  'ON CONFLICT(id) DO UPDATE SET envelope=excluded.envelope;')
          .toNativeUtf8(allocator: calloc);
      final stmt = calloc<Pointer<Void>>();
      final nativeId = id.toNativeUtf8(allocator: calloc);
      final blob = calloc<Uint8>(sealed.isEmpty ? 1 : sealed.length);
      blob.asTypedList(sealed.length).setAll(0, sealed);
      try {
        final rc = sqlite.prepare(db, nativeSql, -1, stmt, nullptr);
        if (rc != _sqliteOk) {
          throw _corruptOrUnknown(sqlite, db, 'prepare write');
        }
        try {
          final idBound = sqlite.bindText(
            stmt.value,
            1,
            nativeId,
            -1,
            _sqliteTransient,
          );
          if (idBound != _sqliteOk) {
            throw _corruptOrUnknown(sqlite, db, 'bind write id');
          }
          final blobBound = sqlite.bindBlob(
            stmt.value,
            2,
            blob,
            sealed.length,
            _sqliteTransient,
          );
          if (blobBound != _sqliteOk) {
            throw _corruptOrUnknown(sqlite, db, 'bind write blob');
          }
          final step = sqlite.step(stmt.value);
          if (step != _sqliteDone) {
            throw _corruptOrUnknown(sqlite, db, 'write step');
          }
        } finally {
          final fin = sqlite.finalize(stmt.value);
          if (fin != _sqliteOk) {
            throw const IssuanceVaultCorrupt('SQLite finalize failed');
          }
        }
      } finally {
        blob.asTypedList(sealed.length).fillRange(0, sealed.length, 0);
        calloc.free(blob);
        calloc.free(nativeId);
        calloc.free(nativeSql);
        calloc.free(stmt);
      }
      _exec('COMMIT;');
      if (_newDatabase) _newDatabase = false;
    } catch (_) {
      try {
        _exec('ROLLBACK;');
      } catch (_) {}
      throw const IssuanceVaultDurabilityUnknown(
        'Journal SQLite commit failed; outcome is unknown',
      );
    }
    final readback = await readSealed(id);
    if (readback == null || !_sameBytes(readback, sealed)) {
      throw const IssuanceVaultDurabilityUnknown(
        'Journal readback does not match the committed BLOB',
      );
    }
  }
  IssuanceVaultCorrupt _corruptOrUnknown(_Sqlite sqlite, Pointer<Void> db, String where) {
    final code = sqlite.errcode(db);
    final message = sqlite.errmsg(db).toDartString();
    if (code == _sqliteCorrupt || code == _sqliteNotadb) {
      return IssuanceVaultCorrupt('$where: corrupt database ($message)');
    }
    return IssuanceVaultCorrupt('$where failed: $message');
  }

  @override
  Future<Uint8List> sealSealed(
    IssuanceVaultContext context,
    Uint8List plaintext,
  ) async {
    return windowsProtectWithEntropy(plaintext, context.aad);
  }

  @override
  Future<Uint8List> openSealed(
    IssuanceVaultContext context,
    Uint8List sealed,
  ) async {
    try {
      return windowsUnprotectWithEntropy(sealed, context.aad);
    } catch (_) {
      throw const IssuanceVaultCorrupt(
        'DPAPI authentication failed (wrong context/profile or corruption)',
      );
    }
  }

  @override
  Future<void> close() async {
    final sqlite = _sqlite;
    final db = _db;
    if (sqlite != null && db != null) {
      final rc = sqlite.close2(db);
      if (rc != _sqliteOk) {
        throw const IssuanceVaultDurabilityUnknown(
          'SQLite close did not confirm physical release',
        );
      }
    }
    _db = null;
    _sqlite = null;
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

Future<IssuanceJournalVault> openWindowsJournalVault(
  String storeIdentity,
) async {
  final root = Directory(windowsLocalAppData());
  final context = IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(storeIdentity),
    storeIdentity: storeIdentity,
  );
  final backend = WindowsSqliteBackend(root: root, context: context);
  // Qualify root and ancestors BEFORE the lease file is created.
  WindowsSqliteBackend.qualifyRoot(root.path);
  final lease = WindowsJournalLease.acquire(backend.leasePath);
  final vault = IssuanceJournalVault(
    storeIdentity: storeIdentity,
    backend: backend,
    lease: lease,
  );
  await vault.open();
  return vault;
}

String issuanceWindowsDigest(IssuanceVaultContext context) =>
    sha256.convert(utf8.encode('${context.vaultId}|${context.storeIdentity}'))
        .toString();
