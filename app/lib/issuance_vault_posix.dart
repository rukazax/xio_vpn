// POSIX (Linux/Android) journal lease and file backend.
//
// Lease: `flock(LOCK_EX|LOCK_NB)` on an open file description. Unlike fcntl
// locks (per process) this excludes a second open in the same process and in
// another Dart isolate, and it is released by the OS when the process dies.
// The lease file is never deleted or replaced while held.
//
// Storage: one opaque prefixed file per journal record; AES-GCM with the
// authenticated context as AAD; temp write + file flush + rename + parent
// directory fsync. Failure after rename but before/at directory fsync is
// reported as durability-unknown, never success.
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:ffi/ffi.dart';

import 'issuance_vault.dart';

const int _oRdwr = 2;
const int _oCreat = 0x40;
const int _oRdonly = 0;
const int _oDirectory = 0x10000;
const int _oWronly = 1;
const int _oExcl = 0x80;
const int _oNofollow = 0x20000;
const int _oNonblock = 0x800;
const int _eintr = 4;
const int _enoent = 2;
const int _lockEx = 2;
const int _lockNb = 4;

typedef _OpenC = Int32 Function(Pointer<Utf8>, Int32, Uint32);
typedef _OpenD = int Function(Pointer<Utf8>, int, int);
typedef _FlockC = Int32 Function(Int32, Int32);
typedef _FlockD = int Function(int, int);
typedef _CloseC = Int32 Function(Int32);
typedef _CloseD = int Function(int);
typedef _FsyncC = Int32 Function(Int32);
typedef _FsyncD = int Function(int);
typedef _WriteC = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _WriteD = int Function(int, Pointer<Uint8>, int);
typedef _ReadC = IntPtr Function(Int32, Pointer<Uint8>, IntPtr);
typedef _ReadD = int Function(int, Pointer<Uint8>, int);
typedef _ErrnoC = Pointer<Int32> Function();
typedef _LseekC = Int64 Function(Int32, Int64, Int32);
typedef _LseekD = int Function(int, int, int);

final class _Posix {
  _Posix() {
    final lib = Platform.isAndroid
        ? DynamicLibrary.open('libc.so')
        : DynamicLibrary.process();
    open = lib.lookupFunction<_OpenC, _OpenD>('open');
    flock = lib.lookupFunction<_FlockC, _FlockD>('flock');
    close = lib.lookupFunction<_CloseC, _CloseD>('close');
    fsync = lib.lookupFunction<_FsyncC, _FsyncD>('fsync');
    write = lib.lookupFunction<_WriteC, _WriteD>('write');
    lseek = lib.lookupFunction<_LseekC, _LseekD>('lseek');
    read = lib.lookupFunction<_ReadC, _ReadD>('read');
    // Android bionic exports __errno (confirmed in NDK 30 stubs for
    // aarch64/arm/x86_64 API 21/26/36); glibc exports __errno_location.
    // No fallback name or alternate loader is attempted.
    errnoLocation = Platform.isAndroid
        ? lib.lookupFunction<_ErrnoC, Pointer<Int32> Function()>('__errno')
        : lib.lookupFunction<_ErrnoC, Pointer<Int32> Function()>(
            '__errno_location',
          );
  }

  late final _OpenD open;
  late final _FlockD flock;
  late final _CloseD close;
  late final _FsyncD fsync;
  late final _WriteD write;
  late final _LseekD lseek;
  late final _ReadD read;
  late final Pointer<Int32> Function() errnoLocation;

  static final _Posix instance = _Posix();
}

void posixFsyncDirectory(String path) {
  final native = path.toNativeUtf8();
  final fd = _Posix.instance.open(native, _oRdonly | _oDirectory, 0);
  if (fd < 0) {
    calloc.free(native);
    throw const IssuanceVaultDurabilityUnknown(
      'Cannot open the journal directory for a durability barrier',
    );
  }
  try {
    if (_Posix.instance.fsync(fd) != 0) {
      throw const IssuanceVaultDurabilityUnknown(
        'Directory fsync failed; the rename is visible but not proven durable',
      );
    }
  } finally {
    _Posix.instance.close(fd);
    calloc.free(native);
  }
}

void posixCreateExclusive600(String path, Uint8List bytes) {
  final native = path.toNativeUtf8();
  final fd = _Posix.instance.open(
    native,
    _oWronly | _oCreat | _oExcl | _oNofollow,
    0x180,
  );
  calloc.free(native);
  if (fd < 0) {
    throw const IssuanceVaultKeyUnavailable(
      'Cannot create the journal key exclusively with mode 0600',
    );
  }
  try {
    var offset = 0;
    while (offset < bytes.length) {
      final buffer = calloc<Uint8>(bytes.length - offset);
      buffer.asTypedList(bytes.length - offset).setAll(0, bytes.sublist(offset));
      final written = _Posix.instance.write(fd, buffer, bytes.length - offset);
      calloc.free(buffer);
      if (written <= 0) {
        throw const IssuanceVaultKeyUnavailable(
          'Cannot write the journal key',
        );
      }
      offset += written;
    }
    if (_Posix.instance.fsync(fd) != 0) {
      throw const IssuanceVaultDurabilityUnknown(
        'Key file fsync failed during creation',
      );
    }
  } finally {
    _Posix.instance.close(fd);
  }
}

void posixFsyncFile(String path) {
  final native = path.toNativeUtf8();
  final fd = _Posix.instance.open(native, _oRdonly, 0);
  calloc.free(native);
  if (fd < 0) {
    throw const IssuanceVaultDurabilityUnknown(
      'Cannot open the key file for its durability barrier',
    );
  }
  try {
    if (_Posix.instance.fsync(fd) != 0) {
      throw const IssuanceVaultDurabilityUnknown(
        'Key file fsync failed; visible key bytes are not proven durable',
      );
    }
  } finally {
    _Posix.instance.close(fd);
  }
}

@pragma('vm:isolate-unsendable')
final class PosixJournalLease extends SettlingJournalLease {
  PosixJournalLease._(this._fd);
  int _fd;

  static PosixJournalLease acquire(String path) {
    final native = path.toNativeUtf8();
    final fd = _Posix.instance.open(native, _oRdwr | _oCreat, 0x180);
    calloc.free(native);
    if (fd < 0) {
      throw const IssuanceVaultUnsupported(
        'Cannot open the journal lease file in the existing root',
      );
    }
    if (_Posix.instance.flock(fd, _lockEx | _lockNb) != 0) {
      _Posix.instance.close(fd);
      throw const IssuanceVaultBusy('Journal lease is held by another owner');
    }
    final lease = PosixJournalLease._(fd)..markHeld();
    return lease;
  }

  @override
  Future<void> release() async {
    if (_fd >= 0) {
      _Posix.instance.close(_fd);
      _fd = -1;
    }
  }
}

@pragma('vm:isolate-unsendable')
final class PosixFileVaultBackend implements IssuanceVaultBackend {
  PosixFileVaultBackend({required this.directory});

  final Directory directory;
  Uint8List? _key;
  bool _closed = false;

  String get keyPath => '${directory.path}/issuance.key';
  String get keyLockPath => '${directory.path}/issuance.key.lock';

  @override
  Future<void> open() async {
    await _requireSafeRoot();
    await _ensureKey();
    // Root and parent directory entries must be durable before READY.
    posixFsyncDirectory(directory.path);
    final parent = directory.parent;
    if (parent.path != directory.path) {
      posixFsyncDirectory(parent.path);
    }
  }

  Future<void> _requireSafeRoot() async {
    if (!await directory.exists()) {
      throw const IssuanceVaultUnsupported(
        'The journal root does not exist; no parent hierarchy is created',
      );
    }
    final leaf = await FileSystemEntity.type(
      directory.path,
      followLinks: false,
    );
    if (leaf != FileSystemEntityType.directory) {
      throw const IssuanceVaultUnsupported(
        'The journal root is not a real directory',
      );
    }
    var current = directory.absolute;
    while (true) {
      final parent = current.parent;
      if (parent.path == current.path) break;
      final type = await FileSystemEntity.type(parent.path, followLinks: false);
      if (type != FileSystemEntityType.directory) {
        throw const IssuanceVaultUnsupported(
          'A journal root ancestor is missing, redirected or not a directory',
        );
      }
      current = parent;
    }
  }

  Future<void> _ensureKey() async {
    // The key is immutable once created and is validated/loaded under the
    // same key lock, with real file+directory barriers, before any record is
    // exposed. A visible-but-not-durable key file must not authorize a fresh
    // record after a restart.
    final lock = PosixJournalLease.acquire(keyLockPath);
    try {
      final keyType = await FileSystemEntity.type(
        keyPath,
        followLinks: false,
      );
      if (keyType == FileSystemEntityType.link ||
          (keyType != FileSystemEntityType.notFound &&
              keyType != FileSystemEntityType.file)) {
        throw const IssuanceVaultKeyUnavailable(
          'The journal key path is a symlink or non-regular file',
        );
      }
      final keyFile = File(keyPath);
      RandomAccessFile? keyHandle;
      if (keyType == FileSystemEntityType.file) {
        final stat = await keyFile.stat();
        if ((stat.mode & 0x1FF) != 0x180) {
          throw const IssuanceVaultKeyUnavailable(
            'Existing journal key permissions are not 0600; refusing to use it',
          );
        }
        try {
          keyHandle = await keyFile.open(mode: FileMode.read);
        } on PathNotFoundException {
          keyHandle = null; // raced away; treated as missing below
        } on FileSystemException {
          throw const IssuanceVaultKeyUnavailable(
            'The journal key exists but cannot be opened',
          );
        }
      }
      if (keyHandle != null) {
        final Uint8List bytes;
        try {
          if (await keyHandle.length() != 32) {
            throw const IssuanceVaultKeyUnavailable(
              'The journal key file is not a 32-byte key',
            );
          }
          bytes = Uint8List.fromList(await keyHandle.read(32));
        } finally {
          await keyHandle.close();
        }
        if (bytes.length != 32) {
          throw const IssuanceVaultKeyUnavailable(
            'The journal key is truncated',
          );
        }
        posixFsyncFile(keyPath);
        posixFsyncDirectory(directory.path);
        _key = bytes;
        return;
      }
      if (await _hasRecordFiles()) {
        throw const IssuanceVaultKeyUnavailable(
          'A journal record exists but its key is missing; refusing to regenerate',
        );
      }
      final key = Uint8List.fromList(
        List<int>.generate(32, (_) => Random.secure().nextInt(256)),
      );
      posixCreateExclusive600(keyPath, key);
      posixFsyncDirectory(directory.path);
      _key = key;
    } on FileSystemException {
      throw const IssuanceVaultKeyUnavailable(
        'Cannot create the journal key exclusively',
      );
    } finally {
      await lock.closeWhenSettled();
    }
  }
  Future<bool> _hasRecordFiles() async {
    await for (final entity in directory.list(followLinks: false)) {
      // Any .bin namespace node (file, link or directory) means a journal
      // namespace exists. A non-regular node must not be read as "fresh" and
      // trigger key generation.
      if (entity.path.endsWith('.bin')) return true;
    }
    return false;
  }

  int _read(int fd, Pointer<Uint8> buffer, int length) {
    for (var attempt = 0; attempt < 8; attempt++) {
      final n = _Posix.instance.read(fd, buffer, length);
      if (n >= 0) return n;
      if (_Posix.instance.errnoLocation().value != _eintr) {
        throw const IssuanceVaultCorrupt(
          'Journal record read failed with a non-EOF error',
        );
      }
    }
    throw const IssuanceVaultCorrupt(
      'Journal record read was interrupted repeatedly',
    );
  }

  @override
  Future<Uint8List?> readSealed(String id) async {
    final file = _fileFor(id);
    final type = FileSystemEntity.typeSync(file.path, followLinks: false);
    if (type == FileSystemEntityType.link ||
        (type != FileSystemEntityType.notFound &&
            type != FileSystemEntityType.file)) {
      throw const IssuanceVaultCorrupt(
        'Journal record exists but is a symlink or non-regular file',
      );
    }
    final native = file.path.toNativeUtf8();
    final fd = _Posix.instance.open(
      native,
      _oRdonly | _oNofollow | _oNonblock,
      0,
    );
    calloc.free(native);
    if (fd < 0) {
      final errno = _Posix.instance.errnoLocation().value;
      if (errno == _enoent) return null; // true ENOENT only
      throw const IssuanceVaultCorrupt(
        'Journal record could not be opened; not treated as absence',
      );
    }
    try {
      if (type == FileSystemEntityType.notFound) {
        throw const IssuanceVaultCorrupt(
          'Journal metadata/file state disagree; refusing a false empty read',
        );
      }
      final length = _Posix.instance.lseek(fd, 0, 2); // SEEK_END
      if (length < 0 || length > issuanceVaultMaxCiphertext) {
        throw const IssuanceVaultCorrupt(
          'Stored journal record exceeds the bounded size',
        );
      }
      if (_Posix.instance.lseek(fd, 0, 0) != 0) {
        throw const IssuanceVaultCorrupt('Journal record seek failed');
      }
      final buffer = calloc<Uint8>(length + 1);
      try {
        var read = 0;
        while (read < length) {
          final n = _read(fd, buffer + read, length - read);
          if (n == 0) {
            throw const IssuanceVaultCorrupt(
              'Journal record ended before the expected length',
            );
          }
          read += n;
        }
        final extra = _read(fd, buffer + read, 1);
        if (extra != 0) {
          throw const IssuanceVaultCorrupt(
            'Journal record grew while reading',
          );
        }
        return Uint8List.fromList(buffer.asTypedList(length));
      } finally {
        calloc.free(buffer);
      }
    } finally {
      _Posix.instance.close(fd);
    }
  }
  @override
  Future<void> writeSealed(String id, Uint8List sealed) async {
    if (sealed.length > issuanceVaultMaxCiphertext) {
      throw const IssuanceVaultDurabilityUnknown('Sealed record too large');
    }
    final file = _fileFor(id);
    final temp = File(
      '${file.path}.tmp.${issuanceVaultRandomHex(6)}',
    );
    try {
      await temp.writeAsBytes(sealed, flush: true);
      await temp.rename(file.path);
    } catch (_) {
      try {
        if (await temp.exists()) await temp.delete();
      } catch (_) {}
      throw const IssuanceVaultDurabilityUnknown(
        'Journal write failed before the rename; outcome is unknown',
      );
    }
    try {
      posixFsyncDirectory(directory.path);
    } catch (_) {
      throw const IssuanceVaultDurabilityUnknown(
        'The rename is visible but the directory barrier failed',
      );
    }
  }

  @override
  Future<Uint8List> sealSealed(
    IssuanceVaultContext context,
    Uint8List plaintext,
  ) async {
    final key = _key;
    if (key == null) {
      throw const IssuanceVaultKeyUnavailable('The journal key is not loaded');
    }
    final nonce = Uint8List.fromList(
      List<int>.generate(12, (_) => Random.secure().nextInt(256)),
    );
    final box = await AesGcm.with256bits().encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: nonce,
      aad: context.aad,
    );
    return Uint8List.fromList(box.concatenation());
  }

  @override
  Future<Uint8List> openSealed(
    IssuanceVaultContext context,
    Uint8List sealed,
  ) async {
    final key = _key;
    if (key == null) {
      throw const IssuanceVaultKeyUnavailable('The journal key is not loaded');
    }
    try {
      final box = SecretBox.fromConcatenation(
        sealed,
        nonceLength: 12,
        macLength: 16,
      );
      final plain = await AesGcm.with256bits().decrypt(
        box,
        secretKey: SecretKey(key),
        aad: context.aad,
      );
      return Uint8List.fromList(plain);
    } catch (_) {
      throw const IssuanceVaultCorrupt(
        'Journal authentication failed (wrong key/context or corruption)',
      );
    }
  }

  @override
  Future<void> close() async {
    _closed = true;
    _key = null;
  }

  File _fileFor(String id) {
    final digest = sha256DigestHex(id);
    return File('${directory.path}/xio-issuance-$digest.bin');
  }

  bool get closed => _closed;

  static String sha256DigestHex(String value) =>
      sha256.convert(utf8.encode(value)).toString();
}

Future<IssuanceJournalVault> openPosixJournalVault({
  required Directory directory,
  required String storeIdentity,
}) async {
  // Validate the context BEFORE any lease file or native resource is created.
  IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(storeIdentity),
    storeIdentity: storeIdentity,
  );
  final lease = PosixJournalLease.acquire(
    '${directory.path}/xio-issuance-lease',
  );
  final backend = PosixFileVaultBackend(directory: directory);
  final vault = IssuanceJournalVault(
    storeIdentity: storeIdentity,
    backend: backend,
    lease: lease,
  );
  await vault.open();
  return vault;
}