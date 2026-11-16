import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// Cooperating GUI document writer ownership, scoped by canonical product
/// directory. It is NOT a helper RPC fence or proof of native resource absence.
class ProductStoreWriterOwner {
  ProductStoreWriterOwner._(this._key, this._file)
      : storeIdentity = sha256.convert(utf8.encode(_key)).toString(),
        controllerNonce = List.generate(16,
          (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0'),
        ).join();
  static final Set<String> _localClaims = {};
  final String _key;
  final RandomAccessFile _file;
  final String storeIdentity, controllerNonce;
  int _pending = 0;
  int _nativePending = 0;
  bool _closing = false, _releaseStarted = false;
  bool _claimRemoved = false;
  final _released = Completer<void>();
  bool get acceptsWrites => !_closing;
  int get pendingWrites => _pending;

  static Future<ProductStoreWriterOwner> acquire(Directory directory) async {
    // Caller creates the product directory before taking ownership; no fallback
    // to another/global directory and no arbitrary privileged helper path.
    var key = await directory.resolveSymbolicLinks();
    if (Platform.isWindows) key = key.toLowerCase();
    if (!_localClaims.add(key)) throw StateError('Product store already owned');
    RandomAccessFile? handle;
    try {
      handle = await File('${directory.path}/.document-writer.lock')
          .open(mode: FileMode.append);
      // Nonblocking exclusive ownership. A second GUI cannot queue behind a
      // dead/closing owner and silently start with stale in-memory data.
      await handle.lock(FileLock.exclusive);
      return ProductStoreWriterOwner._(key, handle);
    } catch (_) {
      await handle?.close();
      _localClaims.remove(key);
      rethrow;
    }
  }

  /// Native publication IO that outlives the file callback. The OS file lock is
  /// retained until BOTH the admitted file IO and this native IO settle, and a
  /// same-process successor is refused for the same span. New native admissions
  /// after logical closing are rejected; already outstanding ones still drain.
  Future<T> native<T>(Future<T> Function() action) {
    if (_closing) {
      return Future<T>.error(StateError('Product writer closing'));
    }
    _nativePending++;
    Future<T> work;
    try {
      work = action();
    } catch (error, stack) {
      work = Future<T>.error(error, stack);
    }
    return work.whenComplete(() {
      _nativePending--;
      _releaseIfSettled();
    });
  }

  Future<T> io<T>(Future<T> Function() action) {
    if (_closing) return Future.error(StateError('Product writer closing'));
    _pending++;
    Future<T> work;
    try {
      work = action();
    } catch (error, stack) {
      work = Future<T>.error(error, stack);
    }
    return work.whenComplete(() {
      _pending--;
      _releaseIfSettled();
    });
  }

  /// Logical disposal is non-blocking and prevents new IO immediately. The OS
  /// file handle/lock is released only after BOTH admitted file IO and native
  /// publication IO settle; this future may therefore stay pending. A failed
  /// physical release never admits a successor.
  Future<void> closeWhenSettled() {
    _closing = true;
    _releaseIfSettled();
    return _released.future;
  }

  void _releaseIfSettled() {
    if (!_closing || _pending != 0 || _nativePending != 0 || _releaseStarted) {
      return;
    }
    _releaseStarted = true;
    unawaited(() async {
      try {
        await _file.unlock();
        await _file.close();
        _claimRemoved = true;
        _localClaims.remove(_key);
        _released.complete();
      } catch (error, stack) {
        // Failed physical release is not permission to admit a successor.
        _released.completeError(error, stack);
      }
    }());
  }
}
