import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Explicit, owned Dart runtime resolver for reviewer child probes.
///
/// A selected owned Flutter root is required (`XIO_REVIEWER_FLUTTER_ROOT` or
/// `FLUTTER_ROOT`); both empty or conflicting selectors fail closed. An
/// explicit `XIO_REVIEWER_DART` must be the canonical native
/// `bin/cache/dart-sdk/bin/dart[.exe]` under that root. No `/opt`, bare PATH,
/// `Platform.resolvedExecutable` (possibly FlutterTester) or other-installation
/// fallback is used.
final class ReviewerDartRuntime {
  ReviewerDartRuntime._(this.executable, this.root);

  final String executable;
  final String? root;

  static const executableVariable = 'XIO_REVIEWER_DART';
  static const rootVariable = 'XIO_REVIEWER_FLUTTER_ROOT';
  static const flutterRootVariable = 'FLUTTER_ROOT';

  static ReviewerDartRuntime resolve({Map<String, String>? environment}) {
    final env = environment ?? Platform.environment;
    final hasExplicitDart = env.containsKey(executableVariable);
    final hasExplicitRoot = env.containsKey(rootVariable);
    final hasFlutterRoot = env.containsKey(flutterRootVariable);
    if (hasExplicitDart && env[executableVariable]!.isEmpty) {
      throw StateError('Explicit Dart executable must not be empty');
    }
    if (hasExplicitRoot && env[rootVariable]!.isEmpty) {
      throw StateError('Explicit Flutter root must not be empty');
    }
    if (hasFlutterRoot && env[flutterRootVariable]!.isEmpty) {
      throw StateError('Selected FLUTTER_ROOT must not be empty');
    }
    final explicitRootRaw = hasExplicitRoot ? env[rootVariable]! : null;
    final flutterRootRaw = hasFlutterRoot ? env[flutterRootVariable]! : null;
    String? selectedRoot;
    if (explicitRootRaw != null) {
      selectedRoot = _ownedRoot(explicitRootRaw);
      if (flutterRootRaw != null) {
        final flutterRoot = _ownedRoot(flutterRootRaw);
        if (flutterRoot != selectedRoot) {
          throw StateError('Explicit and selected Flutter roots conflict');
        }
      }
    } else if (flutterRootRaw != null) {
      selectedRoot = _ownedRoot(flutterRootRaw);
    }
    if (selectedRoot == null) {
      throw StateError('No explicit owned Dart SDK selector is configured');
    }
    final native = _nativeDart(selectedRoot);
    if (hasExplicitDart) {
      final explicit = _executableFile(
        env[executableVariable]!,
        'explicit Dart executable',
      );
      if (explicit != native) {
        throw StateError(
          'Explicit Dart executable is not the selected SDK native Dart',
        );
      }
    }
    return ReviewerDartRuntime._(native, selectedRoot);
  }

  static String _nativeDart(String root) {
    final name = Platform.isWindows ? 'dart.exe' : 'dart';
    final candidate = File(
      '${root.replaceAll('\\', '/')}/bin/cache/dart-sdk/bin/$name',
    );
    if (!candidate.existsSync()) {
      throw StateError('Explicit Flutter root has no native Dart executable');
    }
    final resolved = _executableFile(candidate.path, 'native Dart executable');
    _requireUnder(resolved, root, 'native Dart executable');
    return resolved;
  }

  static String _ownedRoot(String raw) {
    if (!File(raw).isAbsolute) {
      throw StateError('Explicit Flutter root must be absolute');
    }
    final directory = Directory(raw);
    if (!directory.existsSync()) {
      throw StateError('Explicit Flutter root does not exist');
    }
    return _canonical(directory);
  }

  static String _executableFile(String raw, String label) {
    if (!File(raw).isAbsolute) {
      throw StateError('$label must be absolute');
    }
    final file = File(raw);
    if (!file.existsSync()) {
      throw StateError('$label does not exist');
    }
    final resolved = _canonical(file);
    final stat = File(resolved).statSync();
    if (stat.type != FileSystemEntityType.file || stat.size <= 0) {
      throw StateError('$label is not a nonempty regular file');
    }
    if (!Platform.isWindows && (stat.mode & 0x49) == 0) {
      throw StateError('$label is not executable');
    }
    return resolved;
  }

  static String _canonical(FileSystemEntity entity) {
    try {
      return entity.resolveSymbolicLinksSync();
    } on FileSystemException {
      throw StateError('Could not resolve selected runtime path');
    }
  }

  static void _requireUnder(String executable, String root, String label) {
    final normalizedRoot =
        root.endsWith(Platform.pathSeparator) ? root : '$root${Platform.pathSeparator}';
    final normalizedExecutable = executable.replaceAll('\\', '/');
    final normalizedPrefix = normalizedRoot.replaceAll('\\', '/');
    if (!normalizedExecutable.startsWith(normalizedPrefix)) {
      throw StateError('$label is outside the selected owned SDK');
    }
  }

  Future<ProcessResult> run(
    List<String> arguments, {
    Duration timeout = const Duration(seconds: 90),
  }) async {
    final process = await Process.start(
      executable,
      ['--disable-dart-dev', ...arguments],
    );
    final stdoutFuture = process.stdout.transform(utf8.decoder).join();
    final stderrFuture = process.stderr.transform(utf8.decoder).join();
    try {
      final code = await process.exitCode.timeout(timeout);
      return ProcessResult(
        process.pid,
        code,
        await stdoutFuture,
        await stderrFuture,
      );
    } on TimeoutException {
      // Timeout is not settlement: terminate only this demonstrably owned
      // child and reap it before rethrowing.
      process.kill(ProcessSignal.sigkill);
      await process.exitCode;
      await stdoutFuture;
      await stderrFuture;
      rethrow;
    }
  }
}

/// True only for the supported OS lock-contention result. The child probe
/// reports BUSY for these codes; every other failure remains an error.
bool isSupportedLockContention(int? code) {
  if (code == null) return false;
  if (Platform.isLinux) return code == 11 || code == 13;
  if (Platform.isMacOS) return code == 35 || code == 13;
  if (Platform.isWindows) return code == 32 || code == 33;
  return false;
}

String diagnosticForProcess(ProcessResult result) {
  final out = result.stdout.toString().trim();
  final err = result.stderr.toString().trim();
  return 'exit=${result.exitCode} stdout="$out" stderr="$err"';
}