import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Dead-import guard for first-party code.
///
/// `flutter analyze` reports `unused_import` as a warning, but a warning is easy
/// to silence or to lose when the lint set is edited. This test re-derives the
/// same fact from the sources: every relative or `package:xio/` import has to
/// reference at least one declaration of the imported library (its own or one
/// re-exported from it), and a prefixed import has to use its prefix.
///
/// It is deliberately conservative: third-party and `dart:` imports are left to
/// the analyzer, and a library that declares extensions is skipped because an
/// extension can be used without naming it.
final _import = RegExp(
  r'''^import\s+['"]([^'"]+)['"](?:\s+as\s+(\w+))?(?:\s+(?:show|hide)\s+([^;]+))?;''',
  multiLine: true,
);
final _export = RegExp(r'''^export\s+['"]([^'"]+)['"]''', multiLine: true);
final _declaration = RegExp(
  r'^(?:abstract\s+|final\s+|sealed\s+|base\s+|interface\s+)*'
  r'(?:class|enum|mixin|typedef|extension)\s+([A-Za-z_]\w*)',
);
final _getter = RegExp(r'^[^=;]*?\bget\s+([A-Za-z_]\w*)');
final _extension = RegExp(r'^extension\s+[A-Za-z_]', multiLine: true);

/// Declarations a library exposes at top level (column zero only, so class
/// members are not mistaken for exports).
Set<String> declaredNames(String source) {
  final names = <String>{};
  for (final line in source.split('\n')) {
    if (line.isEmpty ||
        line.startsWith(' ') ||
        line.startsWith('\t') ||
        line.startsWith('import ') ||
        line.startsWith('export ') ||
        line.startsWith('part ') ||
        line.startsWith('library') ||
        line.startsWith('//') ||
        line.startsWith('@') ||
        line.startsWith('#')) {
      continue;
    }
    final declared = _declaration.firstMatch(line);
    if (declared != null) {
      names.add(declared[1]!);
      continue;
    }
    final getter = _getter.firstMatch(line);
    if (getter != null) {
      names.add(getter[1]!);
      continue;
    }
    // Top-level variable or function: the last identifier before `=`, `(` or `;`.
    final head = line.split(RegExp(r'[=(;]')).first;
    final identifiers = RegExp(r'[A-Za-z_]\w*').allMatches(head).toList();
    if (identifiers.isNotEmpty) names.add(identifiers.last[0]!);
  }
  return names;
}

/// Names visible through [file], following `export` directives.
Set<String> visibleNames(File file, Directory lib, [Set<String>? seen]) {
  seen ??= <String>{};
  if (!file.existsSync() || !seen.add(file.path)) return <String>{};
  final source = file.readAsStringSync();
  final names = declaredNames(source);
  for (final match in _export.allMatches(source)) {
    names.addAll(visibleNames(_resolve(match[1]!, file, lib), lib, seen));
  }
  return names;
}

File _resolve(String target, File from, Directory lib) {
  if (target.startsWith('package:xio/')) {
    return File('${lib.path}/${target.substring('package:xio/'.length)}');
  }
  return File('${from.parent.path}/$target');
}

List<String> deadImports(Directory root, Directory lib) {
  final problems = <String>[];
  for (final file in root.listSync(recursive: true).whereType<File>()) {
    if (!file.path.endsWith('.dart')) continue;
    final text = file.readAsStringSync();
    final body = text.replaceAll(_import, '');
    for (final match in _import.allMatches(text)) {
      final target = match[1]!;
      final prefix = match[2];
      final shown = match[3];
      final where = file.path.replaceAll('\\', '/');
      if (prefix != null) {
        if (!RegExp('\\b$prefix\\s*\\.').hasMatch(body)) {
          problems.add('$where: prefix "$prefix" of "$target" is never used');
        }
        continue;
      }
      if (target.startsWith('dart:')) continue;
      if (target.startsWith('package:') && !target.startsWith('package:xio/')) {
        continue;
      }
      final resolved = _resolve(target, file, lib);
      if (!resolved.existsSync()) {
        problems.add('$where: imported "$target" does not resolve');
        continue;
      }
      if (_extension.hasMatch(resolved.readAsStringSync())) continue;
      var names = visibleNames(resolved, lib);
      if (shown != null) {
        final listed = shown
            .split(',')
            .map((entry) => entry.trim().split(RegExp(r'\s+')).first)
            .where((entry) => entry.isNotEmpty)
            .toSet();
        final restricted = names.where(listed.contains).toSet();
        names = restricted.isEmpty ? listed : restricted;
      }
      if (names.isEmpty) continue;
      final used = names.any(
        (name) => RegExp('\\b${RegExp.escape(name)}\\b').hasMatch(body),
      );
      if (!used) {
        final sample = names.toList()..sort();
        problems.add('$where: "$target" is imported but unused ($sample)');
      }
    }
  }
  return problems;
}

void main() {
  test('first-party sources have no dead imports', () {
    final packageRoot = Directory.current;
    final lib = Directory('${packageRoot.path}/lib');
    expect(lib.existsSync(), isTrue, reason: 'run from the package root');
    for (final directory in <Directory>[
      lib,
      Directory('${packageRoot.path}/test'),
    ]) {
      expect(directory.existsSync(), isTrue, reason: directory.path);
      final problems = deadImports(directory, lib);
      expect(
        problems,
        isEmpty,
        reason:
            'Dead imports found (flutter analyze reports them as '
            'unused_import):\n${problems.join('\n')}',
      );
    }
  });

  test('the guard itself detects a dead import', () {
    // Self-check: the scan must not silently pass on everything.
    final root = Directory.systemTemp.createTempSync('xio-dead-imports-');
    addTearDown(() => root.deleteSync(recursive: true));
    final lib = Directory('${root.path}/lib')..createSync();
    File('${lib.path}/used.dart').writeAsStringSync('const marker = 1;\n');
    Directory('${root.path}/test').createSync();
    File(
      '${root.path}/test/sample.dart',
    ).writeAsStringSync("import '/nowhere.dart';\nimport 'package:xio/used.dart';\n"
        'void main() {}\n');
    // `used.dart` is imported without using `marker`, and the bogus path does
    // not resolve, so both are reported.
    final problems = deadImports(Directory('${root.path}/test'), lib);
    expect(problems, hasLength(2), reason: problems.join('\n'));
  });
}
