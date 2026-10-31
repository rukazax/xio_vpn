import 'dart:convert';
import 'dart:io';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:flutter_test/flutter_test.dart';

/// Packaging gate, opt-in because it reads the sibling server source tree.
/// Run from app/: XIO_ASSET_AUDIT=1 flutter test test/asset_provenance_test.dart
void main() {
  final enabled = Platform.environment['XIO_ASSET_AUDIT'] == '1';
  test(
    'bundled server archive and bootstrap match the server source tree',
    () async {
      String digest(List<int> bytes) => hashes.sha256.convert(bytes).toString();
      String recipe(String source) {
        final match = RegExp(
          r'^RECIPE=(\d+)',
          multiLine: true,
        ).firstMatch(source);
        return match?.group(1) ?? 'absent';
      }

      final manifest = Map<String, dynamic>.from(
        jsonDecode(await File('assets/xio-server-release.json').readAsString()),
      );
      final archiveBytes = await File('assets/xio-server.tar.gz').readAsBytes();
      final archive = TarDecoder().decodeBytes(
        GZipDecoder().decodeBytes(archiveBytes),
      );
      final problems = <String>[];

      if (manifest['sha256'] != digest(archiveBytes)) {
        problems.add('manifest sha256 does not match xio-server.tar.gz');
      }
      final bundledAdmin = archive.findFile('admin.py');
      if (bundledAdmin == null) {
        problems.add('archive has no admin.py');
      } else {
        final bundledRecipe = recipe(utf8.decode(bundledAdmin.content));
        if (bundledRecipe != '${manifest['recipeVersion']}') {
          problems.add(
            'archive admin.py RECIPE=$bundledRecipe but manifest '
            'recipeVersion=${manifest['recipeVersion']}',
          );
        }
      }
      final sourceAdmin = await File('../server/managed/admin.py')
          .readAsString();
      final sourceRecipe = recipe(sourceAdmin);
      if (sourceRecipe != '${manifest['recipeVersion']}') {
        problems.add(
          'server/managed/admin.py RECIPE=$sourceRecipe but manifest '
          'recipeVersion=${manifest['recipeVersion']}',
        );
      }

      for (final name in [
        'admin.py',
        'rivet-setup.py',
        'dualstack.py',
        'network_stack.py',
        'stack.py',
      ]) {
        final entry = archive.findFile(name);
        if (entry == null) {
          problems.add('archive has no $name');
          continue;
        }
        final source = await File('../server/managed/$name').readAsBytes();
        if (digest(entry.content) != digest(source)) {
          problems.add('$name differs from server/managed/$name');
        }
      }
      final bootstrap = await File('assets/xio-bootstrap.sh').readAsBytes();
      final sourceBootstrap = await File('../server/managed/bootstrap.sh')
          .readAsBytes();
      if (digest(bootstrap) != digest(sourceBootstrap)) {
        problems.add(
          'app/assets/xio-bootstrap.sh differs from '
          'server/managed/bootstrap.sh',
        );
      }

      expect(problems, isEmpty, reason: problems.join('\n'));
    },
    skip: !enabled,
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
