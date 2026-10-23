import 'package:crypto/crypto.dart' as hash;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:archive/archive_io.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:x1o/update_service.dart';
import 'package:x1o/update_installer.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  Map<String, dynamic> manifest() => {
    'schema': 1,
    'tag': 'v0.22.0',
    'version': '0.22.0',
    'build': 5004,
    'notes': 'Test',
    'assets': {
      'windows-x64': {
        'url': '$githubUrl/releases/download/v0.22.0/XIO.zip',
        'size': 10,
        'sha256': 'a' * 64,
      },
    },
  };
  test('installed version matches the build source', () async {
    final source = await File('pubspec.yaml').readAsString();
    expect(source, contains('version: $xioVersion+$xioBuild'));
  });
  test('published envelope verifies with the pinned key and matches final packages', () async {
    final release = await verifyReleaseEnvelope(
      await File('../releases/XIO-update.json').readAsBytes(),
      base64Decode(
        (await File(
          'assets/security/update-ed25519.pub',
        ).readAsString()).trim(),
      ),
    );
    // The last published signed fixture may precede a prepared candidate.
    // Its own asset sizes and digests are still checked below.
    expect(newerVersion(release.version, xioVersion), false);
    expect(release.build, lessThanOrEqualTo(xioBuild));
    expect(release.assets, isNotEmpty);
    // A platform-specific patch need not issue unrelated desktop packages.
    for (final platform in release.assets.keys) {
      final asset = release.forPlatform(platform)!;
      final file = File(
        '../releases/${Uri.parse(asset.url).pathSegments.last}',
      );
      expect(await file.length(), asset.size);
      expect(
        (await hash.sha256.bind(file.openRead()).first).toString(),
        asset.sha256,
      );
    }
  }, skip: !File('../releases/XIO-update.json').existsSync());
  test(
    'only strictly newer semantic versions qualify, never documentation tags',
    () {
      expect(newerVersion('0.21.0', '0.20.9'), true);
      expect(newerVersion('0.21.0', '0.21.0'), false);
      expect(newerVersion('0.20.99', '0.21.0'), false);
      expect(newerVersion('1.0.0', '0.99.99'), true);
      for (final s in [
        'public-launch-v1.0',
        'rivet-docs-v1.0',
        '0.22.0-beta',
        '../../a',
      ]) {
        expect(() => newerVersion(s, xioVersion), throwsFormatException);
      }
    },
  );
  test('weekly schedule persists with 24-hour independent jitter, not a release-wide time', () async {
    final now = DateTime.utc(2026, 10, 19);
    final times = List.generate(100, (i) => nextWeeklyCheck(now, Random(i)));
    expect(
      times.every(
        (d) =>
            d.difference(now) >= const Duration(days: 7) &&
            d.difference(now) < const Duration(days: 8),
      ),
      true,
    );
    expect(
      times.map((d) => d.millisecondsSinceEpoch).toSet().length,
      greaterThan(95),
    );
    final dir = await Directory.systemTemp.createTemp('xio-updates-test');
    addTearDown(() => dir.delete(recursive: true));
    final a = UpdateService(directory: () async => dir, random: Random(5));
    await a.initialize();
    final next = a.next;
    await a.skip(XioRelease(manifest()));
    final b = UpdateService(directory: () async => dir, random: Random(99));
    await b.initialize();
    expect(b.next, next);
    expect(b.state['skip'], 'v0.22.0');
  });
  test(
    'successful installed build cleans only the fixed staging directory',
    () async {
      final dir = await Directory.systemTemp.createTemp('xio-cleanup-test');
      addTearDown(() => dir.delete(recursive: true));
      await Directory('${dir.path}/update-staging').create();
      await File('${dir.path}/update-staging/XIO.apk')
          .writeAsString('old installer');
      await File('${dir.path}/profiles-sentinel').writeAsString('keep');
      await File('${dir.path}/updates.json')
          .writeAsString(jsonEncode({'installBuild': xioBuild}));
      final updater = UpdateService(directory: () async => dir);
      await updater.initialize();
      expect(await Directory('${dir.path}/update-staging').exists(), false);
      expect(
        await File('${dir.path}/profiles-sentinel').readAsString(),
        'keep',
      );
    },
  );
  test(
    'signed manifest rejects modified payload and unrelated signing key',
    () async {
      final algorithm = Ed25519();
      final key = await algorithm.newKeyPair();
      final pub = await key.extractPublicKey();
      final bytes = utf8.encode(jsonEncode(manifest()));
      final signature = await algorithm.sign(bytes, keyPair: key);
      List<int> envelope(List<int> payload) => utf8.encode(
        jsonEncode({
          'payload': base64Encode(payload),
          'signature': base64Encode(signature.bytes),
        }),
      );
      final release = await verifyReleaseEnvelope(envelope(bytes), pub.bytes);
      expect(release.version, '0.22.0');
      expect(release.forPlatform('android-arm64-v8a'), null);
      expect(
        () => verifyReleaseEnvelope(
          envelope([...bytes.take(bytes.length - 1), 32]),
          pub.bytes,
        ),
        throwsFormatException,
      );
      final wrong = await (await algorithm.newKeyPair()).extractPublicKey();
      expect(
        () => verifyReleaseEnvelope(envelope(bytes), wrong.bytes),
        throwsFormatException,
      );
    },
  );
  test('reject asset host substitution, traversal, malformed hashes and huge sizes', () {
    for (final url in [
      'http://github.com/rukazax/xio_vpn/releases/download/v0.22.0/a',
      'https://github.com.evil.test/rukazax/xio_vpn/releases/download/v0.22.0/a',
      'https://user@github.com/rukazax/xio_vpn/releases/download/v0.22.0/a',
      'https://github.com/rukazax/xio_vpn/releases/download/v0.22.0/%2e%2e/a',
      'https://github.com/rukazax/other/releases/download/v0.22.0/a',
    ]) {
      expect(() => validateAssetUrl(url, 'v0.22.0'), throwsFormatException);
    }
    final bad = manifest();
    (bad['assets'] as Map)['windows-x64']['size'] = 900 * 1024 * 1024;
    expect(() => XioRelease(bad), throwsFormatException);
  });
  test('archive traversal, links and duplicate Windows paths fail before extraction', () async {
    final dir = await Directory.systemTemp.createTemp('xio-zip-test');
    addTearDown(() => dir.delete(recursive: true));
    for (final entry in [
      ArchiveFile.string('XIO/../../escape', 'bad'),
      ArchiveFile.string('XIO/a:stream', 'bad'),
      (ArchiveFile.string('XIO/link', '/tmp')
        ..symbolicLink = '/tmp'
        ..mode = 0xa1ff),
      ArchiveFile.string('XIO/xio.EXE', 'duplicate'),
    ]) {
      final archive = Archive()
        ..add(ArchiveFile.string('XIO/XIO.exe', 'exe'))
        ..add(entry);
      final source = File('${dir.path}/test.zip')
        ..writeAsBytesSync(ZipEncoder().encode(archive));
      expect(
        () => extractWindowsUpdate(source.path, '${dir.path}/output'),
        throwsFormatException,
        reason: entry.name,
      );
      expect(Directory('${dir.path}/output').existsSync(), false);
    }
    final archive = Archive()
      ..add(ArchiveFile.string('XIO/XIO.exe', 'exe'))
      ..add(ArchiveFile.string('XIO/data/app.so', 'aot'));
    final source = File('${dir.path}/test.zip')
      ..writeAsBytesSync(ZipEncoder().encode(archive));
    extractWindowsUpdate(source.path, '${dir.path}/output');
    expect(
      File('${dir.path}/output/XIO/data/app.so').readAsStringSync(),
      'aot',
    );
  });
}
