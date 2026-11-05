// Verifies the release update channel end to end against the real 0.24.2
// packages: the signed `XIO-update.json` published as a release asset, the
// pinned Ed25519 key from the application bundle, and the exact size/SHA-256 of
// the Android and Linux packages.
//
// Checked-in signed envelopes are historical protocol fixtures, NOT mirrors of
// mutable release assets. The next fixture exercises UpdateService.check(); its
// URL does not exist on GitHub. Artifact/download gates must instead verify the
// actual XIO-update.json staged alongside the actual packages, with the real
// pinned application key. Never re-sign a fixture merely to make sizes agree.
//
// The package files themselves are not in the repository. Point
// XIO_RELEASE_DIR at a directory with the downloaded release assets to also
// compare sizes and hashes; without it those assertions are skipped.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart' as hash;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/update_service.dart';

class _Headers implements HttpHeaders {
  final values = <String, String>{};
  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    values[name] = value.toString();
  }

  @override
  String? value(String name) => values[name];
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Response extends Stream<List<int>> implements HttpClientResponse {
  final List<int> bytes;
  @override
  final headers = _Headers();
  _Response(this.bytes);
  @override
  int get statusCode => 200;
  @override
  int get contentLength => bytes.length;
  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int>)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => Stream<List<int>>.fromIterable([bytes]).listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Request implements HttpClientRequest {
  final _Response response;
  _Request(this.response);
  @override
  final headers = _Headers();
  @override
  set followRedirects(bool value) {}
  @override
  Future<HttpClientResponse> close() async => response;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

/// Serves a fixed body per exact URL, so a test can tell which request was made.
class _RoutedClient implements HttpClient {
  final Map<String, List<int>> bodies;
  final List<String> requests = [];
  bool closed = false;
  _RoutedClient(this.bodies);
  @override
  set connectionTimeout(Duration? value) {}
  @override
  Future<HttpClientRequest> getUrl(Uri uri) async {
    requests.add(uri.toString());
    if (closed) throw const HttpException('Cancelled');
    final body = bodies[uri.toString()];
    if (body == null) throw HttpException('Unexpected request: $uri');
    return _Request(_Response(body));
  }

  @override
  void close({bool force = false}) => closed = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

const _feedUrl =
    'https://api.github.com/repos/rukazax/xio_vpn/releases?per_page=30';
const _fixtures = 'test/fixtures';

List<int> _feed(String tag) => utf8.encode(
  jsonEncode([
    {
      'draft': false,
      'tag_name': tag,
      'assets': [
        {
          'name': 'XIO-update.json',
          'browser_download_url':
              '$githubUrl/releases/download/$tag/XIO-update.json',
        },
      ],
    },
  ]),
);

String? _releaseDir() {
  final configured = Platform.environment['XIO_RELEASE_DIR'];
  // Explicit opt-in must fail loudly on missing assets, not silently skip.
  if (configured != null) return configured;
  return Directory('../releases').existsSync() ? '../releases' : null;
}

Future<Directory> _temp() => Directory.systemTemp.createTemp('xio-manifest');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'historical 0.24.2 fixture verifies with the pinned application key',
    () async {
      final pinned = base64Decode(
        (await rootBundle.loadString('assets/security/update-ed25519.pub'))
            .trim(),
      );
      final release = await verifyReleaseEnvelope(
        await File('$_fixtures/XIO-update-0.24.2.json').readAsBytes(),
        pinned,
      );
      expect(release.version, '0.24.2');
      expect(release.build, 5019);
      expect(release.tag, 'v${release.version}');
      expect(release.notes, isNotEmpty);
      expect(
        release.assets.keys,
        containsAll(<String>['android-arm64-v8a', 'linux-x64']),
      );
      expect(release.forPlatform('ios'), null);
      expect(release.page, '$releasesUrl/tag/v${release.version}');
    },
  );

  test(
    'published manifest matches the real package sizes and hashes',
    () async {
      final dir = _releaseDir()!;
      final release = await verifyReleaseEnvelope(
        await File('$dir/XIO-update.json').readAsBytes(),
        base64Decode(
          (await rootBundle.loadString('assets/security/update-ed25519.pub'))
              .trim(),
        ),
      );
      for (final platform in release.assets.keys) {
        final asset = release.forPlatform(platform)!;
        final name = Uri.parse(asset.url).pathSegments.last;
        expect(asset.size, greaterThan(0));
        expect(asset.sha256, matches(RegExp(r'^[a-f0-9]{64}$')));
        final file = File('$dir/$name');
        expect(
          file.existsSync(),
          true,
          reason: '$name is declared by the manifest',
        );
        expect(await file.length(), asset.size, reason: '$name size');
        expect(
          (await hash.sha256.bind(file.openRead()).first).toString(),
          asset.sha256,
          reason: '$name sha256',
        );
      }
    },
    skip: _releaseDir() == null
        ? 'set XIO_RELEASE_DIR to the downloaded assets'
        : false,
  );

  test('check() returns the signed release for a build newer than this one', () async {
    final dir = await _temp();
    addTearDown(() => dir.delete(recursive: true));
    final manifest = await File('$_fixtures/XIO-update-next.json')
        .readAsBytes();
    final client = _RoutedClient({
      _feedUrl: _feed('v0.24.3'),
      'https://github.com/rukazax/xio_vpn/releases/download/v0.24.3/XIO-update.json':
          manifest,
    });
    final updater = UpdateService(
      directory: () async => dir,
      random: Random(0),
      clientFactory: () => client,
    );
    final release = await updater.check(manual: true);
    expect(release, isNotNull);
    expect(release!.version, '0.24.3');
    expect(release.build, greaterThan(xioBuild));
    final asset = release.forPlatform('android-arm64-v8a');
    expect(asset, isNotNull);
    expect(
      asset!.sha256,
      'f14a37ce36678e4cd752e55e3f9a9d4ac2e77b01260a83abd14a0ee2eb2b3610',
    );
    expect(Uri.parse(asset.url).pathSegments.take(5), [
      'rukazax',
      'xio_vpn',
      'releases',
      'download',
      'v0.24.3',
    ]);
    expect(client.requests, hasLength(2));
    expect(client.closed, true);
    expect(updater.next, isNotNull);
  });

  test(
    'check() skips a manifest for the installed version without fetching it',
    () async {
      final dir = await _temp();
      addTearDown(() => dir.delete(recursive: true));
      final client = _RoutedClient({_feedUrl: _feed('v$xioVersion')});
      final updater = UpdateService(
        directory: () async => dir,
        random: Random(0),
        clientFactory: () => client,
      );
      expect(await updater.check(manual: true), isNull);
      // The release feed alone decides: a manifest for the installed version is
      // never downloaded.
      expect(client.requests, hasLength(1));
    },
  );

  test('check() refuses a verified manifest advertised under another tag', () async {
    final dir = await _temp();
    addTearDown(() => dir.delete(recursive: true));
    // The real, correctly signed 0.24.2 envelope is offered as if it belonged to
    // v0.24.3. 'Release mismatch' is raised only after verifyReleaseEnvelope has
    // accepted the Ed25519 signature, so this proves the client verifies the
    // published bytes and refuses to re-label them.
    final manifest = await File('$_fixtures/XIO-update-0.24.2.json')
        .readAsBytes();
    final client = _RoutedClient({
      _feedUrl: _feed('v0.24.3'),
      'https://github.com/rukazax/xio_vpn/releases/download/v0.24.3/XIO-update.json':
          manifest,
    });
    final updater = UpdateService(
      directory: () async => dir,
      random: Random(0),
      clientFactory: () => client,
    );
    Object? error;
    try {
      await updater.check(manual: true);
    } catch (e) {
      error = e;
    }
    expect(error, isA<FormatException>());
    expect((error! as FormatException).message, 'Release mismatch');
    expect(client.requests, hasLength(2));
  });

  test(
    'download() accepts the real package bytes for the signed release',
    () async {
      final dir = _releaseDir()!;
      final release = await verifyReleaseEnvelope(
        await File('$dir/XIO-update.json').readAsBytes(),
        base64Decode(
          (await rootBundle.loadString('assets/security/update-ed25519.pub'))
              .trim(),
        ),
      );
      final asset = release.forPlatform('android-arm64-v8a')!;
      final name = Uri.parse(asset.url).pathSegments.last;
      final apk = File('$dir/$name');
      expect(
        apk.existsSync(),
        isTrue,
        reason: '$name is declared by the signed manifest',
      );
      final state = await _temp();
      addTearDown(() => state.delete(recursive: true));
      final client = _RoutedClient({asset.url: await apk.readAsBytes()});
      final updater = UpdateService(
        directory: () async => state,
        random: Random(0),
        clientFactory: () => client,
      );
      final file = await updater.download(release, asset, (_) {});
      expect(await file.length(), apk.lengthSync());
      expect(updater.state['installBuild'], release.build);
      expect(updater.downloading, false);
      expect(client.closed, true);
    },
    skip: _releaseDir() == null
        ? 'set XIO_RELEASE_DIR to the downloaded assets'
        : false,
  );

  test('the published signature covers the payload bytes', () async {
    final pinned = base64Decode(
      (await rootBundle.loadString('assets/security/update-ed25519.pub'))
          .trim(),
    );
    final published = await File('$_fixtures/XIO-update-0.24.2.json')
        .readAsString();
    final envelope = jsonDecode(published) as Map<String, dynamic>;
    final payload = jsonDecode(
      utf8.decode(base64Decode(envelope['payload'] as String)),
    ) as Map<String, dynamic>;
    payload['build'] = (payload['build'] as int) + 1;
    final forged = utf8.encode(
      jsonEncode({
        'payload': base64Encode(utf8.encode(jsonEncode(payload))),
        'signature': envelope['signature'],
      }),
    );
    await expectLater(
      verifyReleaseEnvelope(forged, pinned),
      throwsFormatException,
    );
  });
}
