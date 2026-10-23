// SPDX-License-Identifier: GPL-3.0-only
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';

import 'core.dart';

bool automaticUpdatesEnabled = false;
void Function()? onUpdateRequest;
const xioVersion = '0.22.4';
const xioBuild = 5013;
const githubUrl = 'https://github.com/rukazax/xio_vpn';
const releasesUrl = '$githubUrl/releases';
const playDistribution = bool.fromEnvironment('XIO_PLAY_BUILD');

bool newerVersion(String candidate, String current) {
  List<int> parts(String s) {
    if (!RegExp(r'^\d+\.\d+\.\d+$').hasMatch(s)) {
      throw const FormatException('Invalid version');
    }
    return s.split('.').map(int.parse).toList();
  }

  final a = parts(candidate), b = parts(current);
  for (var i = 0; i < 3; i++) {
    if (a[i] != b[i]) return a[i] > b[i];
  }
  return false;
}

DateTime nextWeeklyCheck(DateTime now, Random random) =>
    now.add(Duration(days: 7, seconds: random.nextInt(24 * 60 * 60)));

void validateAssetUrl(String raw, String tag) {
  final u = Uri.parse(raw);
  if (u.scheme != 'https' ||
      u.host != 'github.com' ||
      u.hasPort ||
      u.userInfo.isNotEmpty ||
      !u.path.startsWith('/rukazax/xio_vpn/releases/download/$tag/') ||
      u.query.isNotEmpty ||
      u.fragment.isNotEmpty ||
      u.pathSegments.last.isEmpty ||
      u.pathSegments.any((s) => s == '..' || s == '.')) {
    throw const FormatException('Invalid update URL');
  }
}

class UpdateAsset {
  final String url, sha256;
  final int size;
  UpdateAsset(Map<String, dynamic> j, String tag)
    : url = j['url'] as String,
      sha256 = j['sha256'] as String,
      size = j['size'] as int {
    validateAssetUrl(url, tag);
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(sha256) ||
        size < 1 ||
        size > 800 * 1024 * 1024) {
      throw const FormatException('Invalid update package');
    }
  }
}

class XioRelease {
  final String tag, version, notes;
  final int build;
  final Map<String, dynamic> assets;
  XioRelease(Map<String, dynamic> j)
    : tag = j['tag'] as String,
      version = j['version'] as String,
      build = j['build'] as int,
      notes = j['notes'] as String,
      assets = Map<String, dynamic>.from(j['assets'] as Map) {
    if (tag != 'v$version' ||
        !RegExp(r'^v\d+\.\d+\.\d+$').hasMatch(tag) ||
        j['schema'] != 1 ||
        build < 1 ||
        notes.length > 12000) {
      throw const FormatException('Invalid release');
    }
    for (final asset in assets.values) {
      UpdateAsset(Map<String, dynamic>.from(asset as Map), tag);
    }
  }
  String get page => '$releasesUrl/tag/$tag';
  UpdateAsset? forPlatform(String platform) => assets[platform] == null
      ? null
      : UpdateAsset(Map<String, dynamic>.from(assets[platform] as Map), tag);
}

Future<XioRelease> verifyReleaseEnvelope(
  List<int> bytes,
  List<int> publicKey,
) async {
  final envelope = jsonDecode(utf8.decode(bytes)) as Map;
  final payload = base64Decode(envelope['payload'] as String);
  final signature = base64Decode(envelope['signature'] as String);
  if (payload.length > 64000 ||
      signature.length != 64 ||
      publicKey.length != 32 ||
      !await Ed25519().verify(
        payload,
        signature: Signature(
          signature,
          publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
        ),
      )) {
    throw const FormatException('Invalid update signature');
  }
  return XioRelease(
    Map<String, dynamic>.from(jsonDecode(utf8.decode(payload)) as Map),
  );
}

/// No credentials or VPN configurations are sent. Only HTTPS GitHub requests.
/// One check in flight; persisted random due time survives process restarts.
class UpdateService {
  static final instance = UpdateService();
  final Random random;
  final HttpClient Function() clientFactory;
  final Future<Directory> Function() directory;
  UpdateService({
    Random? random,
    Future<Directory> Function()? directory,
    HttpClient Function()? clientFactory,
  }) : clientFactory = clientFactory ?? HttpClient.new,
       random = random ?? Random.secure(),
       directory = directory ?? applicationDirectory;
  Map<String, dynamic> state = {};
  bool _loaded = false;
  Future<XioRelease?>? _checking;
  bool downloading = false;
  HttpClient? _downloadClient;
  File? _stateFile;
  Future<void>? _initializing;
  Future<void> initialize() => _initializing ??= _initialize();
  Future<void> _initialize() async {
    if (_loaded) return;
    final dir = await directory();
    _stateFile = File('${dir.path}/updates.json');
    try {
      state = Map<String, dynamic>.from(
        jsonDecode(await _stateFile!.readAsString()) as Map,
      );
    } catch (_) {
      state = {};
    }
    _loaded = true;
    // Only our fixed staging directory is eligible for cleanup.
    final staging = Directory('${dir.path}/update-staging');
    if (state['installBuild'] is int &&
        (state['installBuild'] as int) <= xioBuild) {
      if (Platform.isWindows) {
        await staging.create(recursive: true);
        await File('${staging.path}/installed-${state['installBuild']}')
            .writeAsString(xioVersion, flush: true);
      } else if (await staging.exists()) {
        await staging.delete(recursive: true);
      }
      state.remove('installBuild');
    }
    if (state['next'] == null) {
      state['next'] = nextWeeklyCheck(
        DateTime.now(),
        random,
      ).millisecondsSinceEpoch;
    }
    await _save();
  }

  Future<void> _save() async {
    final temp = File('${_stateFile!.path}.tmp');
    await temp.writeAsString(jsonEncode(state), flush: true);
    await temp.rename(_stateFile!.path);
  }

  bool get due =>
      DateTime.now().millisecondsSinceEpoch >= (state['next'] as int? ?? 0);
  DateTime? get next => state['next'] is int
      ? DateTime.fromMillisecondsSinceEpoch(state['next'] as int)
      : null;
  Future<void> skip(XioRelease release) async {
    state['skip'] = release.tag;
    await _save();
  }

  Future<XioRelease?> check({bool manual = false}) {
    return _checking ??= _check(manual).whenComplete(() => _checking = null);
  }

  Future<XioRelease?> _check(bool manual) async {
    await initialize();
    if (playDistribution) return null;
    if (!manual && !due) return null;
    final now = DateTime.now();
    // Persist before network I/O; failed/offline clients never hammer GitHub.
    final blocked = state['retryAfter'] as int? ?? 0;
    if (now.millisecondsSinceEpoch < blocked) {
      throw StateError('Повторите проверку позже');
    }
    state['next'] = nextWeeklyCheck(now, random).millisecondsSinceEpoch;
    state['retryAfter'] = now
        .add(const Duration(minutes: 5))
        .millisecondsSinceEpoch;
    await _save();
    final client = clientFactory()
      ..connectionTimeout = const Duration(seconds: 15);
    try {
      final headers = <String, String>{};
      if (state['etag'] is String && state['feed'] is List) {
        headers['If-None-Match'] = state['etag'] as String;
      }
      final response = await _get(
        client,
        Uri.parse(
          'https://api.github.com/repos/rukazax/xio_vpn/releases?per_page=30',
        ),
        headers: headers,
      );
      List<dynamic> feed;
      if (response.statusCode == 304) {
        await response.drain<void>();
        feed = state['feed'] as List;
      } else {
        if (response.statusCode != 200) {
          final retry = int.tryParse(
            response.headers.value('retry-after') ?? '',
          );
          if (retry != null) {
            state['retryAfter'] = now
                .add(Duration(seconds: retry.clamp(300, 86400)))
                .millisecondsSinceEpoch;
          }
          final reset = int.tryParse(
            response.headers.value('x-ratelimit-reset') ?? '',
          );
          if (response.headers.value('x-ratelimit-remaining') == '0' &&
              reset != null) {
            state['retryAfter'] = max(
              state['retryAfter'] as int,
              min(
                now.add(const Duration(days: 1)).millisecondsSinceEpoch,
                reset * 1000,
              ),
            );
          }
          await _save();
          throw StateError('GitHub временно недоступен');
        }
        feed = jsonDecode(
          utf8.decode(await _readBounded(response, 2 * 1024 * 1024)),
        ) as List;
        state['feed'] = feed;
        state['etag'] = response.headers.value('etag');
        await _save();
      }
      final key = base64Decode(
        (await rootBundle.loadString('assets/security/update-ed25519.pub'))
            .trim(),
      );
      final candidates =
          feed
              .whereType<Map>()
              .where(
                (j) =>
                    j['draft'] != true &&
                    RegExp(r'^v\d+\.\d+\.\d+$')
                        .hasMatch(j['tag_name'] as String? ?? ''),
              )
              .toList()
            ..sort(
              (a, b) =>
                  newerVersion(
                    (a['tag_name'] as String).substring(1),
                    (b['tag_name'] as String).substring(1),
                  )
                  ? -1
                  : 1,
            );
      for (final j in candidates) {
        final tag = j['tag_name'] as String;
        if (!newerVersion(tag.substring(1), xioVersion)) continue;
        final files = (j['assets'] as List)
            .whereType<Map>()
            .where((a) => a['name'] == 'XIO-update.json')
            .toList();
        if (files.length != 1) continue;
        final url = files.single['browser_download_url'] as String;
        validateAssetUrl(url, tag);
        final r = await _get(client, Uri.parse(url));
        if (r.statusCode != 200) {
          throw StateError('Не удалось получить обновление');
        }
        final release = await verifyReleaseEnvelope(
          await _readBounded(r, 100000),
          key,
        );
        if (release.tag != tag || release.build <= xioBuild) {
          throw const FormatException('Release mismatch');
        }
        if (!manual && state['skip'] == tag) return null;
        return release;
      }
      return null;
    } finally {
      client.close(force: true);
    }
  }

  static Future<HttpClientResponse> _get(
    HttpClient client,
    Uri uri, {
    Map<String, String> headers = const {},
  }) async {
    // Redirects may only lead to GitHub's asset CDN. Never forward credentials.
    for (var i = 0; i < 6; i++) {
      if (uri.scheme != 'https' ||
          !{
            'api.github.com',
            'github.com',
            'release-assets.githubusercontent.com',
            'objects.githubusercontent.com',
          }.contains(uri.host) ||
          uri.userInfo.isNotEmpty ||
          uri.hasPort) {
        throw const FormatException('Unsafe redirect');
      }
      final req = await client.getUrl(uri).timeout(const Duration(seconds: 20));
      req.followRedirects = false;
      req.headers.set('User-Agent', 'XIO/$xioVersion');
      headers.forEach(req.headers.set);
      final response = await req.close().timeout(const Duration(seconds: 30));
      if (![301, 302, 303, 307, 308].contains(response.statusCode)) {
        return response;
      }
      final location = response.headers.value('location');
      await response.drain<void>();
      if (location == null) throw const FormatException('Missing redirect');
      uri = uri.resolve(location);
      headers = {};
    }
    throw const FormatException('Too many redirects');
  }

  static Future<List<int>> _readBounded(
    HttpClientResponse response,
    int max,
  ) async {
    final bytes = <int>[];
    await for (final chunk in response.timeout(const Duration(seconds: 30))) {
      if (bytes.length + chunk.length > max) {
        throw const FormatException('Update response too large');
      }
      bytes.addAll(chunk);
    }
    return bytes;
  }

  Future<String> platformKey() async {
    if (Platform.isAndroid) {
      return 'android-${await native.invokeMethod<String>('updateAbi')}';
    }
    if (Platform.isIOS) return 'ios';
    return '${Platform.isWindows ? 'windows' : 'linux'}-x64';
  }

  void cancelDownload() {
    _downloadClient?.close(force: true);
  }

  Future<File> download(
    XioRelease release,
    UpdateAsset asset,
    void Function(double) progress,
  ) async {
    if (downloading) throw StateError('Обновление уже загружается');
    downloading = true;
    try {
      await initialize();
      return await _download(release, asset, progress);
    } finally {
      downloading = false;
    }
  }

  Future<File> _download(
    XioRelease release,
    UpdateAsset asset,
    void Function(double) progress,
  ) async {
    final dir = Directory('${(await directory()).path}/update-staging');
    await dir.create(recursive: true);
    final file = File('${dir.path}/${Uri.parse(asset.url).pathSegments.last}');
    final partial = File('${file.path}.part');
    final client = clientFactory()
      ..connectionTimeout = const Duration(seconds: 20);
    _downloadClient = client;
    try {
      // Spread user-approved downloads too, rather than starting a release-wide burst.
      await Future<void>.delayed(Duration(milliseconds: random.nextInt(3000)));
      final response = await _get(client, Uri.parse(asset.url));
      if (response.statusCode != 200 ||
          (response.contentLength >= 0 &&
              response.contentLength != asset.size)) {
        throw const FormatException('Package size mismatch');
      }
      final sink = partial.openWrite();
      var count = 0;
      try {
        await for (final chunk in response.timeout(
          const Duration(seconds: 60),
        )) {
          count += chunk.length;
          if (count > asset.size) {
            throw const FormatException('Package size mismatch');
          }
          sink.add(chunk);
          progress(count / asset.size);
        }
      } finally {
        await sink.close();
      }
      if (count != asset.size ||
          (await crypto.sha256.bind(partial.openRead()).first).toString() !=
              asset.sha256) {
        throw const FormatException('Package checksum mismatch');
      }
      await partial.rename(file.path);
      state['installBuild'] = release.build;
      await _save();
      return file;
    } catch (_) {
      if (await partial.exists()) await partial.delete();
      if (await file.exists()) await file.delete();
      rethrow;
    } finally {
      client.close(force: true);
      _downloadClient = null;
      downloading = false;
    }
  }
}
