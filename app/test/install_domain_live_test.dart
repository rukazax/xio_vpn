import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/server_address.dart';

/// Opt-in live installer. Runs the exact product path after opening SSH:
/// VpsService.open -> ManagedService.install -> admin.py init.
///
/// Required:
///   XIO_LIVE_INSTALL=1
///   XIO_LIVE_SSH_HOST, XIO_LIVE_VPN_HOST
///   XIO_LIVE_SSH_PASSWORD or XIO_LIVE_SSH_KEY_FILE
/// Optional:
///   XIO_LIVE_SSH_PORT (22), XIO_LIVE_SSH_USER (root), XIO_LIVE_SSH_PIN,
///   XIO_LIVE_SSH_PASSPHRASE, XIO_LIVE_ASSETS_DIR, XIO_LIVE_CREATE_USER=1,
///   XIO_LIVE_RESULT
///
/// XIO_LIVE_ASSETS_DIR is the AssetBundle seam: a directory containing
/// xio-server.tar.gz, xio-bootstrap.sh and xio-server-release.json. Without
/// it the test uses the app's canonical assets.
class _DirectoryAssets extends CachingAssetBundle {
  _DirectoryAssets(this.directory);
  final Directory directory;

  @override
  Future<ByteData> load(String key) async {
    final file = File('${directory.path}/${key.split('/').last}');
    if (!await file.exists()) {
      throw StateError('Missing live asset: ${file.path}');
    }
    return ByteData.sublistView(await file.readAsBytes());
  }

  @override
  Future<String> loadString(String key, {bool cache = true}) async {
    final data = await load(key);
    return utf8.decode(
      data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes),
    );
  }
}

void main() {
  final enabled = Platform.environment['XIO_LIVE_INSTALL'] == '1';
  test(
    'live install uses the VPN hostname and the product SSH path',
    () async {
      final env = Platform.environment;
      final sshHost = env['XIO_LIVE_SSH_HOST']!;
      final sshPort = int.parse(env['XIO_LIVE_SSH_PORT'] ?? '22');
      final sshUser = env['XIO_LIVE_SSH_USER'] ?? 'root';
      final vpnHost = env['XIO_LIVE_VPN_HOST']!;
      final pin = env['XIO_LIVE_SSH_PIN'] ?? '';
      final password = env['XIO_LIVE_SSH_PASSWORD'] ?? '';
      final keyFile = env['XIO_LIVE_SSH_KEY_FILE'];
      final privateKey = keyFile == null
          ? ''
          : await File(keyFile).readAsString();
      final assetsDir = env['XIO_LIVE_ASSETS_DIR'];
      final assets = assetsDir == null
          ? rootBundle
          : _DirectoryAssets(Directory(assetsDir));
      final work = await Directory.systemTemp.createTemp('xio-live-install-');
      final ssh = VpsService(
        hostKeys: SshHostKeyStore(File('${work.path}/known-hosts.json')),
      );
      final store = AppStore()..directory = work;
      try {
        await ssh.open(
          SshTarget(sshHost, sshPort, sshUser, pin),
          password,
          privateKey,
          env['XIO_LIVE_SSH_PASSPHRASE'] ?? '',
        );
        final service = ManagedService(ssh, assets: assets);
        final server = await service.install(store, publicHost: vpnHost);
        expect(server.host, normalizeServerHost(sshHost));
        expect(server.port, sshPort);
        expect(server.publicHost, normalizeServerHost(vpnHost));
        if (pin.isNotEmpty) expect(server.hostKey, pin);

        final inspect = await service.command({'action': 'inspect'});
        final remote = Map<String, dynamic>.from(inspect['server']);
        expect(inspect['phase'], 'ready');
        expect(remote['id'], server.id);
        expect(remote['host'], server.publicHost);

        Map<String, dynamic>? bundleInfo;
        if (env['XIO_LIVE_CREATE_USER'] == '1') {
          final user = await service.createUser(store, server, 'TG211 live');
          final bundle = await store.exportUser(user);
          final awg = WireGuardProfile.parse(
            bundle.configs['awg']!,
            amnezia: true,
          );
          for (final protocol in ['rivet-h3', 'rivet-s1']) {
            final profile = RivetProfile.parse(bundle.configs[protocol]!);
            expect(profile.endpoint, serverEndpoint(server.publicHost, 8443));
          }
          bundleInfo = {
            'userId': user.id,
            'awgEndpoint': awg.endpoint,
            'rivetEndpoint': serverEndpoint(server.publicHost, 8443),
            'profiles': bundle.configs.keys.toList(),
          };
        }

        final release = await ServerRelease.load(assets);
        final evidence = {
          'ok': true,
          'sshHost': server.host,
          'sshPort': server.port,
          'vpnHost': server.publicHost,
          'serverId': server.id,
          'recipeVersion': remote['recipeVersion'],
          'bundleSha256': remote['bundleSha256'],
          'manifestRecipeVersion': release.recipeVersion,
          'assets': assetsDir ?? 'rootBundle',
          'user': bundleInfo,
          'createdAt': DateTime.now().toUtc().toIso8601String(),
        };
        final resultPath = env['XIO_LIVE_RESULT'];
        if (resultPath != null) {
          await File(resultPath).writeAsString(
            const JsonEncoder.withIndent('  ').convert(evidence),
            flush: true,
          );
        }
        // ignore: avoid_print
        print('XIO_LIVE_INSTALL_RESULT=${jsonEncode(evidence)}');
      } finally {
        await ssh.close();
        store.dispose();
        await work.delete(recursive: true);
      }
    },
    skip: !enabled,
    timeout: const Timeout(Duration(minutes: 30)),
  );
}
