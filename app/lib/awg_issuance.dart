import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import 'awg_export.dart';
import 'core.dart';
import 'credentials.dart';
import 'managed_service.dart';

/// Issues a fresh, independent AmneziaWG peer for a device that has no XIO
/// client (scooter, router, another phone with AmneziaVPN).
///
/// The private key is generated on the phone and never leaves it: the server
/// receives only the public key and returns a profile with a placeholder.
/// A separate key matters — importing the XIO client's own profile into a
/// second device would make both devices fight over the same WG peer.
class AwgIssuance {
  const AwgIssuance._();

  static Future<AwgProfile> newDevice(
    AppStore store,
    ManagedUser user,
    String name,
  ) async {
    final server = store.servers.where((s) => s.id == user.serverId).firstOrNull;
    if (server == null) throw const AwgExportError('Сервер не найден');
    if (server.delegated) {
      throw const AwgExportError(
        'Выдача нового устройства доступна только владельцу сервера',
      );
    }
    final saved = await CredentialVault.read(store.credentialId(server));
    if (saved == null) {
      throw const AwgExportError(
        'Нет сохранённого SSH-доступа к серверу: обновите сервер в настройках',
      );
    }

    final private = await _privateKey();
    final public = await _publicKey(private);
    final id = _identity();

    final ssh = VpsService();
    try {
      await ssh.open(
        SshTarget(server.host, server.port, server.username, server.hostKey),
        saved['password'] ?? '',
        saved['key'] ?? '',
        saved['passphrase'] ?? '',
      );
      final service = ManagedService(ssh);
      final answer = await service.command({
        'action': 'add-awg',
        'serverId': server.id,
        'name': name.trim().isEmpty ? 'device' : name.trim(),
        'id': id,
        'publicKey': public,
      });
      final config = answer['config'];
      if (config is! String || !config.contains('<client-private-key>')) {
        throw const AwgExportError('Сервер вернул профиль без ключа клиента');
      }
      final filled = config.replaceAll('<client-private-key>', private);
      return AwgProfile.parse(filled);
    } finally {
      await ssh.close();
    }
  }

  /// 32 random bytes, clamped exactly like `wg genkey` (curve25519 scalar).
  static Future<String> _privateKey() async {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return base64.encode(bytes);
  }

  static Future<String> _publicKey(String privateBase64) async {
    final bytes = base64.decode(privateBase64);
    final pair = await X25519().newKeyPairFromSeed(bytes);
    final public = await pair.extractPublicKey();
    return base64.encode(public.bytes);
  }

  static String _identity() {
    final random = Random.secure();
    return List.generate(32, (_) => random.nextInt(16).toRadixString(16)).join();
  }
}
