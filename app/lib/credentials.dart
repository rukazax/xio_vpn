import 'windows_crypto.dart';

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as hashing;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';

/// Secrets never enter profiles.json, diagnostics or ordinary user bundles.
class CredentialVault {
  static const channel = MethodChannel('app.x1o/engine');
  static String id(
    String host,
    int port,
    String username, {
    String scope = '',
  }) =>
      'ssh${hashing.sha256.convert(utf8.encode('$host:$port:$username:$scope'))}';
  static Future<Directory> _folder() async {
    final root = Platform.isWindows
        ? Platform.environment['LOCALAPPDATA']!
        : (Platform.environment['XDG_DATA_HOME'] ??
              '${Platform.environment['HOME']}/.local/share');
    final d = Directory('$root/app.x1o.x1o/credentials');
    await d.create(recursive: true);
    if (Platform.isLinux) {
      final p = await Process.run('chmod', ['700', d.path]);
      if (p.exitCode != 0) throw StateError('Не удалось защитить хранилище');
    }
    return d;
  }

  static Future<List<int>> _desktopCrypt(List<int> bytes, bool encrypt) async {
    if (Platform.isWindows) return windowsCrypt(bytes, encrypt);
    // Linux fallback: device-local key in a 0700 directory and a 0600 file.
    // It protects exports/backups; it does not defend against a compromised login.
    final dir = await _folder();
    final file = File('${dir.path}/device.key');
    if (!await file.exists()) {
      final key = SecretKeyData.random(length: 32).bytes;
      await file.writeAsBytes(key, flush: true);
      if ((await Process.run('chmod', ['600', file.path])).exitCode != 0) {
        throw StateError('Не удалось защитить хранилище');
      }
    }
    final key = SecretKey(await file.readAsBytes());
    final aes = AesGcm.with256bits();
    if (encrypt) {
      return (await aes.encrypt(bytes, secretKey: key)).concatenation();
    }
    return aes.decrypt(
      SecretBox.fromConcatenation(bytes, nonceLength: 12, macLength: 16),
      secretKey: key,
    );
  }

  static Future<Map<String, String>?> read(String id) async {
    String? text;
    if (Platform.isAndroid || Platform.isIOS) {
      text = await channel.invokeMethod<String>('credentialRead', {'id': id});
    } else {
      final file = File('${(await _folder()).path}/$id.bin');
      if (!await file.exists()) return null;
      text = utf8.decode(await _desktopCrypt(await file.readAsBytes(), false));
    }
    return text == null ? null : Map<String, String>.from(jsonDecode(text));
  }

  static Future<void> write(String id, Map<String, String> value) async {
    if (!RegExp(r'^(?:ssh|vpn)[a-f0-9]{64}$').hasMatch(id)) {
      throw const FormatException('Invalid credential id');
    }
    final raw = jsonEncode(value);
    if (Platform.isAndroid || Platform.isIOS) {
      await channel.invokeMethod<void>('credentialWrite', {
        'id': id,
        'value': raw,
      });
      return;
    }
    final file = File('${(await _folder()).path}/$id.bin');
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(
      await _desktopCrypt(utf8.encode(raw), true),
      flush: true,
    );
    if (Platform.isLinux &&
        (await Process.run('chmod', ['600', tmp.path])).exitCode != 0) {
      throw StateError('Не удалось защитить хранилище');
    }
    await tmp.rename(file.path);
  }

  static Future<void> delete(String id) async {
    if (Platform.isAndroid || Platform.isIOS) {
      await channel.invokeMethod<void>('credentialDelete', {'id': id});
      return;
    }
    final file = File('${(await _folder()).path}/$id.bin');
    if (await file.exists()) await file.delete();
  }
}
