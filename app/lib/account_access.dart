import 'dart:convert';
import 'dart:io';

import 'credentials.dart';

import 'package:crypto/crypto.dart';

import 'engine_channel.dart';

/// A pinned, account-scoped HTTPS capability, never an SSH/server credential.
class AccountAccess {
  final Uri endpoint;
  final String certificateSha256, token, userId, serverId;
  const AccountAccess(
    this.endpoint,
    this.certificateSha256,
    this.token,
    this.userId,
    this.serverId,
  );
  factory AccountAccess.parse(Map value, String userId, String serverId) {
    const fields = {
      'endpoint',
      'certificateSha256',
      'token',
      'userId',
      'serverId',
    };
    if (value.keys.toSet().difference(fields).isNotEmpty ||
        fields.any((key) => value[key] is! String)) {
      throw const FormatException(
        'Нужен ограниченный API-доступ без SSH/admin-ключей',
      );
    }
    final uri = Uri.tryParse(value['endpoint']);
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment ||
        uri.path != '/v1/subclients' ||
        uri.port < 1 ||
        uri.port > 65535 ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(value['certificateSha256']) ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(value['token']) ||
        value['userId'] != userId ||
        value['serverId'] != serverId) {
      throw const FormatException('Некорректный ограниченный доступ аккаунта');
    }
    return AccountAccess(
      uri,
      value['certificateSha256'],
      value['token'],
      userId,
      serverId,
    );
  }
  Map<String, String> toJson() => {
    'endpoint': endpoint.toString(),
    'certificateSha256': certificateSha256,
    'token': token,
    'userId': userId,
    'serverId': serverId,
  };
}

class AccountVault {
  static String id(String serverId, String userId) =>
      'state${sha256.convert(utf8.encode('client-account/$serverId/$userId'))}';
  static Future<Map<String, dynamic>?> read(
    String serverId,
    String userId,
  ) async {
    if (!Platform.isAndroid && !Platform.isIOS) {
      final saved = await CredentialVault.read(id(serverId, userId));
      return saved == null
          ? null
          : Map<String, dynamic>.from(jsonDecode(saved['record']!));
    }
    final raw = await const EngineChannel().invokeMethod<String>(
      'accountAccessRead',
      {'id': id(serverId, userId)},
    );
    return raw == null ? null : Map<String, dynamic>.from(jsonDecode(raw));
  }

  static Future<void> write(String serverId, String userId, Map value) async {
    if (!Platform.isAndroid && !Platform.isIOS) {
      await CredentialVault.write(id(serverId, userId), {
        'record': jsonEncode(value),
      });
      return;
    }
    await const EngineChannel().invokeMethod<void>('accountAccessWrite', {
      'id': id(serverId, userId),
      'value': jsonEncode(value),
    });
  }

  static Future<void> delete(String serverId, String userId) async {
    if (!Platform.isAndroid && !Platform.isIOS) {
      await CredentialVault.delete(id(serverId, userId));
      return;
    }
    await const EngineChannel().invokeMethod<void>('accountAccessDelete', {
      'id': id(serverId, userId),
    });
  }
}
