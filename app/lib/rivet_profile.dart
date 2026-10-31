import 'dart:convert';

import 'server_address.dart';

const rivetProtocols = ['rivet-h3', 'rivet-s1'];

/// Conservative automatic candidates for restricted networks. This is a policy,
/// not a claim that a protocol works on every Russian operator or allowlist.
const restrictedNetworkProtocols = [
  'xray',
  'rivet-s1',
  'cloak',
  'awg',
  'rivet-h3',
];
const nativeProtocols = ['xray', 'rivet-s1', 'cloak', 'awg', 'rivet-h3'];
Set<String> availableAndroidProtocols = nativeProtocols.toSet();

/// Client material only. Secrets are passed to the encrypted native vault.
class RivetProfile {
  final String protocol, endpoint;
  final Map<String, dynamic> data;
  RivetProfile._(this.protocol, this.endpoint, this.data);
  String get encoded => jsonEncode(data);
  static RivetProfile parse(String raw) {
    try {
      if (raw.length > 16384) throw const FormatException();
      final j = Map<String, dynamic>.from(jsonDecode(raw) as Map);
      const fields = {
        'protocol',
        'endpoint',
        'serverName',
        'pin',
        'gatewayId',
        'id',
        'secret',
        'entryToken',
        'ip',
        'ip6',
        'outerCA',
      };
      if (j.keys.any((k) => !fields.contains(k)) ||
          !rivetProtocols.contains(j['protocol'])) {
        throw const FormatException();
      }
      for (final key in [
        'endpoint',
        'serverName',
        'pin',
        'gatewayId',
        'id',
        'secret',
        'entryToken',
        'ip',
      ]) {
        if (j[key] is! String || (j[key] as String).isEmpty) {
          throw const FormatException();
        }
      }
      final endpoint = ServerEndpoint.parse(j['endpoint'] as String);
      final serverName = j['serverName'] as String;
      if (serverName.contains('[') || serverName.contains(']')) {
        throw const FormatException();
      }
      j['serverName'] = normalizeServerHost(serverName);
      j['endpoint'] = endpoint.formatted;
      for (final entry in {
        'pin': 32,
        'gatewayId': 16,
        'secret': 32,
        'entryToken': 32,
      }.entries) {
        final b = base64Decode(j[entry.key]);
        if (b.length != entry.value || base64Encode(b) != j[entry.key]) {
          throw const FormatException();
        }
      }
      if (j['secret'] == j['entryToken'] ||
          !RegExp(r'^[a-f0-9]{32}$').hasMatch(j['id'])) {
        throw const FormatException();
      }
      final match = RegExp(r'^10\.79\.0\.(\d{1,3})$').firstMatch(j['ip']);
      final slot = match == null ? -1 : int.parse(match[1]!);
      if (slot < 2 || slot > 254 || j['ip'] != '10.79.0.$slot') {
        throw const FormatException();
      }
      if (j['ip6'] != null && j['ip6'] != 'fd79:1::${slot.toRadixString(16)}') {
        throw const FormatException();
      }
      if (j.containsKey('outerCA') &&
          (j['outerCA'] is! String || (j['outerCA'] as String).length > 8192)) {
        throw const FormatException();
      }
      return RivetProfile._(j['protocol'], endpoint.formatted, j);
    } catch (_) {
      throw const FormatException('Некорректный профиль RIVET');
    }
  }
}

int protocolPreference(
  String protocol,
  String preferred, {
  bool restricted = false,
}) {
  if (protocol == preferred) return 0;
  final index = (restricted ? restrictedNetworkProtocols : nativeProtocols)
      .indexOf(protocol);
  return index < 0 ? 100 : index + 1;
}
