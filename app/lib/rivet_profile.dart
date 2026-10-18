import 'dart:convert';

const rivetProtocols = ['rivet-h3', 'rivet-s1'];
const nativeProtocols = [
  'rivet-h3',
  'rivet-s1',
  'awg',
  'wireguard',
  'xray',
  'shadowsocks',
  'openvpn',
  'cloak',
  'ikev2',
  'tailscale',
];

Set<String> availableAndroidProtocols = nativeProtocols
    .where((p) => p != 'ikev2')
    .toSet();

/// Client material only. Secrets are passed to the encrypted native vault.
class RivetProfile {
  final String protocol, endpoint;
  final Map<String, dynamic> data;
  RivetProfile._(this.protocol, this.endpoint, this.data);
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
      final uri = Uri.parse('https://${j['endpoint']}');
      if (uri.host.isEmpty ||
          !uri.hasPort ||
          uri.port < 1 ||
          uri.port > 65535 ||
          uri.userInfo.isNotEmpty ||
          uri.path.isNotEmpty ||
          uri.hasQuery ||
          uri.hasFragment) {
        throw const FormatException();
      }
      if (!RegExp(r'^[a-zA-Z0-9.:-]{1,253}$').hasMatch(j['serverName'])) {
        throw const FormatException();
      }
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
      if (j.containsKey('outerCA') &&
          (j['outerCA'] is! String || (j['outerCA'] as String).length > 8192)) {
        throw const FormatException();
      }
      return RivetProfile._(j['protocol'], j['endpoint'], j);
    } catch (_) {
      throw const FormatException('Некорректный профиль RIVET');
    }
  }
}

int protocolPreference(String protocol, String preferred) {
  if (protocol == preferred) return 0;
  final index = nativeProtocols.indexOf(protocol);
  return index < 0 ? 100 : index + 1;
}
