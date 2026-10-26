import 'build_identity.dart';
import 'protocol_compatibility.dart';
import 'account_access.dart';
import 'client_policy.dart';
import 'engine_channel.dart';
import 'desktop_engine.dart';
import 'probe_tls.dart';
import 'legal_record.dart';
import 'credentials.dart';
import 'rivet_profile.dart';
import 'extended_profile.dart';
export 'extended_profile.dart';
export 'rivet_profile.dart';
import 'status_poll.dart';
import 'l10n.dart';

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'managed_models.dart';
export 'managed_models.dart';

import 'package:cryptography/cryptography.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const native = EngineChannel();
bool get platformTunnel =>
    Platform.isAndroid || Platform.isIOS || DesktopEngine.enabled;
Set<String> get platformProtocols => Platform.isAndroid
    ? availableAndroidProtocols
    : Platform.isIOS
    ? nativeProtocolTargets[ClientPlatform.ios]!
    : DesktopEngine.supported;

Future<Directory> applicationDirectory() async {
  String path;
  if (Platform.isAndroid || Platform.isIOS) {
    path = (await native.invokeMethod<String>('dataDirectory'))!;
  } else if (Platform.isWindows) {
    final base = Platform.environment['LOCALAPPDATA'];
    if (base == null) throw StateError('LOCALAPPDATA is unavailable');
    path = '$base\\${desktopProductDirectory(windows: true)}';
  } else if (Platform.isLinux) {
    final base =
        Platform.environment['XDG_DATA_HOME'] ??
        '${Platform.environment['HOME']}/.local/share';
    path = '$base/${desktopProductDirectory(windows: false)}';
  } else {
    throw UnsupportedError('Unsupported platform');
  }
  final dir = Directory(path);
  await dir.create(recursive: true);
  return dir;
}

class Protocol {
  final String id, name, detail, family;
  const Protocol(this.id, this.name, this.detail, this.family);
  bool get available => platformProtocols.contains(id) && platformTunnel;
}

const protocols = [
  Protocol('xray', 'Xray / VLESS', 'TLS В· REALITY В· XHTTP', 'Xray'),
  Protocol(
    'rivet-s1',
    'RIVET / S1',
    'Р­РєСЃРїРµСЂРёРјРµРЅС‚Р°Р»СЊРЅС‹Р№ В· TLS / WebSocket',
    'RIVET',
  ),
  Protocol('cloak', 'Cloak', 'TLS / TCP', 'Cloak'),
  Protocol('awg', 'AmneziaWG 3.1', 'РћР±С„СѓСЃРєР°С†РёСЏ WireGuard', 'Amnezia'),
  Protocol(
    'rivet-h3',
    'RIVET / H3',
    'Р­РєСЃРїРµСЂРёРјРµРЅС‚Р°Р»СЊРЅС‹Р№ В· QUIC / CONNECT-UDP',
    'RIVET',
  ),
];

class Profile {
  final String id, name, protocol, endpoint;
  const Profile({
    required this.id,
    required this.name,
    required this.protocol,
    required this.endpoint,
  });
  factory Profile.fromJson(Map<String, dynamic> j) => Profile(
    id: j['id'],
    name: j['name'],
    protocol: j['protocol'],
    endpoint: j['endpoint'],
  );
  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'protocol': protocol,
    'endpoint': endpoint,
  };
}

/// Validate the accepted WireGuard subset before any native side effects.
/// Commands and ambiguous duplicate fields are rejected.
/// AWG extension syntax is additionally validated by the pinned native parser.
class WireGuardProfile {
  final String endpoint;
  final bool fullTunnel;
  const WireGuardProfile(this.endpoint, this.fullTunnel);
  static WireGuardProfile parse(String raw, {bool amnezia = false}) {
    if (raw.length > 65536 || raw.contains('\u0000')) {
      throw const FormatException('РЎР»РёС€РєРѕРј Р±РѕР»СЊС€РѕР№ РёР»Рё РїРѕРІСЂРµР¶РґС‘РЅРЅС‹Р№ РїСЂРѕС„РёР»СЊ');
    }
    var section = '';
    var interfaces = 0, peers = 0;
    final fields = <String, Map<String, String>>{};
    for (var line in const LineSplitter().convert(raw)) {
      line = line.split('#').first.trim();
      if (line.isEmpty) continue;
      if (line == '[Interface]') {
        section = 'interface';
        interfaces++;
      } else if (line == '[Peer]') {
        section = 'peer${peers++}';
      } else {
        final at = line.indexOf('=');
        if (section.isEmpty || at < 1) {
          throw const FormatException('РћР¶РёРґР°РµС‚СЃСЏ WireGuard .conf');
        }
        final key = line.substring(0, at).trim().toLowerCase(),
            value = line.substring(at + 1).trim();
        final allowed = section == 'interface'
            ? {
                'privatekey',
                'address',
                'dns',
                'mtu',
                'listenport',
                if (amnezia) ...{
                  'jc',
                  'jmin',
                  'jmax',
                  's1',
                  's2',
                  's3',
                  's4',
                  'h1',
                  'h2',
                  'h3',
                  'h4',
                  'i1',
                  'i2',
                  'i3',
                  'i4',
                  'i5',
                  'headerprotectionkey',
                  'contentpaddingaddition',
                  'rekeyaftertime',
                  'rekeytimeout',
                  'rejectaftertime',
                  'keepalivetimeout',
                  'maxhandshakeattempts',
                  'randomtrailers',
                  'disablecookies',
                },
              }
            : {
                'publickey',
                'presharedkey',
                'allowedips',
                'endpoint',
                'persistentkeepalive',
              };
        if (!allowed.contains(key)) {
          throw FormatException(
            'РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјРѕРµ РїРѕР»Рµ: $key. РљРѕРјР°РЅРґС‹ Рё РїРѕР»СЏ РґСЂСѓРіРѕРіРѕ СЂРµР¶РёРјР° РЅРµ РїСЂРёРЅРёРјР°СЋС‚СЃСЏ.',
          );
        }
        final map = fields.putIfAbsent(section, () => {});
        if (map.containsKey(key) ||
            (value.isEmpty &&
                !(amnezia &&
                    section == 'interface' &&
                    {'i1', 'i2', 'i3', 'i4', 'i5'}.contains(key)))) {
          throw FormatException('РџРѕРІС‚РѕСЂРЅРѕРµ РёР»Рё РїСѓСЃС‚РѕРµ РїРѕР»Рµ: $key');
        }
        map[key] = value;
      }
    }
    if (interfaces != 1 || peers != 1) {
      throw const FormatException('РќСѓР¶РЅС‹ РѕРґРёРЅ Interface Рё РѕРґРёРЅ Peer');
    }
    final i = fields['interface'] ?? {}, peer = fields['peer0'] ?? {};
    if (amnezia) {
      for (final key in ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4']) {
        final value = i[key];
        if (value == null) continue;
        final number = int.tryParse(value);
        final limit = key == 'jc' ? 128 : 1280;
        if (number == null || number < 0 || number > limit) {
          throw FormatException('$key: РІ СЌС‚РѕР№ СЃР±РѕСЂРєРµ РґРѕРїСѓСЃС‚РёРјРѕ 0вЂ¦$limit');
        }
      }
      if (int.parse(i['jmin'] ?? '0') > int.parse(i['jmax'] ?? '1280')) {
        throw const FormatException('Jmin РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ РЅРµ Р±РѕР»СЊС€Рµ Jmax');
      }
      for (final key in ['h1', 'h2', 'h3', 'h4']) {
        final value = i[key];
        if (value == null) continue;
        final parts = value.split('-');
        final numbers = parts.map(int.tryParse).toList();
        if (parts.length > 2 ||
            numbers.any((n) => n == null || n < 0 || n > 4294967295) ||
            (numbers.length == 2 && numbers.first! > numbers.last!)) {
          throw FormatException('$key: РѕР¶РёРґР°РµС‚СЃСЏ uint32 РёР»Рё РґРёР°РїР°Р·РѕРЅ min-max');
        }
      }
    }
    for (final key in [
      i['privatekey'],
      if (amnezia && i.containsKey('headerprotectionkey'))
        i['headerprotectionkey'],
      peer['publickey'],
      if (peer.containsKey('presharedkey')) peer['presharedkey'],
    ]) {
      try {
        if (base64Decode(key ?? '').length != 32) throw const FormatException();
      } catch (_) {
        throw const FormatException(
          'РљР»СЋС‡ WireGuard РґРѕР»Р¶РµРЅ СЃРѕРґРµСЂР¶Р°С‚СЊ 32 Р±Р°Р№С‚Р° Base64',
        );
      }
    }
    if (i['address'] == null ||
        peer['allowedips'] == null ||
        peer['endpoint'] == null) {
      throw const FormatException('РћР±СЏР·Р°С‚РµР»СЊРЅС‹ Address, AllowedIPs Рё Endpoint');
    }
    for (final cidr in '${i['address']},${peer['allowedips']}'.split(',')) {
      final parts = cidr.trim().split('/');
      final ip = InternetAddress.tryParse(parts.first);
      final prefix = parts.length == 2 ? int.tryParse(parts[1]) : null;
      if (ip == null ||
          prefix == null ||
          prefix < 0 ||
          prefix > (ip.type == InternetAddressType.IPv4 ? 32 : 128)) {
        throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ CIDR');
      }
    }
    final endpoint = peer['endpoint']!;
    final match = RegExp(r'^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9._-]+):(\d{1,5})$')
        .firstMatch(endpoint);
    if (match == null ||
        int.parse(match[2]!) < 1 ||
        int.parse(match[2]!) > 65535) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ Endpoint');
    }
    final host = match[1]!;
    if (host.startsWith('[')) {
      if (InternetAddress.tryParse(host.substring(1, host.length - 1)) ==
          null) {
        throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ IPv6 Endpoint');
      }
    } else if (host
        .split('.')
        .any(
          (label) =>
              label.isEmpty || label.startsWith('-') || label.endsWith('-'),
        )) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅРѕРµ РёРјСЏ Endpoint');
    }
    return WireGuardProfile(
      endpoint,
      peer['allowedips']!
              .replaceAll(' ', '')
              .split(',')
              .contains('0.0.0.0/0') &&
          peer['allowedips']!.contains('::/0'),
    );
  }
}

class TunnelStatus {
  final bool active;
  final String state, path;
  final int? rx, tx, handshake;
  const TunnelStatus({
    this.active = false,
    this.state = 'РћС‚РєР»СЋС‡РµРЅРѕ',
    this.path = 'вЂ”',
    this.rx,
    this.tx,
    this.handshake,
  });
}

/// Imports only client data; never SSH credentials, commands or subscription URLs.
class ClientImport {
  final UserBundle? bundle;
  final String? config;
  final String protocol;
  const ClientImport._(this.bundle, this.config, this.protocol);
  static const _awgKeys = {
    'jc',
    'jmin',
    'jmax',
    's1',
    's2',
    's3',
    's4',
    'h1',
    'h2',
    'h3',
    'h4',
    'i1',
    'i2',
    'i3',
    'i4',
    'i5',
    'headerprotectionkey',
    'contentpaddingaddition',
    'rekeyaftertime',
    'rekeytimeout',
    'rejectaftertime',
    'keepalivetimeout',
    'maxhandshakeattempts',
    'randomtrailers',
    'disablecookies',
  };
  static String detect(String raw) {
    if (raw.trim().startsWith('{')) {
      final j = jsonDecode(raw);
      if (j is Map && rivetProtocols.contains(j['protocol'])) {
        return RivetProfile.parse(raw).protocol;
      }
      return ExtendedProfile.parse(raw).protocol;
    }
    if (!RegExp(
      r'^\s*\[Interface\]\s*(?:#.*)?$',
      multiLine: true,
    ).hasMatch(raw)) {
      return ExtendedProfile.parse(raw).protocol;
    }
    var section = '';
    var awg = false;
    for (var line in const LineSplitter().convert(raw)) {
      line = line.split('#').first.trim();
      if (line.startsWith('[')) section = line.toLowerCase();
      final eq = line.indexOf('=');
      if (section == '[interface]' &&
          eq > 0 &&
          _awgKeys.contains(line.substring(0, eq).trim().toLowerCase())) {
        awg = true;
      }
    }
    WireGuardProfile.parse(raw, amnezia: awg);
    if (!awg) {
      throw const FormatException('WireGuard СѓРґР°Р»С‘РЅ РёР· СЌС‚РѕР№ РІРµСЂСЃРёРё XIO');
    }
    return 'awg';
  }

  static String _clientConfig(Map client, Map root) {
    if (client['config'] is String &&
        (client['config'] as String).trim().isNotEmpty) {
      return (client['config'] as String).trim();
    }
    String value(String key) {
      final v = client[key];
      if (v is! String || v.isEmpty || v.contains(RegExp(r'[\r\n\u0000]'))) {
        throw const FormatException();
      }
      return v;
    }

    final key = value('client_priv_key'), publicKey = value('server_pub_key');
    var address = value('client_ip');
    if (!address.contains('/')) {
      final ip = InternetAddress.tryParse(address);
      if (ip == null) throw const FormatException();
      address = '$address/${ip.type == InternetAddressType.IPv4 ? 32 : 128}';
    }
    final host = value('hostName');
    final port = client['port'];
    if (port is! int || port < 1 || port > 65535) throw const FormatException();
    final allowed = client['allowed_ips'];
    if (allowed is! List ||
        allowed.isEmpty ||
        allowed.any(
          (v) => v is! String || v.contains(RegExp(r'[\r\n\u0000]')),
        )) {
      throw const FormatException();
    }
    final out = StringBuffer(
      '[Interface]\nPrivateKey = $key\nAddress = $address\n',
    );
    final dns = <String>[];
    for (final field in ['dns1', 'dns2']) {
      final v = root[field];
      if (v is String && v.isNotEmpty) {
        if (InternetAddress.tryParse(v) == null) throw const FormatException();
        dns.add(v);
      }
    }
    if (dns.isNotEmpty) out.writeln('DNS = ${dns.join(', ')}');
    if (client['mtu'] != null && client['mtu'] != '') {
      out.writeln('MTU = ${value('mtu')}');
    }
    for (final entry in client.entries) {
      if (entry.key is String &&
          _awgKeys.contains((entry.key as String).toLowerCase())) {
        final v = entry.value;
        if (v is! String || v.contains(RegExp(r'[\r\n\u0000]'))) {
          throw const FormatException();
        }
        out.writeln('${entry.key} = $v');
      }
    }
    out.writeln('[Peer]\nPublicKey = $publicKey');
    if (client['psk_key'] != null && client['psk_key'] != '') {
      out.writeln('PresharedKey = ${value('psk_key')}');
    }
    out.writeln(
      'Endpoint = ${host.contains(':') && !host.startsWith('[') ? '[$host]' : host}:$port',
    );
    out.writeln('AllowedIPs = ${allowed.join(', ')}');
    if (client['persistent_keep_alive'] != null &&
        client['persistent_keep_alive'] != '') {
      out.writeln('PersistentKeepalive = ${value('persistent_keep_alive')}');
    }
    return out.toString();
  }

  static ClientImport parse(String input) {
    if (input.length > 200000 || input.contains('\u0000')) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїСЂРѕС„РёР»СЊ XIO');
    }
    final raw = input.replaceFirst(RegExp(r'^\uFEFF'), '').trim();
    if (RegExp(r'^(vless|vmess|trojan|ss)://').hasMatch(raw) ||
        RegExp(r'^\s*client\s*$', multiLine: true).hasMatch(raw)) {
      final parsed = ExtendedProfile.parse(raw);
      return ClientImport._(null, parsed.encoded, parsed.protocol);
    }
    if (raw.startsWith('{')) {
      try {
        final json = jsonDecode(raw);
        if (json is Map && rivetProtocols.contains(json['protocol'])) {
          final parsed = RivetProfile.parse(raw);
          return ClientImport._(null, raw, parsed.protocol);
        }
        if (json is Map && !json.containsKey('containers')) {
          final parsed = ExtendedProfile.parse(raw);
          return ClientImport._(null, parsed.encoded, parsed.protocol);
        }
      } on FormatException {
        rethrow;
      }
    }
    if (raw.startsWith('xio://') || raw.startsWith('x1o://')) {
      final bundle = UserBundle.decode(raw);
      for (final entry in bundle.configs.entries) {
        if (detect(entry.value) != entry.key) {
          throw const FormatException('РџСЂРѕС‚РѕРєРѕР» РЅРµ СЃРѕРІРїР°РґР°РµС‚ СЃ РєРѕРЅС„РёРіСѓСЂР°С†РёРµР№');
        }
      }
      return ClientImport._(bundle, null, 'bundle');
    }
    if (RegExp(
      r'^\s*\[Interface\]\s*(?:#.*)?$',
      multiLine: true,
    ).hasMatch(raw)) {
      return ClientImport._(null, raw, detect(raw));
    }
    try {
      String json = raw;
      if (raw.startsWith('vpn://')) {
        final bytes = base64Url.decode(base64Url.normalize(raw.substring(6)));
        // Qt qCompress has a big-endian length prefix. Some client exports
        // contain raw UTF-8 JSON instead. Bound inflation as it is produced.
        if (bytes.isNotEmpty && bytes.first == 123) {
          json = utf8.decode(bytes);
        } else {
          if (bytes.length < 6) throw const FormatException();
          final size =
              (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
          if (size < 1 || size > 200000) throw const FormatException();
          final out = _LimitedBytes(200000);
          final sink = ZLibDecoder().startChunkedConversion(out);
          // Small chunks also bound the decoder's transient output allocation.
          for (var i = 4; i < bytes.length; i += 256) {
            sink.add(bytes.sublist(i, (i + 256).clamp(0, bytes.length)));
          }
          sink.close();
          if (out.bytes.length != size) throw const FormatException();
          json = utf8.decode(out.bytes);
        }
      }
      final obj = jsonDecode(json);
      if (obj is! Map) throw const FormatException();
      // Only explicit client exports are accepted. Administrative server
      // backups must never confer management permissions through this flow.
      if ([
        'password',
        'userName',
        'privateKey',
      ].any((key) => obj[key] != null && obj[key].toString().isNotEmpty)) {
        throw const FormatException();
      }
      final configs = <String, String>{};
      final containers = obj['containers'];
      if (containers is! List || containers.isEmpty || containers.length > 16) {
        throw const FormatException();
      }
      for (final container in containers) {
        if (container is! Map) throw const FormatException();
        final kind = switch (container['container']) {
          'amnezia-awg' => 'awg',
          'amnezia-xray' => 'xray',
          'amnezia-openvpn-cloak' => 'cloak',
          _ => throw const FormatException(),
        };
        final protocol = container[kind == 'cloak' ? 'openvpn' : kind];
        if (protocol is! Map) throw const FormatException();
        final last = protocol['last_config'];
        final client = last is String ? jsonDecode(last) : last;
        if (client is! Map) {
          throw const FormatException();
        }
        String config;
        if (['xray', 'cloak'].contains(kind)) {
          if (kind == 'cloak') {
            final cloakNode = container['cloak'];
            if (cloakNode is! Map) throw const FormatException();
            final last = cloakNode['last_config'];
            final value = last is String ? jsonDecode(last) : last;
            final cloakRaw = value is Map ? value['config'] ?? value : value;
            final cloak = cloakRaw is String ? jsonDecode(cloakRaw) : cloakRaw;
            config = ExtendedProfile.parse(
              jsonEncode({
                'protocol': 'cloak',
                'config': client['config'],
                'cloak': cloak,
              }),
            ).encoded;
          } else {
            config = ExtendedProfile.parse(jsonEncode(client)).encoded;
          }
        } else {
          config = _clientConfig(client, obj);
        }

        final detected = detect(config);
        if (detected != kind || configs.containsKey(kind)) {
          throw const FormatException();
        }
        configs[kind] = config;
      }
      final name = obj['description'] is String
          ? (obj['description'] as String).trim()
          : '';
      if (name.length > 80) throw const FormatException();
      // Random client-only identity. No managed server is created.
      final id = SecretKeyData.random(length: 16).bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      return ClientImport._(
        UserBundle(name, id, 'external-$id', configs),
        null,
        'bundle',
      );
    } catch (_) {
      throw const FormatException(
        'РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјР°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ. РРјРїРѕСЂС‚РёСЂСѓР№С‚Рµ РєР»РёРµРЅС‚СЃРєРёР№ РїСЂРѕС„РёР»СЊ WireGuard РёР»Рё AmneziaWG.',
      );
    }
  }
}

class _LimitedBytes implements Sink<List<int>> {
  final int limit;
  final List<int> bytes = [];
  _LimitedBytes(this.limit);
  @override
  void add(List<int> data) {
    if (bytes.length + data.length > limit) throw const FormatException();
    bytes.addAll(data);
  }

  @override
  void close() {}
}

class AppStore extends ChangeNotifier {
  LegalRecord? legalRecord;
  String? vpnDisclosure;
  bool enforceConsent = false;
  bool get consentReady =>
      legalRecord?.current == true && vpnDisclosure == vpnDisclosureRevision;
  void setForeground(bool active) {
    _timer?.cancel();
    _timer = null;
    if (active && ready) {
      unawaited(refresh());
      _timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
    }
  }

  Future<void> acknowledgeLegal(String text, String language) async {
    final previous = legalRecord;
    legalRecord = LegalRecord.acknowledge(text, language);
    try {
      await save();
    } catch (_) {
      legalRecord = previous;
      rethrow;
    }
    notifyListeners();
  }

  Future<void> acknowledgeVpn() async {
    final previous = vpnDisclosure;
    vpnDisclosure = vpnDisclosureRevision;
    try {
      await save();
    } catch (_) {
      vpnDisclosure = previous;
      rethrow;
    }
    if (Platform.isAndroid || Platform.isIOS) {
      await native.invokeMethod<void>("setConsent", {
        "revision": legalRevision,
      });
    }
    notifyListeners();
  }

  final Future<bool> Function(Uri)? siteProbe;
  final SecurityContext? probeSecurityContext;
  AppStore({
    this.siteProbe,
    this.probeSecurityContext,
    this.nativeTunnelOverride,
  });
  final bool? nativeTunnelOverride;
  bool get nativeTunnel => nativeTunnelOverride ?? platformTunnel;
  Set<String> get supportedProtocols => nativeTunnelOverride == true
      ? nativeProtocols.toSet()
      : platformProtocols;
  void changed() => notifyListeners();
  final List<Profile> profiles = [];
  final List<String> events = [];
  final List<ManagedServer> servers = [];
  final List<ManagedUser> users = [];
  final Map<String, String> endpointCountries = {};
  String checkSite = 'https://youtube.com';
  String priorityProtocol = Platform.isIOS ? 'rivet-s1' : 'xray';
  int protocolTimeoutSeconds = 15;
  String? connectionCheck;
  String? selectedId;
  TunnelStatus status = const TunnelStatus();
  bool busy = false, ready = false;
  bool serverMaintenance = false;
  String? error;
  Directory? directory;
  Timer? _timer;
  final _statusPoll = StatusPoll();
  bool _storageHealthy = true;
  Future<void> _saveQueue = Future.value();
  String? _activeId;
  Profile? get selected =>
      profiles.where((p) => p.id == selectedId).firstOrNull;
  Profile? get activeProfile =>
      profiles.where((p) => p.id == _activeId).firstOrNull;

  Future<void> load() async {
    if (nativeTunnel) {
      try {
        final list = await native.invokeListMethod<String>(
          'supportedProtocols',
        );
        if (list != null) {
          availableAndroidProtocols = list
              .where(nativeProtocols.contains)
              .toSet();
        }
      } catch (_) {}
    }
    try {
      directory = await applicationDirectory();
      final file = File('${directory!.path}/profiles.json');
      if (await file.exists()) {
        final j = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
        profiles.addAll(
          (j['profiles'] as List).map(
            (p) => Profile.fromJson(Map<String, dynamic>.from(p)),
          ),
        );
        profiles.removeWhere((p) => !nativeProtocols.contains(p.protocol));
        AppLanguages.set(
          AppLanguages.names.containsKey(j['language'])
              ? j['language'] as String
              : null,
        );
        selectedId = j['selected'];
        legalRecord = LegalRecord.parse(j['legalRecord']);
        vpnDisclosure = j['vpnDisclosure'] as String?;
        endpointCountries.addAll(
          Map<String, String>.from(j['endpointCountries'] ?? {}),
        );
        servers.addAll(
          (j['servers'] as List? ?? []).map(
            (v) => ManagedServer.fromJson(Map<String, dynamic>.from(v)),
          ),
        );
        users.addAll(
          (j['users'] as List? ?? []).map(
            (v) => ManagedUser.fromJson(Map<String, dynamic>.from(v)),
          ),
        );
        final profileIds = profiles.map((p) => p.id).toSet();
        for (final user in users) {
          user.profileIds.removeWhere((_, id) => !profileIds.contains(id));
        }
        if (!profileIds.contains(selectedId)) {
          selectedId = profiles.firstOrNull?.id;
        }
        checkSite = validateCheckSite(j['checkSite'] ?? 'https://youtube.com')
            .toString();
        protocolTimeoutSeconds = (j['protocolTimeoutSeconds'] as num? ?? 15)
            .toInt()
            .clamp(5, 60);
        priorityProtocol = nativeProtocols.contains(j['priorityProtocol'])
            ? j['priorityProtocol']
            : Platform.isIOS
            ? 'rivet-s1'
            : 'xray';
      }
      if (nativeTunnel) {
        final id = await native.invokeMethod<String>('activeId');
        if (id != null && profiles.any((p) => p.id == id)) {
          _activeId = id;
          selectedId = id;
        }
      }
      if (Platform.isAndroid) {
        await native.invokeMethod<void>(
          'setLanguage',
          AppLanguages.selected ?? '',
        );
      }
      await refresh();
    } catch (_) {
      _storageHealthy = false;
      error = 'РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РёС‚Р°С‚СЊ СЃРѕСЃС‚РѕСЏРЅРёРµ РїСЂРёР»РѕР¶РµРЅРёСЏ. РЎРѕС…СЂР°РЅС‘РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ РЅРµ РїРµСЂРµР·Р°РїРёСЃР°РЅС‹.';
    }
    if ((Platform.isAndroid || Platform.isIOS) && _storageHealthy) {
      await native.invokeMethod<void>('setConsent', {
        'revision': consentReady ? legalRevision : '',
      });
      await saveNativePlan();
    }
    ready = true;
    notifyListeners();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
    if (Platform.isAndroid &&
        (!enforceConsent || consentReady) &&
        await native.invokeMethod<bool>('consumeConnectRequest') == true) {
      await connect();
    }
  }

  Future<void> save() async {
    if (!_storageHealthy) {
      throw StateError('РџРѕРІСЂРµР¶РґС‘РЅРЅРѕРµ С…СЂР°РЅРёР»РёС‰Рµ Р·Р°С‰РёС‰РµРЅРѕ РѕС‚ РїРµСЂРµР·Р°РїРёСЃРё');
    }
    if (directory == null) throw StateError('РҐСЂР°РЅРёР»РёС‰Рµ РµС‰С‘ РЅРµ РіРѕС‚РѕРІРѕ');
    final file = File('${directory!.path}/profiles.json');
    final tmp = File('${file.path}.tmp');
    final payload = jsonEncode({
      'schema': 2,
      'legalRecord': legalRecord?.toJson(),
      'vpnDisclosure': vpnDisclosure,
      'language': AppLanguages.selected,
      'servers': servers.map((s) => s.toJson()).toList(),
      'users': users.map((u) => u.toJson()).toList(),
      'checkSite': checkSite,
      'priorityProtocol': priorityProtocol,
      'protocolTimeoutSeconds': protocolTimeoutSeconds,
      'selected': selectedId,
      'endpointCountries': endpointCountries,
      'profiles': profiles.map((p) => p.toJson()).toList(),
    });
    final previous = _saveQueue;
    final completed = Completer<void>();
    _saveQueue = completed.future;
    try {
      await previous;
      await tmp.writeAsString(payload, flush: true);
      if (Platform.isLinux) {
        final permissions = await Process.run('chmod', ['600', tmp.path]);
        if (permissions.exitCode != 0) {
          throw StateError('РќРµ СѓРґР°Р»РѕСЃСЊ Р·Р°С‰РёС‚РёС‚СЊ С„Р°Р№Р» РїСЂРѕС„РёР»РµР№');
        }
      }
      await tmp.rename(file.path);
      await saveNativePlan();
    } finally {
      completed.complete();
    }
  }

  Future<void> setLanguage(String? code) async {
    final old = AppLanguages.selected;
    AppLanguages.set(code);
    try {
      await save();
    } catch (_) {
      AppLanguages.set(old);
      rethrow;
    }
    if (Platform.isAndroid) {
      await native.invokeMethod<void>('setLanguage', code ?? '');
    }
    notifyListeners();
  }

  void log(String event) {
    events.insert(
      0,
      '${DateTime.now().toIso8601String().substring(11, 19)}  $event',
    );
    if (events.length > 100) events.removeLast();
  }

  Future<void> select(String id) async {
    if (busy || status.active) {
      throw StateError('РЎРЅР°С‡Р°Р»Р° РѕС‚РєР»СЋС‡РёС‚Рµ С‚РµРєСѓС‰РёР№ С‚СѓРЅРЅРµР»СЊ');
    }
    selectedId = id;
    connectionCheck = null;
    await save();
    await refresh();
    notifyListeners();
  }

  String serverFlagForProfile(Profile p) {
    final user = users
        .where((u) => u.profileIds.values.contains(p.id))
        .firstOrNull;
    return servers.where((s) => s.id == user?.serverId).firstOrNull?.flag ??
        countryFlag(endpointCountries[p.endpoint] ?? '');
  }

  Future<void> resolveCountry(String endpoint) async {
    if (clientOnlyBuild || endpointCountries.containsKey(endpoint)) return;
    final host = Uri.tryParse('udp://$endpoint')?.host;
    if (host == null ||
        host.isEmpty ||
        host == 'localhost' ||
        host.startsWith('127.') ||
        host.startsWith('10.') ||
        host.startsWith('192.168.') ||
        host.startsWith('198.18.') ||
        host.startsWith('172.') ||
        host.contains(':')) {
      return;
    }
    final server = servers
        .where((s) => s.host == host && s.country.isNotEmpty)
        .firstOrNull;
    if (server != null) {
      endpointCountries[endpoint] = server.country;
      return;
    }
    final http = HttpClient()..connectionTimeout = const Duration(seconds: 3);
    try {
      final request = await http
          .getUrl(Uri.https('ipapi.co', '/$host/country/'))
          .timeout(const Duration(seconds: 3));
      request.followRedirects = false;
      final response = await request.close().timeout(
        const Duration(seconds: 3),
      );
      if (response.statusCode == 200) {
        final bytes = await response
            .take(1)
            .first
            .timeout(const Duration(seconds: 3));
        if (bytes.length <= 16) {
          final value = utf8.decode(bytes).trim();
          if (RegExp(r'^[A-Z]{2}$').hasMatch(value)) {
            endpointCountries[endpoint] = value;
          }
        }
      }
    } catch (_) {
    } finally {
      http.close(force: true);
    }
  }

  String credentialId(ManagedServer server) => CredentialVault.id(
    server.host,
    server.port,
    server.username,
    scope: server.actorId,
  );
  Future<void> importServer(String raw) async {
    if (clientOnlyBuild) {
      throw const FormatException(
        'XIO Client РїСЂРёРЅРёРјР°РµС‚ С‚РѕР»СЊРєРѕ РєР»РёРµРЅС‚СЃРєРёРµ РїСЂРѕС„РёР»Рё, Р±РµР· РґРѕСЃС‚СѓРїР° Рє СЃРµСЂРІРµСЂСѓ',
      );
    }
    if (raw.length > 100000 || !raw.startsWith('xio-server://')) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ СЃРµСЂРІРµСЂР°');
    }
    try {
      final data = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(raw.substring(13)))),
      );
      if (data['schema'] != 1) throw const FormatException();
      final server = ManagedServer.fromJson(
        Map<String, dynamic>.from(data['server']),
      );
      SshTarget(
        server.host,
        server.port,
        server.username,
        server.hostKey,
      ).validate();
      if (server.id.isEmpty ||
          server.name.length > 80 ||
          !RegExp(r'^[a-zA-Z0-9-]{1,80}$').hasMatch(server.id)) {
        throw const FormatException();
      }
      final credentials = Map<String, String>.from(data['credentials']);
      if (credentials.keys.any(
            (k) => !['password', 'key', 'passphrase'].contains(k),
          ) ||
          credentials.values.any((v) => v.length > 32768)) {
        throw const FormatException();
      }
      if ((credentials['password'] ?? '').isEmpty &&
          (credentials['key'] ?? '').isEmpty) {
        throw const FormatException();
      }
      final existing = servers.where((s) => s.id == server.id).firstOrNull;
      if (existing != null &&
          (existing.host != server.host ||
              existing.actorId != server.actorId)) {
        throw const FormatException();
      }
      final id = credentialId(server),
          previous = await CredentialVault.read(id);
      await CredentialVault.write(id, credentials);
      try {
        if (existing == null) {
          servers.add(server);
        } else {
          servers[servers.indexOf(existing)] = server;
        }
        await save();
      } catch (_) {
        if (existing == null) {
          servers.remove(server);
        } else {
          final index = servers.indexOf(server);
          if (index >= 0) servers[index] = existing;
        }
        if (previous != null) {
          await CredentialVault.write(id, previous);
        } else {
          await CredentialVault.delete(id);
        }
        rethrow;
      }
      notifyListeners();
    } catch (_) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ СЃРµСЂРІРµСЂР°');
    }
  }

  Future<String> exportServer(ManagedServer server) async {
    final credentials = await CredentialVault.read(credentialId(server));
    if (credentials == null) throw StateError('РЎРЅР°С‡Р°Р»Р° РїРѕРґРєР»СЋС‡РёС‚РµСЃСЊ Рє СЃРµСЂРІРµСЂСѓ');
    return 'xio-server://${base64Url.encode(utf8.encode(jsonEncode({'schema': 1, 'server': server.toJson(), 'credentials': credentials})))}';
  }

  /// The same plan drives foreground connection and Android's background tile.
  List<Profile> connectionCandidates(Profile? initial) {
    if (serverMaintenance || initial == null) return [];
    final user = users
        .where((u) => u.profileIds.values.contains(initial.id))
        .firstOrNull;
    if (user?.revoked == true) return [];
    // The small client connects only to the explicitly selected profile.
    if (clientOnlyBuild) {
      return supportedProtocols.contains(initial.protocol) ? [initial] : [];
    }
    final candidates =
        (user == null
                ? [initial]
                : profiles
                      .where(
                        (p) =>
                            user.profileIds.values.contains(p.id) &&
                            nativeProtocols.contains(p.protocol),
                      )
                      .toList())
            .where(
              (p) =>
                  nativeProtocols.contains(p.protocol) &&
                  (!nativeTunnel || supportedProtocols.contains(p.protocol)),
            )
            .toList();
    candidates.sort(
      (a, b) =>
          protocolPreference(
            a.protocol,
            priorityProtocol,
            restricted: true,
          ).compareTo(
            protocolPreference(b.protocol, priorityProtocol, restricted: true),
          ),
    );
    return candidates;
  }

  Future<void> saveNativePlan() async {
    if (!Platform.isAndroid) return;
    final candidates = connectionCandidates(selected);
    await native.invokeMethod<void>(
      'saveConnectionPlan',
      jsonEncode({
        'ids': candidates
            .where((v) => availableAndroidProtocols.contains(v.protocol))
            .map((v) => v.id)
            .toList(),
        'site': checkSite,
        'timeoutSeconds': protocolTimeoutSeconds,
      }),
    );
  }

  Future<void> importConnection(String raw, {String name = ''}) async {
    if (raw.trim().startsWith('xio-server://')) {
      await importServer(raw.trim());
      return;
    }
    final imported = ClientImport.parse(raw);
    if (imported.bundle != null) {
      final b = imported.bundle!;
      await importBundle(
        UserBundle(
          name.trim().isEmpty ? b.name : name.trim(),
          b.userId,
          b.serverId,
          b.configs,
          adminAccess: b.adminAccess,
          clientAccess: b.clientAccess,
        ),
      );
    } else if (extendedProtocols.contains(imported.protocol)) {
      await addExtended(name, imported.config!);
    } else if (rivetProtocols.contains(imported.protocol)) {
      await addRivet(name, imported.config!);
    } else {
      await addWireGuard(
        name,
        imported.config!,
        amnezia: imported.protocol == 'awg',
      );
    }
  }

  Future<void> addExtended(String name, String raw) async {
    final parsed = ExtendedProfile.parse(raw);
    if (!nativeTunnel || !nativeProtocols.contains(parsed.protocol)) {
      throw UnsupportedError(
        'РљР»РёРµРЅС‚СЃРєРёР№ РґРІРёР¶РѕРє СЌС‚РѕРіРѕ РїСЂРѕС‚РѕРєРѕР»Р° РµС‰С‘ РЅРµ РёРЅС‚РµРіСЂРёСЂРѕРІР°РЅ',
      );
    }
    final id =
        '${nativePrefix[parsed.protocol]}${DateTime.now().microsecondsSinceEpoch}';
    final previous = selectedId;
    await native.invokeMethod('saveConfig', {
      'id': id,
      'config': parsed.encoded,
    });
    profiles.add(
      Profile(
        id: id,
        name: name.trim().isEmpty
            ? (parsed.name.isNotEmpty
                  ? parsed.name
                  : protocols.firstWhere((p) => p.id == parsed.protocol).name)
            : name.trim(),
        protocol: parsed.protocol,
        endpoint: parsed.endpoint,
      ),
    );
    if (!status.active) selectedId = id;
    try {
      await save();
    } catch (_) {
      profiles.removeWhere((p) => p.id == id);
      selectedId = previous;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    notifyListeners();
  }

  Future<void> addRivet(String name, String raw) async {
    if (!nativeTunnel) {
      throw UnsupportedError('The platform tunnel engine is unavailable');
    }
    final parsed = RivetProfile.parse(raw);
    final id =
        '${parsed.protocol == 'rivet-h3' ? 'rvh' : 'rvs'}${DateTime.now().microsecondsSinceEpoch}';
    final previous = selectedId;
    await native.invokeMethod('saveConfig', {'id': id, 'config': raw});
    profiles.add(
      Profile(
        id: id,
        name: name.trim().isEmpty ? 'RIVET' : name.trim(),
        protocol: parsed.protocol,
        endpoint: parsed.endpoint,
      ),
    );
    if (!status.active) selectedId = id;
    try {
      await save();
    } catch (_) {
      profiles.removeWhere((p) => p.id == id);
      selectedId = previous;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    notifyListeners();
  }

  Future<void> addWireGuard(
    String name,
    String raw, {
    bool amnezia = true,
  }) async {
    if (!nativeTunnel) {
      throw UnsupportedError('The platform tunnel engine is unavailable');
    }
    if (!amnezia) {
      throw const FormatException('WireGuard СѓРґР°Р»С‘РЅ РёР· СЌС‚РѕР№ РІРµСЂСЃРёРё XIO');
    }
    final parsed = WireGuardProfile.parse(raw, amnezia: true);
    await resolveCountry(parsed.endpoint);
    final protocol = amnezia ? 'awg' : 'wireguard';
    final id =
        '${amnezia ? 'awg' : 'wg'}${DateTime.now().microsecondsSinceEpoch}';
    final previousId = selectedId;
    await native.invokeMethod('saveConfig', {'id': id, 'config': raw});
    profiles.add(
      Profile(
        id: id,
        name: name.trim().isEmpty
            ? AppLanguages.text('РњРѕР№ ${amnezia ? 'AmneziaWG' : 'WireGuard'}')
            : name.trim(),
        protocol: protocol,
        endpoint: parsed.endpoint,
      ),
    );
    if (!status.active) selectedId = id;
    try {
      await save();
    } catch (_) {
      profiles.removeWhere((p) => p.id == id);
      selectedId = previousId;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    log('РџСЂРѕС„РёР»СЊ $protocol РґРѕР±Р°РІР»РµРЅ');
    notifyListeners();
  }

  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
  }) async {
    if (timeoutSeconds != null && (timeoutSeconds < 5 || timeoutSeconds > 60)) {
      throw const FormatException('Р’СЂРµРјСЏ РѕР¶РёРґР°РЅРёСЏ: РѕС‚ 5 РґРѕ 60 СЃРµРєСѓРЅРґ');
    }
    final normalized = validateCheckSite(site).toString();
    if (!nativeProtocols.contains(priority)) {
      throw const FormatException('РџСЂРѕС‚РѕРєРѕР» РїРѕРєР° РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ');
    }
    final oldSite = checkSite, oldPriority = priorityProtocol;
    final oldTimeout = protocolTimeoutSeconds;
    checkSite = normalized;
    priorityProtocol = priority;
    protocolTimeoutSeconds = timeoutSeconds ?? protocolTimeoutSeconds;
    connectionCheck = null;
    try {
      await save();
    } catch (_) {
      checkSite = oldSite;
      priorityProtocol = oldPriority;
      protocolTimeoutSeconds = oldTimeout;
      rethrow;
    }
    notifyListeners();
  }

  Future<bool> checkConnection({
    Duration timeout = const Duration(seconds: 15),
  }) async {
    if (timeout <= Duration.zero) return false;
    connectionCheck = 'РџСЂРѕРІРµСЂРєР° $checkSiteвЂ¦';
    notifyListeners();
    final clock = Stopwatch()..start();
    HttpClient? activeClient;
    final deadline = Timer(timeout, () => activeClient?.close(force: true));
    Duration remaining() {
      final left = timeout - clock.elapsed;
      if (left <= Duration.zero) throw TimeoutException('Connection deadline');
      return left;
    }

    Duration phaseBudget(Duration maximum) {
      final left = remaining();
      return left < maximum ? left : maximum;
    }

    try {
      if (!status.active) throw StateError('VPN РѕС‚РєР»СЋС‡С‘РЅ');
      if (siteProbe != null) {
        final ok = await siteProbe!(validateCheckSite(checkSite))
            .timeout(remaining());
        connectionCheck = ok ? 'РЎР°Р№С‚ РґРѕСЃС‚СѓРїРµРЅ' : 'РЎР°Р№С‚ РЅРµРґРѕСЃС‚СѓРїРµРЅ';
        return ok;
      }
      final tls =
          probeSecurityContext ?? await ProbeTls.context.timeout(remaining());
      while (true) {
        final client = HttpClient(context: tls)
          ..connectionTimeout = phaseBudget(const Duration(seconds: 3));
        activeClient = client;
        try {
          var url = validateCheckSite(checkSite);
          for (var redirect = 0; redirect <= 4; redirect++) {
            final request = await client
                .getUrl(url)
                .timeout(phaseBudget(const Duration(seconds: 3)));
            request.followRedirects = false;
            final response = await request.close().timeout(
              phaseBudget(const Duration(seconds: 5)),
            );
            if (const [301, 302, 303, 307, 308].contains(response.statusCode)) {
              final location = response.headers.value(
                HttpHeaders.locationHeader,
              );
              if (redirect == 4 || location == null) {
                throw const HttpException('Invalid HTTPS redirect');
              }
              // A connectivity check never silently downgrades HTTPS to HTTP.
              url = validateCheckSite(url.resolve(location).toString());
              await response.drain<void>().timeout(remaining());
              continue;
            }
            final code = response.statusCode;
            connectionCheck = code >= 200 && code < 400
                ? 'РЎР°Р№С‚ РґРѕСЃС‚СѓРїРµРЅ В· HTTP $code'
                : 'РЎР°Р№С‚ РѕС‚РІРµС‚РёР» HTTP $code';
            return code >= 200 && code < 400;
          }
        } on HandshakeException {
          rethrow; // Certificate failures are never relaxed or retried as trust.
        } on SocketException {
          // A fresh socket can recover from a route transition inside one attempt.
        } on TimeoutException {
          // Retry only within the original absolute per-protocol budget.
        } finally {
          client.close(force: true);
          activeClient = null;
        }
        if (remaining() <= const Duration(milliseconds: 250)) return false;
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    } catch (_) {
      connectionCheck = 'РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РєСЂС‹С‚СЊ $checkSite';
      return false;
    } finally {
      deadline.cancel();
      activeClient?.close(force: true);
      notifyListeners();
    }
  }

  Future<ManagedUser> importBundle(UserBundle bundle) async {
    if (clientOnlyBuild && bundle.adminAccess != null) {
      throw const FormatException(
        'РќСѓР¶РµРЅ РєР»РёРµРЅС‚СЃРєРёР№ РїСЂРѕС„РёР»СЊ Р±РµР· SSH-РґРѕСЃС‚СѓРїР° Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР°',
      );
    }
    final capability = bundle.clientAccess == null
        ? null
        : AccountAccess.parse(
            bundle.clientAccess!,
            bundle.userId,
            bundle.serverId,
          );
    final previousUser = users
        .where((u) => u.id == bundle.userId && u.serverId == bundle.serverId)
        .firstOrNull;
    if (previousUser != null &&
        previousUser.profileIds.isNotEmpty &&
        capability == null) {
      throw const FormatException('РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓР¶Рµ РґРѕР±Р°РІР»РµРЅ');
    }
    if (previousUser?.revoked == true) {
      throw const FormatException('Р”РѕСЃС‚СѓРї РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РѕС‚РѕР·РІР°РЅ');
    }
    ManagedUser? imported;
    ManagedServer? adminServer;
    if (bundle.adminAccess != null) {
      adminServer = ManagedServer.fromJson(
        Map<String, dynamic>.from(bundle.adminAccess!['server']),
      );
      SshTarget(
        adminServer.host,
        adminServer.port,
        adminServer.username,
        adminServer.hostKey,
      ).validate();
      if (adminServer.id != bundle.serverId ||
          adminServer.actorId != bundle.userId ||
          SSHKeyPair.fromPem(bundle.adminAccess!['key']).single.name !=
              'ssh-ed25519') {
        throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ СЃРµСЂРІРµСЂР°');
      }
    }
    for (final e in bundle.configs.entries) {
      if (rivetProtocols.contains(e.key)) {
        final p = RivetProfile.parse(e.value);
        if (p.protocol != e.key || p.data['id'] != bundle.userId) {
          throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїСЂРѕС„РёР»СЊ RIVET');
        }
      } else if (extendedProtocols.contains(e.key)) {
        if (ExtendedProfile.parse(e.value).protocol != e.key) {
          throw const FormatException('РџСЂРѕС‚РѕРєРѕР» РЅРµ СЃРѕРІРїР°РґР°РµС‚ СЃ РєРѕРЅС„РёРіСѓСЂР°С†РёРµР№');
        }
      } else {
        WireGuardProfile.parse(e.value, amnezia: e.key == 'awg');
      }
    }
    if (previousUser != null &&
        previousUser.profileIds.isNotEmpty &&
        capability != null) {
      final oldRecord = await AccountVault.read(bundle.serverId, bundle.userId);
      final previousFlag = previousUser.statistics['clientAccount'];
      await AccountVault.write(bundle.serverId, bundle.userId, {
        ...?(oldRecord),
        'access': capability.toJson(),
      });
      previousUser.statistics['clientAccount'] = true;
      try {
        await save();
      } catch (_) {
        if (previousFlag == null) {
          previousUser.statistics.remove('clientAccount');
        } else {
          previousUser.statistics['clientAccount'] = previousFlag;
        }
        if (oldRecord == null) {
          await AccountVault.delete(bundle.serverId, bundle.userId);
        } else {
          await AccountVault.write(bundle.serverId, bundle.userId, oldRecord);
        }
        rethrow;
      }
      notifyListeners();
      return previousUser;
    }
    final ids = <String, String>{};
    bool addedAdminServer = false;
    Map<String, String>? previousAdminCredential;
    String? adminCredentialId;
    bool credentialSnapshotReady = false;
    final oldSelected = selectedId;
    Map<String, dynamic>? previousAccount;
    bool accountWritten = false;
    try {
      for (final e in bundle.configs.entries) {
        if (extendedProtocols.contains(e.key)) {
          await addExtended(bundle.name, e.value);
        } else if (rivetProtocols.contains(e.key)) {
          await addRivet(bundle.name, e.value);
        } else {
          await addWireGuard(
            '${bundle.name} В· ${e.key == 'awg' ? 'AmneziaWG' : 'WireGuard'}',
            e.value,
            amnezia: e.key == 'awg',
          );
        }
        ids[e.key] = profiles.last.id;
      }
      final user = ManagedUser(
        id: bundle.userId,
        name: bundle.name,
        serverId: bundle.serverId,
        profileIds: ids,
      );
      if (previousUser != null) {
        users.remove(previousUser);
        user.statistics = previousUser.statistics;
      }
      user.admin = bundle.adminAccess != null;
      user.userLimit = bundle.adminAccess?['limit'] as int? ?? 0;
      if (adminServer != null) {
        if (!servers.any((s) => s.id == adminServer!.id)) {
          servers.add(adminServer);
          addedAdminServer = true;
        }
        adminCredentialId = credentialId(adminServer);
        previousAdminCredential = await CredentialVault.read(adminCredentialId);
        credentialSnapshotReady = true;
        await CredentialVault.write(adminCredentialId, {
          'key': bundle.adminAccess!['key'],
          'password': '',
          'passphrase': '',
        });
      }
      if (capability != null) {
        previousAccount = await AccountVault.read(user.serverId, user.id);
        await AccountVault.write(user.serverId, user.id, {
          'access': capability.toJson(),
        });
        accountWritten = true;
        user.statistics['clientAccount'] = true;
      }
      users.add(user);
      imported = user;
      if (!status.active) {
        selectedId = ids[priorityProtocol] ?? ids.values.first;
      }
      await save();
      notifyListeners();
      return user;
    } catch (_) {
      if (accountWritten) {
        if (previousAccount == null) {
          await AccountVault.delete(bundle.serverId, bundle.userId);
        } else {
          await AccountVault.write(
            bundle.serverId,
            bundle.userId,
            previousAccount,
          );
        }
      }
      if (imported != null) users.remove(imported);
      if (addedAdminServer) servers.remove(adminServer);
      if (adminCredentialId != null && credentialSnapshotReady) {
        if (previousAdminCredential != null) {
          await CredentialVault.write(
            adminCredentialId,
            previousAdminCredential,
          );
        } else {
          await CredentialVault.delete(adminCredentialId);
        }
      }
      if (previousUser != null && !users.contains(previousUser)) {
        users.add(previousUser);
      }
      for (final id in ids.values) {
        profiles.removeWhere((p) => p.id == id);
        await native.invokeMethod('deleteConfig', {'id': id});
      }
      selectedId = oldSelected;
      await save();
      notifyListeners();
      rethrow;
    }
  }

  Future<UserBundle> exportUser(ManagedUser user) async {
    if (user.revoked) throw StateError('Р”РѕСЃС‚СѓРї РѕС‚РѕР·РІР°РЅ');
    final configs = <String, String>{};
    for (final entry in user.profileIds.entries) {
      configs[entry.key] = (await native.invokeMethod<String>('readConfig', {
        'id': entry.value,
      }))!;
    }
    Map<String, dynamic>? access;
    if (user.admin && !clientOnlyBuild) {
      final saved = await AccountVault.read(user.serverId, user.id);
      if (saved == null) {
        throw StateError(
          'Р’С‹РґР°Р№С‚Рµ РѕРіСЂР°РЅРёС‡РµРЅРЅС‹Р№ РґРѕСЃС‚СѓРї Р°РєРєР°СѓРЅС‚Р° РёР· РїРѕР»РЅРѕР№ РІРµСЂСЃРёРё',
        );
      }
      access = AccountAccess.parse(
        Map.from(saved['access']),
        user.id,
        user.serverId,
      ).toJson();
    }
    return UserBundle(
      user.name,
      user.id,
      user.serverId,
      configs,
      clientAccess: access,
    );
  }

  Future<void> forgetServer(String id) async {
    if (status.active || busy) throw StateError('РЎРЅР°С‡Р°Р»Р° РѕС‚РєР»СЋС‡РёС‚Рµ VPN');
    final ownUsers = users.where((u) => u.serverId == id).toList();
    for (final user in ownUsers) {
      final server = servers.where((s) => s.id == id).firstOrNull;
      if (server != null) {
        await CredentialVault.delete(
          CredentialVault.id(
            server.host,
            server.port,
            server.username,
            scope: user.id,
          ),
        );
      }
      // remove() prunes this very map, so iterate a snapshot.
      for (final profile in user.profileIds.values.toList()) {
        await remove(profile);
      }
    }
    users.removeWhere((u) => u.serverId == id);
    final forgotten = servers.where((s) => s.id == id).toList();
    for (final server in forgotten) {
      await CredentialVault.delete(credentialId(server));
    }
    servers.removeWhere((s) => s.id == id);
    await save();
    notifyListeners();
  }

  Future<void> remove(String id) async {
    if (busy || _activeId == id) throw StateError('РЎРЅР°С‡Р°Р»Р° РѕС‚РєР»СЋС‡РёС‚Рµ РїСЂРѕС„РёР»СЊ');
    final previous = profiles.toList();
    final previousId = selectedId;
    final previousUsers = users
        .map((u) => Map<String, String>.from(u.profileIds))
        .toList();
    profiles.removeWhere((p) => p.id == id);
    // The imported user record is what makes a later import of the same
    // xio:// container fail with "user already added"; the profile and its
    // user reference must disappear together.
    for (final user in users) {
      user.profileIds.removeWhere((_, profileId) => profileId == id);
    }
    if (selectedId == id) selectedId = profiles.firstOrNull?.id;
    try {
      await save();
    } catch (_) {
      profiles
        ..clear()
        ..addAll(previous);
      for (var i = 0; i < users.length && i < previousUsers.length; i++) {
        users[i].profileIds
          ..clear()
          ..addAll(previousUsers[i]);
      }
      selectedId = previousId;
      rethrow;
    }
    if (nativeTunnel) {
      await native.invokeMethod('deleteConfig', {'id': id});
    }
    notifyListeners();
  }

  Future<void> connect() async {
    if (enforceConsent && !consentReady) {
      throw StateError("РЎРЅР°С‡Р°Р»Р° РѕР·РЅР°РєРѕРјСЊС‚РµСЃСЊ СЃ Р»РёС†РµРЅР·РёРµР№ Рё СѓРІРµРґРѕРјР»РµРЅРёРµРј VPN");
    }
    if (nativeTunnel &&
        await native.invokeMethod<bool>('connectionBusy') == true) {
      return;
    }
    final initial = selected;
    if (initial == null || busy || serverMaintenance || status.active) return;
    final user = users
        .where((u) => u.profileIds.values.contains(initial.id))
        .firstOrNull;
    if (user?.revoked == true) {
      error = 'Р”РѕСЃС‚СѓРї РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РѕС‚РѕР·РІР°РЅ';
      notifyListeners();
      return;
    }
    final candidates = connectionCandidates(initial);
    busy = true;
    error = null;
    connectionCheck = null;
    notifyListeners();
    try {
      for (final p in candidates) {
        selectedId = p.id;
        notifyListeners();
        try {
          if (nativeProtocols.contains(p.protocol) && nativeTunnel) {
            final started = DateTime.now().millisecondsSinceEpoch;
            final activation = await native.invokeMapMethod<String, dynamic>(
              'connect',
              {'id': p.id, 'timeoutMillis': protocolTimeoutSeconds * 1000},
            );
            _activeId = p.id;
            final attempt = Stopwatch()..start();
            final budget =
                Duration(seconds: protocolTimeoutSeconds) -
                Duration(
                  milliseconds: (activation?['connectMillis'] as num? ?? 0)
                      .toInt(),
                );
            // Generate traffic to trigger handshake, then require a fresh handshake.
            await refresh(fresh: true);
            final website = await checkConnection(
              timeout: budget - attempt.elapsed,
            );
            if (!website) throw StateError('РџСЂРѕРІРµСЂРєР° СЃРѕРµРґРёРЅРµРЅРёСЏ РЅРµ РїСЂРѕР№РґРµРЅР°');
            for (
              var i = 0;
              attempt.elapsed < budget &&
                  (status.handshake ?? 0) < started - 2000;
              i++
            ) {
              await Future<void>.delayed(const Duration(milliseconds: 500));
              await refresh();
            }
            if (!website ||
                !status.active ||
                (status.handshake ?? 0) < started - 2000) {
              throw StateError('РџСЂРѕРІРµСЂРєР° СЃРѕРµРґРёРЅРµРЅРёСЏ РЅРµ РїСЂРѕР№РґРµРЅР°');
            }
          } else {
            continue;
          }
          await save();
          log('РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРё РІС‹Р±СЂР°РЅ ${p.protocol}; СЃР°Р№С‚ РґРѕСЃС‚СѓРїРµРЅ');
          return;
        } catch (e) {
          if (nativeTunnel) {
            await native.invokeMethod('disconnect');
          }
          _activeId = null;
          status = const TunnelStatus();
          log('РџСЂРѕРІРµСЂРєР° ${p.protocol} РЅРµ РїСЂРѕР№РґРµРЅР°');
          if (e is PlatformException &&
              (e.code == 'DENIED' || e.code == 'ROUTING')) {
            rethrow;
          }
        }
      }
      throw StateError(
        'РќРё РѕРґРёРЅ РґРѕСЃС‚СѓРїРЅС‹Р№ РјР°СЂС€СЂСѓС‚ РЅРµ РїСЂРѕС€С‘Р» РїСЂРѕРІРµСЂРєСѓ СЃР°Р№С‚Р°. РџСЂРѕРІРµСЂСЊС‚Рµ С‚РѕС‡РєСѓ РІС…РѕРґР°: СЃРјРµРЅР° РїСЂРѕС‚РѕРєРѕР»Р° РЅРµ СЃРЅРёРјР°РµС‚ Р±Р»РѕРєРёСЂРѕРІРєСѓ IP.',
      );
    } catch (e) {
      selectedId = initial.id;
      error = e is StateError
          ? e.message
          : e is PlatformException && e.code == 'ROUTING'
          ? e.message
          : 'РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕРґРєР»СЋС‡РёС‚СЊСЃСЏ: РїСЂРѕРІРµСЂСЊС‚Рµ РїСЂРѕС„РёР»СЊ, СЃРµС‚СЊ Рё СЂР°Р·СЂРµС€РµРЅРёРµ VPN.';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> disconnect() async {
    if (busy) return;
    busy = true;
    notifyListeners();
    try {
      if (nativeTunnel) {
        await native.invokeMethod('disconnect');
      }
      _activeId = null;
      status = const TunnelStatus();
      error = null;
      connectionCheck = null;
      log('РўСѓРЅРЅРµР»СЊ РѕС‚РєР»СЋС‡С‘РЅ');
    } catch (_) {
      error = 'РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РєР»СЋС‡РёС‚СЊ С‚СѓРЅРЅРµР»СЊ. РџСЂРѕРІРµСЂСЊС‚Рµ СЃРёСЃС‚РµРјРЅСѓСЋ СЃР»СѓР¶Р±Сѓ.';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> refresh({bool fresh = false}) =>
      _statusPoll.run(_readStatus, fresh: fresh);

  Future<void> _readStatus() async {
    try {
      final p = activeProfile ?? selected;
      if (nativeProtocols.contains(p?.protocol) && nativeTunnel) {
        final j = Map<String, dynamic>.from(
          (await native.invokeMapMethod<String, dynamic>('status')) ?? {},
        );
        final up = j['active'] == true;
        status = TunnelStatus(
          active: up,
          state: up
              ? (j['phase'] == 'reconnecting'
                    ? 'РџРѕРІС‚РѕСЂРЅРѕРµ РїРѕРґРєР»СЋС‡РµРЅРёРµвЂ¦'
                    : 'РРЅС‚РµСЂС„РµР№СЃ Р°РєС‚РёРІРµРЅ')
              : 'РћС‚РєР»СЋС‡РµРЅРѕ',
          path: up ? '${j['protocol'] ?? p!.protocol}' : 'вЂ”',
          rx: j['rx'],
          tx: j['tx'],
          handshake: j['handshake'],
        );
        if (up) {
          _activeId = j['id'];
        } else {
          _activeId = null;
        }
      }
    } catch (_) {
      status = TunnelStatus(
        active: _activeId != null,
        state: 'РЎРѕСЃС‚РѕСЏРЅРёРµ РЅРµРёР·РІРµСЃС‚РЅРѕ В· РїСЂРѕРІРµСЂСЊС‚Рµ СЃР»СѓР¶Р±Сѓ',
        path: 'вЂ”',
      );
    } finally {
      notifyListeners();
    }
  }

  Map<String, dynamic> diagnosticReport(List<Map<String, dynamic>> checks) => {
    'application': 'XIO',
    'version': '0.22.3',
    'createdAt': DateTime.now().toUtc().toIso8601String(),
    'platform': Platform.operatingSystem,
    'tunnelState': status.state,
    'path': status.path,
    'checks': checks,
    'notes': 'РўРµСЃС‚С‹ РґРѕСЃС‚СѓРїРЅРѕСЃС‚Рё РЅРµ РґРѕРєР°Р·С‹РІР°СЋС‚ РѕС‚СЃСѓС‚СЃС‚РІРёРµ DNS/IPv6-СѓС‚РµС‡РµРє. РљР»СЋС‡Рё Рё РєРѕРЅС„РёРіСѓСЂР°С†РёРё РЅРµ РІРєР»СЋС‡РµРЅС‹.',
  };

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}

class SshTarget {
  final String host, username, fingerprint;
  final int port;
  const SshTarget(this.host, this.port, this.username, [this.fingerprint = '']);
  void validate() {
    if (host.isEmpty ||
        host.startsWith('-') ||
        !RegExp(r'^[a-zA-Z0-9.:-]+$').hasMatch(host)) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ Р°РґСЂРµСЃ VPS');
    }
    if (port < 1 || port > 65535) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ SSH-РїРѕСЂС‚');
    }
    if (!RegExp(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$').hasMatch(username)) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ');
    }
    if (fingerprint.isNotEmpty &&
        !RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
      throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ SHA256-РѕС‚РїРµС‡Р°С‚РѕРє SSH');
    }
  }
}

/// Automatically remembers the first host key before authentication is allowed.
/// A changed key is never silently accepted or overwritten.
class SshHostKeyStore {
  final File? file;
  SshHostKeyStore([this.file]);
  static Future<void> _pending = Future.value();

  Future<void> verify(SshTarget target, String fingerprint) async {
    final previous = _pending;
    final done = Completer<void>();
    _pending = done.future;
    await previous;
    try {
      final storage =
          file ??
          File('${(await applicationDirectory()).path}/ssh-known-hosts.json');
      Map<String, dynamic> keys = {};
      if (await storage.exists()) {
        final decoded = jsonDecode(await storage.readAsString());
        if (decoded is! Map<String, dynamic> ||
            decoded.values.any(
              (v) =>
                  v is! String ||
                  !RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(v),
            )) {
          throw const FormatException('РџРѕРІСЂРµР¶РґРµРЅРѕ С…СЂР°РЅРёР»РёС‰Рµ РєР»СЋС‡РµР№ SSH');
        }
        keys = decoded;
      }
      final endpoint = '[${target.host.toLowerCase()}]:${target.port}';
      final known = keys[endpoint];
      if (known != null && known != fingerprint) {
        throw const FormatException(
          'РљР»СЋС‡ SSH СЃРµСЂРІРµСЂР° РёР·РјРµРЅРёР»СЃСЏ. РџРѕРґРєР»СЋС‡РµРЅРёРµ РѕСЃС‚Р°РЅРѕРІР»РµРЅРѕ. '
          'РџСЂРѕРІРµСЂСЊС‚Рµ СЃРµСЂРІРµСЂ РїРµСЂРµРґ РїРѕРІС‚РѕСЂРЅРѕР№ РЅР°СЃС‚СЂРѕР№РєРѕР№.',
        );
      }
      if (known == null) {
        if (!RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
          throw const FormatException('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РєР»СЋС‡ SSH СЃРµСЂРІРµСЂР°');
        }
        keys[endpoint] = fingerprint;
        await storage.parent.create(recursive: true);
        final temp = File('${storage.path}.tmp');
        await temp.writeAsString(jsonEncode(keys), flush: true);
        await temp.rename(storage.path);
      }
    } on FileSystemException {
      throw const FormatException(
        'РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕС…СЂР°РЅРёС‚СЊ РёР»Рё РїСЂРѕС‡РёС‚Р°С‚СЊ РєР»СЋС‡ SSH СЃРµСЂРІРµСЂР°',
      );
    } on FormatException catch (e) {
      if (e.message.startsWith('РљР»СЋС‡ SSH') ||
          e.message.startsWith('РќРµ СѓРґР°Р»РѕСЃСЊ') ||
          e.message.startsWith('РќРµРєРѕСЂСЂРµРєС‚РЅС‹Р№ РєР»СЋС‡')) {
        rethrow;
      }
      throw const FormatException('РџРѕРІСЂРµР¶РґРµРЅРѕ С…СЂР°РЅРёР»РёС‰Рµ РєР»СЋС‡РµР№ SSH');
    } finally {
      done.complete();
    }
  }
}

class VpsService {
  final SshHostKeyStore hostKeys;
  VpsService({SshHostKeyStore? hostKeys})
    : hostKeys = hostKeys ?? SshHostKeyStore();
  SSHClient? _client;
  SshTarget? target;
  String verifiedFingerprint = '';
  Future<void> open(
    SshTarget t,
    String password,
    String privateKey,
    String passphrase,
  ) async {
    t.validate();
    await close();
    final identities = privateKey.trim().isEmpty
        ? <SSHKeyPair>[]
        : await compute(_decodeKey, (privateKey, passphrase));
    final socket = await SSHSocket.connect(
      t.host,
      t.port,
      timeout: const Duration(seconds: 12),
    );
    Object? hostKeyError;
    final c = SSHClient(
      socket,
      username: t.username,
      identities: identities,
      onPasswordRequest: () => password,
      onVerifyHostKey: (type, fp) async {
        final fingerprint = utf8.decode(fp);
        if (t.fingerprint.isNotEmpty && fingerprint != t.fingerprint) {
          return false;
        }
        try {
          await hostKeys.verify(t, fingerprint);
          verifiedFingerprint = fingerprint;
          return true;
        } catch (e) {
          hostKeyError = e;
          return false;
        }
      },
      handshakeTimeout: const Duration(seconds: 15),
      authTimeout: const Duration(seconds: 20),
    );
    _client = c;
    try {
      await c.authenticated;
      target = t;
    } catch (_) {
      await close();
      if (hostKeyError != null) throw hostKeyError!;
      rethrow;
    }
  }

  static List<SSHKeyPair> _decodeKey((String, String) input) =>
      SSHKeyPair.fromPem(input.$1, input.$2.isEmpty ? null : input.$2);
  Future<String> preflight() async {
    final result = await _client!
        .runWithResult(r'''set -eu
printf 'OS: '; . /etc/os-release; printf '%s %s\n' "$ID" "$VERSION_ID"
printf 'ARCH: '; uname -m
printf 'UID: '; id -u
printf 'KERNEL: '; uname -r
printf '\nDISK\n'; df -h / | tail -n 1
printf '\nLISTENERS\n'; ss -lntu | head -n 25
printf '\nROUTES\n'; ip -4 route show
printf '\nX1O\n'; if test -e /etc/wireguard/x1o0.conf; then printf 'existing installation\n'; else printf 'not installed\n'; fi
''')
        .timeout(const Duration(seconds: 20));
    if (result.exitCode != 0) {
      throw StateError('РџСЂРµРґРїСЂРѕРІРµСЂРєР° VPS Р·Р°РІРµСЂС€РёР»Р°СЃСЊ РѕС€РёР±РєРѕР№');
    }
    return utf8.decode(result.stdout, allowMalformed: true);
  }

  Future<String> installWireGuard(String script) async {
    if (target == null || target!.username != 'root') {
      throw StateError(
        'Р РµС†РµРїС‚ С‚СЂРµР±СѓРµС‚ SSH-РІС…РѕРґ root; sudo РІ СЌС‚РѕР№ РІРµСЂСЃРёРё РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ',
      );
    }
    final keypair = await X25519().newKeyPair();
    final public = base64Encode((await keypair.extractPublicKey()).bytes);
    final private = base64Encode(await keypair.extractPrivateKeyBytes());
    final session = await _client!.execute("sh -s -- '$public'");
    // The public key is the sole argument; private client material never leaves this process.
    final output = session.stdout.fold<List<int>>([], (a, b) => a..addAll(b));
    final errors = session.stderr.fold<List<int>>([], (a, b) => a..addAll(b));
    session.write(Uint8List.fromList(utf8.encode(script)));
    await session.stdin.close();
    try {
      await session.done.timeout(const Duration(minutes: 4));
    } on TimeoutException {
      session.kill(SSHSignal.TERM);
      throw StateError(
        'РЈСЃС‚Р°РЅРѕРІРєР° РЅРµ Р·Р°РІРµСЂС€РёР»Р°СЃСЊ РІРѕРІСЂРµРјСЏ. РџСЂРѕРІРµСЂСЊС‚Рµ Р¶СѓСЂРЅР°Р» /var/log/x1o-install.log РЅР° VPS.',
      );
    }
    final out = utf8.decode(await output, allowMalformed: true);
    await errors;
    if (session.exitCode != 0) {
      throw StateError(
        'РЈСЃС‚Р°РЅРѕРІРєР° РїСЂРµСЂРІР°РЅР°. РР·РјРµРЅРµРЅРёСЏ РјРѕРіР»Рё РїСЂРёРјРµРЅРёС‚СЊСЃСЏ С‡Р°СЃС‚РёС‡РЅРѕ; Р¶СѓСЂРЅР°Р» /var/log/x1o-install.log РЅР° VPS.',
      );
    }
    final match = RegExp(r'X1O_SERVER_KEY=([A-Za-z0-9+/]{43}=)')
        .firstMatch(out);
    if (match == null) throw StateError('РќРµС‚ РїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅРѕРіРѕ РєР»СЋС‡Р° СЃРµСЂРІРµСЂР°');
    final host = target!.host.contains(':')
        ? '[${target!.host}]'
        : target!.host;
    return '[Interface]\nPrivateKey = $private\nAddress = 10.77.0.2/32, fd77:1::2/128\nDNS = 9.9.9.9\nMTU = 1280\n\n[Peer]\nPublicKey = ${match[1]}\nEndpoint = $host:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n';
  }

  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (_client == null || target == null) {
      throw StateError('РЎРЅР°С‡Р°Р»Р° РїРѕРґРєР»СЋС‡РёС‚РµСЃСЊ РїРѕ SSH');
    }
    final session = await _client!.execute(command);
    final output = session.stdout.fold<List<int>>([], (a, b) => a..addAll(b));
    final errors = session.stderr.drain<void>();
    session.stdin.add(Uint8List.fromList(input));
    await session.stdin.close();
    final bytes = await output.timeout(timeout);
    await errors;
    await session.done.timeout(timeout);
    // JSON operation errors are decoded by the caller; never echo stderr/secrets.
    if (session.exitCode != 0 && bytes.isEmpty) {
      throw StateError('РћРїРµСЂР°С†РёСЏ СЃРµСЂРІРµСЂР° Р·Р°РІРµСЂС€РёР»Р°СЃСЊ РѕС€РёР±РєРѕР№');
    }
    return bytes;
  }

  Future<void> close() async {
    final c = _client;
    _client = null;
    target = null;
    if (c != null) await c.close();
  }
}

class NetworkChecks {
  static Future<List<Map<String, dynamic>>> run(String host, int port) async {
    if (host.isEmpty ||
        port < 1 ||
        port > 65535 ||
        host.contains(RegExp(r'\s'))) {
      throw const FormatException('РџСЂРѕРІРµСЂСЊС‚Рµ Р°РґСЂРµСЃ Рё РїРѕСЂС‚');
    }
    final result = <Map<String, dynamic>>[];
    var timer = Stopwatch()..start();
    try {
      final addresses = await InternetAddress.lookup(host)
          .timeout(const Duration(seconds: 8));
      result.add({
        'test': 'DNS',
        'ok': true,
        'ms': timer.elapsedMilliseconds,
        'detail': addresses
            .map((a) => a.type == InternetAddressType.IPv6 ? 'IPv6' : 'IPv4')
            .toSet()
            .join(', '),
      });
    } catch (_) {
      result.add({
        'test': 'DNS',
        'ok': false,
        'detail': 'РРјСЏ РЅРµ СЂР°Р·СЂРµС€РµРЅРѕ РёР»Рё С‚Р°Р№Рј-Р°СѓС‚',
      });
    }
    final samples = <int>[];
    for (var i = 0; i < 3; i++) {
      timer = Stopwatch()..start();
      try {
        final s = await Socket.connect(
          host,
          port,
          timeout: const Duration(seconds: 5),
        );
        samples.add(timer.elapsedMilliseconds);
        s.destroy();
      } catch (_) {}
    }
    result.add({
      'test': 'TCP :$port',
      'ok': samples.isNotEmpty,
      'ms': samples.isEmpty
          ? null
          : samples.reduce((a, b) => a + b) ~/ samples.length,
      'detail':
          '${samples.length}/3 TCP-СЃРѕРµРґРёРЅРµРЅРёР№. Р­С‚Рѕ РЅРµ ICMP RTT Рё РЅРµ С‚РµСЃС‚ РїСЂРѕРїСѓСЃРєРЅРѕР№ СЃРїРѕСЃРѕР±РЅРѕСЃС‚Рё.',
    });
    return result;
  }
}
