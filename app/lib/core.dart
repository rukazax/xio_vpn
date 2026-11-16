import 'build_identity.dart';
import 'version.dart';
import 'cascade_model.dart';
import 'mtproto_link.dart';
export 'mtproto_link.dart';
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
import 'server_address.dart';
export 'extended_profile.dart';
export 'rivet_profile.dart';
import 'status_poll.dart';
import 'connection_attempt.dart';
import 'connection_plan.dart';
import 'policy_channel.dart';
import 'policy_publication.dart';
import 'store_writer_owner.dart';
export 'connection_attempt.dart';
export 'policy_channel.dart' show PolicyFailure;
import 'l10n.dart';
import 'routing_domains.dart';

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'managed_models.dart';
export 'managed_models.dart';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const native = EngineChannel();
bool get platformTunnel =>
    Platform.isAndroid || Platform.isIOS || DesktopEngine.enabled;

/// Android-экран настроек раздельного туннелирования.
///
/// `Platform.isAndroid` нельзя переопределить в widget-тестах, поэтому те же
/// экраны включаются и оверрайдом платформы: на настольных сборках
/// `defaultTargetPlatform` никогда не `android`, поведение не меняется.
bool get androidSettingsUi =>
    Platform.isAndroid || defaultTargetPlatform == TargetPlatform.android;
Set<String> get platformProtocols => Platform.isAndroid
    ? availableAndroidProtocols
    : Platform.isIOS
    ? nativeProtocolTargets[ClientPlatform.ios]!
    : DesktopEngine.supported;

/// Canonical product-store identity: lowercase hex SHA-256 of the canonical
/// product directory. This is the same key the cooperating writer owner uses;
/// it is not a helper nonce and not a controller identity. A filesystem that
/// cannot resolve links falls back to the absolute path instead of failing
/// hydration.
Future<String> policyStoreIdentity(Directory directory) async {
  var key = directory.absolute.path;
  try {
    key = await directory.resolveSymbolicLinks();
  } catch (_) {}
  if (Platform.isWindows) key = key.toLowerCase();
  return crypto.sha256.convert(utf8.encode(key)).toString();
}

/// 16 random bytes as 32 lowercase hex characters.
String policyNonce() => List.generate(
  16,
  (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0'),
).join();

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

/// The watchdog probes DNS every 15 s until a tunnel has answered six checks in a
/// row, then every 20 s: half the radio wakeups for a link already proven stable.
/// Any failure resets the counter, so detection stays at 15+20 s.
Duration watchdogIntervalFor(int healthyChecks) => healthyChecks >= 6
    ? const Duration(seconds: 20)
    : const Duration(seconds: 15);

class Protocol {
  final String id, name, detail, family;
  const Protocol(this.id, this.name, this.detail, this.family);
  bool get available => platformProtocols.contains(id) && platformTunnel;
}

const protocols = [
  Protocol('xray', 'Xray / VLESS', 'TLS · REALITY · XHTTP', 'Xray'),
  Protocol(
    'rivet-s1',
    'RIVET / S1',
    'Экспериментальный · TLS / WebSocket',
    'RIVET',
  ),
  Protocol('awg', 'AmneziaWG 3.1', 'Обфускация WireGuard', 'Amnezia'),
  Protocol(
    'rivet-h3',
    'RIVET / H3',
    'Экспериментальный · QUIC / CONNECT-UDP',
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
      throw const FormatException('Слишком большой или повреждённый профиль');
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
          throw const FormatException('Ожидается WireGuard .conf');
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
            'Неподдерживаемое поле: $key. Команды и поля другого режима не принимаются.',
          );
        }
        final map = fields.putIfAbsent(section, () => {});
        if (map.containsKey(key) ||
            (value.isEmpty &&
                !(amnezia &&
                    section == 'interface' &&
                    {'i1', 'i2', 'i3', 'i4', 'i5'}.contains(key)))) {
          throw FormatException('Повторное или пустое поле: $key');
        }
        map[key] = value;
      }
    }
    if (interfaces != 1 || peers != 1) {
      throw const FormatException('Нужны один Interface и один Peer');
    }
    final i = fields['interface'] ?? {}, peer = fields['peer0'] ?? {};
    if (amnezia) {
      for (final key in ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4']) {
        final value = i[key];
        if (value == null) continue;
        final number = int.tryParse(value);
        final limit = key == 'jc' ? 128 : 1280;
        if (number == null || number < 0 || number > limit) {
          throw FormatException('$key: в этой сборке допустимо 0…$limit');
        }
      }
      if (int.parse(i['jmin'] ?? '0') > int.parse(i['jmax'] ?? '1280')) {
        throw const FormatException('Jmin должен быть не больше Jmax');
      }
      for (final key in ['h1', 'h2', 'h3', 'h4']) {
        final value = i[key];
        if (value == null) continue;
        final parts = value.split('-');
        final numbers = parts.map(int.tryParse).toList();
        if (parts.length > 2 ||
            numbers.any((n) => n == null || n < 0 || n > 4294967295) ||
            (numbers.length == 2 && numbers.first! > numbers.last!)) {
          throw FormatException('$key: ожидается uint32 или диапазон min-max');
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
          'Ключ WireGuard должен содержать 32 байта Base64',
        );
      }
    }
    if (i['address'] == null ||
        peer['allowedips'] == null ||
        peer['endpoint'] == null) {
      throw const FormatException('Обязательны Address, AllowedIPs и Endpoint');
    }
    for (final cidr in '${i['address']},${peer['allowedips']}'.split(',')) {
      final parts = cidr.trim().split('/');
      final ip = InternetAddress.tryParse(parts.first);
      final prefix = parts.length == 2 ? int.tryParse(parts[1]) : null;
      if (ip == null ||
          prefix == null ||
          prefix < 0 ||
          prefix > (ip.type == InternetAddressType.IPv4 ? 32 : 128)) {
        throw const FormatException('Некорректный CIDR');
      }
    }
    final endpoint = ServerEndpoint.parse(peer['endpoint']!);
    return WireGuardProfile(
      endpoint.formatted,
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
  final String phase, recoveryId;
  final bool recoveryPending, cleanupPending;
  final int recoveryRemainingMillis;
  const TunnelStatus({
    this.active = false,
    this.state = 'Отключено',
    this.path = '—',
    this.rx,
    this.tx,
    this.handshake,
    this.phase = 'disconnected',
    this.recoveryId = '',
    this.recoveryPending = false,
    this.cleanupPending = false,
    this.recoveryRemainingMillis = 0,
  });

  /// Value equality: an unchanged status must not cause a repaint.
  @override
  bool operator ==(Object other) =>
      other is TunnelStatus &&
      other.active == active &&
      other.state == state &&
      other.path == path &&
      other.rx == rx &&
      other.tx == tx &&
      other.handshake == handshake &&
      other.phase == phase &&
      other.recoveryId == recoveryId &&
      other.recoveryPending == recoveryPending &&
      other.cleanupPending == cleanupPending &&
      other.recoveryRemainingMillis == recoveryRemainingMillis;
  @override
  int get hashCode => Object.hash(
    active,
    state,
    path,
    rx,
    tx,
    handshake,
    phase,
    recoveryId,
    recoveryPending,
    cleanupPending,
    recoveryRemainingMillis,
  );
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
      throw const FormatException('WireGuard удалён из этой версии XIO');
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
    final host = normalizeServerHost(value('hostName'));
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
    out.writeln('Endpoint = ${serverEndpoint(host, port)}');
    out.writeln('AllowedIPs = ${allowed.join(', ')}');
    if (client['persistent_keep_alive'] != null &&
        client['persistent_keep_alive'] != '') {
      out.writeln('PersistentKeepalive = ${value('persistent_keep_alive')}');
    }
    return out.toString();
  }

  static ClientImport parse(String input) {
    if (input.length > 200000 || input.contains('\u0000')) {
      throw const FormatException('Некорректный профиль XIO');
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
    if (raw.startsWith('xio://')) {
      final bundle = UserBundle.decode(raw);
      for (final entry in bundle.configs.entries) {
        if (detect(entry.value) != entry.key) {
          throw const FormatException('Протокол не совпадает с конфигурацией');
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
          // OpenVPN/Cloak удалён из XIO: профиль с этим контейнером
          // отклоняется целиком, а не импортируется частично.
          'amnezia-openvpn-cloak' => throw const FormatException(
            'transport removed: openvpn/cloak',
          ),
          _ => throw const FormatException(),
        };
        final protocol = container[kind];
        if (protocol is! Map) throw const FormatException();
        final last = protocol['last_config'];
        final client = last is String ? jsonDecode(last) : last;
        if (client is! Map) {
          throw const FormatException();
        }
        String config;
        if (kind == 'xray') {
          config = ExtendedProfile.parse(jsonEncode(client)).encoded;
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
        'Неподдерживаемая конфигурация. Импортируйте клиентский профиль WireGuard или AmneziaWG.',
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
    final changed = _foreground != active;
    _foreground = active;
    if (screenSecuritySupported && changed) {
      if (!active) {
        // An Activity/window may be recreated while hidden. Its old ACK is
        // not evidence about the next window (which starts secure natively).
        _screenSecurityRevision++;
        screenSecurityEnabled = null;
        if (!_disposed) notifyListeners();
      } else if (ready) {
        unawaited(applyScreenSecurity());
      }
    }
    _timer?.cancel();
    _timer = null;
    if (active && ready) {
      unawaited(refresh());
      _timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
    }
    // A visible window may probe at once; a hidden one waits for its budget.
    if (changed && active) _lastProbeAt = 0;
  }

  Future<void> acknowledgeLegal(String text, String language) async {
    final previous = legalRecord;
    legalRecord = LegalRecord.acknowledge(text, language);
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      legalRecord = previous;
      rethrow;
    }
    if (!_disposed) notifyListeners();
  }

  Future<void> acknowledgeVpn() async {
    final previous = vpnDisclosure;
    vpnDisclosure = vpnDisclosureRevision;
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      vpnDisclosure = previous;
      rethrow;
    }
    if (Platform.isAndroid || Platform.isIOS) {
      await native.invokeMethod<void>("setConsent", {
        "revision": legalRevision,
      });
    }
    if (!_disposed) notifyListeners();
  }

  final Future<bool> Function(Uri)? siteProbe;
  final SecurityContext? probeSecurityContext;
  AppStore({
    this.siteProbe,
    this.probeSecurityContext,
    this.nativeTunnelOverride,
    this.domainLookup,
  });

  /// Подменяемый DNS для доменных правил: тесты не ходят в сеть.
  final DomainAddressLookup? domainLookup;
  final bool? nativeTunnelOverride;
  bool get nativeTunnel => nativeTunnelOverride ?? platformTunnel;
  Set<String> get supportedProtocols => nativeTunnelOverride == true
      ? nativeProtocols.toSet()
      : platformProtocols;
  void changed() {
    if (!_disposed) notifyListeners();
  }
  final List<Profile> profiles = [];
  final List<String> events = [];
  final List<ManagedServer> servers = [];
  final List<ManagedUser> users = [];
  final Map<String, String> endpointCountries = {};
  String checkSite = 'https://youtube.com';
  // Disabled by default: a connection is confirmed by the tunnel itself
  // (fresh handshake, counters, DNS through the tunnel) unless the owner
  // explicitly opts into the HTTPS-site probe in the settings.
  bool siteCheckEnabled = false;
  // Android ships the native AmneziaWG engine and it is the proven default
  // transport here; automatic fallback still covers RIVET and Xray.
  String priorityProtocol = Platform.isAndroid
      ? 'awg'
      : Platform.isIOS
      ? 'rivet-s1'
      : 'xray';
  ConnectionPolicy _connectionPolicy = ConnectionPolicy.automatic;
  ConnectionPolicy get connectionPolicy => _connectionPolicy;

  /// Fixture injection only. Product code must publish through
  /// [setConnectionPolicy] or [saveConnectionSettings] so one owned snapshot is
  /// written; the plain field is intentionally read-only.
  @visibleForTesting
  set connectionPolicyForTesting(ConnectionPolicy value) {
    _connectionPolicy = value;
    if (_hasRawConnectionPolicy) _rawConnectionPolicy = value.toJson();
  }

  /// Owned-test write trace: never populated in production.
  @visibleForTesting
  bool traceDocumentWrites = false;
  @visibleForTesting
  final List<String> documentWriteTrace = [];
  int protocolTimeoutSeconds = 15;

  /// Loaded `connectionPolicy` value exactly as stored. While the stored value
  /// is invalid it is re-emitted verbatim by every later save: fail-closed must
  /// keep the bytes, never normalize or erase them.
  Object? _rawConnectionPolicy;
  bool _hasRawConnectionPolicy = false;

  /// Present-but-invalid durable policy: admission is blocked and the reason is
  /// visible. This is not a "fake unknown" state for the clean path.
  bool _policyInvalid = false;
  String? policyError;
  bool get policyInvalid => _policyInvalid;

  /// A publication/reconciliation whose outcome is not proven this session.
  /// `_policyUnconfirmed` means the durable document may already contain the new
  /// snapshot (after rename / lost reply); `_policyReconcileRequired` means a
  /// durable receipt exists but native did not ACK it in this instance.
  bool _policyUnconfirmed = false;
  bool _policyReconcileRequired = false;

  /// Last publication-level failure exposed to the UI (stable code + English
  /// diagnostic). Cleared only by a later successful publication.
  String? _policyFailureCode;
  String? _policyFailureMessage;

  /// Monotonic publication epoch, bumped whenever a new READY is adopted. A
  /// recovery captures it and must abort if any newer publication won meanwhile.
  int _policyEpoch = 0;

  /// A reconciliation owns the document/native writer. It is surfaced to the UI
  /// (busy/disabled controls) but a NEWER publication is allowed to supersede
  /// it; the recovery then aborts on the epoch/CAS check before its rename.
  bool _recoveryInFlight = false;

  /// A versioned publication is admitted and has not reached READY/failure.
  /// Confirmation must be false from this admission through the exact READY.
  bool _policyPublicationInFlight = false;

  /// The durable document currently reflects [connectionPolicy] (read back on
  /// load or renamed by this session). It is separate from a native ACK.
  bool _documentConfirmed = false;

  /// Committed versioned receipt and the exact plan it describes. Both are set
  /// only by an acknowledged publication; a restart without them is not proof
  /// of durable native state.
  PolicyReceipt? _policyReceipt;
  PublicationSnapshot? _committedPlan;

  /// Owned tests run on a desktop host; this selects the activation attachment
  /// encoding (Android map vs desktop JSON string) without touching the profile.
  @visibleForTesting
  bool? androidActivationForTesting;

  /// Durable receipt exactly as stored. It is evidence that versioned state
  /// exists (so a missing live receipt is not legacy), never a reusable
  /// instance authority: a restart requires reconciliation.
  Object? _rawConnectionPlanReceipt;
  PolicyChannel? _policyChannel;
  bool _policyCapability = false;

  /// Cooperating GUI document writer, bound by the real controller lifecycle
  /// (never inferred from an empty struct). Null in owned tests.
  ProductStoreWriterOwner? _productWriter;

  /// Set when the controller lifecycle could not obtain cooperating ownership
  /// (for example a second same-path controller). Writes are refused instead of
  /// silently racing the real owner; rendering still works.
  Object? _writerUnavailable;

  /// Canonical product-store identity: lowercase hex SHA-256 of the canonical
  /// product directory (the same key the cooperating writer owner uses). Null
  /// until the store directory is known.
  String? _storeIdentity;
  String? get storeIdentity => _storeIdentity;

  /// True when versioned policy state exists in the durable document or in this
  /// session. A missing receipt is only legacy on a pristine document.
  bool get policyReceiptRequired =>
      _hasRawConnectionPolicy ||
      _rawConnectionPlanReceipt != null ||
      _policyReceipt != null;

  /// Versioned state exists but this session holds no native ACK yet.
  bool get policyReconciliationPending =>
      _policyReceipt == null &&
      (_rawConnectionPlanReceipt != null ||
          (_hasRawConnectionPolicy && _policyCapability));
  bool get policyCapable => _policyCapability;
  Map<String, dynamic>? get committedPlan => _committedPlan?.plan;
  PolicyReceipt? get committedReceipt => _policyReceipt;

  /// Stable reason code for the UI; never rely on the message text. `null` only
  /// when a mode edit is admissible right now.
  String? get connectionPolicyError => connectionModeBlocker();

  /// English diagnostic fallback. The UI localizes [connectionPolicyError]
  /// codes with its own catalogue keys; product logic never asserts on text.
  String? get connectionPolicyMessage => policyError;

  /// Last publication/wire-limit failure for the UI: stable code (for example
  /// `POLICY_OVERSIZE`, a local product code) plus an English diagnostic.
  /// `null` after any later successful publication.
  String? get connectionPolicyFailureCode => _policyFailureCode;
  String? get connectionPolicyFailureMessage => _policyFailureMessage;

  /// An after-rename/native-unknown publication exists (no rollback claimed).
  bool get policyUnconfirmed => _policyUnconfirmed;

  /// A publication/reconcile round is outstanding or its outcome is unknown.
  bool get connectionModePending =>
      _policyUnconfirmed ||
      _policyReconcileRequired ||
      _documentAdmission.busy ||
      !ready;

  /// What actually backs the displayed mode. `document` is not a native ACK;
  /// `none` covers pending/unknown publication, unresolved reconciliation and
  /// the preserved malformed document.
  ConnectionModeConfirmation get connectionModeConfirmation {
    if (_disposed || _policyInvalid) return ConnectionModeConfirmation.none;
    if (_policyPublicationInFlight) return ConnectionModeConfirmation.none;
    if (_policyUnconfirmed || _policyReconcileRequired) {
      return ConnectionModeConfirmation.none;
    }
    if (_policyChannel?.ready == true &&
        _policyReceipt != null &&
        _committedPlan != null &&
        _policyReceipt!.planGeneration == _committedPlan!.generation) {
      return ConnectionModeConfirmation.native;
    }
    if (!_hasRawConnectionPolicy && _rawConnectionPlanReceipt == null) {
      return ConnectionModeConfirmation.legacyAutomatic;
    }
    return _documentConfirmed
        ? ConnectionModeConfirmation.document
        : ConnectionModeConfirmation.none;
  }

  /// Positively true only when an exact live native READY receipt describes the
  /// current generation. False on begin/revoke/dispose/restart/pending/error,
  /// and false for a merely stored/legacy automatic choice: this is NOT the
  /// tunnel state and legacy defaults must not be shown as native-confirmed.
  bool get connectionModeConfirmed =>
      connectionModeConfirmation == ConnectionModeConfirmation.native;

  /// Same predicate the setter enforces, so the UI never infers private state.
  bool get canChangeConnectionMode => connectionModeBlocker() == null;

  String? connectionModeBlocker() {
    if (_disposed) return 'disposed';
    if (_writerUnavailable != null) return 'persistence';
    if (!ready) return 'loading';
    if (_policyInvalid) return 'corrupt';
    if (_policyUnconfirmed) return 'publishPending';
    if (_recoveryInFlight) return 'persistence';
    if (_documentAdmission.busy) return 'persistence';
    if (busy ||
        status.active ||
        _desired ||
        reconnecting ||
        cleanupIncomplete ||
        _connectRound != null ||
        _retry != null ||
        _watchdog != null ||
        _nativeRecoveryLease != null) {
      return 'busy';
    }
    // Native safety is unknown after a restart/failed reply: block edits until
    // an explicit reconcile proves the durable snapshot.
    if (_policyReconcileRequired) return 'reconcileRequired';
    return null;
  }

  static const _modeBusyCodes = {
    'busy': 'POLICY_BUSY',
    'persistence': 'POLICY_BUSY',
    'loading': 'POLICY_BUSY',
    'disposed': 'POLICY_BUSY',
    'corrupt': 'POLICY_INVALID',
    'publishPending': 'POLICY_PENDING',
    'reconcileRequired': 'POLICY_UNKNOWN',
  };

  bool _restoreAllowed(Object error) =>
      error is! PublicationFailure ||
      error.phase == PublicationPhase.beforeRename;

  void _markPostRenameUnknown() {
    _policyUnconfirmed = true;
    _policyReconcileRequired = true;
    if (!_disposed) notifyListeners();
  }
  void _notifySafe() {
    if (!_disposed) notifyListeners();
  }

  void _recordPolicyFailure(Object error) {
    PolicyFailure? failure;
    if (error is PolicyFailure) {
      failure = error;
    } else if (error is PublicationFailure && error.cause is PolicyFailure) {
      failure = error.cause as PolicyFailure;
    }
    _policyFailureCode = failure?.code ?? 'POLICY_UNKNOWN';
    _policyFailureMessage = failure?.message ?? '$error';
    if (!_disposed) notifyListeners();
  }

  void _clearPolicyFailure() {
    if (_policyFailureCode == null && _policyFailureMessage == null) return;
    _policyFailureCode = null;
    _policyFailureMessage = null;
  }
  /// The setter lets a newer publication supersede an in-flight recovery; the
  /// epoch/CAS abort in the recovery prevents a stale overwrite. The UI reads
  /// the stricter getter, so controls stay disabled while a recovery runs.
  String? _modeSetterBlocker() {
    if (_disposed) return 'disposed';
    if (_writerUnavailable != null) return 'persistence';
    if (!ready) return 'loading';
    if (_policyInvalid) return 'corrupt';
    if (_policyUnconfirmed) return 'publishPending';
    if (_documentAdmission.busy) return 'persistence';
    if (busy ||
        status.active ||
        _desired ||
        reconnecting ||
        cleanupIncomplete ||
        _connectRound != null ||
        _retry != null ||
        _watchdog != null ||
        _nativeRecoveryLease != null) {
      return 'busy';
    }
    if (_policyReconcileRequired) return 'reconcileRequired';
    return null;
  }
  PolicyFailure _modeFailure(String blocker) => PolicyFailure(
    _modeBusyCodes[blocker] ?? 'POLICY_UNKNOWN',
    'Connection mode cannot change now: $blocker',
  );


  /// Сторонние DNS-резолверы из настроек: до двух адресов (IPv4/IPv6/домен).
  /// По умолчанию Quad9 — то же значение, что раньше писалось в AWG-профили.
  List<String> dnsServers = [...defaultDnsServers];

  /// Автозапуск при загрузке устройства (Android: BOOT_COMPLETED-ресивер).
  bool autostart = false;

  /// Автоподключение после запуска приложения.
  bool autoConnectOnStart = false;

  /// Desired persisted permission, NOT evidence that a window flag was applied.
  bool allowScreenshots = false;
  bool get screenSecuritySupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// Last acknowledged Android window-flag request; null means unknown.
  /// This is not a guarantee against OS/root/capture bypass.
  bool? screenSecurityEnabled;
  bool screenSecurityPreferenceKnown = true;
  Future<void> _screenSecurityQueue = Future<void>.value();
  int _screenSecurityRevision = 0;
  int _screenSecurityPending = 0;
  bool get screenSecurityBusy => _screenSecurityPending != 0;
  String? connectionCheck;
  String? selectedId;

  /// Двухсерверная схема: адрес bridge (IPv4/домен) и exit (только IPv6).
  /// Пустые строки означают «каскад не настроен».
  String cascadeBridge = '';
  String cascadeExit = '';

  /// Каскад включён. Функция бесплатная, поэтому на новом профиле она включена
  /// сразу; выключить можно вручную, и выбор запоминается.
  bool cascadeUnlocked = true;

  /// Итог последней проверки каскада — для схемы на главном экране.
  bool cascadeHealthOk = false;
  int? cascadeHealthPingMs;
  String cascadeExitIpv6 = '';
  String cascadeExitIp = '';
  String cascadeCheckedAt = '';
  String cascadeBridgeCountry = '';
  String cascadeExitCountry = '';

  /// Ссылка MTProto-прокси для Telegram в каноническом виде `tg://proxy?…`.
  /// Пустая строка означает «прокси в приложении не настроен»: приложение
  /// ничего не подключает само, оно только передаёт ссылку в Telegram.
  String mtprotoLink = '';

  /// Доменные правила раздельного туннелирования (Android): `youtube.com`,
  /// `*.example.com`. Источник — нативная политика (IP-правила и домены лежат
  /// в одном файле); поле кэширует список для подключения и журнала.
  List<String> splitDomains = [];

  /// Адреса, полученные разрешением [splitDomains] в последний раз.
  List<String> splitResolvedAddresses = const [];
  SplitDomainSync? _splitSync;

  TunnelStatus status = const TunnelStatus();
  bool busy = false, ready = false;
  bool serverMaintenance = false;
  String? error;
  Directory? directory;
  Timer? _timer;
  // Live connection control: while the tunnel is up the app re-checks it and
  // reconnects (through the same protocol-fallback plan) when the link is lost.
  Timer? _watchdog;
  int _watchdogMisses = 0;
  int _watchdogHealthy = 0;

  /// A tunnel that answered six checks in a row is checked half as often.
  Duration get _watchdogInterval => watchdogIntervalFor(_watchdogHealthy);
  Timer? _retry;
  int _retryCount = 0;
  bool _desired = false;
  bool reconnecting = false;
  bool autoReconnect = true;
  // Battery budget for the link check. A DNS lookup through the tunnel wakes the
  // radio, so the watchdog first looks for free evidence (fresh handshake or a
  // moving receive counter) and only then spends a probe — never more often than
  // [_backgroundProbeMillis] while the window is hidden.
  bool _foreground = true;
  static const int _handshakeFreshMillis = 150000;
  static const int _backgroundProbeMillis = 90000;
  int _lastProbeAt = 0;
  int? _lastRx;
  final _statusPoll = StatusPoll();
  // A native reply belongs to the lifecycle that requested it, not the next
  // activation/teardown (or a controller whose timers were already disposed).
  int _statusEpoch = 0;
  void Function()? _cancelConnectionProbe;
  void _invalidateConnectionStatus() {
    _statusEpoch++;
    _cancelConnectionProbe?.call();
    _cancelConnectionProbe = null;
  }

  bool _disposed = false;
  ConnectionRound? _connectRound;
  Future<void>? _nativeCleanup;
  bool cleanupIncomplete = false;
  int _roundSerial = 0;
  int _operationEpoch = 0;
  int _reconnectEpoch = 0;
  String? _nativeRecoveryKey;
  ConnectionRound? _nativeRecoveryLease;
  int _nativeRecoverySeen = 0;
  final Set<String> _nativeRecoveryStages = {};
  bool _storageHealthy = true;
  Future<void>? _loadFuture;
  // Any explicit control supersedes startup, even before hydration begins.
  int _startupIntentEpoch = 0;
  bool _startupStatusIdle = false;
  ConnectionRound? _desktopStartupRound;
  Future<void> _saveQueue = Future.value();
  String? _activeId;
  String? _attemptedProfileId;
  Profile? get attemptedProfile =>
      profiles.where((p) => p.id == _attemptedProfileId).firstOrNull;
  Profile? get selected =>
      profiles.where((p) => p.id == selectedId).firstOrNull;
  Profile? get activeProfile =>
      profiles.where((p) => p.id == _activeId).firstOrNull;

  /// Нативный вызов, без которого приложение обязано всё равно запуститься.
  ///
  /// Старый нативный слой может не знать метод и ответить
  /// `PlatformException(ENGINE, …)`. Это не повод оставлять пользователя на
  /// сплэше: настройка просто не применится до следующего включения.
  Future<void> _tolerateNative(Future<void> Function() action) async {
    try {
      await action();
    } catch (_) {
      // Нативная сторона не поддерживает вызов — старт важнее настройки.
    }
  }

  // Hydration and startup intent are consumed once, even with duplicate callers.
  // Hydration itself owns a document mutation ticket: a mode reservation cannot
  // enter between reading the durable bytes and reconciling them.
  Future<void> load() => _loadFuture ??= withDocumentMutation(_load);

  Future<void> _load() async {
    if (_disposed) return;
    var capabilitiesKnown = false;
    var persistedAutoConnect = false;
    if (nativeTunnel) {
      try {
        final list = await native.invokeListMethod<String>(
          'supportedProtocols',
        );
        if (list != null) {
          capabilitiesKnown = true;
          availableAndroidProtocols = list
              .where(nativeProtocols.contains)
              .toSet();
        }
      } catch (_) {}
    }
    if (_disposed) return;
    try {
      // A caller may inject `directory` (tests, embedders); resolve the platform
      // default only when none was provided. macOS is not a supported host, so
      // applicationDirectory() throws there by design and must not be forced.
      directory ??= await applicationDirectory();
      _storeIdentity ??= await policyStoreIdentity(directory!);
      final file = File('${directory!.path}/profiles.json');
      if (await file.exists()) {
        final j = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
        // Mode and priority are parsed BEFORE any selection repair: a present
        // but invalid value blocks admission and keeps its exact bytes.
        if (j.containsKey('connectionPolicy')) {
          _hasRawConnectionPolicy = true;
          _rawConnectionPolicy = j['connectionPolicy'];
          try {
            _connectionPolicy = ConnectionPolicy.parse(_rawConnectionPolicy);
          } catch (_) {
            _policyInvalid = true;
            policyError =
                'Saved connection mode is malformed; choose the mode again. '
                'Other data is unchanged.';
          }
        }
        if (j.containsKey('connectionPlanReceipt')) {
          _rawConnectionPlanReceipt = j['connectionPlanReceipt'];
          try {
            DocumentPlanReceipt.parse(_rawConnectionPlanReceipt);
          } catch (_) {
            _rawConnectionPlanReceipt = null;
            _policyInvalid = true;
            policyError ??=
                'Saved plan receipt is corrupt; connection is blocked until an '
                'explicit recovery.';
          }
        }
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
        // Manual mode owns its selection: a missing or unusable selected profile
        // is an honest empty candidate set, never repaired to another profile.
        if (connectionPolicy == ConnectionPolicy.automatic && !_policyInvalid) {
          if (!profileIds.contains(selectedId)) {
            selectedId = profiles.firstOrNull?.id;
          }
        }
        checkSite = validateCheckSite(j['checkSite'] ?? 'https://youtube.com')
            .toString();
        siteCheckEnabled = j['siteCheckEnabled'] == true;
        final storedDns = (j['dnsServers'] as List? ?? const [])
            .whereType<String>()
            .toList();
        if (storedDns.any((value) => value.trim().isNotEmpty)) {
          try {
            dnsServers = validateDnsServers(storedDns);
          } catch (_) {
            // Keep unsupported legacy DNS visible/editable and preserve it on
            // unrelated saves. Issuance validates before any remote effects.
            dnsServers = storedDns;
          }
        }
        autostart = j['autostart'] == true;
        persistedAutoConnect = j['autoConnectOnStart'] == true;
        autoConnectOnStart = persistedAutoConnect;
        allowScreenshots = j['allowScreenshots'] == true;
        cascadeBridge =
            validateCascadeBridge(j['cascadeBridge'] as String? ?? '') ?? '';
        cascadeExit =
            validateCascadeExit(j['cascadeExit'] as String? ?? '') ?? '';
        // Каскад бесплатный: отсутствие флага в старом профиле значит «включён».
        cascadeUnlocked = j['cascadeUnlocked'] != false;
        cascadeHealthOk = j['cascadeHealthOk'] == true;
        final ping = j['cascadeHealthPingMs'];
        cascadeHealthPingMs = ping is int && ping > 0 ? ping : null;
        cascadeExitIpv6 = j['cascadeExitIpv6'] as String? ?? '';
        cascadeExitIp = j['cascadeExitIp'] as String? ?? '';
        cascadeCheckedAt = j['cascadeCheckedAt'] as String? ?? '';
        cascadeBridgeCountry =
            _countryCode(j['cascadeBridgeCountry'] as String? ?? '') ??
            cascadeCountryForAddress(cascadeBridge);
        cascadeExitCountry =
            _countryCode(j['cascadeExitCountry'] as String? ?? '') ??
            cascadeCountryForAddress(cascadeExit);
        // Некорректная или устаревшая ссылка не роняет загрузку профиля:
        // экран покажет «не настроено», остальные настройки сохранятся.
        mtprotoLink =
            parseMtprotoLink(j['mtprotoLink'] as String? ?? '')?.link ?? '';
        // Доменные правила — рядом с IP-правилами раздельного
        // туннелирования. Повреждённые записи пропускаем: профиль важнее.
        final storedDomains = <String>[];
        for (final entry in (j['splitDomains'] as List? ?? const [])) {
          if (entry is! String) continue;
          final rule = normalizeDomainRule(entry);
          if (rule != null && !storedDomains.contains(rule)) {
            storedDomains.add(rule);
          }
        }
        splitDomains = storedDomains;
        autoReconnect = j['autoReconnect'] != false;
        protocolTimeoutSeconds = (j['protocolTimeoutSeconds'] as num? ?? 15)
            .toInt()
            .clamp(5, 60);
        final storedPriority = j['priorityProtocol'];
        if (storedPriority != null && storedPriority is! String) {
          // Plan identity compares the document value with the plan; a wrong
          // type must block, not be silently replaced by a platform default.
          _policyInvalid = true;
          policyError ??=
              'Saved protocol priority has the wrong type; connection is '
              'blocked until an explicit recovery.';
        }
        priorityProtocol = storedPriority is String &&
                nativeProtocols.contains(storedPriority)
            ? storedPriority
            : Platform.isIOS
            ? 'rivet-s1'
            : 'xray';
        // The durable bytes were read and validated; this confirms the document
        // selection, not a native envelope.
        if (!_policyInvalid) _documentConfirmed = true;
      }
      if (nativeTunnel) {
        final id = await native.invokeMethod<String>('activeId');
        if (id != null && profiles.any((p) => p.id == id)) {
          _activeId = id;
          // Native active state never rewrites a manual (or blocked) durable
          // selection: the user's chosen id stays the admission target.
          if (connectionPolicy == ConnectionPolicy.automatic && !_policyInvalid) {
            selectedId = id;
          }
        }
      }
      if (Platform.isAndroid) {
        await native.invokeMethod<void>(
          'setLanguage',
          AppLanguages.selected ?? '',
        );
      }
      await refresh();
      screenSecurityPreferenceKnown = true;
    } catch (_) {
      _storageHealthy = false;
      // A default in memory is not proof of the unreadable persisted choice.
      screenSecurityPreferenceKnown = false;
      error = 'Не удалось прочитать состояние приложения. Сохранённые данные не перезаписаны.';
    }
    try {
      if ((Platform.isAndroid || Platform.isIOS) && _storageHealthy) {
        await _tolerateNative(
          () => native.invokeMethod<void>('setConsent', {
            'revision': consentReady ? legalRevision : '',
          }),
        );
        await _tolerateNative(saveNativePlan);
      }
      if (Platform.isAndroid && _storageHealthy) {
        // Kotlin keeps its own copy: the boot receiver and the notification
        // permission check run before Flutter is started.
        await _tolerateNative(
          () =>
              native.invokeMethod<void>('setAutostart', {'enabled': autostart}),
        );
        await _tolerateNative(
          () => native.invokeMethod<void>('setAutoConnectOnStart', {
            'enabled': autoConnectOnStart,
          }),
        );
        // Доменные правила живут в нативной политике: подтягиваем их, чтобы
        // «Маршрутизация» и подключение видели один и тот же список.
        await _tolerateNative(loadSplitDomains);
      }
      if (_storageHealthy) await applyScreenSecurity();
    } finally {
      // `load()` вызывается через `unawaited`. Если исключение выйдет наружу,
      // `ready` не наступит и приложение навсегда останется на сплэше — именно
      // это случилось на сборке, где native ещё не знал `setAutostart`.
      if (!_disposed) {
        ready = true;
        if (!_disposed) notifyListeners();
      }
    }
    if (_disposed) return;
    // Capability discovery is a read: a missing versioned API leaves automatic
    // on the legacy plan channel and manual fail-closed.
    await discoverPolicyCapability();
    if (_policyCapability && !_policyInvalid && policyReceiptRequired) {
      try {
        await reconcilePolicy();
      } catch (_) {
        // Reconciliation failure is "native safety unknown", not a cleared plan.
        _policyReconcileRequired = true;
        policyError ??=
            'Saved plan could not be reconciled with the engine; manual '
            'activation is blocked until recovery.';
      }
    }
    // A load that finished while the window was already hidden must not revive
    // the three-second UI poll.
    if (_foreground) {
      _timer = Timer.periodic(const Duration(seconds: 3), (_) => refresh());
    }
    if (Platform.isAndroid && (!enforceConsent || consentReady)) {
      final requested =
          await native.invokeMethod<bool>('consumeConnectRequest') == true;
      // «Автоподключение после запуска»: the owner asked for the selected
      // profile to be raised on app start, unless the tunnel is already up.
      final automatic =
          autoConnectOnStart && !status.active && selected != null;
      if (requested || automatic) await connect();
    } else if ((Platform.isLinux || Platform.isWindows) &&
        _startupIntentEpoch == 0 &&
        _storageHealthy &&
        capabilitiesKnown &&
        nativeTunnel &&
        persistedAutoConnect &&
        autoConnectOnStart &&
        (!enforceConsent || consentReady) &&
        _startupStatusIdle &&
        !status.active &&
        !busy &&
        !cleanupIncomplete &&
        connectionCandidates(selected).isNotEmpty) {
      // No new policy or OS login registration: use the existing owner/budget
      // pipeline, which also checks native connectionBusy before activation.
      await _connect(startup: true);
    }
  }

  /// Включает каскад бесплатно (биллинг ещё не подключён) и запоминает выбор.
  Future<void> setCascadeUnlocked(bool value) =>
      withDocumentMutation(() => _setCascadeUnlocked(value));

  Future<void> _setCascadeUnlocked(bool value) async {
    if (cascadeUnlocked == value) return;
    cascadeUnlocked = value;
    await save();
    if (!_disposed) notifyListeners();
  }

  /// Запоминает итог проверки каскада для главного экрана.
  Future<void> setCascadeHealth({
    required bool ok,
    int? pingMs,
    String exitIpv6 = '',
    String exitIp = '',
    String checkedAt = '',
  }) async {
    cascadeHealthOk = ok;
    cascadeHealthPingMs = ok ? pingMs : null;
    cascadeExitIpv6 = ok ? exitIpv6 : '';
    cascadeExitIp = ok ? exitIp : '';
    cascadeCheckedAt = checkedAt;
    if (!ok) {
      cascadeBridgeCountry = cascadeCountryForAddress(cascadeBridge);
      cascadeExitCountry = cascadeCountryForAddress(cascadeExit);
    } else if (exitIp.isNotEmpty) {
      final derived = cascadeCountryForAddress(exitIp);
      cascadeExitCountry =
          _countryCode(cascadeExitCountry) ??
          (derived.isEmpty ? cascadeExitCountry : derived);
    }
    await save();
    if (!_disposed) notifyListeners();
  }

  /// Проверяет фактический выходной адрес с телефона. Возвращает адрес или
  /// `null`, если запрос не удался. Вызывающий сохраняет результат через
  /// [setCascadeHealth]; сеть не блокирует загрузку профиля.
  Future<String?> probeCascadeEgress() async {
    final http = HttpClient()..connectionTimeout = const Duration(seconds: 5);
    try {
      final request = await http
          .getUrl(Uri.https('api.ipify.org', '/'))
          .timeout(const Duration(seconds: 6));
      final response = await request.close().timeout(
        const Duration(seconds: 6),
      );
      if (response.statusCode != 200) return null;
      final text = await utf8
          .decoder
          .bind(response)
          .join()
          .timeout(const Duration(seconds: 6));
      final value = text.trim();
      if (value.isEmpty || value.length > 64) return null;
      final address = InternetAddress.tryParse(value);
      return address?.address;
    } catch (_) {
      return null;
    } finally {
      http.close(force: true);
    }
  }

  String? _countryCode(String value) {
    final code = value.trim().toUpperCase();
    return RegExp(r'^[A-Z]{2}$').hasMatch(code) ? code : null;
  }

  /// Сохраняет адреса каскада. Пустая строка допустима и означает «не настроено».
  Future<bool> setCascadeServers({String? bridge, String? exit}) =>
      withDocumentMutation(() => _setCascadeServers(bridge: bridge, exit: exit));

  Future<bool> _setCascadeServers({String? bridge, String? exit}) async {
    final nextBridge = bridge == null
        ? cascadeBridge
        : (validateCascadeBridge(bridge) ?? '');
    final nextExit = exit == null
        ? cascadeExit
        : (validateCascadeExit(exit) ?? '');
    if (bridge != null && bridge.trim().isNotEmpty && nextBridge.isEmpty)
      return false;
    if (exit != null && exit.trim().isNotEmpty && nextExit.isEmpty)
      return false;
    cascadeBridge = nextBridge;
    cascadeExit = nextExit;
    cascadeBridgeCountry = cascadeCountryForAddress(nextBridge);
    cascadeExitCountry = cascadeCountryForAddress(nextExit);
    await save();
    if (!_disposed) notifyListeners();
    return true;
  }

  /// Сохраняет ссылку MTProto-прокси. Пустая строка допустима и означает
  /// «не настроено». Некорректную ссылку не сохраняем и возвращаем `false` —
  /// экран показывает причину отказа.
  Future<bool> setMtprotoLink(String value) =>
      withDocumentMutation(() => _setMtprotoLink(value));

  Future<bool> _setMtprotoLink(String value) async {
    final text = value.trim();
    if (text.isEmpty) {
      if (mtprotoLink.isEmpty) return true;
      mtprotoLink = '';
      await save();
      if (!_disposed) notifyListeners();
      return true;
    }
    final parsed = parseMtprotoLink(text);
    if (parsed == null) return false;
    // Канонический вид: t.me-ссылка из буфера станет tg:// и наоборот,
    // повторное сохранение того же адреса не пишет файл.
    if (parsed.link == mtprotoLink) return true;
    mtprotoLink = parsed.link;
    await save();
    if (!_disposed) notifyListeners();
    return true;
  }

  /// Разрешение доменных правил в адреса. Один экземпляр на приложение:
  /// кэш на 10 минут живёт между подключениями и переподключениями.
  SplitDomainSync get splitSync => _splitSync ??= SplitDomainSync(
    resolver: SplitDomainResolver(
      lookup: domainLookup ?? const SystemDomainAddressLookup(),
    ),
    apply: (_) async =>
        throw StateError('Routing apply requires an owned lease'),
  );

  int _routingGeneration = 0;
  static int _routingSerial = 0;
  Map<String, String>? _routingLease;

  Future<void> _cancelRoutingLease(Map<String, String> lease) async {
    try {
      await native.invokeMethod<void>('routingCancel', lease);
    } catch (_) {
      // Local ownership is already revoked. A new native begin/save supersedes
      // this exact lease; activation also requires a current native receipt.
    }
  }

  void _invalidateRouting({bool discardCache = false}) {
    _routingGeneration++;
    _splitSync?.invalidate(discardCache: discardCache);
    final lease = _routingLease;
    _routingLease = null;
    if (lease != null) unawaited(_cancelRoutingLease(lease));
  }

  /// Читает доменные правила из нативной политики раздельного туннелирования.
  ///
  /// Нативная сторона — источник истины: экран «Маршрутизация» пишет правила
  /// туда, а поле [splitDomains] кэширует список для подключения. Старый
  /// native-слой без метода не ломает запуск: остаётся прежний список.
  Future<void> loadSplitDomains() async {
    if (!androidSettingsUi) return;
    final policy = await native.invokeMapMethod<String, dynamic>('routingGet');
    if (policy == null) return;
    final raw = (policy['domains'] as List?)?.whereType<String>() ?? const [];
    final valid = <String>[];
    for (final entry in raw) {
      final rule = normalizeDomainRule(entry);
      if (rule != null && !valid.contains(rule)) valid.add(rule);
    }
    splitDomains = valid;
  }

  /// Запоминает доменные правила, сохранённые экраном «Маршрутизация».
  ///
  /// Кэш разрешения сбрасывается: следующее подключение возьмёт свежие IP,
  /// а старые адреса нативная сторона уже заменила при сохранении правил.
  Future<void> setSplitDomains(List<String> domains) =>
      withDocumentMutation(() => _setSplitDomains(domains));

  Future<void> _setSplitDomains(List<String> domains) async {
    final next = <String>[];
    for (final entry in domains) {
      final rule = normalizeDomainRule(entry);
      if (rule == null) {
        throw FormatException(
          'Некорректный домен «$entry»: нужно имя без схемы и слэшей, '
          'например youtube.com или *.example.com',
        );
      }
      if (!next.contains(rule)) next.add(rule);
    }
    // The native editor may also have changed manual networks or mode while
    // leaving the domain list identical: revoke before the equality shortcut.
    _invalidateRouting(discardCache: true);
    if (listEquals(next, splitDomains)) return;
    splitDomains = next;
    splitResolvedAddresses = const [];
    if (directory != null) await save();
    if (!_disposed) notifyListeners();
  }

  /// Разрешает [splitDomains] в адреса и передаёт их нативной стороне.
  ///
  /// Вызывается перед подключением: правила применяются при активации
  /// туннеля. Повторное разрешение — не чаще раза в 10 минут (кэш
  /// [SplitDomainSync]); пустой список доменов очищает нативные адреса,
  /// поэтому устаревшие маршруты не остаются после правки правил.
  Future<void> syncSplitDomains({bool force = false}) async {
    if (!androidSettingsUi || !nativeTunnel) return;
    final generation = ++_routingGeneration;
    bool current() => !_disposed && generation == _routingGeneration;
    void requireCurrent() {
      if (!current()) throw StateError('Routing resolution superseded');
    }

    final previous = _routingLease;
    _routingLease = null;
    if (previous != null) unawaited(_cancelRoutingLease(previous));
    final token =
        '${DateTime.now().microsecondsSinceEpoch}-${++_routingSerial}';
    Map<String, String>? owned;
    try {
      final policy = await native.invokeMapMethod<String, dynamic>(
        'routingBegin',
        {'lease': token, 'resolutionId': force ? null : splitSync.resolutionId},
      );
      final revision = policy?['revision'];
      final resolutionId = policy?['resolutionId'];
      if (policy == null ||
          revision is! String ||
          revision.isEmpty ||
          resolutionId is! String ||
          resolutionId.isEmpty ||
          policy['reuseAllowed'] is! bool ||
          policy['lease'] != token) {
        throw StateError('Versioned routing policy unavailable');
      }
      final lease = {'revision': revision, 'lease': token};
      owned = lease;
      // A DOWN/new begin may have won while the channel reply was delayed.
      requireCurrent();
      _routingLease = lease;
      final rules = (policy['domains'] as List).cast<String>();
      final networks = (policy['networks'] as List).cast<String>();
      if (networks.length > 128) throw StateError('Routing capacity exceeded');
      final result = await splitSync.refresh(
        rules: rules,
        force: force || policy['reuseAllowed'] != true,
        resolutionId: resolutionId,
        reuseNativeResolution: policy['reuseAllowed'] as bool,
        addressCapacity: 128 - networks.length,
        isCurrent: current,
        applyCurrent: (addresses, validity) async {
          requireCurrent();
          await native.invokeMethod<void>('routingResolved', {
            ...lease,
            'networks': addresses,
            'validForMillis': validity.inMilliseconds,
            'resolutionId': resolutionId,
          });
          requireCurrent();
        },
      );
      requireCurrent();
      splitDomains = rules;
      splitResolvedAddresses = result;
    } catch (_) {
      if (owned != null) await _cancelRoutingLease(owned);
      if (current()) {
        _routingLease = null;
        splitResolvedAddresses = const [];
      }
      throw PlatformException(
        code: 'ROUTING',
        message: 'Не удалось полностью применить доменные правила. Проверьте DNS и лимиты маршрутов.',
      );
    }
  }

  final StoreMutationAdmission _documentAdmission = StoreMutationAdmission();
  bool get documentMutationPending =>
      _documentAdmission.busy || _recoveryInFlight;

  /// Count intent synchronously, before a queued body or native/vault await.
  /// Ordinary intents may queue concurrently (notably the C7 screen queue).
  /// The exclusive mode reservation cannot enter until every intent settles.
  Future<T> withDocumentMutation<T>(Future<T> Function() action) {
    late final StoreMutationIntent intent;
    try {
      intent = _documentAdmission.ordinary();
    } catch (error, stack) {
      return Future<T>.error(error, stack);
    }
    // Admission and settlement are both visible: the UI must disable controls
    // while a document write is in flight, not only after it succeeds.
    if (_productWriter != null && !_productWriter!.acceptsWrites) {
      intent.release();
      return Future<T>.error(const PolicyFailure(
        'POLICY_UNKNOWN',
        'The product store writer is closed',
      ));
    }
    // Ordinary admitted mutations may perform native config/delete/vault
    // effects after the document rename; the physical owner must cover those
    // too, not only policy publications.
    final hold = _beginWriterHold();
    if (!_disposed) notifyListeners();
    void settle() {
      _endWriterHold(hold);
      intent.release();
      if (!_disposed) notifyListeners();
    }

    try {
      return action().whenComplete(settle);
    } catch (error, stack) {
      settle();
      return Future<T>.error(error, stack);
    }
  }

  /// Minimal generic owned-mutation boundary for a future graph commit (a
  /// durable issuance journal is a separate owner). Acquire the ticket before
  /// the first await, pass it to the commit, and treat a [PublicationFailure]
  /// phase as WIRE-V2 §5 says: only `beforeRename` may compensate.
  StoreMutationIntent beginOwnedDocumentMutation() => _documentAdmission.ordinary();

  void releaseOwnedDocumentMutation(StoreMutationIntent ticket) => ticket.release();

  /// Commits one frozen document through an already-owned ticket. Refuses a
  /// revoked or FOREIGN ticket (issued by another Store) instead of writing
  /// behind a newer owner.
  Future<void> commitOwnedDocument(StoreMutationIntent ticket) =>
      _commitOwnedDocument(ticket);

  Future<void> _commitOwnedDocument(StoreMutationIntent ticket) async {
    if (!ticket.ownedBy(_documentAdmission) || !ticket.current) {
      throw const PolicyFailure(
        'POLICY_STALE',
        'The document mutation ticket does not belong to this store or was revoked',
      );
    }
    await _saveDocument(ticket: ticket);
  }

  /// Binds the cooperating product-store writer acquired by the real controller
  /// lifecycle. A second controller fails its own `acquire` before reaching
  /// here, so this is not an optional suggestion: once attached, every physical
  /// document IO runs through the owned handle.
  void attachProductWriter(ProductStoreWriterOwner writer) {
    _productWriter = writer;
    _storeIdentity ??= writer.storeIdentity;
    // The elevated helper is bound to the same canonical identity.
    DesktopEngine.storeIdentity = _storeIdentity;
  }

  ProductStoreWriterOwner? get productWriter => _productWriter;

  /// The controller lifecycle calls this when it could not acquire the product
  /// writer (second controller, unsupported path). The store stays readable and
  /// refuses every write with an honest blocker.
  void markProductWriterUnavailable(Object cause) {
    _writerUnavailable = cause;
    policyError = 'Another controller owns this product store';
    if (!_disposed) notifyListeners();
  }

  bool get productWriterUnavailable => _writerUnavailable != null;

  Future<T> _withProductWriter<T>(Future<T> Function() action) {
    final writer = _productWriter;
    if (writer == null) return action();
    if (!writer.acceptsWrites) {
      return Future<T>.error(const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure('POLICY_UNKNOWN', 'The product store writer is closed'),
      ));
    }
    return writer.io(action);
  }

  /// Every ordinary write carries its own admission ticket into the physical
  /// writer, so dispose/revocation is checked immediately before the rename.
  /// A plan-sensitive change under versioned policy is published as ONE new
  /// owned publication (fresh transaction/generation/receipt), never as an
  /// ordinary save with a stale receipt.
  Future<void> save() async {
    if (_disposed) throw StateError('Store is disposed');
    if (_policyChannel != null && !_policyInvalid) {
      if (await _planDiffersFromCommitted()) {
        await _publishPlanSensitive();
        return;
      }
    }
    if (_productWriter != null && !_productWriter!.acceptsWrites) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'The product store writer is closed',
      );
    }
    final intent = _documentAdmission.ordinary();
    final hold = _beginWriterHold();
    if (!_disposed) notifyListeners();
    try {
      await _saveDocument(ticket: intent);
    } finally {
      _endWriterHold(hold);
      intent.release();
      if (!_disposed) notifyListeners();
    }
  }

  /// True when the current document would derive a different plan than the one
  /// the live receipt describes (or versioned state exists without a receipt).
  Future<bool> _planDiffersFromCommitted() async {
    final snapshot = _committedPlan;
    if (snapshot == null) return policyReceiptRequired || _hasRawConnectionPolicy;
    try {
      // The native receipt binds the whole durable document, not only the
      // derived plan. A settings field that is stored in profiles.json (for
      // example the cascade addresses) therefore needs a fresh publication even
      // when the traffic plan itself is unchanged. Compare the document bodies
      // without the receipt, which every publication replaces.
      Map<String, Object?> withoutReceipt(Map<String, Object?> value) =>
          Map<String, Object?>.from(value)..remove('connectionPlanReceipt');
      final current = withoutReceipt(
        Map<String, Object?>.from(documentPayload()),
      );
      final committed = withoutReceipt(
        Map<String, Object?>.from(snapshot.document),
      );
      if (jsonEncode(current) != jsonEncode(committed)) return true;
      final plan = await _derivePlan(
        Map<String, dynamic>.from(documentPayload()),
        android: Platform.isAndroid,
      );
      return jsonEncode(plan.json) != jsonEncode(snapshot.plan);
    } catch (_) {
      return true; // let the publication surface the typed failure
    }
  }

  bool _planPublicationInFlight = false;

  /// Registers a physical writer hold for a whole native publication (begin →
  /// validate → commit). Dispose closes the writer only after it settles.
  void _requireWriterOpen() {
    final writer = _productWriter;
    if (writer != null && !writer.acceptsWrites) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'The product store writer is closed',
      );
    }
  }

  Completer<void>? _beginWriterHold() {
    final writer = _productWriter;
    if (writer == null) return null;
    final hold = Completer<void>();
    unawaited(writer.native(() => hold.future));
    return hold;
  }

  void _endWriterHold(Completer<void>? hold) {
    if (hold != null && !hold.isCompleted) hold.complete();
  }

  /// Publishes the current document as ONE owned versioned publication: fresh
  /// transaction/generation, durable receipt before READY, desktop validation
  /// preflight before begin/rename, and a product-writer hold across the native
  /// commit. Used by every plan-sensitive mutation (selection, graph, config,
  /// settings, routing) when the versioned capability exists.
  Future<void> _publishPlanSensitive() async {
    final channel = _policyChannel;
    if (channel == null || _policyInvalid) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'Versioned publication requires a policy capability',
      );
    }
    if (_planPublicationInFlight) {
      throw const PolicyFailure(
        'POLICY_BUSY',
        'Another policy publication is in flight',
      );
    }
    _planPublicationInFlight = true;
    _requireWriterOpen();
    // Admission starts now: cached receipt/plan/confirmation are no longer valid
    // for the new intent, even if the publication later fails before rename.
    final previousReceipt = _durableReceiptTransaction();
    _policyPublicationInFlight = true;
    _policyReceipt = null;
    _committedPlan = null;
    _documentConfirmed = false;
    _policyUnconfirmed = false;
    _notifySafe();
    StoreMutationIntent? ticket;
    Completer<void>? hold;
    try {
      ticket = _documentAdmission.ordinary();
      hold = _beginWriterHold();
      final transactionId = policyNonce();
      final generation = policyNonce();
      final document = Map<String, dynamic>.from(documentPayload());
      final plan = await _derivePlan(document, android: Platform.isAndroid);
      document['connectionPlanReceipt'] = {
        'schema': 1,
        'transactionId': transactionId,
        'planGeneration': generation,
        'plan': plan.json,
      };
      final snapshot = PublicationSnapshot(
        transactionId: transactionId,
        generation: generation,
        document: document,
        plan: plan.json,
      );
      Map<String, Object?>? validation;
      if (_desktopSession) {
        validation = await _buildValidation(
          plan.json,
          documentBytes: jsonEncode(document),
        );
      }
      final transaction = channel.transaction(snapshot);
      await transaction.begin();
      try {
        await _saveDocument(
          ticket: ticket,
          documentOverride: document,
          expectedDurableTransaction: previousReceipt,
        );
      } catch (error) {
        try {
          await transaction.block();
        } catch (_) {}
        _policyReconcileRequired = true;
        if (error is PublicationFailure &&
            error.phase != PublicationPhase.beforeRename) {
          _policyUnconfirmed = true;
        }
        _recordPolicyFailure(error);
        rethrow;
      }
      try {
        if (validation != null) {
          await _ensureDurableSnapshot(snapshot, ticket: ticket);
          await transaction.validate(validation);
        }
        await transaction.commit();
        await _verifyFreshNativeReady(transaction.channel, snapshot!);
        final receipt = transaction.channel.committed;
        if (receipt == null) {
          throw const PolicyFailure(
            'POLICY_UNKNOWN',
            'No ready receipt after commit',
          );
        }
        if (_disposed) {
          throw const PolicyFailure(
            'POLICY_STALE',
            'The store was disposed before the publication was adopted',
          );
        }
        adoptCommittedPolicy(snapshot: snapshot, receipt: receipt);
        await _ensureDurableSnapshot(snapshot, ticket: ticket);
        _policyUnconfirmed = false;
        _policyReconcileRequired = false;
        _clearPolicyFailure();
      } catch (error) {
        _policyUnconfirmed = true;
        _policyReconcileRequired = true;
        _recordPolicyFailure(error);
        throw error is PublicationFailure
            ? error
            : PublicationFailure(PublicationPhase.renamedNativeUnconfirmed, error);
      }
      if (!_disposed) notifyListeners();
    } finally {
      _planPublicationInFlight = false;
      _policyPublicationInFlight = false;
      _endWriterHold(hold);
      ticket?.release();
    }
  }
  /// Desktop: after a successful commit/reconcile ACK, require a FRESH native
  /// state proving exact CLEAN READY for this snapshot's six-field identity.
  /// The six-field ACK alone carries no resource proof, so [_adoptAck] stays
  /// conservative (Android keeps OWNED after ACK until a fresh clean state).
  Future<void> _verifyFreshNativeReady(
    PolicyChannel channel,
    PublicationSnapshot snapshot,
  ) async {
    if (!_desktopSession) return;
    PolicyNativeState state;
    try {
      state = await channel.queryState();
    } catch (error) {
      _policyReceipt = null;
      _committedPlan = null;
      _policyUnconfirmed = true;
      _policyReconcileRequired = true;
      throw PublicationFailure(
        PublicationPhase.renamedNativeUnconfirmed,
        error,
      );
    }
    final receipt = state.receipt;
    final exact = state.readyForAdmission &&
        receipt != null &&
        receipt.storeIdentity == channel.storeIdentity &&
        receipt.controllerNonce == channel.controllerNonce &&
        receipt.instanceNonce == channel.instanceNonce &&
        receipt.transactionId == snapshot.transactionId &&
        receipt.planGeneration == snapshot.generation;
    if (!exact) {
      _policyReceipt = null;
      _committedPlan = null;
      _policyUnconfirmed = true;
      _policyReconcileRequired = true;
      throw PublicationFailure(
        PublicationPhase.renamedNativeUnconfirmed,
        const PolicyFailure(
          'POLICY_UNKNOWN',
          'Fresh native state is not the exact CLEAN READY receipt for this publication',
        ),
      );
    }
  }
  Object? _durableReceiptTransaction() {
    final live = _committedPlan?.transactionId;
    if (live != null) return live;
    final raw = _rawConnectionPlanReceipt;
    if (raw is Map) return raw['transactionId'];
    return null;
  }

  /// True when the durable receipt transaction no longer equals [expected]
  /// (a newer publication won). A read failure is treated as a mismatch.
  Future<bool> _durableReceiptDiffers(Object? expected) async {
    if (directory == null) return false;
    try {
      final document = Map<String, dynamic>.from(
        jsonDecode(await File('${directory!.path}/profiles.json').readAsString())
            as Map,
      );
      final receipt = document['connectionPlanReceipt'];
      final current = receipt is Map ? receipt['transactionId'] : null;
      return current != expected;
    } catch (_) {
      return true;
    }
  }
  /// Aborts before the rename when another writer changed the durable plan
  /// receipt while this write was outstanding (stale overwrite guard).
  Future<void> _assertDurableReceiptUnchanged([Object? expectedOverride]) async {
    final expected = expectedOverride ?? _durableReceiptTransaction();
    if (expected == null || directory == null) return;
    Object? current;
    try {
      final document = Map<String, dynamic>.from(
        jsonDecode(await File('${directory!.path}/profiles.json').readAsString())
            as Map,
      );
      final receipt = document['connectionPlanReceipt'];
      if (receipt is Map) current = receipt['transactionId'];
    } catch (_) {
      return;
    }
    if (current == null) return;
    if (current != expected) {
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure(
          'POLICY_STALE',
          'The durable policy changed while this write was outstanding (expected  current )',
        ),
      );
    }
  }
  static const _ticketRevoked = PolicyFailure(
    'POLICY_STALE',
    'The document mutation ticket was revoked before the write could commit',
  );

  /// Throws before the rename when the owning ticket is no longer current, so a
  /// revoked/disposed ticket can never rename as the current owner. A rename
  /// already dispatched is not undone: its outcome stays "after rename".
  void _requireTicketBeforeRename(StoreMutationIntent? ticket) {
    if (ticket != null && !ticket.current) {
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        _ticketRevoked,
      );
    }
  }

  /// Save outcomes are typed: a failure before the rename may compensate only
  /// its own unchanged owner; a failure after the rename is a durable new
  /// document with unconfirmed native state, never a rollback.
  Future<void> _saveDocument({
    StoreMutationIntent? ticket,
    Map<String, Object?>? documentOverride,
    Object? expectedDurableTransaction,
    int? expectedPolicyEpoch,
  }) async {
    if (_writerUnavailable != null) {
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure(
          'POLICY_UNKNOWN',
          'This controller does not own the product store writer',
        ),
      );
    }
    if (!_storageHealthy) {
      throw StateError('Повреждённое хранилище защищено от перезаписи');
    }
    if (directory == null) throw StateError('Хранилище ещё не готово');
    final file = File('${directory!.path}/profiles.json');
    final tmp = File('${file.path}.tmp');
    final previous = _saveQueue;
    final completed = Completer<void>();
    _saveQueue = completed.future;
    var renamed = false;
    try {
      // Waited queue predecessors may have been long; ownership is rechecked
      // after the drain and again immediately before the rename dispatch.
      await previous;
      _requireTicketBeforeRename(ticket);
      if (expectedPolicyEpoch != null && _policyEpoch != expectedPolicyEpoch) {
        throw const PublicationFailure(
          PublicationPhase.beforeRename,
          PolicyFailure(
            'POLICY_STALE',
            'A newer publication won while this write was outstanding',
          ),
        );
      }
      await _assertDurableReceiptUnchanged(expectedDurableTransaction);
      // A queued ordinary write captures its document when its turn starts, not
      // when it was enqueued: a stale earlier snapshot must never overwrite a
      // newer publication. An explicit override is already frozen by its owner.
      final payload = jsonEncode(documentOverride ?? documentPayload());
      if (traceDocumentWrites) {
        documentWriteTrace.add(
          '${documentOverride != null ? 'frozen' : 'live'}:'
          '${RegExp(r'"transactionId":"([a-f0-9]{32})"').firstMatch(payload)?.group(1) ?? '-'}',
        );
      }
      try {
        await _withProductWriter(() async {
          _requireTicketBeforeRename(ticket);
          await tmp.writeAsString(payload, flush: true);
          _requireTicketBeforeRename(ticket);
          if (Platform.isLinux) {
            final permissions = await Process.run('chmod', ['600', tmp.path]);
            if (permissions.exitCode != 0) {
              throw StateError('Не удалось защитить файл профилей');
            }
          }
          // Durable CAS read first; fresh synchronous owner/ticket/epoch/dispose
          // guards immediately after that await and immediately before dispatch
          // of the rename, with no intervening await.
          await _assertDurableReceiptUnchanged(expectedDurableTransaction);
          _requireTicketBeforeRename(ticket);
          if (_disposed) {
            throw const PublicationFailure(
              PublicationPhase.beforeRename,
              PolicyFailure(
                'POLICY_STALE',
                'The store was disposed before the rename',
              ),
            );
          }
          if (expectedPolicyEpoch != null && _policyEpoch != expectedPolicyEpoch) {
            throw const PublicationFailure(
              PublicationPhase.beforeRename,
              PolicyFailure(
                'POLICY_STALE',
                'A newer publication won while this write was outstanding',
              ),
            );
          }
          await tmp.rename(file.path);
        });
        renamed = true;
      } catch (error) {
        if (error is PublicationFailure) rethrow;
        throw PublicationFailure(PublicationPhase.beforeRename, error);
      }
      try {
        // The published plan is derived from the same immutable bytes that were
        // just renamed, never from mutable Store state.
        await _publishDocumentPlan(payload);
      } catch (error) {
        throw PublicationFailure(
          PublicationPhase.renamedNativeUnconfirmed,
          error,
        );
      }
      if (renamed && ticket != null && !ticket.current) {
        // The document is already durable; a revoked ticket may not claim it.
        throw const PublicationFailure(
          PublicationPhase.renamedNativeUnconfirmed,
          _ticketRevoked,
        );
      }
      _documentConfirmed = true;
    } finally {
      completed.complete();
    }
  }

  /// The exact document body that would be renamed. Exposed for owned tests and
  /// for deriving plan bytes from one immutable capture.
  Map<String, Object?> documentPayload() => {
    'schema': 2,
    'legalRecord': legalRecord?.toJson(),
    'vpnDisclosure': vpnDisclosure,
    'language': AppLanguages.selected,
    'servers': servers.map((s) => s.toJson()).toList(),
    'users': users.map((u) => u.toJson()).toList(),
    'cascadeBridge': cascadeBridge,
    'cascadeUnlocked': cascadeUnlocked,
    'cascadeExit': cascadeExit,
    'cascadeHealthOk': cascadeHealthOk,
    'cascadeHealthPingMs': cascadeHealthPingMs,
    'cascadeExitIpv6': cascadeExitIpv6,
    'cascadeExitIp': cascadeExitIp,
    'cascadeCheckedAt': cascadeCheckedAt,
    'cascadeBridgeCountry': cascadeBridgeCountry,
    'cascadeExitCountry': cascadeExitCountry,
    'mtprotoLink': mtprotoLink,
    'splitDomains': splitDomains,
    'checkSite': checkSite,
    'siteCheckEnabled': siteCheckEnabled,
    'dnsServers': dnsServers,
    'autostart': autostart,
    'autoConnectOnStart': autoConnectOnStart,
    'allowScreenshots': allowScreenshots,
    'autoReconnect': autoReconnect,
    'priorityProtocol': priorityProtocol,
    'protocolTimeoutSeconds': protocolTimeoutSeconds,
    'selected': selectedId,
    'endpointCountries': endpointCountries,
    'profiles': profiles.map((p) => p.toJson()).toList(),
    // Invalid bytes are re-emitted verbatim: no silent repair, no erasure.
    'connectionPolicy': _hasRawConnectionPolicy
        ? _rawConnectionPolicy
        : connectionPolicy.toJson(),
    if (_policyReceipt != null && _committedPlan != null)
      'connectionPlanReceipt': {
        'schema': 1,
        'transactionId': _policyReceipt!.transactionId,
        'planGeneration': _policyReceipt!.planGeneration,
        'plan': _committedPlan!.plan,
      }
    else if (_rawConnectionPlanReceipt != null)
      'connectionPlanReceipt': _rawConnectionPlanReceipt,
  };


  Future<void> setLanguage(String? code) =>
      withDocumentMutation(() => _setLanguage(code));

  Future<void> _setLanguage(String? code) async {
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
    if (!_disposed) notifyListeners();
  }

  void log(String event) {
    events.insert(
      0,
      '${DateTime.now().toIso8601String().substring(11, 19)}  $event',
    );
    if (events.length > 100) events.removeLast();
  }

  Future<void> select(String id) =>
      withDocumentMutation(() => _select(id));

  Future<void> _select(String id) async {
    if (busy || status.active) {
      throw StateError('Сначала отключите текущий туннель');
    }
    selectedId = id;
    connectionCheck = null;
    await save();
    await refresh();
    if (!_disposed) notifyListeners();
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
  Future<void> importServer(String raw) =>
      withDocumentMutation(() => _importServer(raw));

  Future<void> _importServer(String raw) async {
    if (clientOnlyBuild) {
      throw const FormatException(
        'XIO Client принимает только клиентские профили, без доступа к серверу',
      );
    }
    if (raw.length > 100000 || !raw.startsWith('xio-server://')) {
      throw const FormatException('Некорректная конфигурация сервера');
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
      } catch (error) {
        if (!_restoreAllowed(error)) {
          _markPostRenameUnknown();
          rethrow;
        }
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
      if (!_disposed) notifyListeners();
    } catch (_) {
      throw const FormatException('Некорректная конфигурация сервера');
    }
  }

  Future<String> exportServer(ManagedServer server) async {
    final credentials = await CredentialVault.read(credentialId(server));
    if (credentials == null) throw StateError('Сначала подключитесь к серверу');
    return 'xio-server://${base64Url.encode(utf8.encode(jsonEncode({'schema': 1, 'server': server.toJson(), 'credentials': credentials})))}';
  }

  /// The same plan drives foreground connection and Android's background tile.
  List<Profile> connectionCandidates(Profile? initial) {
    if (serverMaintenance || initial == null) return [];
    final user = users
        .where((u) => u.profileIds.values.contains(initial.id))
        .firstOrNull;
    if (user?.revoked == true) return [];
    // Every build and platform keeps the same order: the selected profile
    // first, then protocol variants of the same endpoint (a fingerprint-blocked
    // protocol is replaced by another one), and only after them other profiles
    // allowed for this account.
    int preference(Profile p) =>
        protocolPreference(p.protocol, priorityProtocol, restricted: true);
    bool usable(Profile p) =>
        nativeProtocols.contains(p.protocol) &&
        (!nativeTunnel || supportedProtocols.contains(p.protocol));
    final pool =
        (clientOnlyBuild || user == null
                ? profiles
                : profiles
                      .where(
                        (p) =>
                            user.profileIds.values.contains(p.id) &&
                            nativeProtocols.contains(p.protocol),
                      )
                      .toList())
            .where(usable)
            .toList();
    final ordered = <Profile>[];
    void add(Profile p) {
      if (!ordered.any((x) => x.id == p.id)) ordered.add(p);
    }

    if (usable(initial)) add(initial);
    if (connectionPolicy == ConnectionPolicy.selectedOnly) return ordered;
    final variants =
        pool
            .where((p) => p.id != initial.id && p.endpoint == initial.endpoint)
            .toList()
          ..sort((a, b) => preference(a).compareTo(preference(b)));
    for (final p in variants) {
      add(p);
    }
    final fallbacks =
        pool
            .where((p) => p.id != initial.id && p.endpoint != initial.endpoint)
            .toList()
          ..sort((a, b) => preference(a).compareTo(preference(b)));
    for (final p in fallbacks) {
      add(p);
    }
    return ordered;
  }

  /// Publishes the Android plan for the current durable document. The payload is
  /// the immutable v2 plan derived from the same bytes that will be renamed.
  Future<void> saveNativePlan({
    bool? androidForTesting,
    Map<String, dynamic>? document,
  }) async {
    // Exercise the actual channel payload in host tests; production stays Android-only.
    if (!(androidForTesting ?? Platform.isAndroid)) return;
    // Invalid durable policy has no admissible plan: fail closed, do not guess.
    if (_policyInvalid) return;
    final plan = await _derivePlan(document ?? documentPayload(), android: true);
    await native.invokeMethod<void>('saveConnectionPlan', plan.bytes);
  }

  /// Reads the exact stored config bytes for the bounded candidate set. Missing
  /// or unreadable config stays `null`; the plan builder decides admissibility.
  Future<Map<String, String?>> _readConfigBytes(Iterable<String> ids) async {
    final result = <String, String?>{};
    for (final id in ids) {
      try {
        result[id] = await native.invokeMethod<String>('readConfig', {'id': id});
      } catch (_) {
        result[id] = null;
      }
    }
    return result;
  }

  bool get _desktopSession => Platform.isWindows || Platform.isLinux;

  /// Reads back the exact renamed document bytes and the exact stored config
  /// bytes for the plan's candidates, under the current writer ownership. The
  /// desktop helper re-hashes these independently (WIRE-V2 §8).
  Future<Map<String, Object?>> _buildValidation(
    Map<String, dynamic> plan, {
    String? documentBytes,
  }) async {
    final bytes = documentBytes ??
        await File('${directory!.path}/profiles.json').readAsString();
    final ids = (plan['ids'] as List).cast<String>();
    final configs = <String, String?>{};
    for (final id in ids) {
      try {
        configs[id] = await native.invokeMethod<String>('readConfig', {
          'id': id,
        });
      } catch (_) {
        configs[id] = null;
      }
    }
    return PolicyValidation.build(documentBytes: bytes, configs: configs);
  }

  /// Reads the durable document back and, if a queued/stale writer produced a
  /// different transaction, rewrites the frozen snapshot while this owner still
  /// holds the publication. Returns the exact bytes now on disk.
  Future<String> _ensureDurableSnapshot(
    PublicationSnapshot snapshot, {
    StoreMutationIntent? ticket,
  }) async {
    final file = File('${directory!.path}/profiles.json');
    var bytes = await file.readAsString();
    Object? storedTransaction;
    try {
      final document = Map<String, dynamic>.from(jsonDecode(bytes) as Map);
      final receipt = document['connectionPlanReceipt'];
      if (receipt is Map) storedTransaction = receipt['transactionId'];
    } catch (_) {}
    if (storedTransaction != snapshot.transactionId) {
      await _saveDocument(documentOverride: snapshot.document, ticket: ticket);
      bytes = await file.readAsString();
    }
    return bytes;
  }

  /// One plan derivation from one immutable document map.
  Future<ConnectionPlan> _derivePlan(
    Map<String, dynamic> document, {
    required bool android,
  }) async {
    Object? routing;
    if (android) {
      // Android publishes the typed routing snapshot. A missing snapshot is
      // POLICY_INVALID, never silently "all".
      routing = await native.invokeMapMethod<String, dynamic>('routingGet');
      if (routing == null) {
        throw const FormatException('Routing policy unavailable');
      }
    }
    final ids = <String>{
      for (final profile in connectionCandidates(selected)) profile.id,
    };
    final selectedIdentifier = selectedId;
    if (selectedIdentifier != null) ids.add(selectedIdentifier);
    final configs = await _readConfigBytes(ids);
    return ConnectionPlan.fromDocument(
      document,
      supportedProtocols: supportedProtocols,
      clientOnly: clientOnlyBuild,
      platform: android ? PolicyPlatform.android : PolicyPlatform.desktop,
      routing: android ? routing : null,
      config: (id) => configs[id],
    );
  }

  /// Publication of the plan that belongs to one already-reviewed document body.
  ///
  /// Versioned `policyBegin`/`policyCommit` publication is owned by the native
  /// worker (WIRE-V2 §3); until that envelope exists this sends the same
  /// immutable v2 plan through the existing plan channel, so a background
  /// consumer never sees a plan derived from mutable Store state.
  Future<void> _publishDocumentPlan(String payload) async {
    if (_policyInvalid) return;
    final document = Map<String, dynamic>.from(jsonDecode(payload) as Map);
    // Off-Android this is a no-op, but it stays on the same call path so an
    // owned embedder/test can observe the exact post-rename outcome.
    await saveNativePlan(document: document);
  }

  /// Discovers the versioned native policy capability once per session. Absence
  /// (old Android layer, missing/unreachable desktop helper) is not success: it
  /// leaves manual activation fail-closed while automatic stays on the legacy
  /// plan channel.
  Future<void> discoverPolicyCapability() async {
    if (_policyChannel != null) return;
    final identity = _storeIdentity;
    if (identity == null) return;
    final channel = PolicyChannel(
      invoke: (method, arguments) =>
          native.invokeMethod<Object?>(method, arguments),
      storeIdentity: identity,
      controllerNonce: policyNonce(),
    );
    try {
      await channel.discover();
    } catch (_) {
      return;
    }
    _policyChannel = channel;
    _policyCapability = true;
  }

  /// Adopts an acknowledged versioned publication. Only the owned publication
  /// path (or an owned test fixture) may call this; a receipt from another
  /// generation/transaction is POLICY_STALE.
  void adoptCommittedPolicy({
    required PublicationSnapshot snapshot,
    required PolicyReceipt receipt,
  }) {
    if (receipt.planGeneration != snapshot.generation ||
        receipt.transactionId != snapshot.transactionId ||
        _storeIdentity == null ||
        receipt.storeIdentity != _storeIdentity) {
      throw const PolicyFailure(
        'POLICY_STALE',
        'The receipt does not describe this store or plan generation',
      );
    }
    _policyReceipt = receipt;
    _committedPlan = snapshot;
    _policyCapability = true;
    _policyEpoch++;
    _documentConfirmed = true;
  }

  /// A blocked reconciliation drops every admission claim: the document may have
  /// been renamed, so no receipt is trusted until a new commit ACKs.
  void invalidateCommittedPolicy() {
    if (_policyReceipt == null && _committedPlan == null) return;
    _policyReceipt = null;
    _committedPlan = null;
    if (!_disposed) notifyListeners();
  }

  /// Settles a dead persisted pending transaction through the documented
  /// recovery protocol (WIRE-V2 §9): inspect native state, abort the SAME dead
  /// transaction (3-key request), re-inspect, and only then treat the lane as
  /// reusable. A STALE rejection is never interpreted as "safe to release".
  Future<PolicyNativeState?> settleNativePending() async {
    final channel = _policyChannel;
    if (channel == null) return null;
    var state = await channel.queryState();
    // Any observed non-READY/stale native identity synchronously clears the
    // confirmation: it must not survive an inspection that disproved it.
    final observedNotReady = state.state != 'ready';
    final staleTransaction = _policyReceipt != null &&
        state.transactionId != null &&
        state.transactionId != _policyReceipt!.transactionId;
    if (observedNotReady || staleTransaction) {
      _policyReceipt = null;
      _committedPlan = null;
      _policyReconcileRequired = true;
      if (!_disposed) notifyListeners();
    }
    if (!const {'pending', 'pendingUnknown'}.contains(state.phase)) {
      return state;
    }
    final dead = state.pendingTransaction ?? state.transactionId;
    if (dead == null) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'A pending publication has no transaction identity to settle',
      );
    }
    await channel.abort(transactionId: dead);
    state = await channel.queryState();
    if (const {'pending', 'pendingUnknown'}.contains(state.phase)) {
      throw const PolicyFailure(
        'POLICY_BUSY',
        'The native policy lane is still settling its previous publication',
      );
    }
    return state;
  }

  /// Reconciles the durable document with the versioned native envelope after a
  /// restart or a lost reply: the document is authoritative and native commits
  /// exactly it under a fresh transaction. Failure keeps manual activation
  /// fail-closed and visible; it never guesses a previous mode.
  Future<void> reconcilePolicy({
    Map<String, dynamic>? document,
    Duration wait = const Duration(seconds: 20),
    StoreMutationIntent? ticket,
    Object? expectedDurableTransaction,
    int? expectedPolicyEpoch,
  }) async {
    final channel = _policyChannel;
    if (channel == null || _policyInvalid || directory == null) return;
    _requireWriterOpen();
    // Admission starts before the first await: drop the cached confirmation.
    _policyPublicationInFlight = true;
    _policyReceipt = null;
    _committedPlan = null;
    _documentConfirmed = false;
    _policyUnconfirmed = false;
    _notifySafe();
    // A queued ordinary body must settle before this exclusive publication.
    await _saveQueue;
    if (_desktopSession && !channel.validationSupported) {
      // A desktop helper without the validation extension cannot prove the
      // bytes it is about to mark READY; never claim it.
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'The local helper cannot validate the policy document before READY',
      );
    }
    // A persisted pending lane must be settled before a fresh proposal; the
    // app never retries a dead transaction blindly.
    final settledNative = await settleNativePending();
    // CAS: pass the generation observed in the LAST settlement/query (after any
    // abort/reinspect). A fresh helper without one stays null; never fall back
    // to the durable/desired new generation. Android has no desktop CAS field,
    // but its journal still rejects a READY replacement without the exact
    // committed generation, so bind the generation from the native receipt.
    final reconcileExpectedGeneration = policyReconcileGeneration(
      settledNative,
      desktop: _desktopSession,
    );
    final normalExpectedGeneration = _desktopSession
        ? (settledNative?.casGeneration ?? settledNative?.receipt?.planGeneration)
        : null;
    // Hold the physical product writer for the WHOLE native publication, not
    // just the tmp/rename: dispose must not release it before native settles.
    final hold = _beginWriterHold();
    try {
      return await () async {
    final snapshotDocument = Map<String, dynamic>.from(
      document ?? documentPayload(),
    );
    final transactionId = policyNonce();
    final generation = policyNonce();
    final plan = await _derivePlan(
      snapshotDocument,
      android: Platform.isAndroid,
    );
    // Native READY requires a durable connectionPlanReceipt matching THIS
    // proposal (Android §4). The app owns that document write; native never
    // writes the app document.
    snapshotDocument['connectionPlanReceipt'] = {
      'schema': 1,
      'transactionId': transactionId,
      'planGeneration': generation,
      'plan': plan.json,
    };
    final snapshot = PublicationSnapshot(
      transactionId: transactionId,
      generation: generation,
      document: snapshotDocument,
      plan: plan.json,
    );
    final nativeReadyBound = _desktopSession &&
        settledNative != null &&
        settledNative.readyForAdmission &&
        channel.committed != null &&
        channel.committed!.storeIdentity == channel.storeIdentity &&
        channel.committed!.controllerNonce == channel.controllerNonce &&
        channel.committed!.instanceNonce == channel.instanceNonce;
    if (nativeReadyBound &&
        (settledNative!.casGeneration == null ||
            settledNative.casGeneration !=
                settledNative.receipt!.planGeneration)) {
      // READY must carry the same generation in CAS metadata and its own
      // nested receipt; a change is rejected BEFORE begin/rename.
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure(
          'POLICY_STALE',
          'The native READY identity/generation changed before recovery',
        ),
      );
    }
    final normalRoute = nativeReadyBound;
    final transaction = normalRoute
        ? channel.transaction(
            snapshot,
            expectedGeneration: normalExpectedGeneration,
          )
        : channel.reconciliation(
            snapshot,
            expectedGeneration: reconcileExpectedGeneration,
          );
    // Preflight the validation caps BEFORE the app rename: an oversized
    // document must not replace the old durable bytes or fence native READY.
    final validation = _desktopSession
        ? await _buildValidation(
            plan.json,
            documentBytes: jsonEncode(snapshotDocument),
          )
        : null;
    if (expectedPolicyEpoch != null && _policyEpoch != expectedPolicyEpoch) {
      // A newer publication was adopted after this recovery captured its
      // snapshot: abort BEFORE the rename so it cannot overwrite that winner.
      _policyReconcileRequired = false;
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure(
          'POLICY_STALE',
          'A newer policy publication won before this recovery could commit',
        ),
      );
    }
    if (_disposed) {
      throw const PublicationFailure(
        PublicationPhase.beforeRename,
        PolicyFailure(
          'POLICY_STALE',
          'The store was disposed during recovery',
        ),
      );
    }
    if (expectedDurableTransaction != null) {
      // CAS against the durable receipt captured before this recovery: a newer
      // publication that committed meanwhile must win, never be overwritten by
      // an older recovery snapshot.
      final currentFile = File('${directory!.path}/profiles.json');
      Object? durableTransaction;
      try {
        final current = Map<String, dynamic>.from(
          jsonDecode(await currentFile.readAsString()) as Map,
        );
        final receipt = current['connectionPlanReceipt'];
        if (receipt is Map) durableTransaction = receipt['transactionId'];
      } catch (_) {}
      if (durableTransaction != expectedDurableTransaction) {
        _policyReconcileRequired = false;
        throw const PublicationFailure(
          PublicationPhase.beforeRename,
          PolicyFailure(
            'POLICY_STALE',
            'The durable snapshot changed by a newer publication',
          ),
        );
      }
    }
    // Capture the ORIGINAL pre-BEGIN receipt/CAS and epoch. Nothing sampled
    // after the BEGIN await may legitimize a newer document for this reserved
    // transaction.
    final previousRawReceipt = _rawConnectionPlanReceipt;
    final originalDurableTransaction = expectedDurableTransaction ??
        (previousRawReceipt is Map
            ? previousRawReceipt['transactionId']
            : null);
    var begun = false;
    if (normalRoute) {
      // READY+CLEAN+bound receipt: use the normal begin→rename→validate→commit
      // route. Go's begin authority still fences current/cleanup races; any
      // STALE fails BEFORE the rename and the document stays untouched.
      try {
        await transaction.begin();
        begun = true;
      } catch (error) {
        _policyReconcileRequired = true;
        throw PublicationFailure(PublicationPhase.beforeRename, error);
      }
      // The BEGIN await is the race window: read the durable CAS FIRST, then
      // take fresh synchronous dispose/epoch/ticket guards immediately after
      // that await and before touching the raw receipt or renaming. A newer
      // winner must survive; abort the SAME reserved transaction.
      final durableChanged =
          await _durableReceiptDiffers(originalDurableTransaction);
      if (_disposed ||
          (expectedPolicyEpoch != null && _policyEpoch != expectedPolicyEpoch) ||
          durableChanged) {
        try {
          await transaction.block();
        } catch (_) {}
        _policyReconcileRequired = true;
        throw const PublicationFailure(
          PublicationPhase.beforeRename,
          PolicyFailure(
            'POLICY_STALE',
            'A newer publication superseded the reserved recovery transaction',
          ),
        );
      }
    }
    // Ordinary saves that slip in before this publication ACKs must re-emit the
    // same new receipt instead of the previous one.
    _rawConnectionPlanReceipt = snapshotDocument['connectionPlanReceipt'];
    try {
      await _saveDocument(
        documentOverride: snapshotDocument,
        ticket: ticket,
        expectedDurableTransaction: originalDurableTransaction,
        expectedPolicyEpoch: expectedPolicyEpoch,
      );
    } catch (error) {
      if (begun) {
        try {
          await transaction.block();
        } catch (_) {}
      }
      final durableChangedNow =
          await _durableReceiptDiffers(originalDurableTransaction);
      final epochChangedNow =
          expectedPolicyEpoch != null && _policyEpoch != expectedPolicyEpoch;
      if ((error is! PublicationFailure ||
              error.phase == PublicationPhase.beforeRename) &&
          !durableChangedNow &&
          !epochChangedNow &&
          !_disposed) {
        // Restore the old raw receipt only when no newer winner/epoch/dispose
        // exists; a stale abort must not clobber newer authority in memory.
        _rawConnectionPlanReceipt = previousRawReceipt;
      }
      _policyReconcileRequired = true;
      throw error is PublicationFailure
          ? error
          : PublicationFailure(PublicationPhase.beforeRename, error);
    }
    if (validation != null) {
      try {
        // Durability is proven by the readback; the validated bytes are the
        // exact frozen snapshot this reconcile commits.
        await _ensureDurableSnapshot(snapshot, ticket: ticket);
        await transaction.validate(validation);
      } catch (error) {
        try {
          await transaction.block();
        } catch (_) {}
        _policyReconcileRequired = true;
        throw PublicationFailure(
          PublicationPhase.renamedNativeUnconfirmed,
          error,
        );
      }
    }
    try {
      await transaction.commit().timeout(wait);
    } catch (error) {
      try {
        // The native lane keeps physical ownership until it can ACK a block.
        await transaction.block();
      } catch (_) {}
      _policyReceipt = null;
      _committedPlan = null;
      _policyReconcileRequired = true;
      // A rejected reconcile may have persisted BLOCKED (recoverable) or may
      // still own the lane; inspect instead of assuming a safe release.
      final settled = await _policyChannel!.queryState();
      if (const {'pending', 'pendingUnknown'}.contains(settled.phase)) {
        throw const PolicyFailure(
          'POLICY_BUSY',
          'The native policy lane still owns its previous publication',
        );
      }
      throw PublicationFailure(
        PublicationPhase.renamedNativeUnconfirmed,
        error,
      );
    }
    await _verifyFreshNativeReady(channel, snapshot);
    final receipt = channel.committed;
    if (receipt == null) {
      _policyReconcileRequired = true;
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'No ready receipt after reconciliation',
      );
    }
    if (_disposed) {
      throw const PublicationFailure(
        PublicationPhase.renamedNativeUnconfirmed,
        PolicyFailure(
          'POLICY_STALE',
          'The store was disposed before reconciliation was adopted',
        ),
      );
    }
    adoptCommittedPolicy(snapshot: snapshot, receipt: receipt);
    _clearPolicyFailure();
    await _ensureDurableSnapshot(snapshot, ticket: ticket);
    _policyReconcileRequired = false;
    _policyUnconfirmed = false;
    _clearPolicyFailure();
    if (!_policyInvalid) policyError = null;
    _notifySafe();
      }();
    } finally {
      _endWriterHold(hold);
      _policyPublicationInFlight = false;
      _notifySafe();
    }
  }

  /// Activation attachment for exactly one candidate, or the untouched legacy
  /// automatic path on a pristine document (WIRE-V2 §2.1).
  Map<String, Object?> _activationArguments(Profile candidate) {
    final receipt = _policyReceipt;
    final snapshot = _committedPlan;
    if (receipt != null && snapshot != null) {
      return PolicyActivation.arguments(
        snapshot: snapshot,
        candidateId: candidate.id,
        receipt: receipt,
        receiptRequired: true,
        platform: (androidActivationForTesting ?? Platform.isAndroid)
            ? PolicyPlatform.android
            : PolicyPlatform.desktop,
      );
    }
    if (connectionPolicy == ConnectionPolicy.selectedOnly && _policyCapability) {
      throw const PolicyFailure(
        'POLICY_UNSUPPORTED',
        'Manual mode requires a reconciled committed plan',
      );
    }
    // Pristine legacy document, or automatic before the first versioned ACK:
    // the existing automatic path is untouched and is never presented as manual.
    return const {};
  }

  /// Idle-only manual/automatic switch through the same single-snapshot
  /// publication as [saveConnectionSettings] (one owner, one rename, one plan).
  Future<void> setConnectionPolicy(ConnectionPolicy value) async {
    if (_disposed) throw StateError('Store is disposed');
    final blocker = _modeSetterBlocker();
    if (blocker != null) throw _modeFailure(blocker);
    if (_connectionPolicy == value) return;
    await _publishSettingsSnapshot(policy: value);
  }

  /// Explicit recovery for a preserved but malformed durable policy. Never
  /// called implicitly: unrelated saves keep the invalid bytes. The repaired
  /// snapshot is only confirmed after its own rename (and, when the native
  /// layer supports versioned policy, after an exact ACK).
  Future<void> repairConnectionPolicy(ConnectionPolicy value) async {
    if (_disposed) throw StateError('Store is disposed');
    if (!_policyInvalid) {
      await setConnectionPolicy(value);
      return;
    }
    if (!ready) throw _modeFailure('loading');
    if (busy ||
        status.active ||
        _desired ||
        reconnecting ||
        cleanupIncomplete ||
        _connectRound != null ||
        _retry != null ||
        _watchdog != null ||
        _nativeRecoveryLease != null) {
      throw _modeFailure('busy');
    }
    late final StoreMutationIntent ticket;
    try {
      ticket = _documentAdmission.policy();
    } catch (_) {
      throw _modeFailure('persistence');
    }
    final previousPolicy = _connectionPolicy;
    final previousRaw = _rawConnectionPolicy;
    final previousHas = _hasRawConnectionPolicy;
    final previousInvalid = _policyInvalid;
    final previousMessage = policyError;
    _connectionPolicy = value;
    _rawConnectionPolicy = value.toJson();
    _hasRawConnectionPolicy = true;
    _rawConnectionPlanReceipt = null;
    _policyReceipt = null;
    _committedPlan = null;
    _policyUnconfirmed = false;
    if (!_disposed) notifyListeners();
    try {
      await _saveDocument(ticket: ticket);
    } catch (error) {
      _connectionPolicy = previousPolicy;
      _rawConnectionPolicy = previousRaw;
      _hasRawConnectionPolicy = previousHas;
      _policyInvalid = previousInvalid;
      policyError = previousMessage;
      rethrow;
    } finally {
      ticket.release();
    }
    // Durable bytes are now validated and renamed; native safety is separate.
    _policyInvalid = false;
    policyError = null;
    if (_policyCapability) {
      try {
        await reconcilePolicy();
      } catch (_) {
        _policyReconcileRequired = true;
        policyError = 'Saved policy could not be reconciled with the engine';
      }
    }
    if (!_disposed) notifyListeners();
  }

  /// Bounded retry for a pending/unconfirmed publication or a required native
  /// reconciliation. Re-reads the durable document, validates it, and only
  /// clears the blocker after the rename is proven (and an exact native ACK
  /// when versioned policy exists). No error-free path clears it by itself.
  Future<void> retryPolicyReconciliation() async {
    if (_disposed) throw StateError('Store is disposed');
    if (_policyInvalid) {
      throw const PolicyFailure(
        'POLICY_INVALID',
        'Preserved malformed policy requires an explicit repair',
      );
    }
    final dir = directory;
    if (dir == null) throw _modeFailure('loading');
    // Synchronously capture the publication epoch and take the physical writer
    // hold BEFORE the first read/await. The recovery must not take the
    // Store-exclusive admission (a newer mode publication is allowed to win);
    // it revalidates the epoch and the durable receipt immediately before the
    // rename and aborts pre-rename if either changed.
    final epoch = _policyEpoch;
    _recoveryInFlight = true;
    if (!_disposed) notifyListeners();
    Completer<void>? hold;
    try {
      hold = _beginWriterHold();
      final file = File('${dir.path}/profiles.json');
      if (!await file.exists()) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'No durable document to reconcile',
      );
    }
    final Map<String, dynamic> durable;
    try {
      durable = Map<String, dynamic>.from(
        jsonDecode(await file.readAsString()) as Map,
      );
    } catch (_) {
      throw const PolicyFailure(
        'POLICY_UNKNOWN',
        'The durable document could not be read',
      );
    }
      // Re-validate the actual durable state, not the in-memory claim.
      if (durable.containsKey('connectionPolicy')) {
        ConnectionPolicy.parse(durable['connectionPolicy']);
      }
      Object? durableTransaction;
      if (durable.containsKey('connectionPlanReceipt')) {
        durableTransaction =
            DocumentPlanReceipt.parse(durable['connectionPlanReceipt'])
                .transactionId;
      }
      if (_policyCapability) {
        try {
          await reconcilePolicy(
            document: durable,
            expectedDurableTransaction: durableTransaction,
            expectedPolicyEpoch: epoch,
          );
        } catch (error) {
          _recordPolicyFailure(error);
          rethrow;
        }
      }
      _policyUnconfirmed = false;
      _policyReconcileRequired = false;
      _clearPolicyFailure();
      policyError = null;
      if (!_disposed) notifyListeners();
    } finally {
      _recoveryInFlight = false;
      _endWriterHold(hold);
      if (!_disposed) notifyListeners();
    }
  }

  /// Publishes one frozen settings+mode snapshot under one exclusive owner.
  Future<void> _publishSettingsSnapshot({
    String? site,
    String? priority,
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    required ConnectionPolicy policy,
  }) async {
    late final StoreMutationIntent ticket;
    try {
      ticket = _documentAdmission.policy();
    } catch (_) {
      throw _modeFailure('persistence');
    }
    _requireWriterOpen();
    _policyUnconfirmed = false;
    final versioned = _policyChannel != null;
    if (versioned) {
      // Admission starts before any await: no cached confirmation survives it.
      _policyPublicationInFlight = true;
      _policyReceipt = null;
      _committedPlan = null;
      _documentConfirmed = false;
    }
    final hold = _beginWriterHold();
    _notifySafe(); // acquisition: UI disables controls immediately
    try {
      // Drain a queued ordinary body that has not started yet: after the
      // exclusive owner is taken, its late write must not land behind ours.
      await _saveQueue;
      await _applySettings(
        site: site,
        priority: priority,
        timeoutSeconds: timeoutSeconds,
        siteCheck: siteCheck,
        reconnect: reconnect,
        policy: policy,
        ticket: ticket,
        versioned: versioned,
      );
    } catch (error) {
      _recordPolicyFailure(error);
      rethrow;
    } finally {
      ticket.release();
      _endWriterHold(hold);
      _policyPublicationInFlight = false;
      _notifySafe(); // settlement
    }
  }


  Future<void> importConnection(String raw, {String name = ''}) =>
      withDocumentMutation(() => _importConnection(raw, name: name));

  Future<void> _importConnection(String raw, {String name = ''}) async {
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

  Future<void> addExtended(String name, String raw) =>
      withDocumentMutation(() => _addExtended(name, raw));

  Future<void> _addExtended(String name, String raw) async {
    final parsed = ExtendedProfile.parse(raw);
    if (!nativeTunnel || !nativeProtocols.contains(parsed.protocol)) {
      throw UnsupportedError(
        'Клиентский движок этого протокола ещё не интегрирован',
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
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      profiles.removeWhere((p) => p.id == id);
      selectedId = previous;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    if (!_disposed) notifyListeners();
  }

  Future<void> addRivet(String name, String raw) =>
      withDocumentMutation(() => _addRivet(name, raw));

  Future<void> _addRivet(String name, String raw) async {
    if (!nativeTunnel) {
      throw UnsupportedError('The platform tunnel engine is unavailable');
    }
    final parsed = RivetProfile.parse(raw);
    final id =
        '${parsed.protocol == 'rivet-h3' ? 'rvh' : 'rvs'}${DateTime.now().microsecondsSinceEpoch}';
    final previous = selectedId;
    await native.invokeMethod('saveConfig', {
      'id': id,
      'config': parsed.encoded,
    });
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
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      profiles.removeWhere((p) => p.id == id);
      selectedId = previous;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    if (!_disposed) notifyListeners();
  }

  Future<void> addWireGuard(
    String name,
    String raw, {
    bool amnezia = true,
  }) => withDocumentMutation(
    () => _addWireGuard(name, raw, amnezia: amnezia),
  );

  Future<void> _addWireGuard(
    String name,
    String raw, {
    bool amnezia = true,
  }) async {
    if (!nativeTunnel) {
      throw UnsupportedError('The platform tunnel engine is unavailable');
    }
    if (!amnezia) {
      throw const FormatException('WireGuard удалён из этой версии XIO');
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
            ? AppLanguages.text('Мой ${amnezia ? 'AmneziaWG' : 'WireGuard'}')
            : name.trim(),
        protocol: protocol,
        endpoint: parsed.endpoint,
      ),
    );
    if (!status.active) selectedId = id;
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      profiles.removeWhere((p) => p.id == id);
      selectedId = previousId;
      await native.invokeMethod('deleteConfig', {'id': id});
      rethrow;
    }
    log('Профиль $protocol добавлен');
    if (!_disposed) notifyListeners();
  }

  /// Publishes the connection settings and, when [policy] is supplied, the
  /// durable mode as ONE frozen snapshot under ONE owned admission: a single
  /// rename and a single plan identity, never two sequential publications.
  /// Omitting [policy] keeps the pre-existing settings-only semantics.
  Future<void> saveConnectionSettings(
    String site,
    String priority, {
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    ConnectionPolicy? policy,
  }) async {
    if (timeoutSeconds != null && (timeoutSeconds < 5 || timeoutSeconds > 60)) {
      throw const FormatException('Время ожидания: от 5 до 60 секунд');
    }
    final normalized = validateCheckSite(site).toString();
    if (!nativeProtocols.contains(priority)) {
      throw const FormatException('Протокол пока не поддерживается');
    }
    if (policy != null) {
      final blocker = _modeSetterBlocker();
      if (blocker != null) throw _modeFailure(blocker);
      if (policy == _connectionPolicy &&
          normalized == checkSite &&
          priority == priorityProtocol &&
          (timeoutSeconds ?? protocolTimeoutSeconds) ==
              protocolTimeoutSeconds &&
          (siteCheck ?? siteCheckEnabled) == siteCheckEnabled &&
          (reconnect ?? autoReconnect) == autoReconnect) {
        return;
      }
      await _publishSettingsSnapshot(
        site: normalized,
        priority: priority,
        timeoutSeconds: timeoutSeconds,
        siteCheck: siteCheck,
        reconnect: reconnect,
        policy: policy,
      );
      return;
    }
    if (_policyChannel != null) {
      // Plan-sensitive settings under versioned policy are ONE new owned
      // publication with a fresh receipt/generation; the old receipt must never
      // stay valid for changed content.
      await _publishSettingsSnapshot(
        policy: _connectionPolicy,
        site: normalized,
        priority: priority,
        timeoutSeconds: timeoutSeconds,
        siteCheck: siteCheck,
        reconnect: reconnect,
      );
      return;
    }
    await withDocumentMutation(
      () => _applySettings(
        site: normalized,
        priority: priority,
        timeoutSeconds: timeoutSeconds,
        siteCheck: siteCheck,
        reconnect: reconnect,
      ),
    );
  }

  Future<void> _applySettings({
    String? site,
    String? priority,
    int? timeoutSeconds,
    bool? siteCheck,
    bool? reconnect,
    ConnectionPolicy? policy,
    StoreMutationIntent? ticket,
    bool versioned = false,
  }) async {
    final oldSite = checkSite, oldPriority = priorityProtocol;
    final oldTimeout = protocolTimeoutSeconds;
    final oldSiteCheck = siteCheckEnabled;
    final oldReconnect = autoReconnect;
    final oldPolicy = _connectionPolicy;
    final oldRaw = _rawConnectionPolicy;
    final oldHasRaw = _hasRawConnectionPolicy;
    final oldRawReceipt = _rawConnectionPlanReceipt;
    final oldDocumentConfirmed = _documentConfirmed;
    void restore() {
      checkSite = oldSite;
      priorityProtocol = oldPriority;
      protocolTimeoutSeconds = oldTimeout;
      siteCheckEnabled = oldSiteCheck;
      autoReconnect = oldReconnect;
      _connectionPolicy = oldPolicy;
      _rawConnectionPolicy = oldRaw;
      _hasRawConnectionPolicy = oldHasRaw;
      _rawConnectionPlanReceipt = oldRawReceipt;
      _documentConfirmed = oldDocumentConfirmed;
    }

    if (site != null) checkSite = site;
    if (priority != null) priorityProtocol = priority;
    protocolTimeoutSeconds = timeoutSeconds ?? protocolTimeoutSeconds;
    siteCheckEnabled = siteCheck ?? siteCheckEnabled;
    autoReconnect = reconnect ?? autoReconnect;
    if (policy != null) {
      _connectionPolicy = policy;
      _rawConnectionPolicy = policy.toJson();
      _hasRawConnectionPolicy = true;
    }
    connectionCheck = null;

    // A versioned publication fences native READY at `begin`: from this point
    // the previous confirmation is gone even if the document write never
    // happens. Only an ACK for the new generation restores native confirmation.
    PublicationSnapshot? snapshot;
    PolicyChannelTransaction? transaction;
    Map<String, Object?>? validation;
    Object? previousReceipt;
    if (versioned) {
      final channel = _policyChannel;
      if (channel == null) {
        restore();
        throw _modeFailure('reconcileRequired');
      }
      if (_desktopSession && !channel.validationSupported) {
        restore();
        throw const PolicyFailure(
          'POLICY_UNSUPPORTED',
          'The local helper cannot validate the policy document before READY',
        );
      }
      previousReceipt = _durableReceiptTransaction();
      _policyReceipt = null;
      _committedPlan = null;
      _documentConfirmed = false;
      _policyUnconfirmed = false;
      _policyReconcileRequired = false;
      if (!_disposed) notifyListeners();
      var begun = false;
      try {
        final transactionId = policyNonce();
        final generation = policyNonce();
        final document = Map<String, dynamic>.from(documentPayload());
        final plan = await _derivePlan(
          document,
          android: Platform.isAndroid,
        );
        // The durable receipt written by this rename must describe exactly the
        // transaction native is about to commit/reconcile (Android 4).
        document['connectionPlanReceipt'] = {
          'schema': 1,
          'transactionId': transactionId,
          'planGeneration': generation,
          'plan': plan.json,
        };
        snapshot = PublicationSnapshot(
          transactionId: transactionId,
          generation: generation,
          document: document,
          plan: plan.json,
        );
        // Preflight the desktop validation caps BEFORE begin/rename: an
        // oversized document must fail here, leaving the old document and the
        // native READY authority untouched, with an explicit UI reason.
        if (_desktopSession) {
          validation = await _buildValidation(
            plan.json,
            documentBytes: jsonEncode(document),
          );
        }
        // Any ordinary save that slips in before this publication commits must
        // re-emit the SAME new receipt, never the previous one.
        _rawConnectionPlanReceipt = document['connectionPlanReceipt'];
        transaction = channel.transaction(snapshot);
        await transaction.begin();
        begun = true;
      } catch (error) {
        // Only a started begin may have fenced native READY.
        if (begun) _policyReconcileRequired = true;
        restore();
        rethrow;
      }
    }

    try {
      await _saveDocument(
        ticket: ticket,
        documentOverride: snapshot?.document,
        expectedDurableTransaction: previousReceipt,
      );
    } catch (error) {
      final afterRename = error is PublicationFailure &&
          error.phase != PublicationPhase.beforeRename;
      if (!afterRename) restore();
      if (transaction != null) {
        try {
          // The native lane keeps physical ownership until it ACKs a block.
          await transaction.block();
        } catch (_) {}
        _policyReconcileRequired = true;
      }
      if (afterRename) {
        // The rename may already be durable: keep the new in-memory snapshot and
        // say the publication is unconfirmed instead of restoring old fields.
        _policyUnconfirmed = true;
        policyError = 'The connection settings save did not finish';
        if (!_disposed) notifyListeners();
      }
      rethrow;
    }

    if (transaction != null) {
      try {
        if (_desktopSession && validation != null) {
          // Durability is proven by the readback; the validated bytes are the
          // exact frozen snapshot this transaction commits.
          await _ensureDurableSnapshot(snapshot!);
          await transaction.validate(validation);
        }
        await transaction.commit();
        await _verifyFreshNativeReady(transaction.channel, snapshot!);
        final receipt = transaction.channel.committed;
        if (receipt == null) {
          throw const PolicyFailure(
            'POLICY_UNKNOWN',
            'No ready receipt after commit',
          );
        }
        if (_disposed) {
          throw const PolicyFailure(
            'POLICY_STALE',
            'The store was disposed before the publication was adopted',
          );
        }
        adoptCommittedPolicy(snapshot: snapshot!, receipt: receipt);
        await _ensureDurableSnapshot(snapshot);
        _policyReconcileRequired = false;
        _policyUnconfirmed = false;
        _clearPolicyFailure();
      } catch (error) {
        _recordPolicyFailure(error);
        _policyUnconfirmed = true;
        _policyReconcileRequired = true;
        policyError = 'The connection settings save did not finish';
        if (!_disposed) notifyListeners();
        throw PublicationFailure(
          PublicationPhase.renamedNativeUnconfirmed,
          error,
        );
      }
    } else {
      _policyUnconfirmed = false;
    }
    _documentConfirmed = true;
    if (!_policyInvalid) policyError = null;
    if (!_disposed) notifyListeners();
  }

  /// Сохраняет выбранный набор сторонних DNS-резолверов.
  ///
  /// [servers] проверяется как IPv4/IPv6/домен, не больше двух адресов. Пустой
  /// список недопустим: профиль без DNS отдаёт имена системному резолверу.
  Future<void> setDnsServers(List<String> servers) =>
      withDocumentMutation(() => _setDnsServers(servers));

  Future<void> _setDnsServers(List<String> servers) async {
    final normalized = validateDnsServers(servers);
    final previous = dnsServers;
    dnsServers = normalized;
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      dnsServers = previous;
      rethrow;
    }
    if (!_disposed) notifyListeners();
  }

  /// Автозапуск после загрузки устройства. На Android переключает
  /// BOOT_COMPLETED-ресивер; сбой канала не отменяет сохранённый выбор — он
  /// применится при следующем запуске.
  Future<void> setAutostart(bool value) =>
      withDocumentMutation(() => _setAutostart(value));

  Future<void> _setAutostart(bool value) async {
    if (autostart == value) return;
    final previous = autostart;
    autostart = value;
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      autostart = previous;
      rethrow;
    }
    if (Platform.isAndroid) {
      try {
        await native.invokeMethod<void>('setAutostart', {'enabled': value});
      } catch (_) {
        // Канал есть только в мобильной сборке; флаг уже сохранён.
      }
    }
    if (!_disposed) notifyListeners();
  }

  /// Автоподключение после запуска приложения.
  Future<void> setAutoConnectOnStart(bool value) =>
      withDocumentMutation(() => _setAutoConnectOnStart(value));

  Future<void> _setAutoConnectOnStart(bool value) async {
    // Even a no-op explicit choice supersedes persisted startup intent.
    _startupIntentEpoch++;
    final startupRound = _desktopStartupRound;
    if (startupRound != null && identical(startupRound, _connectRound)) {
      _desired = false;
      startupRound.cancel();
    }
    if (autoConnectOnStart == value) return;
    final previous = autoConnectOnStart;
    autoConnectOnStart = value;
    try {
      await save();
    } catch (error) {
      if (!_restoreAllowed(error)) {
        _markPostRenameUnknown();
        rethrow;
      }
      autoConnectOnStart = previous;
      rethrow;
    }
    if (Platform.isAndroid) {
      try {
        await native.invokeMethod<void>('setAutoConnectOnStart', {
          'enabled': value,
        });
      } catch (_) {
        // Канал есть только в мобильной сборке; флаг уже сохранён.
      }
    }
    if (!_disposed) notifyListeners();
  }

  /// Serialize preference writes AND native requests. A superseded ACK must
  /// never describe a newer selection. Reapplications read the preference only
  /// when their turn starts, not when a secret dialog enqueues them.
  Future<void> _queueScreenSecurity(
    Future<void> Function(int revision) action,
  ) {
    final revision = ++_screenSecurityRevision;
    _screenSecurityPending++;
    screenSecurityEnabled = null;
    final result = _screenSecurityQueue.then((_) async {
      if (_disposed) {
        _screenSecurityPending--;
        return;
      }
      if (!_disposed) notifyListeners();
      try {
        await action(revision);
      } finally {
        _screenSecurityPending--;
        if (!_disposed) notifyListeners();
      }
    });
    // Keep failures visible to the setter's caller, without poisoning the queue.
    _screenSecurityQueue = result.then<void>((_) {}, onError: (Object _) {});
    return result;
  }

  Future<bool> _ackScreenSecurity(int revision) async {
    // The store may have been disposed while its preference write was pending.
    // Never let that obsolete owner alter a replacement store's window.
    if (_disposed) return false;
    final enabled = !allowScreenshots;
    try {
      // Android's existing contract is success(null), after addFlags/clearFlags.
      await native.invokeMethod<void>('secureScreen', {'enabled': enabled});
      if (!_disposed && revision == _screenSecurityRevision) {
        screenSecurityEnabled = enabled;
      }
      return true;
    } catch (_) {
      if (!_disposed && revision == _screenSecurityRevision) {
        screenSecurityEnabled = null;
      }
      return false;
    }
  }

  Future<void> setAllowScreenshots(bool value) =>
      withDocumentMutation(() => _setAllowScreenshots(value));

  Future<void> _setAllowScreenshots(bool value) {
    if (!screenSecuritySupported) {
      return Future<void>.error(
        StateError(
          'На этой платформе приложение не блокирует снимки и запись экрана.',
        ),
      );
    }
    return _queueScreenSecurity((revision) async {
      final previous = allowScreenshots;
      allowScreenshots = value;
      try {
        await save();
        if (_disposed) return;
        screenSecurityPreferenceKnown = true;
      } catch (_) {
        if (_disposed) return;
        allowScreenshots = previous;
        // save() can fail AFTER rename (native-plan synchronization). Restore
        // disk too; if that also fails, do not claim the preference is saved.
        try {
          await save();
          if (_disposed) return;
          screenSecurityPreferenceKnown = true;
        } catch (_) {
          if (_disposed) return;
          screenSecurityPreferenceKnown = false;
        }
        await _ackScreenSecurity(revision);
        if (_disposed) return;
        throw StateError('Не удалось сохранить настройку');
      }
      final acknowledged = await _ackScreenSecurity(revision);
      if (_disposed) return;
      if (!acknowledged) {
        // Preserve the user's saved opt-in; retries/startup will reapply it.
        throw StateError('Не удалось подтвердить настройку снимков экрана.');
      }
    });
  }

  /// Startup and secret dialogs safely reapply the global preference. Failures
  /// are published as unknown, not thrown into fire-and-forget lifecycle code.
  Future<void> applyScreenSecurity() {
    if (!screenSecuritySupported) return Future<void>.value();
    return _queueScreenSecurity((revision) async {
      await _ackScreenSecurity(revision);
    });
  }

  /// Confirms the tunnel without contacting a third-party website: a fresh
  /// handshake, live counters and a DNS answer resolved through the tunnel are
  /// enough to know that payload reaches the exit.
  Future<bool> verifyTunnel({
    Duration timeout = const Duration(seconds: 15),
  }) async {
    if (_disposed || timeout <= Duration.zero) return false;
    final epoch = _statusEpoch;
    bool current() => !_disposed && epoch == _statusEpoch;
    connectionCheck = 'Проверка туннеля…';
    if (!_disposed) notifyListeners();
    final clock = Stopwatch()..start();
    Duration left() => timeout - clock.elapsed;
    var dns = false;
    try {
      while (current() && clock.elapsed < timeout) {
        try {
          await refresh().timeout(left());
        } on TimeoutException {
          break;
        }
        if (!current() || !status.active || left() <= Duration.zero) break;
        if (!dns) {
          try {
            final budget = left() < const Duration(seconds: 4)
                ? left()
                : const Duration(seconds: 4);
            final addrs = await InternetAddress.lookup('example.com')
                .timeout(budget);
            dns = addrs.isNotEmpty;
          } catch (_) {
            // Keep polling: DNS may answer only after the first payload.
          }
        }
        final handshake = status.handshake ?? 0;
        final traffic = (status.tx ?? 0) > 0;
        if (handshake > 0 && (dns || traffic)) break;
        if (!current() || left() <= Duration.zero) break;
        await Future<void>.delayed(
          left() < const Duration(milliseconds: 500)
              ? left()
              : const Duration(milliseconds: 500),
        );
      }
      if (!current() || clock.elapsed >= timeout) return false;
      final ok =
          status.active &&
          (status.handshake ?? 0) > 0 &&
          (dns || (status.tx ?? 0) > 0);
      // Two whole strings instead of an interpolation: both are catalogue keys,
      // so the suffix is translated with the rest of the sentence.
      connectionCheck = ok
          ? (dns ? 'Туннель активен · DNS через туннель' : 'Туннель активен')
          : 'Туннель не подтверждён';
      return ok;
    } finally {
      if (current()) if (!_disposed) notifyListeners();
    }
  }

  Future<bool> checkConnection({
    Duration timeout = const Duration(seconds: 15),
  }) async {
    if (_disposed || timeout <= Duration.zero) return false;
    final epoch = _statusEpoch;
    bool current() => !_disposed && epoch == _statusEpoch;
    connectionCheck = 'Проверка $checkSite…';
    if (!_disposed) notifyListeners();
    final clock = Stopwatch()..start();
    HttpClient? activeClient;
    void cancelProbe() => activeClient?.close(force: true);
    _cancelConnectionProbe?.call();
    _cancelConnectionProbe = cancelProbe;
    final deadline = Timer(timeout, cancelProbe);
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
      if (!status.active) throw StateError('VPN отключён');
      if (siteProbe != null) {
        final ok = await siteProbe!(validateCheckSite(checkSite))
            .timeout(remaining());
        if (!current()) return false;
        connectionCheck = ok ? 'Сайт доступен' : 'Сайт недоступен';
        return ok;
      }
      final tls =
          probeSecurityContext ?? await ProbeTls.context.timeout(remaining());
      while (current()) {
        final client = HttpClient(context: tls)
          ..connectionTimeout = phaseBudget(const Duration(seconds: 3));
        activeClient = client;
        try {
          var url = validateCheckSite(checkSite);
          for (var redirect = 0; redirect <= 4; redirect++) {
            final request = await client
                .getUrl(url)
                .timeout(phaseBudget(const Duration(seconds: 3)));
            if (!current()) return false;
            request.followRedirects = false;
            final response = await request.close().timeout(
              phaseBudget(const Duration(seconds: 5)),
            );
            if (!current()) return false;
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
            if (!current()) return false;
            final code = response.statusCode;
            connectionCheck = code >= 200 && code < 400
                ? 'Сайт доступен · HTTP $code'
                : 'Сайт ответил HTTP $code';
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
      return false;
    } catch (_) {
      if (current()) connectionCheck = 'Не удалось открыть $checkSite';
      return false;
    } finally {
      deadline.cancel();
      if (identical(_cancelConnectionProbe, cancelProbe)) {
        _cancelConnectionProbe = null;
      }
      activeClient?.close(force: true);
      if (current()) if (!_disposed) notifyListeners();
    }
  }

  Future<ManagedUser> importBundle(UserBundle bundle) =>
      withDocumentMutation(() => _importBundle(bundle));

  Future<ManagedUser> _importBundle(UserBundle bundle) async {
    if (clientOnlyBuild && bundle.adminAccess != null) {
      throw const FormatException(
        'Нужен клиентский профиль без SSH-доступа администратора',
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
      throw const FormatException('Пользователь уже добавлен');
    }
    if (previousUser?.revoked == true) {
      throw const FormatException('Доступ пользователя отозван');
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
        throw const FormatException('Некорректная конфигурация сервера');
      }
    }
    for (final e in bundle.configs.entries) {
      if (rivetProtocols.contains(e.key)) {
        final p = RivetProfile.parse(e.value);
        if (p.protocol != e.key || p.data['id'] != bundle.userId) {
          throw const FormatException('Некорректный профиль RIVET');
        }
      } else if (extendedProtocols.contains(e.key)) {
        if (ExtendedProfile.parse(e.value).protocol != e.key) {
          throw const FormatException('Протокол не совпадает с конфигурацией');
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
      if (!_disposed) notifyListeners();
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
            '${bundle.name} · ${e.key == 'awg' ? 'AmneziaWG' : 'WireGuard'}',
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
      if (!_disposed) notifyListeners();
      return user;
    } catch (error) {
      if (!_restoreAllowed(error)) {
        // The rename already committed the imported graph: never compensate
        // remotely or roll the in-memory graph back on an unconfirmed write.
        _markPostRenameUnknown();
        rethrow;
      }
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
      if (!_disposed) notifyListeners();
      rethrow;
    }
  }

  Future<UserBundle> exportUser(ManagedUser user) async {
    if (user.revoked) throw StateError('Доступ отозван');
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
          'Выдайте ограниченный доступ аккаунта из полной версии',
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

  Future<void> forgetServer(String id) =>
      withDocumentMutation(() => _forgetServer(id));

  Future<void> _forgetServer(String id) async {
    if (status.active || busy) throw StateError('Сначала отключите VPN');
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
    if (!_disposed) notifyListeners();
  }

  Future<void> remove(String id) =>
      withDocumentMutation(() => _remove(id));

  Future<void> _remove(String id) async {
    if (busy || _activeId == id) throw StateError('Сначала отключите профиль');
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
    // Automatic may fall to the first remaining profile; manual keeps the user's
    // chosen ID even when it is now missing (honest empty candidate set).
    if (connectionPolicy == ConnectionPolicy.automatic &&
        !_policyInvalid &&
        selectedId == id) {
      selectedId = profiles.firstOrNull?.id;
    }
    try {
      await save();
    } catch (error) {
      final afterRename = error is PublicationFailure &&
          error.phase != PublicationPhase.beforeRename;
      if (afterRename) {
        // Disk may already contain the removal: never restore the old whole
        // document or the old profile in memory. Surface reconciliation instead.
        _policyUnconfirmed = true;
        if (!_disposed) notifyListeners();
      } else {
        profiles
          ..clear()
          ..addAll(previous);
        for (var i = 0; i < users.length && i < previousUsers.length; i++) {
          users[i].profileIds
            ..clear()
            ..addAll(previousUsers[i]);
        }
        selectedId = previousId;
      }
      rethrow;
    }
    if (nativeTunnel) {
      await native.invokeMethod('deleteConfig', {'id': id});
    }
    if (!_disposed) notifyListeners();
  }

  /// Overridable monotonic clock boundary for deterministic lifecycle tests.
  ConnectionRound createConnectionRound({
    Duration maximum = const Duration(seconds: 30),
    void Function()? onExpire,
  }) => ConnectionRound(maximum: maximum, onExpire: onExpire);

  Future<bool> _cleanupNativeRound(
    ConnectionRound round,
    String roundId,
  ) async {
    if (!nativeTunnel) return true;
    var cleanup = _nativeCleanup;
    if (cleanup == null) {
      cleanupIncomplete = true;
      cleanup = native.invokeMethod<void>('disconnect', {
        'roundId': roundId,
        'timeoutMillis': round.remaining.inMilliseconds.clamp(1, 30000),
      });
      _nativeCleanup = cleanup;
      final owned = cleanup;
      final operation = _operationEpoch;
      unawaited(
        cleanup.then<void>(
          (_) {
            if (identical(_nativeCleanup, owned)) {
              _nativeCleanup = null;
              cleanupIncomplete = false;
              if (!_disposed && operation == _operationEpoch) {
                if (_desired &&
                    autoReconnect &&
                    error != null &&
                    !busy &&
                    !reconnecting) {
                  _scheduleRecovery();
                }
                if (!_disposed) notifyListeners();
              }
            }
          },
          onError: (Object _, StackTrace _) {
            if (identical(_nativeCleanup, owned)) {
              _nativeCleanup = null;
              cleanupIncomplete = true;
              if (!_disposed && operation == _operationEpoch) if (!_disposed) notifyListeners();
            }
          },
        ),
      );
    }
    final left = round.remaining;
    if (left <= Duration.zero) return false;
    try {
      await cleanup.timeout(left);
      return true;
    } catch (_) {
      return false;
    }
  }

  void _scheduleRecovery() {
    if (_disposed ||
        !_desired ||
        !autoReconnect ||
        cleanupIncomplete ||
        _retryCount >= 20) {
      return;
    }
    _retryCount++;
    _retry?.cancel();
    _retry = Timer(Duration(seconds: _retryCount <= 3 ? 5 : 15), () {
      _retry = null;
      unawaited(_reconnect());
    });
  }

  Future<void> connect({bool resuming = false}) async {
    _startupIntentEpoch++;
    final startupRound = _desktopStartupRound;
    if (startupRound != null && identical(startupRound, _connectRound)) {
      // An explicit UP supersedes pending startup just like DOWN. Reuse the
      // existing bounded teardown before handing ownership to the new request.
      final down = disconnect();
      final intent = _startupIntentEpoch;
      await down;
      if (_disposed || intent != _startupIntentEpoch) return;
    }
    await _connect(resuming: resuming);
  }

  Future<void> _connect({bool resuming = false, bool startup = false}) async {
    if (_disposed) return;
    if (enforceConsent && !consentReady) {
      throw StateError("Сначала ознакомьтесь с лицензией и уведомлением VPN");
    }
    // Present-but-invalid durable policy blocks every UP source, including
    // startup and retry, and says why instead of silently repairing it.
    if (_policyInvalid) {
      error = policyError;
      if (!_disposed) notifyListeners();
      return;
    }
    final initial = selected;
    if (initial == null) {
      if (connectionPolicy == ConnectionPolicy.selectedOnly && !_policyInvalid) {
        error =
            'Manual mode: the selected profile is unavailable. Choose a profile again.';
        if (!_disposed) notifyListeners();
      }
      return;
    }
    if (busy || serverMaintenance || status.active || cleanupIncomplete) {
      return;
    }
    final user = users
        .where((u) => u.profileIds.values.contains(initial.id))
        .firstOrNull;
    if (user?.revoked == true) {
      error = 'Доступ пользователя отозван';
      if (!_disposed) notifyListeners();
      return;
    }
    final candidates = connectionCandidates(initial);
    final policy = connectionPolicy;
    if (candidates.isEmpty && policy == ConnectionPolicy.selectedOnly) {
      // Missing, deleted, unsupported or revoked manual selection: no other
      // profile is tried and no auto-repair happens. Legacy native layers that
      // cannot acknowledge selectedOnly fail closed at activation instead.
      error =
          'Manual mode: the selected profile is unavailable. Choose a profile again.';
      if (!_disposed) notifyListeners();
      return;
    }
    final previousDesired = _desired;
    final operation = ++_operationEpoch;
    bool current() => !_disposed && operation == _operationEpoch;
    final roundId =
        '${DateTime.now().microsecondsSinceEpoch}-${++_roundSerial}';
    late final ConnectionRound round;
    round = createConnectionRound(
      onExpire: () {
        if (!current() || !identical(_connectRound, round)) return;
        // Revoke publication BEFORE starting/awaiting cleanup.
        _invalidateRouting();
        _invalidateConnectionStatus();
        _activeId = null;
        status = const TunnelStatus(
          state: 'Превышено время подключения (30 с)',
        );
        error = 'Превышено время подключения (30 с)';
        if (!_disposed) notifyListeners();
      },
    );
    _connectRound = round;
    if (startup) _desktopStartupRound = round;
    _invalidateRouting();
    _invalidateConnectionStatus();
    _retry?.cancel();
    _retry = null;
    _nativeRecoveryLease?.close();
    _nativeRecoveryLease = null;
    _nativeRecoveryKey = null;
    _nativeRecoverySeen = 0;
    _nativeRecoveryStages.clear();
    if (!resuming) _retryCount = 0;
    busy = true;
    error = null;
    connectionCheck = null;
    if (!_disposed) notifyListeners();
    var nativeIssued = false;
    var accepted = false;
    bool startupConsentCurrent() {
      if (!startup || !enforceConsent || consentReady) return true;
      // An obsolete startup continuation cannot clear a newer owner's intent.
      if (current() && identical(_connectRound, round)) _desired = false;
      return false;
    }
    try {
      if (nativeTunnel) {
        final nativeBusy = await round.run(
          () => native.invokeMethod<bool>('connectionBusy'),
        );
        if (nativeBusy == true || (startup && nativeBusy != false)) {
          if (current()) _desired = previousDesired;
          return;
        }
      }
      if (!current() || !round.current) {
        throw TimeoutException('Connection round');
      }
      if (!startupConsentCurrent()) return;
      _desired = true;
      if (resuming && !await _cleanupNativeRound(round, roundId)) {
        throw StateError('Отключение VPN не завершено');
      }
      // A functional clean path: after a helper restart the durable snapshot is
      // reconciled under THIS round before any candidate activation, so manual
      // mode is not a permanent dead end. Failure stays an honest error.
      if (_policyCapability && _policyReceipt == null) {
        // Any document written by this build carries connectionPolicy, so the
        // native side already treats it as versioned. A receipt is therefore
        // required even on the first connect after an import, before the
        // in-memory versioned flag has been re-read from disk.
        try {
          await round.run(() => reconcilePolicy());
        } catch (_) {
          _policyReconcileRequired = true;
          throw const PolicyFailure(
            'POLICY_UNKNOWN',
            'The saved plan could not be reconciled with the local engine',
          );
        }
      }
      // This work consumes the SAME round, not a fresh activation timeout.
      await round.run(() => syncSplitDomains());
      for (final p in candidates) {
        if (!current() ||
            !round.current ||
            round.workRemaining <= Duration.zero) {
          throw TimeoutException('Connection round');
        }
        _invalidateConnectionStatus();
        // Attempt display is transient. Automatic fallback must not rewrite
        // the user's durable selection or a generation-bound manual plan.
        _attemptedProfileId = p.id;
        if (!_disposed) notifyListeners();
        final ceiling = Duration(seconds: protocolTimeoutSeconds);
        final end =
            round.elapsed +
            (round.workRemaining < ceiling ? round.workRemaining : ceiling);
        Duration attemptLeft() {
          final left = end - round.elapsed;
          return round.limit(left > Duration.zero ? left : Duration.zero);
        }

        try {
          if (!nativeProtocols.contains(p.protocol) || !nativeTunnel) continue;
          if (!startupConsentCurrent()) return;
          final started = DateTime.now().millisecondsSinceEpoch;
          // Attachment validation precedes the effect: a stale receipt or a
          // manual candidate that is not the committed selection is refused
          // before any native stop/setup.
          final attachment = _activationArguments(p);
          nativeIssued = true;
          final activation = await round.run(
            () => native.invokeMapMethod<String, dynamic>('connect', {
              'id': p.id,
              'timeoutMillis': attemptLeft().inMilliseconds.clamp(1, 30000),
              'roundMillis': round.remaining.inMilliseconds.clamp(1, 30000),
              'roundId': roundId,
              'policy': policy.toJson(),
              ...attachment,
            }),
            ceiling: attemptLeft(),
          );
          if (policy == ConnectionPolicy.selectedOnly &&
              activation?['policyMode'] != policy.name) {
            throw PlatformException(
              code: 'UNSUPPORTED_POLICY',
              message: 'Native selectedOnly policy unavailable',
            );
          }
          if (!current() || !round.current) {
            throw TimeoutException('Connection round');
          }
          _activeId = p.id;
          await round.run(() => refresh(fresh: true), ceiling: attemptLeft());
          final verified = await round.run(
            () => siteCheckEnabled
                ? checkConnection(timeout: attemptLeft())
                : verifyTunnel(timeout: attemptLeft()),
            ceiling: attemptLeft(),
          );
          if (!verified) throw StateError('Проверка соединения не пройдена');
          while (round.current &&
              attemptLeft() > Duration.zero &&
              (status.handshake ?? 0) < started - 2000) {
            await round.run(
              () => Future<void>.delayed(const Duration(milliseconds: 250)),
              ceiling: attemptLeft(),
            );
            await round.run(() => refresh(), ceiling: attemptLeft());
          }
          if (!round.current ||
              !status.active ||
              (status.handshake ?? 0) < started - 2000) {
            throw StateError('Проверка соединения не пройдена');
          }
          // The accepted attempt becomes the durable selection through this
          // owned save: no mid-round write, and an unproven failure restores
          // the previous user-visible id (a post-rename outcome keeps it).
          final previousSelection = selectedId;
          selectedId = p.id;
          try {
            await round.run(() => save());
          } catch (error) {
            if (error is! PublicationFailure ||
                error.phase == PublicationPhase.beforeRename) {
              selectedId = previousSelection;
            }
            rethrow;
          }
          if (!current() || !round.current) {
            throw TimeoutException('Connection round');
          }
          accepted = true;
          _retryCount = 0;
          log(
            siteCheckEnabled
                ? 'Автоматически выбран ${p.protocol}; сайт доступен'
                : 'Автоматически выбран ${p.protocol}; туннель подтверждён',
          );
          return;
        } catch (e) {
          if (current()) {
            _invalidateConnectionStatus();
            _activeId = null;
            status = const TunnelStatus();
          }
          if (nativeIssued) {
            nativeIssued = false;
            if (!await _cleanupNativeRound(round, roundId)) {
              throw StateError('Отключение VPN не завершено');
            }
          }
          if (!current() ||
              !round.current ||
              round.remaining <= Duration.zero) {
            rethrow;
          }
          log('Проверка ${p.protocol} не пройдена');
          if (e is PolicyFailure || e is PublicationFailure) {
            // Identity/admission refusals and unconfirmed document writes are
            // never "this protocol failed, try the next one".
            rethrow;
          }
          if (e is PlatformException &&
              const [
                'DENIED',
                'ROUTING',
                'BUSY',
                'UNSUPPORTED_POLICY',
                'CLEANUP',
              ].contains(e.code)) {
            rethrow;
          }
        }
      }
      throw StateError(
        'Ни один доступный маршрут не подтвердил туннель. Проверьте точку входа и доступность сервера.',
      );
    } catch (e) {
      if (current()) {
        _invalidateConnectionStatus();
        _activeId = null;
        status = const TunnelStatus();
      }
      if (nativeIssued) await _cleanupNativeRound(round, roundId);
      if (current()) {
        error = !_desired
            ? null
            : cleanupIncomplete
            ? 'Отключение VPN не завершено'
            : e is PolicyFailure
            ? e.message
            : e is PublicationFailure
            ? 'Saving the connection state did not finish. Check the saved data.'
            : e is TimeoutException
            ? 'Превышено время подключения (30 с)'
            : e is StateError
            ? e.message
            : e is PlatformException && e.code == 'ROUTING'
            ? e.message
            : 'Не удалось подключиться: проверьте профиль, сеть и разрешение VPN.';
      }
    } finally {
      round.close();
      if (identical(_connectRound, round)) _connectRound = null;
      if (identical(_desktopStartupRound, round)) _desktopStartupRound = null;
      if (current()) {
        _attemptedProfileId = null;
        if (!accepted) _invalidateRouting();
        busy = false;
        if (!accepted && !resuming && _desired) _scheduleRecovery();
        if (!_disposed) notifyListeners();
      }
    }
  }

  Future<void> disconnect() async {
    _startupIntentEpoch++;
    if (_disposed || (busy && _connectRound == null)) return;
    final operation = ++_operationEpoch;
    _reconnectEpoch++;
    reconnecting = false;
    bool current() => !_disposed && operation == _operationEpoch;
    final activeRound = _connectRound;
    final before = status;
    final beforeId = _activeId;
    final round = activeRound ?? createConnectionRound();
    activeRound?.cancel();
    _invalidateRouting();
    _invalidateConnectionStatus();
    _desired = false;
    _watchdog?.cancel();
    _watchdog = null;
    _watchdogMisses = 0;
    _nativeRecoveryLease?.close();
    _nativeRecoveryLease = null;
    _nativeRecoveryKey = null;
    _retry?.cancel();
    _retry = null;
    _retryCount = 0;
    busy = true;
    _activeId = null;
    _attemptedProfileId = null;
    status = const TunnelStatus();
    if (!_disposed) notifyListeners();
    try {
      if (!await _cleanupNativeRound(round, 'disconnect-${++_roundSerial}')) {
        throw StateError('Отключение VPN не завершено');
      }
      if (!current()) return;
      error = null;
      connectionCheck = null;
      // Ownership was revoked before DOWN; fresh DNS may be re-applied only
      // after obtaining a new revision-bound native lease.
      log('Туннель отключён');
    } catch (_) {
      // An immediate explicit DOWN error retains the last known interface
      // snapshot (not Internet proof). Expired/connecting rounds never restore it.
      if (activeRound == null && round.current && current()) {
        status = before;
        _activeId = beforeId;
      }
      if (current()) {
        error = 'Не удалось отключить туннель. Проверьте системную службу.';
      }
    } finally {
      if (activeRound == null) round.close();
      if (current()) {
        _invalidateConnectionStatus();
        busy = false;
        if (!_disposed) notifyListeners();
      }
    }
  }

  Future<void> refresh({bool fresh = false}) =>
      _statusPoll.run(_readStatus, fresh: fresh);

  Future<void> _readStatus() async {
    if (_disposed) return;
    final epoch = _statusEpoch;
    final before = status;
    _startupStatusIdle = false;
    try {
      final p = activeProfile ?? selected;
      if (nativeProtocols.contains(p?.protocol) && nativeTunnel) {
        final j = Map<String, dynamic>.from(
          (await native.invokeMapMethod<String, dynamic>('status')) ?? {},
        );
        if (_disposed || epoch != _statusEpoch) return;
        // Absence/errors are not proof of an idle desktop helper. Older desktop
        // helpers explicitly return active:false without a phase when idle.
        _startupStatusIdle = j['active'] == false &&
            (j['phase'] == null || j['phase'] == 'disconnected') &&
            (j['recoveryPending'] == null || j['recoveryPending'] == false) &&
            (j['cleanupPending'] == null || j['cleanupPending'] == false);
        final up =
            j['active'] == true &&
            !cleanupIncomplete &&
            j['recoveryPending'] != true &&
            j['cleanupPending'] != true;
        status = TunnelStatus(
          active: up,
          state: up
              ? (j['phase'] == 'reconnecting'
                    ? 'Повторное подключение…'
                    : 'Интерфейс активен')
              : j['recoveryPending'] == true
              ? 'Повторное подключение…'
              : 'Отключено',
          path: up ? '${j['protocol'] ?? p!.protocol}' : '—',
          rx: j['rx'],
          tx: j['tx'],
          handshake: j['handshake'],
          phase: j['phase'] as String? ?? 'disconnected',
          recoveryId: j['recoveryId']?.toString() ?? '',
          recoveryPending: j['recoveryPending'] == true,
          recoveryRemainingMillis:
              (j['recoveryRemainingMillis'] as num?)?.toInt() ?? 0,
          cleanupPending: cleanupIncomplete || j['cleanupPending'] == true,
        );
        if (up) {
          _activeId = j['id'];
        } else {
          _activeId = null;
        }
      }
    } catch (_) {
      if (_disposed || epoch != _statusEpoch) return;
      _startupStatusIdle = false;
      status = TunnelStatus(
        active: _activeId != null,
        state: 'Состояние неизвестно · проверьте службу',
        path: '—',
      );
    } finally {
      if (!_disposed && epoch == _statusEpoch) {
        _syncWatchdog();
        // A poll that learned nothing new must not rebuild the shell: the idle
        // screen used to be redrawn every three seconds.
        if (before != status) if (!_disposed) notifyListeners();
      }
    }
  }

  /// Runs while the owner wants the tunnel: it re-checks the live link and
  /// restores the connection when the engine dropped or the link died, on every
  /// platform and build.
  void _syncWatchdog() {
    if (!_disposed && _desired && autoReconnect && !cleanupIncomplete) {
      _watchdog ??= Timer.periodic(
        _watchdogInterval,
        (_) => unawaited(_watchdogTick()),
      );
    } else {
      _watchdog?.cancel();
      _watchdog = null;
      _watchdogMisses = 0;
    }
  }

  Future<void> _watchdogTick() async {
    if (_disposed ||
        reconnecting ||
        busy ||
        !_desired ||
        _retry != null ||
        cleanupIncomplete) {
      return;
    }
    final epoch = _statusEpoch;
    // The engine may have dropped the tunnel on its own: restore it. The read
    // is a method-channel call, not a socket, so it costs no radio time.
    await refresh();
    if (_disposed || epoch != _statusEpoch || !_desired || reconnecting) return;
    if (status.recoveryPending && !status.cleanupPending) {
      final key = '${status.recoveryId}:${status.phase}';
      if (_nativeRecoveryKey != key) {
        if (_nativeRecoveryKey?.split(':').first != status.recoveryId) {
          _nativeRecoverySeen++;
        }
        _nativeRecoveryKey = key;
        _nativeRecoveryLease?.close();
        _nativeRecoveryLease = null;
        final maximum = status.phase == 'cooldown' ? 15000 : 30000;
        final left = status.recoveryRemainingMillis;
        if (const ['reconnecting', 'cooldown'].contains(status.phase) &&
            _nativeRecoveryStages.add(key) &&
            status.recoveryId.isNotEmpty &&
            left > 0 &&
            left <= maximum &&
            _nativeRecoverySeen <= 3) {
          _nativeRecoveryLease = createConnectionRound(
            maximum: Duration(milliseconds: left),
          );
        }
      }
      // Same id/stage NEVER renews its original monotonic lease on another poll.
      if (_nativeRecoveryLease?.current == true &&
          _nativeRecoveryLease!.remaining > Duration.zero) {
        return;
      }
    } else {
      _nativeRecoveryLease?.close();
      _nativeRecoveryLease = null;
      _nativeRecoveryKey = null;
      if (status.active) {
        _nativeRecoverySeen = 0;
        _nativeRecoveryStages.clear();
      }
    }
    if (!status.active) {
      await _reconnect();
      return;
    }
    // Free liveness evidence first: a fresh handshake or moving counters prove
    // that payload still crosses the tunnel, so no DNS query is spent.
    if (_tunnelLooksAlive()) {
      _watchdogMisses = 0;
      if (_watchdogHealthy < 6) _watchdogHealthy++;
      return;
    }
    // A DNS answer is the fallback probe. While the window is hidden it is
    // budgeted: a lookup on a sleeping radio wakes the whole modem. A probe
    // that already missed is confirmed on the next tick, so detection of a real
    // outage keeps the original two-miss latency.
    final now = DateTime.now().millisecondsSinceEpoch;
    if (!_foreground &&
        _watchdogMisses == 0 &&
        now - _lastProbeAt < _backgroundProbeMillis) {
      return;
    }
    _lastProbeAt = now;
    var alive = false;
    try {
      final addrs = await InternetAddress.lookup('example.com')
          .timeout(const Duration(seconds: 6));
      alive = addrs.isNotEmpty;
    } catch (_) {
      alive = false;
    }
    if (_disposed || epoch != _statusEpoch || !_desired) return;
    if (alive) {
      _watchdogMisses = 0;
      if (_watchdogHealthy < 6) _watchdogHealthy++;
      return;
    }
    // Two consecutive misses rule out a single lost DNS answer.
    if (++_watchdogMisses < 2) return;
    _watchdogMisses = 0;
    await _reconnect();
  }

  /// True when the engine itself reports recent traffic: a handshake younger
  /// than [_handshakeFreshMillis] or a receive counter that moved since the last
  /// tick. Both are cheaper and stronger than a DNS round trip.
  ///
  /// Only the *receive* counter counts: `tx` advances even when the packets are
  /// sent into a black hole (UDP/TCP sockets on a dead link still accept writes),
  /// so trusting it would let a broken tunnel look alive and suppress the very
  /// reconnects this watchdog exists for.
  bool _tunnelLooksAlive() {
    final handshake = status.handshake ?? 0;
    final now = DateTime.now().millisecondsSinceEpoch;
    final rx = status.rx;
    final moved = rx != null && rx > (_lastRx ?? 0);
    _lastRx = rx;
    return moved || (handshake > 0 && now - handshake < _handshakeFreshMillis);
  }

  Future<void> _reconnect() async {
    if (_disposed || !_desired || reconnecting || busy || cleanupIncomplete) {
      return;
    }
    final recovery = ++_reconnectEpoch;
    bool current() => !_disposed && recovery == _reconnectEpoch && _desired;
    reconnecting = true;
    connectionCheck = 'Связь потеряна · переподключение…';
    log('Связь потеряна; переподключение');
    _invalidateConnectionStatus();
    status = const TunnelStatus();
    _activeId = null;
    if (!_disposed) notifyListeners();
    try {
      // Teardown of the old owner is INSIDE connect's one thirty-second round.
      await connect(resuming: true);
      if (!current()) return;
      if (!status.active) {
        throw StateError(error ?? 'Переподключение не удалось');
      }
      _retryCount = 0;
    } catch (e) {
      if (current()) {
        error = e is StateError ? e.message : 'Переподключение не удалось';
        _scheduleRecovery();
      }
    } finally {
      if (current()) {
        reconnecting = false;
        if (!_disposed) notifyListeners();
      }
    }
  }

  Map<String, dynamic> diagnosticReport(List<Map<String, dynamic>> checks) => {
    'application': 'XIO',
    'version': xioVersion,
    'createdAt': DateTime.now().toUtc().toIso8601String(),
    'platform': Platform.operatingSystem,
    'tunnelState': status.state,
    'path': status.path,
    'checks': checks,
    'notes': 'Тесты доступности не доказывают отсутствие DNS/IPv6-утечек. Ключи и конфигурации не включены.',
  };

  @override
  void dispose() {
    _disposed = true;
    _documentAdmission.dispose();
    // Logical disposal stops new IO immediately; the physical lock stays held
    // until every admitted write settles (never closed early).
    unawaited(_productWriter?.closeWhenSettled());
    _invalidateRouting();
    _operationEpoch++;
    _reconnectEpoch++;
    _connectRound?.cancel();
    _nativeRecoveryLease?.close();
    _invalidateConnectionStatus();
    _desired = false;
    _timer?.cancel();
    _watchdog?.cancel();
    _watchdog = null;
    _retry?.cancel();
    _retry = null;
    super.dispose();
  }
}

class SshTarget {
  final String host, username, fingerprint;
  final int port;
  const SshTarget(this.host, this.port, this.username, [this.fingerprint = '']);
  void validate() {
    normalizeServerHost(host);
    if (port < 1 || port > 65535) {
      throw const FormatException('Некорректный SSH-порт');
    }
    if (!RegExp(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$').hasMatch(username)) {
      throw const FormatException('Некорректный пользователь');
    }
    if (fingerprint.isNotEmpty &&
        !RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
      throw const FormatException('Некорректный SHA256-отпечаток SSH');
    }
  }
}

/// Releases an SSH password only after the server host key was accepted for
/// this connection. dartssh2 verifies the host key before userauth; this gate
/// keeps that ordering an explicit invariant and fails closed if the library
/// or a future client ever asks for a password first.
class SshPasswordGate {
  bool _verified = false;
  String _fingerprint = '';
  bool get verified => _verified;
  String get fingerprint => _fingerprint;

  void accept(String fingerprint) {
    if (!RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
      throw const FormatException('Некорректный ключ SSH сервера');
    }
    if (_verified && _fingerprint != fingerprint) {
      throw const FormatException('Ключ SSH сервера изменился в рамках сессии');
    }
    _verified = true;
    _fingerprint = fingerprint;
  }

  String release(String password) {
    if (!_verified) {
      throw StateError('SSH-пароль не отправлен: ключ сервера ещё не проверен');
    }
    return password;
  }

  void close() {
    _verified = false;
    _fingerprint = '';
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
          throw const FormatException('Повреждено хранилище ключей SSH');
        }
        keys = decoded;
      }
      // Alias spellings (case, trailing root dot, bracketed IPv6) must share
      // one pin entry; otherwise a re-spelled host could auto-trust a new key.
      final host = canonicalServerHost(target.host);
      final endpoint = '[$host]:${target.port}';
      final known = keys[endpoint];
      if (known != null && known != fingerprint) {
        throw const FormatException(
          'Ключ SSH сервера изменился. Подключение остановлено. '
          'Проверьте сервер перед повторной настройкой.',
        );
      }
      if (known == null) {
        if (!RegExp(r'^SHA256:[A-Za-z0-9+/]{43}$').hasMatch(fingerprint)) {
          throw const FormatException('Некорректный ключ SSH сервера');
        }
        keys[endpoint] = fingerprint;
        await storage.parent.create(recursive: true);
        final temp = File('${storage.path}.tmp');
        await temp.writeAsString(jsonEncode(keys), flush: true);
        await temp.rename(storage.path);
      }
    } on FileSystemException {
      throw const FormatException(
        'Не удалось сохранить или прочитать ключ SSH сервера',
      );
    } on FormatException catch (e) {
      if (e.message.startsWith('Ключ SSH') ||
          e.message.startsWith('Не удалось') ||
          e.message.startsWith('Некорректный ключ') ||
          e.message.startsWith('Некорректный IP') ||
          e.message.startsWith('Некорректный IPv6')) {
        rethrow;
      }
      throw const FormatException('Повреждено хранилище ключей SSH');
    } finally {
      done.complete();
    }
  }
}

typedef SocketConnector = Future<SSHSocket> Function(
  String host,
  int port,
  Duration timeout,
);

/// Test seam for the SSH client. Production uses [SSHClient] with the same
/// host-key and password callbacks that [VpsService.open] supplies.
typedef SshClientFactory = SSHClient Function({
  required SSHSocket socket,
  required String username,
  required List<SSHKeyPair> identities,
  required String Function() onPasswordRequest,
  required SSHHostkeyVerifyHandler onVerifyHostKey,
});

SSHClient _defaultSshClient({
  required SSHSocket socket,
  required String username,
  required List<SSHKeyPair> identities,
  required String Function() onPasswordRequest,
  required SSHHostkeyVerifyHandler onVerifyHostKey,
}) => SSHClient(
  socket,
  username: username,
  identities: identities,
  onPasswordRequest: onPasswordRequest,
  onVerifyHostKey: onVerifyHostKey,
  handshakeTimeout: const Duration(seconds: 15),
  authTimeout: const Duration(seconds: 20),
);

/// A remote command exited with a non-zero status.
///
/// Carries the raw exit code and both output streams so a caller that
/// deliberately decodes a structured JSON error body can still read
/// [stdoutBytes]; a caller that only needs the failure keeps the message
/// generic. [stderrBytes] are kept raw and are never echoed into UI or logs.
class SshCommandFailure implements Exception {
  SshCommandFailure(this.exitCode, this.stdoutBytes, this.stderrBytes);

  /// Remote exit status, or -1 when the channel closed without reporting one
  /// (for example a signal termination).
  final int exitCode;

  /// Raw stdout of the remote command.
  final List<int> stdoutBytes;

  /// Raw stderr of the remote command. Never surface this to the user.
  final List<int> stderrBytes;

  @override
  String toString() => 'SshCommandFailure(exitCode: $exitCode)';
}

/// Pure boundary for a completed SSH command: stdout bytes on exit code 0, or a
/// typed [SshCommandFailure] on any other exit. Split out so the contract is
/// unit-testable without a live SSH transport.
List<int> sshCommandOutcome(
  int? exitCode,
  List<int> stdoutBytes,
  List<int> stderrBytes,
) {
  if (exitCode != 0) {
    throw SshCommandFailure(exitCode ?? -1, stdoutBytes, stderrBytes);
  }
  return stdoutBytes;
}

class VpsService {
  final SshHostKeyStore hostKeys;
  final ServerLookup? lookup;

  /// Optional socket factory for deterministic address-order tests; production
  /// uses the platform socket via [SSHSocket.connect].
  final SocketConnector? socketConnector;
  final SshClientFactory clientFactory;
  VpsService({
    SshHostKeyStore? hostKeys,
    this.lookup,
    this.socketConnector,
    SshClientFactory? clientFactory,
  }) : hostKeys = hostKeys ?? SshHostKeyStore(),
       clientFactory = clientFactory ?? _defaultSshClient;
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
    final sshHost = normalizeServerHost(t.host);
    final identities = privateKey.trim().isEmpty
        ? <SSHKeyPair>[]
        : await compute(_decodeKey, (privateKey, passphrase));
    final socket = await _connect(sshHost, t.port);
    Object? hostKeyError;
    final passwordGate = SshPasswordGate();
    final c = clientFactory(
      socket: socket,
      username: t.username,
      identities: identities,
      onPasswordRequest: () => passwordGate.release(password),
      onVerifyHostKey: (type, fp) async {
        final fingerprint = utf8.decode(fp);
        if (t.fingerprint.isNotEmpty && fingerprint != t.fingerprint) {
          return false;
        }
        try {
          await hostKeys.verify(t, fingerprint);
          passwordGate.accept(fingerprint);
          verifiedFingerprint = fingerprint;
          return true;
        } catch (e) {
          hostKeyError = e;
          return false;
        }
      },
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

  /// Tries interleaved A/AAAA answers through the platform resolver.
  ///
  /// DNS is bounded separately (8 s per family, queried in parallel); the 12 s
  /// deadline here covers only socket attempts. Once a socket is established no
  /// other address is tried: the host key is verified against [SshTarget] in
  /// that session and a pin mismatch aborts before authentication.
  Future<SSHSocket> _connect(String host, int port) async {
    final candidates = await resolveServerHost(host, lookup: lookup);
    final deadline = DateTime.now().add(const Duration(seconds: 12));
    Object? lastError;
    for (final candidate in candidates) {
      final remaining = deadline.difference(DateTime.now());
      if (remaining <= Duration.zero) break;
      final perAttempt = candidates.length == 1
          ? remaining
          : (remaining < const Duration(seconds: 5)
                ? remaining
                : const Duration(seconds: 5));
      try {
        return await (socketConnector?.call(candidate.host, port, perAttempt) ??
            SSHSocket.connect(candidate.host, port, timeout: perAttempt));
      } catch (e) {
        lastError = e;
      }
    }
    if (lastError != null) throw lastError;
    throw const FormatException('Не удалось подключиться к серверу');
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
printf '\nXIO\n'; if test -e /etc/wireguard/xio0.conf; then printf 'existing installation\n'; else printf 'not installed\n'; fi
''')
        .timeout(const Duration(seconds: 20));
    if (result.exitCode != 0) {
      throw StateError('Предпроверка VPS завершилась ошибкой');
    }
    return utf8.decode(result.stdout, allowMalformed: true);
  }

  Future<String> installWireGuard(String script) async {
    if (target == null || target!.username != 'root') {
      throw StateError(
        'Рецепт требует SSH-вход root; sudo в этой версии не поддерживается',
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
        'Установка не завершилась вовремя. Проверьте журнал /var/log/xio-install.log на VPS.',
      );
    }
    final out = utf8.decode(await output, allowMalformed: true);
    await errors;
    if (session.exitCode != 0) {
      throw StateError(
        'Установка прервана. Изменения могли примениться частично; журнал /var/log/xio-install.log на VPS.',
      );
    }
    final match = RegExp(r'XIO_SERVER_KEY=([A-Za-z0-9+/]{43}=)')
        .firstMatch(out);
    if (match == null) throw StateError('Нет подтверждённого ключа сервера');
    final host = target!.host.contains(':')
        ? '[${target!.host}]'
        : target!.host;
    return '[Interface]\nPrivateKey = $private\nAddress = 10.77.0.2/32, fd77:1::2/128\nDNS = 9.9.9.9\nMTU = 1280\n\n[Peer]\nPublicKey = ${match[1]}\nEndpoint = $host:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n';
  }

  /// Uploads [bytes] to [path] through SFTP.
  ///
  /// The server archive is ~21 MB. Pushing it through a command's stdin depends
  /// on channel window and flow-control behaviour that the app cannot observe: a
  /// short write only surfaces later as "bundle digest mismatch" and the user
  /// sees a generic failure. Uploading first keeps the remote command short and
  /// short-lived, and the remote digest check reads a complete file.
  ///
  /// Writes are issued one chunk at a time on purpose: a pipelined
  /// [SftpFile.writeBytes] call returned while the tail of a 21 MB file was still
  /// unacknowledged, leaving a truncated upload behind a successful future.
  Future<void> upload(String path, List<int> bytes) async {
    final c = _client;
    if (c == null || target == null) {
      throw StateError('Сначала подключитесь по SSH');
    }
    const chunkSize = 128 * 1024;
    final sftp = await c.sftp();
    try {
      final file = await sftp.open(
        path,
        mode:
            SftpFileOpenMode.create |
            SftpFileOpenMode.write |
            SftpFileOpenMode.truncate,
      );
      try {
        for (var offset = 0; offset < bytes.length; offset += chunkSize) {
          final end = offset + chunkSize < bytes.length
              ? offset + chunkSize
              : bytes.length;
          await file.writeBytes(
            Uint8List.fromList(bytes.sublist(offset, end)),
            offset: offset,
            chunkSize: chunkSize,
            maxPendingRequests: 1,
          );
        }
      } finally {
        await file.close();
      }
    } finally {
      await sftp.close();
    }
  }

  Future<List<int>> executeInput(
    String command,
    List<int> input, {
    Duration timeout = const Duration(minutes: 6),
  }) async {
    if (_client == null || target == null) {
      throw StateError('Сначала подключитесь по SSH');
    }
    final session = await _client!.execute(command);
    final output = session.stdout.fold<List<int>>([], (a, b) => a..addAll(b));
    final errors = session.stderr.fold<List<int>>([], (a, b) => a..addAll(b));
    session.stdin.add(Uint8List.fromList(input));
    await session.stdin.close();
    final bytes = await output.timeout(timeout);
    final stderrBytes = await errors.timeout(timeout);
    await session.done.timeout(timeout);
    // A non-zero exit is a failure even when the command printed to stdout:
    // callers that decode a structured JSON error body catch [SshCommandFailure]
    // and read its stdoutBytes deliberately. Never echo stderr/secrets.
    return sshCommandOutcome(session.exitCode, bytes, stderrBytes);
  }

  Future<void> close() async {
    final c = _client;
    _client = null;
    target = null;
    if (c != null) await c.close();
  }
}

class NetworkChecks {
  static Future<List<Map<String, dynamic>>> run(
    String host,
    int port, {
    ServerLookup? lookup,
  }) async {
    final normalized = normalizeServerHost(host);
    if (port < 1 || port > 65535) {
      throw const FormatException('Проверьте адрес и порт');
    }
    final result = <Map<String, dynamic>>[];
    var timer = Stopwatch()..start();
    var candidates = <ServerAddressCandidate>[];
    try {
      candidates = await resolveServerHost(normalized, lookup: lookup);
      final v4 = candidates.where((c) => c.family == 'IPv4').length;
      final v6 = candidates.where((c) => c.family == 'IPv6').length;
      result.add({
        'test': 'DNS',
        'ok': true,
        'ms': timer.elapsedMilliseconds,
        'detail': [if (v4 > 0) 'IPv4', if (v6 > 0) 'IPv6'].join(', '),
      });
    } catch (_) {
      result.add({
        'test': 'DNS',
        'ok': false,
        'detail': 'Имя не разрешено или тайм-аут',
      });
    }
    final samples = <int>[];
    final families = <String>{};
    for (var i = 0; i < 3; i++) {
      timer = Stopwatch()..start();
      final candidate = candidates.isEmpty
          ? null
          : candidates[i % candidates.length];
      try {
        final s = await Socket.connect(
          candidate?.host ?? normalized,
          port,
          timeout: const Duration(seconds: 5),
        );
        samples.add(timer.elapsedMilliseconds);
        if (candidate != null) families.add(candidate.family);
        s.destroy();
      } catch (_) {}
    }
    result.add({
      'test': 'TCP :$port',
      'ok': samples.isNotEmpty,
      'ms': samples.isEmpty
          ? null
          : samples.reduce((a, b) => a + b) ~/ samples.length,
      'detail': families.isEmpty
          ? '${samples.length}/3 TCP-соединений. Это не ICMP RTT и не тест пропускной способности.'
          : '${samples.length}/3 TCP-соединений · ${families.join(', ')}. '
                'Это не ICMP RTT и не тест пропускной способности.',
    });
    return result;
  }
}
