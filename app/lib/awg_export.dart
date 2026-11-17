/// Standalone AmneziaWG ("AWG 3.1") profile export.
///
/// The XIO client already stores a ready-to-use AmneziaWG config per issued
/// user, bound to the server that terminates the tunnel. In a cascade that is
/// the FIRST server: it forwards `xioawg0` into the exit tunnel, so any device
/// importing the exported profile is routed through the second server without
/// installing XIO at all.
///
/// This module only parses and normalises that text. It never invents
/// obfuscation parameters: Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5 must stay exactly
/// what the server uses, otherwise the handshake is silently dropped.
library;

class AwgExportError implements Exception {
  const AwgExportError(this.message);
  final String message;
  @override
  String toString() => message;
}

class AwgProfile {
  AwgProfile._(this.text, this.endpoint, this.address, this.dns, this.keepalive);

  /// Normalised, ready-to-import `.conf` text.
  final String text;
  final String endpoint;
  final String address;
  final String dns;
  final String? keepalive;

  String get host {
    final at = endpoint.lastIndexOf(':');
    if (endpoint.startsWith('[')) {
      final close = endpoint.indexOf(']');
      return close > 0 ? endpoint.substring(1, close) : endpoint;
    }
    return at > 0 ? endpoint.substring(0, at) : endpoint;
  }

  /// True when the text carries at least one AmneziaWG obfuscation parameter,
  /// i.e. it is not a plain WireGuard profile.
  bool get obfuscated {
    final lower = text.toLowerCase();
    return lower.contains('\njc =') ||
        lower.contains('\ns1 =') ||
        lower.contains('\nh1 =') ||
        lower.contains('\ni1 =');
  }

  /// Filename safe on Android and other importers.
  static String fileName(String name) {
    final cleaned = name
        .trim()
        .replaceAll(RegExp(r'[^A-Za-z0-9._-]+'), '-')
        .replaceAll(RegExp(r'-{2,}'), '-')
        .replaceAll(RegExp(r'^-|-$'), '');
    final base = cleaned.isEmpty ? 'xio-awg' : cleaned;
    return base.toLowerCase().endsWith('.conf') ? base : '$base.conf';
  }

  /// Parses the stored config and normalises it for a third-party client.
  ///
  /// Requirements are the ones a full-tunnel import needs: one `[Interface]`
  /// with a private key and address, one `[Peer]` with a public key and an
  /// endpoint. AllowedIPs is forced to both default routes so the profile
  /// cannot silently become split-tunnel; the original is preserved only when
  /// it already covers both families.
  factory AwgProfile.parse(String raw) {
    if (raw.length > 65536 || raw.contains('\u0000')) {
      throw const AwgExportError('Профиль повреждён или слишком велик');
    }
    final sections = <String, List<List<String>>>{};
    String section = '';
    var interfaces = 0, peers = 0;
    for (var line in raw.replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n')) {
      line = line.split('#').first.trim();
      if (line.isEmpty) continue;
      final lower = line.toLowerCase();
      if (lower == '[interface]') {
        section = 'interface';
        interfaces++;
        sections.putIfAbsent(section, () => []);
      } else if (lower == '[peer]') {
        section = 'peer${peers++}';
        sections.putIfAbsent(section, () => []);
      } else {
        final at = line.indexOf('=');
        if (section.isEmpty || at < 1) {
          throw const AwgExportError('Ожидается WireGuard/AmneziaWG .conf');
        }
        sections[section]!.add([
          line.substring(0, at).trim(),
          line.substring(at + 1).trim(),
        ]);
      }
    }
    if (interfaces != 1 || peers != 1) {
      throw const AwgExportError('Нужны один [Interface] и один [Peer]');
    }
    final iface = sections['interface']!;
    final peer = sections['peer0']!;
    String? value(List<List<String>> list, String key) {
      for (final entry in list) {
        if (entry[0].toLowerCase() == key) return entry[1];
      }
      return null;
    }

    void require(String? value, String message) {
      if (value == null || value.isEmpty) throw AwgExportError(message);
    }

    require(value(iface, 'privatekey'), 'В профиле нет PrivateKey');
    require(value(iface, 'address'), 'В профиле нет Address');
    require(value(peer, 'publickey'), 'В профиле нет PublicKey сервера');
    require(value(peer, 'endpoint'), 'В профиле нет Endpoint');
    final endpoint = value(peer, 'endpoint')!;
    final address = value(iface, 'address')!;

    const leading = ['privatekey', 'address', 'dns', 'mtu', 'listenport'];
    final out = <String>['[Interface]'];
    out.add('PrivateKey = ${value(iface, 'privatekey')}');
    out.add('Address = ${value(iface, 'address')}');
    out.add('DNS = ${value(iface, 'dns') ?? '9.9.9.9, 2620:fe::fe'}');
    out.add('MTU = ${value(iface, 'mtu') ?? '1280'}');
    final listenPort = value(iface, 'listenport');
    if (listenPort != null && listenPort.isNotEmpty) {
      out.add('ListenPort = $listenPort');
    }
    for (final entry in iface) {
      final key = entry[0].toLowerCase();
      if (leading.contains(key) || key == 'allowedips' || entry[1].isEmpty) continue;
      out.add('${_label(key)} = ${entry[1]}');
    }
    out.add('');
    out.add('[Peer]');
    out.add('PublicKey = ${value(peer, 'publickey')}');
    final psk = value(peer, 'presharedkey');
    if (psk != null && psk.isNotEmpty) out.add('PresharedKey = $psk');
    // Full IPv4 tunnel always. IPv6 only when the server's own profile
    // advertised it: a bridge without a working IPv6 default route cannot
    // carry ::/0, and forcing it blackholes IPv6-preferring clients.
    final originalAllowed = (value(peer, 'allowedips') ?? '')
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
    final v6 = originalAllowed.where((e) => e.contains(':')).toList();
    final allowed = <String>[
      '0.0.0.0/0',
      if (v6.any((e) => e == '::/0')) '::/0' else ...v6,
    ];
    out.add('AllowedIPs = ${allowed.join(', ')}');
    out.add('Endpoint = $endpoint');
    final keepalive = value(peer, 'persistentkeepalive') ?? '25';
    out.add('PersistentKeepalive = $keepalive');
    for (final entry in peer) {
      final key = entry[0].toLowerCase();
      if (key == 'publickey' || key == 'presharedkey' || key == 'allowedips' ||
          key == 'endpoint' || key == 'persistentkeepalive' || entry[1].isEmpty) {
        continue;
      }
      out.add('${_label(key)} = ${entry[1]}');
    }
    return AwgProfile._(
      '${out.join('\n')}\n',
      endpoint,
      address,
      value(iface, 'dns') ?? '9.9.9.9, 2620:fe::fe',
      keepalive,
    );
  }

  static String _label(String key) {
    const map = {
      'privatekey': 'PrivateKey', 'address': 'Address', 'dns': 'DNS',
      'mtu': 'MTU', 'listenport': 'ListenPort', 'jc': 'Jc', 'jmin': 'Jmin',
      'jmax': 'Jmax', 's1': 'S1', 's2': 'S2', 's3': 'S3', 's4': 'S4',
      'h1': 'H1', 'h2': 'H2', 'h3': 'H3', 'h4': 'H4', 'i1': 'I1', 'i2': 'I2',
      'i3': 'I3', 'i4': 'I4', 'i5': 'I5',
      'headerprotectionkey': 'HeaderProtectionKey',
      'contentpaddingaddition': 'ContentPaddingAddition',
      'rekeyaftertime': 'RekeyAfterTime', 'rekeytimeout': 'RekeyTimeout',
      'rejectaftertime': 'RejectAfterTime',
      'keepalivetimeout': 'KeepaliveTimeout',
      'maxhandshakeattempts': 'MaxHandshakeAttempts',
      'randomtrailers': 'RandomTrailers', 'disablecookies': 'DisableCookies',
      'publickey': 'PublicKey', 'presharedkey': 'PresharedKey',
      'allowedips': 'AllowedIPs', 'endpoint': 'Endpoint',
    };
    return map[key] ?? key;
  }
}
