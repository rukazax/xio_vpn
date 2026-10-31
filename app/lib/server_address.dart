import 'dart:io';

/// Raw host for socket/DNS operations. URI brackets belong only to endpoints.
String normalizeServerHost(String input) {
  var host = input.trim();
  if (host.startsWith('[') || host.endsWith(']')) {
    if (!host.startsWith('[') || !host.endsWith(']')) {
      throw const FormatException('Некорректный IPv6-адрес сервера');
    }
    final raw = host.substring(1, host.length - 1);
    final address = InternetAddress.tryParse(raw);
    if (address == null || address.type != InternetAddressType.IPv6) {
      throw const FormatException('Некорректный IPv6-адрес сервера');
    }
    return address.address;
  }
  final address = InternetAddress.tryParse(host);
  if (address != null) return address.address;
  if (host.isEmpty ||
      host.length > 253 ||
      host.contains(':') ||
      RegExp(r'^[0-9.]+$').hasMatch(host)) {
    throw const FormatException('Некорректный IP или домен сервера');
  }
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  if (name.isEmpty ||
      name
          .split('.')
          .any(
            (label) =>
                label.isEmpty ||
                label.length > 63 ||
                !RegExp(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$')
                    .hasMatch(label),
          )) {
    throw const FormatException('Некорректный IP или домен сервера');
  }
  return host;
}

/// Stable identity for a host in local trust/storage records.
///
/// DNS names are case-insensitive and a single trailing root dot is the same
/// name, so case and `example.com.` must not create separate pin entries for
/// the same server. IP literals are already canonicalized by
/// [InternetAddress.tryParse]. The transport still uses the original spelling.
String canonicalServerHost(String input) {
  final host = normalizeServerHost(input);
  if (InternetAddress.tryParse(host) != null) return host;
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  return name.toLowerCase();
}

String serverEndpoint(String input, int port) {
  if (port < 1 || port > 65535) {
    throw const FormatException('Некорректный порт сервера');
  }
  final host = normalizeServerHost(input);
  return host.contains(':') ? '[$host]:$port' : '$host:$port';
}

/// A validated `host:port` pair. IPv6 hosts are bracketed only when rendered.
class ServerEndpoint {
  final String host;
  final int port;
  const ServerEndpoint._(this.host, this.port);
  factory ServerEndpoint.parse(String input) {
    final value = input.trim();
    if (value.isEmpty || value.length > 300) {
      throw const FormatException('Некорректный адрес сервера');
    }
    String hostPart, portPart;
    if (value.startsWith('[')) {
      final close = value.indexOf(']');
      if (close < 0 || close + 1 >= value.length || value[close + 1] != ':') {
        throw const FormatException('Некорректный адрес сервера');
      }
      hostPart = value.substring(0, close + 1);
      portPart = value.substring(close + 2);
    } else {
      final colon = value.lastIndexOf(':');
      if (colon <= 0 || value.indexOf(':') != colon) {
        throw const FormatException('Некорректный адрес сервера');
      }
      hostPart = value.substring(0, colon);
      portPart = value.substring(colon + 1);
    }
    if (!RegExp(r'^\d{1,5}$').hasMatch(portPart)) {
      throw const FormatException('Некорректный адрес сервера');
    }
    final port = int.parse(portPart);
    if (port < 1 || port > 65535) {
      throw const FormatException('Некорректный адрес сервера');
    }
    return ServerEndpoint._(normalizeServerHost(hostPart), port);
  }
  String get formatted => serverEndpoint(host, port);
  @override
  String toString() => formatted;
}

/// Pluggable platform lookup, used by deterministic tests and diagnostics.
typedef ServerLookup = Future<List<InternetAddress>> Function(
  String host,
  InternetAddressType type,
);

class ServerAddressCandidate {
  final InternetAddress address;
  const ServerAddressCandidate(this.address);
  String get host => address.address;
  String get family =>
      address.type == InternetAddressType.IPv6 ? 'IPv6' : 'IPv4';
  @override
  String toString() => '$family $host';
}

/// Resolves a domain through the platform resolver and asks for A and AAAA
/// separately, so a missing family does not hide the other one. Answers are
/// interleaved (IPv4, IPv6, next IPv4, …) before any caller budget, because a
/// long IPv4 list must not crowd out a usable IPv6 address (and vice versa).
/// IP literals bypass DNS. No address is ever substituted for the configured
/// hostname.
Future<List<ServerAddressCandidate>> resolveServerHost(
  String input, {
  ServerLookup? lookup,
  Duration timeout = const Duration(seconds: 8),
}) async {
  final host = normalizeServerHost(input);
  final literal = InternetAddress.tryParse(host);
  if (literal != null) return [ServerAddressCandidate(literal)];
  final resolve =
      lookup ??
      (String host, InternetAddressType type) =>
          InternetAddress.lookup(host, type: type);
  Future<List<InternetAddress>> query(InternetAddressType type) async {
    try {
      return await resolve(host, type).timeout(timeout);
    } catch (_) {
      return const <InternetAddress>[];
    }
  }

  final answers = await Future.wait([
    query(InternetAddressType.IPv4),
    query(InternetAddressType.IPv6),
  ]);
  final v4 = answers[0], v6 = answers[1];
  final seen = <String>{};
  final candidates = <ServerAddressCandidate>[];
  void add(InternetAddress address) {
    if (seen.add(address.address)) {
      candidates.add(ServerAddressCandidate(address));
    }
  }

  // Interleave both families before the caller's attempt budget so neither a
  // long A list starves the only AAAA answer nor the reverse.
  final length = v4.length > v6.length ? v4.length : v6.length;
  for (var i = 0; i < length; i++) {
    if (i < v4.length) add(v4[i]);
    if (i < v6.length) add(v6[i]);
  }
  if (candidates.isEmpty) {
    throw const FormatException('Имя не разрешено или тайм-аут DNS');
  }
  return candidates;
}
