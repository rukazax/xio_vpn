import 'dart:io';

import 'package:xio/routing_domains.dart';

/// Поддельный DNS для тестов доменных правил: сеть не используется.
class FakeDomainLookup implements DomainAddressLookup {
  FakeDomainLookup([this.answers = const {}]);

  final Map<String, List<String>> answers;
  final List<String> calls = [];
  final List<Duration> timeouts = [];

  /// Когда включено, каждое имя отвечает сбоем — как недоступный DNS.
  bool failing = false;

  @override
  Future<List<String>> lookup(
    String host, {
    required Duration timeout,
  }) async {
    calls.add(host);
    timeouts.add(timeout);
    if (failing) throw const SocketException('DNS недоступен');
    return answers[host] ?? const [];
  }
}
