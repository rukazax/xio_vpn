import 'dart:async';
import 'dart:io';

/// Доменные правила раздельного туннелирования.
///
/// Правила хранятся как есть (`youtube.com`, `*.example.com`), а IP-адреса
/// получаются разрешением имён при подключении: Android VPN не умеет
/// маршрутизировать по имени, поэтому результат подставляется в правила
/// вместе с введёнными вручную IP/CIDR. Модуль не зависит от Flutter и
/// нативной стороны, чтобы разрешение и валидацию можно было покрыть тестами
/// с поддельным DNS.

/// Максимум доменных правил в одном списке (как и у IP-правил).
const maxDomainRules = 128;

/// Максимум имён, разрешаемых за один проход: wildcard не должен превращать
/// список в бесконечный обход всех поддоменов.
const maxDomainLookups = 64;

/// Максимум адресов, передаваемых нативной стороне. Политика принимает 128
/// сетей вместе с введёнными вручную IP — оставляем запас.
const maxResolvedAddresses = 96;

final _label = RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$');
final _tld = RegExp(r'^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$');
final _ipv4 = RegExp(
  r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}'
  r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$',
);

/// Канонический вид доменного правила или `null`, если запись некорректна.
///
/// Допустимо: `youtube.com`, `www.youtube.com`, `*.example.com`.
/// Недопустимо: схема (`https://`), слэши и путь, порт, пробелы, одиночная
/// метка (`localhost`), `*` без домена, пустые метки, дефис по краям метки.
String? normalizeDomainRule(String input) {
  final raw = input.trim();
  if (raw.isEmpty) return null;
  final wildcard = raw.startsWith('*.');
  final host = _normalizeHost(wildcard ? raw.substring(2) : raw);
  if (host == null) return null;
  return wildcard ? '*.$host' : host;
}

String? _normalizeHost(String input) {
  final text = input.toLowerCase();
  if (text.length > 253) return null;
  // Только имя: без схемы, слэшей, порта, якорей и учётных данных.
  if (text.contains('/') ||
      text.contains(':') ||
      text.contains('@') ||
      text.contains('?') ||
      text.contains('#') ||
      text.contains('*') ||
      text.contains(' ') ||
      text.contains('\\')) {
    return null;
  }
  final host = text.endsWith('.') ? text.substring(0, text.length - 1) : text;
  if (host.isEmpty) return null;
  final labels = host.split('.');
  // Одна метка — не домен: правило маршрутизации по такому имени бессмысленно.
  if (labels.length < 2) return null;
  for (final label in labels) {
    if (!_label.hasMatch(label)) return null;
  }
  return _tld.hasMatch(labels.last) ? host : null;
}

/// Литеральный IPv4 (без ведущих нулей, как и в нативной проверке).
bool isIpv4Literal(String input) => _ipv4.hasMatch(input.trim());

/// Литеральный IPv6. Zone-id (`fe80::1%eth0`) отвергается: транспорт его не
/// поддерживает, а `InternetAddress.tryParse` принимает молча.
bool isIpv6Literal(String input) {
  final text = input.trim();
  if (!text.contains(':') || text.contains('%') || text.contains('/')) {
    return false;
  }
  final address = InternetAddress.tryParse(text);
  return address != null && address.type == InternetAddressType.IPv6;
}

/// IPv4/IPv6/CIDR — то, что нативная сторона принимает в списке сетей.
bool isIpOrCidr(String input) {
  final text = input.trim();
  if (text.isEmpty) return false;
  final parts = text.split('/');
  if (parts.length > 2) return false;
  final address = parts.first;
  final ipv4 = isIpv4Literal(address);
  if (!ipv4 && !isIpv6Literal(address)) return false;
  if (parts.length == 1) return true;
  final raw = parts[1];
  if (!RegExp(r'^(?:0|[1-9][0-9]{0,2})$').hasMatch(raw)) return false;
  final max = ipv4 ? 32 : 128;
  return int.parse(raw) <= max;
}

/// Разбивает многострочный ввод на записи (строки, запятые, точки с запятой).
List<String> splitRoutingEntries(String raw) => raw
    .split(RegExp(r'[\s,;]+'))
    .map((value) => value.trim())
    .where((value) => value.isNotEmpty)
    .toList();

/// Проверяет и нормализует введённые домены, сохраняя порядок и убирая дубли.
///
/// Бросает [FormatException] с первой некорректной записью: молча выкидывать
/// правила нельзя — человек должен увидеть, что именно не принято.
List<String> parseDomainEntries(String raw) {
  final result = <String>[];
  for (final entry in splitRoutingEntries(raw)) {
    final rule = normalizeDomainRule(entry);
    if (rule == null) {
      throw FormatException(
        'Некорректный домен «$entry»: нужно имя без схемы и слэшей, '
        'например youtube.com или *.example.com',
      );
    }
    if (!result.contains(rule)) result.add(rule);
  }
  if (result.length > maxDomainRules) {
    throw const FormatException('Слишком много доменов: не более 128');
  }
  return result;
}

/// Проверяет введённые вручную сети и возвращает их без изменений.
List<String> parseNetworkEntries(String raw) {
  final result = splitRoutingEntries(raw);
  for (final entry in result) {
    if (!isIpOrCidr(entry)) {
      throw FormatException(
        'Некорректный адрес «$entry»: укажите IPv4, IPv6 или подсеть CIDR',
      );
    }
  }
  if (result.length > 128) {
    throw const FormatException('Слишком много адресов: не более 128');
  }
  return result;
}

/// Разрешение имени в адреса. Отдельный интерфейс, чтобы тесты обходились
/// без сети и без реального DNS.
abstract class DomainAddressLookup {
  Future<List<String>> lookup(String host, {required Duration timeout});
}

/// Системный резолвер: то же `InternetAddress.lookup`, что и у остального
/// приложения, с жёстким таймаутом на имя.
class SystemDomainAddressLookup implements DomainAddressLookup {
  const SystemDomainAddressLookup();

  @override
  Future<List<String>> lookup(String host, {required Duration timeout}) async {
    final addresses = await InternetAddress.lookup(host)
        .timeout(timeout, onTimeout: () => const <InternetAddress>[]);
    return [
      for (final address in addresses)
        if (isIpv4Literal(address.address) || isIpv6Literal(address.address))
          address.address,
    ];
  }
}

/// Результат разрешения набора доменных правил.
class DomainResolution {
  const DomainResolution({
    required this.byRule,
    required this.addresses,
    required this.queried,
    required this.failed,
  });

  /// правило → полученные адреса (пусто, если имя не разрешилось).
  final Map<String, List<String>> byRule;

  /// Все адреса без повторов, отсортированы: один и тот же ввод даёт один и
  /// тот же набор правил.
  final List<String> addresses;

  /// Имена, к которым обращались. Нужны, чтобы следующий проход знал
  /// «известные поддомены» wildcard-правил.
  final List<String> queried;

  /// Имена, которые не разрешились. Подключение из-за них не блокируется:
  /// недоступный DNS не должен оставлять человека без VPN.
  final List<String> failed;

  /// Сколько обращений к DNS было сделано.
  int get lookups => queried.length;
}

/// Разрешает доменные правила в адреса.
///
/// Wildcard `*.example.com` разрешает корень `example.com` и известные
/// поддомены (прямые потомки из уже разрешённых имён или явных записей того
/// же списка). Глубже одного уровня не идём: иначе wildcard превращается в
/// неограниченный обход DNS.
class SplitDomainResolver {
  SplitDomainResolver({
    DomainAddressLookup? lookup,
    Duration? timeout,
    int? maxLookups,
    int? maxAddresses,
  }) : _lookup = lookup ?? const SystemDomainAddressLookup(),
       _timeout = timeout ?? const Duration(seconds: 3),
       _maxLookups = maxLookups ?? maxDomainLookups,
       _maxAddresses = maxAddresses ?? maxResolvedAddresses;

  final DomainAddressLookup _lookup;
  final Duration _timeout;
  final int _maxLookups;
  final int _maxAddresses;

  Future<DomainResolution> resolve(
    Iterable<String> rules, {
    Iterable<String> knownHosts = const [],
  }) async {
    final byRule = <String, List<String>>{};
    final all = <String>{};
    final queried = <String>[];
    final failed = <String>[];

    // Одно имя — один запрос: правило и поддомен wildcard не должны
    // удваивать DNS.
    final cache = <String, List<String>>{};

    Future<List<String>> ask(String host) async {
      final known = cache[host];
      if (known != null) return known;
      if (queried.length >= _maxLookups) return const [];
      queried.add(host);
      try {
        final addresses = await _lookup.lookup(host, timeout: _timeout);
        final valid = [
          for (final address in addresses)
            if (isIpv4Literal(address) || isIpv6Literal(address)) address,
        ];
        cache[host] = valid;
        return valid;
      } catch (_) {
        failed.add(host);
        cache[host] = const [];
        return const [];
      }
    }

    String? concrete(String host) {
      final rule = normalizeDomainRule(host);
      if (rule == null || rule.startsWith('*.')) return null;
      return rule;
    }

    for (final raw in rules) {
      final rule = normalizeDomainRule(raw);
      if (rule == null) continue;
      if (!rule.startsWith('*.')) {
        final addresses = await ask(rule);
        byRule[rule] = [...addresses]..sort();
        all.addAll(addresses);
        continue;
      }
      final apex = rule.substring(2);
      final addresses = <String>[];
      void take(Iterable<String> values) {
        for (final value in values) {
          if (!addresses.contains(value)) addresses.add(value);
        }
      }

      take(await ask(apex));
      // Прямые потомки, известные из предыдущих ответов и из этого же списка.
      final children = <String>{};
      for (final host in knownHosts) {
        final candidate = concrete(host);
        if (candidate != null) children.add(candidate);
      }
      for (final other in rules) {
        final candidate = concrete(other);
        if (candidate != null) children.add(candidate);
      }
      final direct =
          children
              .where(
                (host) =>
                    host != apex &&
                    host.endsWith('.$apex') &&
                    host.split('.').length == apex.split('.').length + 1,
              )
              .toList()
            ..sort();
      for (final host in direct) {
        take(await ask(host));
      }
      addresses.sort();
      byRule[rule] = addresses;
      all.addAll(addresses);
    }
    return DomainResolution(
      byRule: byRule,
      addresses: (all.toList()..sort()).take(_maxAddresses).toList(),
      queried: queried,
      failed: failed,
    );
  }
}

/// Держит разрешённые адреса в актуальном состоянии и передаёт их нативной
/// стороне.
///
/// Разрешение повторяется не чаще [ttl] (10 минут): DNS-запрос поднимает
/// радио, а правила маршрутизации меняются редко. Каждая передача заменяет
/// набор целиком, поэтому старые адреса не накапливаются, а очистка списка
/// доменов очищает и нативные маршруты.
class SplitDomainSync {
  SplitDomainSync({
    required this.apply,
    SplitDomainResolver? resolver,
    this.ttl = const Duration(minutes: 10),
    DateTime Function()? clock,
  }) : _resolver = resolver ?? SplitDomainResolver(),
       _clock = clock ?? DateTime.now;

  /// Передача действующего набора адресов нативной стороне.
  final Future<void> Function(List<String> addresses) apply;
  final SplitDomainResolver _resolver;
  final DateTime Function() _clock;
  final Duration ttl;

  List<String> _addresses = const [];
  List<String> _known = const [];
  String _signature = '';
  DateTime? _resolvedAt;
  int _resolutions = 0;
  DomainResolution? _last;

  /// Адреса, переданные нативной стороне последним проходом.
  List<String> get addresses => List.unmodifiable(_addresses);

  /// Сколько раз правила действительно разрешались (для журнала и тестов).
  int get resolutions => _resolutions;

  /// Последний результат разрешения: имена, которые не ответили, тоже нужны.
  DomainResolution? get lastResolution => _last;

  /// Забыть кэш: следующее подключение разрешит домены заново.
  void invalidate() {
    // Адреса остаются действующими до следующего разрешения: очистка
    // списка правил должна снять их отдельным вызовом [refresh].
    _signature = '';
    _resolvedAt = null;
    _known = const [];
  }

  /// Разрешает [rules] и отдаёт адреса нативной стороне.
  ///
  /// Возвращает действующий набор адресов. Повторный вызов в пределах [ttl]
  /// с тем же списком ничего не делает и не пишет файл политики.
  Future<List<String>> refresh({
    required Iterable<String> rules,
    bool force = false,
  }) async {
    final normalized = <String>[];
    for (final rule in rules) {
      final value = normalizeDomainRule(rule);
      if (value != null && !normalized.contains(value)) normalized.add(value);
    }
    normalized.sort();
    final key = normalized.join(',');
    final now = _clock();
    final fresh =
        _resolvedAt != null &&
        now.difference(_resolvedAt!) < ttl &&
        key == _signature;
    if (!force && fresh) return addresses;

    if (normalized.isEmpty) {
      _signature = '';
      _resolvedAt = now;
      _known = const [];
      _last = const DomainResolution(
        byRule: {},
        addresses: [],
        queried: [],
        failed: [],
      );
      if (_addresses.isEmpty) return const [];
      _addresses = const [];
      await apply(const <String>[]);
      return const [];
    }

    final resolution = await _resolver.resolve(normalized, knownHosts: _known);
    _last = resolution;
    _resolutions++;
    _addresses = resolution.addresses;
    _known = {..._known, ...resolution.queried}.toList();
    _signature = key;
    _resolvedAt = now;
    await apply(_addresses);
    return addresses;
  }
}
