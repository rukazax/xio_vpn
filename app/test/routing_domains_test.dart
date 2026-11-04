import 'package:flutter_test/flutter_test.dart';
import 'package:xio/routing_domains.dart';

import 'support/domain_lookup.dart';

void main() {
  group('доменное правило', () {
    test('принимает домен и wildcard в каноническом виде', () {
      expect(normalizeDomainRule('youtube.com'), 'youtube.com');
      expect(normalizeDomainRule('  YouTube.COM. '), 'youtube.com');
      expect(normalizeDomainRule('www.youtube.com'), 'www.youtube.com');
      expect(normalizeDomainRule('*.example.com'), '*.example.com');
      expect(normalizeDomainRule('*.Example.COM'), '*.example.com');
      expect(normalizeDomainRule('xn--80ak6aa92e.com'), 'xn--80ak6aa92e.com');
    });

    test('отвергает схему, слэши, порт и одиночную метку', () {
      for (final bad in [
        'https://youtube.com',
        'youtube.com/',
        'youtube.com/watch',
        'youtube.com:443',
        'user@youtube.com',
        'youtube.com?x=1',
        '*',
        '*.',
        'localhost',
        '.com',
        'youtube..com',
        '-youtube.com',
        'youtube-.com',
        'youtube',
        'youtube.c',
        'пример.рф',
        '',
        '   ',
      ]) {
        expect(normalizeDomainRule(bad), isNull, reason: bad);
      }
    });
  });

  group('проверка адресов', () {
    test('IPv4, IPv6 и CIDR сохраняют прежнее поведение', () {
      for (final good in [
        '203.0.113.5',
        '10.0.0.0/8',
        '0.0.0.0/0',
        '::1',
        '2001:db8::/32',
        '::/0',
      ]) {
        expect(isIpOrCidr(good), isTrue, reason: good);
      }
      for (final bad in [
        'fe80::1%eth0',
        '01.2.3.4',
        '256.0.0.1',
        '1.2.3.4/33',
        '::/129',
        'example.com',
        '10.0.0.0/',
        '10.0.0.0/8/24',
        '',
      ]) {
        expect(isIpOrCidr(bad), isFalse, reason: bad);
      }
    });

    test('домены в списке сетей не принимаются', () {
      expect(() => parseNetworkEntries('10.0.0.0/8, example.com'), throwsFormatException);
      expect(parseNetworkEntries('10.0.0.0/8, ::1'), ['10.0.0.0/8', '::1']);
    });
  });

  group('ввод списка доменов', () {
    test('разбирает строки, запятые и дубли', () {
      expect(
        parseDomainEntries('youtube.com, *.EXAMPLE.com;\nyoutube.com\n'),
        ['youtube.com', '*.example.com'],
      );
      expect(parseDomainEntries('   '), isEmpty);
    });

    test('сообщает, какая именно запись некорректна', () {
      expect(
        () => parseDomainEntries('youtube.com\nhttps://rutube.ru'),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('https://rutube.ru'),
          ),
        ),
      );
    });

    test('ограничивает число правил', () {
      final many = List.generate(maxDomainRules + 1, (i) => 'd$i.example.com');
      expect(many.length, maxDomainRules + 1);
      expect(() => parseDomainEntries(many.join('\n')), throwsFormatException);
    });
  });

  group('разрешение доменов', () {
    test('обычный домен превращается в свои адреса', () async {
      final lookup = FakeDomainLookup({
        'youtube.com': ['203.0.113.5', '203.0.113.6'],
      });
      final resolution = await SplitDomainResolver(lookup: lookup).resolve([
        'youtube.com',
        'absent.example.org',
      ]);
      expect(resolution.byRule['youtube.com'], ['203.0.113.5', '203.0.113.6']);
      expect(resolution.byRule['absent.example.org'], isEmpty);
      expect(resolution.addresses, ['203.0.113.5', '203.0.113.6']);
      expect(resolution.failed, isEmpty);
      expect(resolution.lookups, 2);
    });

    test('wildcard разрешает корень и известные поддомены, но не глубже', () async {
      final lookup = FakeDomainLookup({
        'example.com': ['198.51.100.1'],
        'mail.example.com': ['198.51.100.2'],
        'a.mail.example.com': ['198.51.100.3'],
        'other.example.net': ['198.51.100.4'],
      });
      final resolution = await SplitDomainResolver(lookup: lookup).resolve(
        ['*.example.com', 'mail.example.com'],
        knownHosts: ['a.mail.example.com', 'other.example.net'],
      );
      expect(lookup.calls, ['example.com', 'mail.example.com']);
      expect(resolution.byRule['*.example.com'], [
        '198.51.100.1',
        '198.51.100.2',
      ]);
      expect(resolution.addresses, ['198.51.100.1', '198.51.100.2']);
    });

    test('сбои DNS и мусор в ответе не блокируют остальные правила', () async {
      final lookup = FakeDomainLookup({
        'youtube.com': ['203.0.113.5', 'not-an-address'],
      });
      final resolver = SplitDomainResolver(lookup: lookup);
      final first = await resolver.resolve(['youtube.com']);
      expect(first.addresses, ['203.0.113.5']);

      lookup.failing = true;
      final second = await resolver.resolve(['youtube.com']);
      expect(second.addresses, isEmpty);
      expect(second.failed, ['youtube.com']);
    });

    test('таймаут передаётся резолверу и ограничивает обход', () async {
      final lookup = FakeDomainLookup({
        'example.com': ['198.51.100.1'],
        for (var i = 0; i < 30; i++) 's$i.example.com': ['10.0.0.$i'],
      });
      final resolver = SplitDomainResolver(
        lookup: lookup,
        timeout: const Duration(seconds: 7),
        maxLookups: 5,
      );
      final resolution = await resolver.resolve(
        ['*.example.com'],
        knownHosts: [for (var i = 0; i < 30; i++) 's$i.example.com'],
      );
      expect(lookup.timeouts, everyElement(const Duration(seconds: 7)));
      expect(resolution.lookups, 5);
      expect(lookup.calls.length, 5);
    });

    test('число адресов ограничено запасом нативной политики', () async {
      final lookup = FakeDomainLookup({
        'example.com': [
          for (var i = 0; i < maxResolvedAddresses + 20; i++) '10.1.${i ~/ 250}.${i % 250}',
        ],
      });
      final resolution = await SplitDomainResolver(
        lookup: lookup,
      ).resolve(['example.com']);
      expect(resolution.addresses.length, maxResolvedAddresses);
    });
  });

  group('синхронизация адресов', () {
    test('передаёт адреса нативной стороне и живёт по кэшу 10 минут', () async {
      final lookup = FakeDomainLookup({
        'youtube.com': ['203.0.113.5'],
        'example.com': ['198.51.100.1'],
      });
      final applied = <List<String>>[];
      var now = DateTime.utc(2026, 11, 5, 12);
      final sync = SplitDomainSync(
        apply: (addresses) async => applied.add(addresses),
        resolver: SplitDomainResolver(lookup: lookup),
        clock: () => now,
      );

      expect(await sync.refresh(rules: ['youtube.com']), ['203.0.113.5']);
      expect(applied, [
        ['203.0.113.5'],
      ]);
      expect(sync.resolutions, 1);

      // В пределах десяти минут DNS не спрашиваем и файл политики не пишем.
      now = now.add(const Duration(minutes: 9, seconds: 59));
      expect(await sync.refresh(rules: ['youtube.com']), ['203.0.113.5']);
      expect(lookup.calls, ['youtube.com']);
      expect(applied, hasLength(1));
      expect(sync.resolutions, 1);

      now = now.add(const Duration(minutes: 1));
      await sync.refresh(rules: ['youtube.com']);
      expect(lookup.calls, ['youtube.com', 'youtube.com']);
      expect(applied, hasLength(2));
      expect(sync.resolutions, 2);
    });

    test('изменение списка разрешает заново, очистка снимает адреса', () async {
      final lookup = FakeDomainLookup({
        'youtube.com': ['203.0.113.5'],
        'example.com': ['198.51.100.1'],
      });
      final applied = <List<String>>[];
      var now = DateTime.utc(2026, 11, 5, 12);
      final sync = SplitDomainSync(
        apply: (addresses) async => applied.add(addresses),
        resolver: SplitDomainResolver(lookup: lookup),
        clock: () => now,
      );

      await sync.refresh(rules: ['youtube.com']);
      now = now.add(const Duration(minutes: 1));
      // Другой список — новый проход, старые адреса заменяются целиком.
      expect(await sync.refresh(rules: ['example.com']), ['198.51.100.1']);
      expect(applied, [
        ['203.0.113.5'],
        ['198.51.100.1'],
      ]);

      now = now.add(const Duration(minutes: 1));
      expect(await sync.refresh(rules: const []), isEmpty);
      expect(applied, [
        ['203.0.113.5'],
        ['198.51.100.1'],
        <String>[],
      ]);
      expect(sync.addresses, isEmpty);
    });

    test('invalidate и force обходят кэш', () async {
      final lookup = FakeDomainLookup({
        'youtube.com': ['203.0.113.5'],
      });
      final applied = <List<String>>[];
      final sync = SplitDomainSync(
        apply: (addresses) async => applied.add(addresses),
        resolver: SplitDomainResolver(lookup: lookup),
      );
      await sync.refresh(rules: ['youtube.com']);
      await sync.refresh(rules: ['youtube.com'], force: true);
      expect(sync.resolutions, 2);

      sync.invalidate();
      await sync.refresh(rules: ['youtube.com']);
      expect(sync.resolutions, 3);
      expect(applied, hasLength(3));
    });

    test('пустой список с самого начала ничего не пишет', () async {
      var applied = 0;
      final sync = SplitDomainSync(apply: (_) async => applied++);
      expect(await sync.refresh(rules: const []), isEmpty);
      expect(applied, 0);
    });
  });
}
