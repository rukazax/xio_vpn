import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/routing_domains.dart';

import 'support/domain_lookup.dart';

class PartialLookup implements DomainAddressLookup {
  @override
  Future<List<String>> lookup(String host, {required Duration timeout}) async {
    if (host.startsWith('bad')) throw StateError('injected DNS failure');
    return ['192.0.2.1'];
  }
}

void main() {
  test(
    'lookup/address limits and empty DNS expose incomplete, not success',
    () async {
      final lookup = FakeDomainLookup({
        'a.example.org': ['192.0.2.1', '192.0.2.2'],
      });
      final capped = await SplitDomainResolver(
        lookup: lookup,
        maxLookups: 1,
        maxAddresses: 1,
      ).resolve(['a.example.org', 'b.example.org']);
      expect(capped.complete, isFalse);
      expect(capped.incomplete, contains('lookup-capacity:b.example.org'));
      expect(capped.incomplete, contains('address-capacity'));
      expect(capped.addresses, hasLength(1));
      final empty = await SplitDomainResolver(lookup: FakeDomainLookup({}))
          .resolve(['a.example.org']);
      expect(empty.complete, isFalse);
      expect(empty.incomplete, contains('empty-answer:a.example.org'));
    },
  );
  test('DNS exception is incomplete even with a successful sibling', () async {
    final result = await SplitDomainResolver(lookup: PartialLookup())
        .resolve(['ok.example.org', 'bad.example.org']);
    expect(result.complete, isFalse);
    expect(result.failed, ['bad.example.org']);
  });
  test('duplicates and order do not consume extra address capacity', () async {
    final sync = SplitDomainSync(
      resolver: SplitDomainResolver(
        lookup: FakeDomainLookup({
          'a.example.org': ['192.0.2.2', '192.0.2.1', '192.0.2.1'],
          'b.example.org': ['192.0.2.2'],
        }),
      ),
      apply: (_) async {},
    );
    expect(
      await sync.refresh(
        rules: ['b.example.org', 'a.example.org', 'a.example.org'],
        addressCapacity: 2,
      ),
      ['192.0.2.1', '192.0.2.2'],
    );
    expect(sync.lastResolution!.complete, isTrue);
  });
  test('new leases reuse DNS without renewing its original expiry', () async {
    var now = DateTime.utc(2026, 11, 5);
    final lookup = FakeDomainLookup({
      'a.example.org': ['192.0.2.1'],
    });
    final lifetime = <Duration>[];
    final sync = SplitDomainSync(
      resolver: SplitDomainResolver(lookup: lookup),
      clock: () => now,
      apply: (_) async {},
    );
    Future<void> apply(List<String> _, Duration validity) async {
      lifetime.add(validity);
    }

    await sync.refresh(rules: ['a.example.org'], applyCurrent: apply);
    now = now.add(const Duration(minutes: 9));
    sync.invalidate(discardCache: false);
    await sync.refresh(rules: ['a.example.org'], applyCurrent: apply);
    expect(lookup.calls, hasLength(1));
    expect(lifetime, [const Duration(minutes: 10), const Duration(minutes: 1)]);
    now = now.add(const Duration(minutes: 1));
    await sync.refresh(rules: ['a.example.org'], applyCurrent: apply);
    expect(lookup.calls, hasLength(2));
  });
  test(
    'invalidation while awaiting apply prevents a fresh cache commit',
    () async {
      final entered = Completer<void>();
      final release = Completer<void>();
      var calls = 0;
      final sync = SplitDomainSync(
        resolver: SplitDomainResolver(
          lookup: FakeDomainLookup({
            'a.example.org': ['192.0.2.1'],
          }),
        ),
        apply: (_) async {
          if (++calls == 1) {
            entered.complete();
            await release.future;
          }
        },
      );
      final pending = sync.refresh(rules: ['a.example.org']);
      final rejected = expectLater(pending, throwsStateError);
      await entered.future;
      sync.invalidate();
      release.complete();
      await rejected;
      expect(sync.addresses, isEmpty);
      expect(sync.lastResolution, isNull);
      await sync.refresh(rules: ['a.example.org']);
      expect(calls, 2);
      expect(sync.addresses, ['192.0.2.1']);
    },
  );
}
