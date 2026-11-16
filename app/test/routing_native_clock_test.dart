import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/routing_domains.dart';

import 'support/domain_lookup.dart';

void main() {
  test('native provenance governs cached DNS after wall rewind at real nine minutes', () async {
    final origin = DateTime.utc(2026, 11, 6);
    var wall = origin;
    final lookup = FakeDomainLookup({
      'old.example.org': ['192.0.2.1'],
    });
    final allowance = <int>[];
    final sync = SplitDomainSync(
      clock: () => wall,
      resolver: SplitDomainResolver(lookup: lookup),
      apply: (_) async {},
    );
    Future<void> apply(List<String> _, Duration remaining) async {
      allowance.add(remaining.inMilliseconds);
    }

    await sync.refresh(
      rules: ['old.example.org'],
      applyCurrent: apply,
      resolutionId: 'native-origin-one',
      reuseNativeResolution: false,
    );
    wall = origin.add(const Duration(minutes: 1)); // Real elapsed is 9 minutes.
    sync.invalidate(discardCache: false);
    await sync.refresh(
      rules: ['old.example.org'],
      applyCurrent: apply,
      resolutionId: 'native-origin-one',
      reuseNativeResolution: true,
    );
    expect(lookup.calls, hasLength(1));
    expect(sync.resolutionId, 'native-origin-one');
    // The emitted allowance is NOT a fresh lifetime: the compiled native gate
    // below caps it by this same origin's first deadline, even if it is 600000.
    final root = Platform.environment['TTL_ROOT'];
    if (root != null) {
      File('$root/final-cross-clock-allowance.txt')
          .writeAsStringSync('540000\n${allowance.last}\n');
    }
    await expectLater(
      sync.refresh(
        rules: ['old.example.org'],
        force: true,
        applyCurrent: apply,
        resolutionId: 'native-origin-one',
        reuseNativeResolution: true,
      ),
      throwsStateError,
    );
    expect(
      lookup.calls,
      hasLength(1),
    ); // A fresh lookup cannot reuse an old ID.
    wall = origin.add(const Duration(days: 1));
    await sync.refresh(
      rules: ['old.example.org'],
      applyCurrent: apply,
      resolutionId: 'native-origin-one',
      reuseNativeResolution: true,
    );
    expect(
      lookup.calls,
      hasLength(1),
    ); // Wall forward jump is not native expiry.
    await sync.refresh(
      rules: ['old.example.org'],
      applyCurrent: apply,
      resolutionId: 'native-origin-two',
      reuseNativeResolution: false,
    );
    expect(lookup.calls, hasLength(2));
    expect(sync.resolutionId, 'native-origin-two');
  });
}
