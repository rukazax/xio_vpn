import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/core.dart';
import 'package:xio/routing_domains.dart';

class Lookup extends DomainAddressLookup {
  int calls = 0;
  final Future<List<String>> Function(String) answer;
  Lookup(this.answer);
  @override
  Future<List<String>> lookup(String host, {required Duration timeout}) {
    calls++;
    return answer(host);
  }
}

class MemoryStore extends AppStore {
  MemoryStore(Lookup lookup)
    : super(
        nativeTunnelOverride: true,
        domainLookup: lookup,
        siteProbe: (_) async => true,
      );
  @override
  Future<void> save() async {}
}

/// A native policy protocol fake, not a replacement AppStore or resolver.
class RoutingNative {
  List<String> domains = ['old.example.org'];
  List<String> networks = [];
  String revision = 'r1';
  String? lease;
  String? ready;
  String? origin;
  String? candidate;
  int serial = 0;
  int elapsed = 0;
  int deadline = 0;
  int connects = 0;
  int applyCalls = 0;
  final applied = <List<String>>[];
  Future<void> Function(String)? beginGate;
  Future<void> Function()? applyGate;
  bool failApply = false;
  bool successful = false;
  bool active = false;
  final appliedLeases = <String?>[];
  void edit(List<String> rules) {
    domains = rules;
    revision = '${revision}x';
    origin = null;
    lease = null;
    ready = null;
  }

  Future<dynamic> handle(MethodCall call) async {
    final a = Map<String, dynamic>.from(call.arguments as Map? ?? {});
    switch (call.method) {
      case 'routingGet':
        return {
          'mode': 'ipInclude',
          'domains': domains,
          'networks': networks,
          'revision': revision,
        };
      case 'routingBegin':
        final reuse =
            origin != null && a['resolutionId'] == origin && elapsed < deadline;
        candidate = reuse ? origin : 'resolution-${++serial}';
        if (!reuse) deadline = elapsed + 600000;
        final captured = {
          'resolutionId': candidate,
          'reuseAllowed': reuse,
          'mode': 'ipInclude',
          'domains': List.of(domains),
          'networks': List.of(networks),
          'revision': revision,
          'lease': a['lease'],
        };
        lease = a['lease'];
        ready = null;
        await beginGate?.call(lease!);
        return captured;
      case 'routingCancel':
        if (a['revision'] == revision && a['lease'] == lease) {
          lease = null;
          ready = null;
        }
        return null;
      case 'routingResolved':
        applyCalls++;
        await applyGate?.call();
        if (failApply) throw PlatformException(code: 'ROUTING');
        // Legacy support here is intentional only for baseline execution: the
        // old source has no revision protocol. New-source tests require leases.
        if (a.containsKey('revision') &&
            (a['revision'] != revision || a['lease'] != lease)) {
          throw PlatformException(code: 'ROUTING', message: 'stale');
        }
        applied.add(List<String>.from(a['networks']));
        appliedLeases.add(lease);
        ready = lease;
        origin = candidate;
        return null;
      case 'connectionBusy':
        return false;
      case 'connect':
        connects++;
        active = successful;
        return null;
      case 'disconnect':
        active = false;
        return null;
      case 'status':
        return {
          'active': active,
          'id': 'awg1',
          'protocol': 'awg',
          'handshake': DateTime.now().millisecondsSinceEpoch,
          'tx': 1,
          'rx': 1,
        };
      default:
        return null;
    }
  }
}

Future<void> flushAsync() async {
  // A queue barrier, not a wall-clock race: drain continuations after opening
  // injected gates, including the method-channel microtasks they create.
  await Future<void>(() {});
  await Future<void>(() {});
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late RoutingNative nativeFake;
  final stores = <AppStore>[];
  AppStore store(Lookup lookup) {
    final s = MemoryStore(lookup)..autoReconnect = false;
    s.profiles.add(
      const Profile(
        id: 'awg1',
        name: 'synthetic',
        protocol: 'awg',
        endpoint: '203.0.113.1:51820',
      ),
    );
    s.selectedId = 'awg1';
    stores.add(s);
    return s;
  }

  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    nativeFake = RoutingNative();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, nativeFake.handle);
  });
  tearDown(() async {
    for (final s in stores) {
      s.dispose();
    }
    stores.clear();
    await flushAsync();
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(native, null);
  });

  test(
    '65 distinct rules refuse activation without installing a subset',
    () async {
      nativeFake.domains = List.generate(65, (i) => 'd$i.example.org');
      final lookup = Lookup(
        (host) async => [
          '192.0.2.${int.parse(host.split('.').first.substring(1)) + 1}',
        ],
      );
      final s = store(lookup);
      await s.connect();
      expect(lookup.calls, lessThanOrEqualTo(64));
      expect(nativeFake.connects, 0);
      expect(nativeFake.applied, isEmpty);
      expect(s.error, isNotNull);
    },
  );
  test(
    '97 answers refuse activation with the 96 address budget intact',
    () async {
      final s = store(
        Lookup((_) async => List.generate(97, (i) => '192.0.2.${i + 1}')),
      );
      await s.connect();
      expect(nativeFake.connects, 0);
      expect(nativeFake.applied, isEmpty);
    },
  );
  test('128 manual networks leave no capacity for a domain answer', () async {
    nativeFake.networks = List.generate(128, (i) => '10.0.$i.0/24');
    final s = store(Lookup((_) async => ['192.0.2.1']));
    await s.connect();
    expect(nativeFake.connects, 0);
    expect(nativeFake.applied, isEmpty);
  });
  test('empty and partial DNS answers refuse an incomplete policy', () async {
    nativeFake.domains = ['empty.example.org', 'ok.example.org'];
    final s = store(
      Lookup((host) async => host.startsWith('empty') ? [] : ['192.0.2.1']),
    );
    await s.connect();
    expect(nativeFake.connects, 0);
    expect(nativeFake.applied, isEmpty);
  });
  test(
    'failed native apply retries instead of reporting a fresh cache hit',
    () async {
      final s = store(Lookup((_) async => ['192.0.2.1']));
      nativeFake.failApply = true;
      await expectLater(
        s.syncSplitDomains(),
        throwsA(isA<PlatformException>()),
      );
      expect(s.splitSync.addresses, isEmpty);
      nativeFake.failApply = false;
      await s.syncSplitDomains();
      expect(nativeFake.applyCalls, 2);
      expect(nativeFake.applied, [
        ['192.0.2.1'],
      ]);
    },
  );
  test('failed clear preserves prior applied state and retries', () async {
    final s = store(Lookup((_) async => ['192.0.2.1']));
    await s.syncSplitDomains();
    nativeFake.edit([]);
    nativeFake.failApply = true;
    await expectLater(s.syncSplitDomains(), throwsA(isA<PlatformException>()));
    expect(s.splitSync.addresses, ['192.0.2.1']);
    nativeFake.failApply = false;
    await s.syncSplitDomains();
    expect(nativeFake.applyCalls, 3);
    expect(nativeFake.applied.last, isEmpty);
  });
  for (final cause in [
    'expired',
    'restart',
    'policy edit',
    'cache missing',
    'force',
  ]) {
    test(
      '$cause provenance requires one fresh lookup then permits owned reuse',
      () async {
        final lookup = Lookup((_) async => ['192.0.2.1']);
        final s = store(lookup);
        await s.syncSplitDomains();
        final oldId = nativeFake.origin;
        if (cause == 'expired') nativeFake.elapsed = 600000;
        if (cause == 'restart') nativeFake.origin = null;
        if (cause == 'policy edit') {
          nativeFake.edit(List.of(nativeFake.domains));
        }
        if (cause == 'cache missing') s.splitSync.invalidate();
        await s.syncSplitDomains(force: cause == 'force');
        expect(lookup.calls, 2);
        expect(nativeFake.origin, isNot(oldId));
        await s.syncSplitDomains();
        expect(lookup.calls, 2);
        expect(nativeFake.applied, hasLength(3));
      },
    );
  }

  for (final newer in [false, true]) {
    test(
      'old gated connect never applies after DOWN (new policy=$newer)',
      () async {
        final entered = Completer<void>();
        final release = Completer<List<String>>();
        final s = store(
          Lookup((host) {
            if (host.startsWith('old')) {
              entered.complete();
              return release.future;
            }
            return Future.value(['192.0.2.2']);
          }),
        );
        final pending = s.connect();
        await entered.future;
        await s.disconnect();
        await pending;
        expect(s.busy, isFalse);
        if (newer) {
          nativeFake.edit(['new.example.org']);
          await s.syncSplitDomains(force: true);
        }
        release.complete(['192.0.2.1']);
        await flushAsync();
        expect(
          nativeFake.applied,
          newer
              ? [
                  ['192.0.2.2'],
                ]
              : isEmpty,
        );
        expect(s.splitSync.addresses, newer ? ['192.0.2.2'] : isEmpty);
      },
    );
  }
  test(
    'late begin reply cannot start DNS or cancel a newer native lease',
    () async {
      final entered = Completer<void>();
      final release = Completer<void>();
      var begins = 0;
      nativeFake.beginGate = (_) async {
        if (++begins == 1) {
          entered.complete();
          await release.future;
        }
      };
      final lookup = Lookup((_) async => ['192.0.2.2']);
      final s = store(lookup);
      final pending = s.connect();
      await entered.future;
      await s.disconnect();
      await pending;
      nativeFake.edit(['new.example.org']);
      await s.syncSplitDomains();
      final winningLease = nativeFake.ready;
      release.complete();
      await flushAsync();
      expect(lookup.calls, 1);
      expect(nativeFake.ready, winningLease);
      expect(winningLease, isNotNull);
      expect(nativeFake.applied, [
        ['192.0.2.2'],
      ]);
    },
  );
  test(
    'rule edit during apply rejects write and never commits stale cache',
    () async {
      final entered = Completer<void>();
      final release = Completer<void>();
      nativeFake.applyGate = () async {
        entered.complete();
        await release.future;
      };
      final s = store(Lookup((_) async => ['192.0.2.1']));
      final pending = s.syncSplitDomains();
      final rejected = expectLater(pending, throwsA(isA<PlatformException>()));
      await entered.future;
      nativeFake.edit(['new.example.org']);
      await s.setSplitDomains(['new.example.org']);
      release.complete();
      await rejected;
      expect(nativeFake.applied, isEmpty);
      expect(s.splitSync.addresses, isEmpty);
    },
  );
  test(
    'DOWN/new connect re-applies fresh cached DNS under a new native lease',
    () async {
      final lookup = Lookup((_) async => ['192.0.2.1']);
      final s = store(lookup)..siteCheckEnabled = true;
      nativeFake.successful = true;
      await s.connect();
      expect(s.status.active, isTrue);
      final oldLease = nativeFake.ready;
      await s.disconnect();
      expect(nativeFake.ready, isNull);
      await s.connect();
      expect(s.status.active, isTrue);
      expect(lookup.calls, 1);
      expect(nativeFake.applied, [
        ['192.0.2.1'],
        ['192.0.2.1'],
      ]);
      expect(nativeFake.ready, isNot(oldLease));
      expect(nativeFake.appliedLeases.toSet(), hasLength(2));
    },
  );
  test(
    'empty domain standard policy needs no DNS and connects normally',
    () async {
      nativeFake.domains = [];
      nativeFake.successful = true;
      final lookup = Lookup((_) async => throw StateError('unexpected DNS'));
      final s = store(lookup)..siteCheckEnabled = true;
      await s.connect();
      expect(s.status.active, isTrue);
      expect(lookup.calls, 0);
      expect(nativeFake.applied, [<String>[]]);
    },
  );
  test(
    'a new admitted connect revokes an older standalone resolution',
    () async {
      final entered = Completer<void>();
      final release = Completer<List<String>>();
      final s = store(
        Lookup((host) {
          if (host.startsWith('old')) {
            entered.complete();
            return release.future;
          }
          return Future.value(['192.0.2.2']);
        }),
      );
      final old = s.syncSplitDomains();
      final rejected = expectLater(old, throwsA(isA<PlatformException>()));
      await entered.future;
      nativeFake.edit(['new.example.org']);
      await s.connect();
      release.complete(['192.0.2.1']);
      await rejected;
      expect(nativeFake.applied, [
        ['192.0.2.2'],
      ]);
    },
  );
  test(
    'dispose revokes gated resolver even without a replacement refresh',
    () async {
      final entered = Completer<void>();
      final release = Completer<List<String>>();
      final s = store(
        Lookup((_) {
          entered.complete();
          return release.future;
        }),
      );
      final pending = s.syncSplitDomains();
      final rejected = expectLater(pending, throwsA(isA<PlatformException>()));
      await entered.future;
      s.dispose();
      stores.remove(s);
      release.complete(['192.0.2.1']);
      await rejected;
      expect(nativeFake.applied, isEmpty);
    },
  );
}
