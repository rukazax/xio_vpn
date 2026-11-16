import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_attempt.dart';
import 'package:xio/connection_plan.dart';
import 'package:xio/policy_channel.dart';
import 'package:xio/policy_publication.dart';

const _tx = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const _gen = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const _store = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';

Map<String, dynamic> planFor(String mode, {List<String> ids = const ['awg1']}) => {
  'schema': 2,
  'selectedId': 'awg1',
  'ids': ids,
  'profiles': [for (final id in ids) {'id': id, 'configDigest': 'c' * 64}],
  'policy': {'mode': mode, 'roundMillis': 30000},
};

PublicationSnapshot snapshot(
  [String mode = 'automatic', List<String> ids = const ['awg1']]) =>
    PublicationSnapshot(
      transactionId: _tx,
      generation: _gen,
      document: {},
      plan: planFor(mode, ids: ids),
    );

PolicyReceipt receipt({String generation = _gen}) => PolicyReceipt.parse({
  'version': 1,
  'storeIdentity': _store,
  'instanceNonce': 'c' * 32,
  'controllerNonce': 'e' * 32,
  'transactionId': _tx,
  'planGeneration': generation,
});

Map<String, dynamic> ack(Map request, String state) => {
  'version': 1,
  'instanceNonce': request['instanceNonce'],
  'controllerNonce': request['controllerNonce'],
  'transactionId': request['transactionId'],
  'planGeneration': request['planGeneration'],
  'state': state,
};

PolicyChannel channel(PolicyInvoke invoke) =>
    PolicyChannel(invoke: invoke, storeIdentity: _store, controllerNonce: 'e' * 32);

Matcher policyFailure(String code) =>
    throwsA(isA<PolicyFailure>().having((e) => e.code, 'code', code));

void main() {
  test('strict persisted schema accepts missing only as automatic default', () {
    expect(ConnectionPolicy.fromDocument({}), ConnectionPolicy.automatic);
    for (final policy in ConnectionPolicy.values) {
      expect(ConnectionPolicy.parse(policy.toJson()), policy);
    }
    for (final invalid in [
      null,
      true,
      'automatic',
      <String, Object?>{},
      {'mode': 'automatic'},
      {'mode': 'selectedOnly', 'roundMillis': 30000.0},
      {'mode': 'selectedOnly', 'roundMillis': '30000'},
      {'mode': 'future', 'roundMillis': 30000},
      {'mode': 'automatic', 'roundMillis': 30001},
      {'mode': 'automatic', 'roundMillis': 30000, 'future': true},
    ]) {
      expect(
        () => ConnectionPolicy.fromDocument({'connectionPolicy': invalid}),
        throwsFormatException,
      );
    }
  });

  test('receipt parse is exact and round-trips the wire shape', () {
    final value = receipt();
    expect(PolicyReceipt.parse(value.toJson()), value);
    expect(value.toJson().keys.first, 'version');
    for (final broken in <Object?>[
      null,
      <String, Object?>{},
      {...value.toJson(), 'version': 2},
      {...value.toJson(), 'version': 1.0},
      {...value.toJson(), 'extra': true},
      {...value.toJson(), 'storeIdentity': 'D' * 64},
      {...value.toJson(), 'instanceNonce': 'c' * 31},
      {...value.toJson(), 'planGeneration': 'g' * 32},
      ({...value.toJson()}..remove('transactionId')),
    ]) {
      expect(() => PolicyReceipt.parse(broken), throwsFormatException);
    }
  });

  for (final response in <Object?>[
    null,
    true,
    <String, Object?>{},
    {'version': 1},
    {'version': 0},
    {'version': 1.0, 'instanceNonce': 'c' * 32, 'state': 'ready', 'resourceState': 'clean'},
    {'version': 1, 'instanceNonce': 'C' * 32, 'state': 'ready', 'resourceState': 'clean'},
    {'version': 1, 'instanceNonce': 'c' * 32, 'state': 'manual', 'resourceState': 'clean'},
    {'version': 1, 'instanceNonce': 'c' * 32, 'state': 'ready', 'resourceState': null},
  ]) {
    test('unsupported or malformed capability never downgrades: $response', () async {
      final subject = channel((_, _) async => response);
      await expectLater(subject.discover(), policyFailure('POLICY_UNSUPPORTED'));
      expect(subject.receipt, isNull);
      expect(subject.committed, isNull);
      expect(subject.ready, isFalse);
    });
  }

  for (final broken in ['null', 'extra', 'nonce', 'generation', 'state']) {
    test('transport success with $broken receipt does not publish ready', () async {
      final subject = channel((method, arguments) async {
        if (method == 'policyCapabilities') {
          return {'version': 1, 'instanceNonce': 'c' * 32, 'state': 'blocked', 'resourceState': 'clean'};
        }
        final request = arguments as Map;
        if (method == 'policyBegin') return ack(request, 'pending');
        final response = ack(request, 'ready');
        switch (broken) {
          case 'null':
            return null;
          case 'extra':
            response['unrecognized'] = true;
          case 'nonce':
            response['instanceNonce'] = 'f' * 32;
          case 'generation':
            response['planGeneration'] = 'f' * 32;
          case 'state':
            response['state'] = 'pending';
        }
        return response;
      });
      await subject.discover();
      final transaction = subject.transaction(snapshot());
      await transaction.begin();
      await expectLater(transaction.commit(), policyFailure('POLICY_UNKNOWN'));
      expect(subject.receipt, isNull);
      expect(subject.committed, isNull);
    });
  }

  test('late commit reply after helper restart cannot authorize old instance', () async {
    var instance = 'c' * 32;
    final entered = Completer<void>();
    final reply = Completer<Object?>();
    late Map request;
    final subject = channel((method, arguments) async {
      if (method == 'policyCapabilities') {
        return {'version': 1, 'instanceNonce': instance, 'state': 'blocked', 'resourceState': 'clean'};
      }
      request = arguments as Map;
      if (method == 'policyBegin') return ack(request, 'pending');
      entered.complete();
      return reply.future;
    });
    await subject.discover();
    final transaction = subject.transaction(snapshot());
    await transaction.begin();
    final failed = expectLater(transaction.commit(), policyFailure('POLICY_STALE'));
    await entered.future;
    final old = Map.of(request);
    instance = 'f' * 32;
    await subject.discover();
    reply.complete(ack(old, 'ready'));
    await failed;
    expect(subject.receipt, isNull);
  });

  test('exact ready receipt binds the next expected generation and abort is blocked', () async {
    final requests = <Map>[];
    final subject = channel((method, arguments) async {
      if (method == 'policyCapabilities') {
        return {'version': 1, 'instanceNonce': 'c' * 32, 'state': 'blocked', 'resourceState': 'clean'};
      }
      final request = arguments as Map;
      requests.add(request);
      return ack(request, switch (method) {
        'policyBegin' => 'pending',
        'policyCommit' => 'ready',
        _ => 'blocked',
      });
    });
    await subject.discover();
    final transaction = subject.transaction(snapshot());
    await transaction.begin();
    await transaction.commit();
    expect(subject.receipt?['planGeneration'], _gen);
    expect(subject.receipt?['storeIdentity'], _store);
    expect(subject.committed, receipt());
    expect(subject.ready, isTrue);
    expect(subject.request(snapshot())['expectedGeneration'], _gen);
    await transaction.block();
    expect(subject.receipt, isNull);
    expect(subject.committed, isNull);
    expect(subject.ready, isFalse);
    expect(requests.map((r) => r['expectedGeneration']), [null, null, null]);
  });

  group('activation attachment', () {
    test('android carries the typed receipt including storeIdentity', () {
      final arguments = PolicyActivation.arguments(
        snapshot: snapshot('selectedOnly'),
        candidateId: 'awg1',
        receipt: receipt(),
        receiptRequired: true,
      );
      expect(arguments, {'policyReceipt': receipt().toJson()});
      final encoded = (arguments['policyReceipt'] as Map);
      expect(encoded['storeIdentity'], _store);
      expect(encoded.keys, ['version', 'storeIdentity', 'instanceNonce', 'controllerNonce', 'transactionId', 'planGeneration']);
    });

    test('desktop carries the same receipt as one JSON string', () {
      final arguments = PolicyActivation.arguments(
        snapshot: snapshot('selectedOnly'),
        candidateId: 'awg1',
        receipt: receipt(),
        receiptRequired: true,
        platform: PolicyPlatform.desktop,
      );
      expect(arguments.keys, ['PolicyReceiptJSON']);
      expect(jsonDecode(arguments['PolicyReceiptJSON'] as String), receipt().toJson());
    });

    test('receipt of another generation is POLICY_STALE', () {
      expect(
        () => PolicyActivation.arguments(
          snapshot: snapshot(),
          candidateId: 'awg1',
          receipt: receipt(generation: 'f' * 32),
          receiptRequired: true,
        ),
        policyFailure('POLICY_STALE'),
      );
    });

    test('candidate outside the committed plan is POLICY_STALE', () {
      expect(
        () => PolicyActivation.arguments(
          snapshot: snapshot(),
          candidateId: 'xr9',
          receipt: receipt(),
          receiptRequired: true,
        ),
        policyFailure('POLICY_STALE'),
      );
    });

    for (final ids in [
      ['awg1', 'xr2'],
      ['xr2'],
    ]) {
      test('manual activation of $ids is not the sole selected profile', () {
        expect(
          () => PolicyActivation.arguments(
            snapshot: snapshot('selectedOnly', ids),
            candidateId: 'awg1',
            receipt: receipt(),
            receiptRequired: true,
          ),
          policyFailure('POLICY_STALE'),
        );
      });
    }

    test('pristine legacy document keeps the untouched automatic path', () {
      expect(PolicyActivation.receiptRequired({}), isFalse);
      expect(
        PolicyActivation.arguments(
          snapshot: snapshot(),
          candidateId: 'awg1',
          receipt: null,
          receiptRequired: PolicyActivation.receiptRequiredFor(
            {'selected': 'awg1', 'profiles': []},
            publicationPendingOrUnknown: false,
          ),
        ),
        isEmpty,
      );
    });

    for (final document in <Map<String, dynamic>>[
      {'connectionPolicy': {'mode': 'selectedOnly', 'roundMillis': 30000}},
      {'connectionPlanReceipt': <String, Object?>{}},
    ]) {
      test('versioned document ${document.keys.single} requires a receipt', () {
        expect(PolicyActivation.receiptRequired(document), isTrue);
        expect(
          () => PolicyActivation.arguments(
            snapshot: snapshot(),
            candidateId: 'awg1',
            receipt: null,
            receiptRequired: PolicyActivation.receiptRequiredFor(
              document,
              publicationPendingOrUnknown: false,
            ),
          ),
          policyFailure('POLICY_UNSUPPORTED'),
        );
      });
    }

    test('pending or unknown publication also requires a receipt', () {
      final document = <String, dynamic>{'selected': 'awg1'};
      expect(PolicyActivation.receiptRequired(document), isFalse);
      expect(
        () => PolicyActivation.arguments(
          snapshot: snapshot(),
          candidateId: 'awg1',
          receipt: null,
          receiptRequired: PolicyActivation.receiptRequiredFor(
            document,
            publicationPendingOrUnknown: true,
          ),
        ),
        policyFailure('POLICY_UNSUPPORTED'),
      );
    });

    test('automatic plan may start from a non-selected candidate', () {
      expect(
        PolicyActivation.arguments(
          snapshot: snapshot('automatic', ['awg1', 'xr2']),
          candidateId: 'xr2',
          receipt: receipt(),
          receiptRequired: true,
        ),
        isNotEmpty,
      );
    });
  });

  group('desktop validation receipt and bounds', () {
    PolicyChannel validating(Map<String, Object?> response) => PolicyChannel(
      invoke: (method, arguments) async {
        if (method == 'policyCapabilities') {
          return {
            'version': 1,
            'instanceNonce': 'c' * 32,
            'state': 'blocked',
            'resourceState': 'clean',
            'validation': 1,
          };
        }
        if (method == 'policyBegin') {
          return {
            'version': 1,
            'instanceNonce': 'c' * 32,
            'controllerNonce': 'e' * 32,
            'transactionId': _tx,
            'planGeneration': _gen,
            'state': 'pending',
          };
        }
        if (method == 'policyCommit') {
          return {
            'version': 1,
            'instanceNonce': 'c' * 32,
            'controllerNonce': 'e' * 32,
            'transactionId': _tx,
            'planGeneration': _gen,
            'state': 'ready',
          };
        }
        return response;
      },
      storeIdentity: _store,
      controllerNonce: 'e' * 32,
    );

    Map<String, Object?> receipt(Map<String, Object?> validation) => {
      'version': 1,
      'instanceNonce': 'c' * 32,
      'controllerNonce': 'e' * 32,
      'transactionId': _tx,
      'documentDigest': validation['documentDigest'],
    };

    test('exact five-field validation ACK is accepted', () async {
      final validation = PolicyValidation.build(
        documentBytes: '{"schema":2}',
        configs: {'awg1': 'cfg'},
      );
      final subject = validating(receipt(validation));
      await subject.discover();
      expect(subject.validationSupported, isTrue);
      final transaction = subject.transaction(snapshot());
      await transaction.begin();
      await transaction.validate(validation);
      expect(subject.receipt, isNull); // not READY
    });

    for (final broken in ['controller', 'digest', 'extra', 'state']) {
      test('validation ACK with $broken is POLICY_UNVERIFIED', () async {
        final validation = PolicyValidation.build(
          documentBytes: '{"schema":2}',
          configs: {'awg1': 'cfg'},
        );
        final response = receipt(validation);
        switch (broken) {
          case 'controller':
            response['controllerNonce'] = 'f' * 32;
          case 'digest':
            response['documentDigest'] = 'f' * 64;
          case 'extra':
            response['state'] = 'validated';
          case 'state':
            response.remove('documentDigest');
            response['state'] = 'validated';
        }
        final subject = validating(response);
        await subject.discover();
        final transaction = subject.transaction(snapshot());
        await transaction.begin();
        await expectLater(
          transaction.validate(validation),
          throwsA(
            isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_UNVERIFIED'),
          ),
        );
      });
    }

    test('wire guards reject oversized inputs', () {
      expect(
        () => PolicyValidation.build(
          documentBytes: 'x' * (512 * 1024 + 1),
          configs: {'awg1': 'cfg'},
        ),
        throwsA(
          isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_OVERSIZE'),
        ),
      );
      expect(
        () => PolicyValidation.build(
          documentBytes: 'doc',
          configs: {'awg1': 'x' * 200001},
        ),
        throwsA(
          isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_OVERSIZE'),
        ),
      );
      // Exactly at the per-config guard is accepted.
      final value = PolicyValidation.build(
        documentBytes: 'doc',
        configs: {'awg1': 'x' * 200000},
      );
      expect(value['schema'], 1);
    });
  });
}
