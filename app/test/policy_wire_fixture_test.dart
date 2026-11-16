import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_attempt.dart';
import 'package:xio/policy_channel.dart';
import 'package:xio/policy_publication.dart';

/// Cross-language oracle: the Dart side must emit exactly the JSON the Android
/// native worker accepts (work/report/android-native-policy-20261106/
/// WIRE-DELTA-ANDROID.md at 849a677, wire commit e7c9e6d). A same-language fake
/// answering its own shape is not evidence of interoperability.
void main() {
  final fixture = Map<String, dynamic>.from(
    jsonDecode(File('test/fixtures/policy-wire-android.json').readAsStringSync())
        as Map,
  );
  Map<String, dynamic> part(String key) =>
      Map<String, dynamic>.from(fixture[key] as Map);

  PublicationSnapshot snapshot() => PublicationSnapshot(
    transactionId: part('identity')['transactionId'] as String,
    generation: part('identity')['planGeneration'] as String,
    document: const {},
    plan: part('plan'),
  );

  PolicyChannel channel(List<MethodCallLike> calls, {String state = 'ready'}) =>
      PolicyChannel(
        invoke: (method, arguments) async {
          calls.add(MethodCallLike(method, arguments));
          return switch (method) {
            'policyCapabilities' => part('capabilities'),
            'policyBegin' => part('beginAck'),
            'policyCommit' => part('commitAck'),
            'policyReconcile' => part('commitAck'),
            'policyAbort' => part('abortResponse'),
            _ => null,
          };
        },
        storeIdentity: part('identity')['storeIdentity'] as String,
        controllerNonce: part('identity')['controllerNonce'] as String,
      );

  test('capabilities fixture parses exactly', () async {
    final calls = <MethodCallLike>[];
    final subject = channel(calls);
    await subject.discover();
    expect(subject.instanceNonce, part('identity')['instanceNonce']);
    expect(subject.state, 'ready');
    expect(subject.resourceState, 'clean');
  });

  test('begin/commit request is byte-equal to the Android fixture', () async {
    final calls = <MethodCallLike>[];
    final subject = channel(calls);
    await subject.discover();
    final transaction = subject.transaction(snapshot());
    final built = subject.request(snapshot());
    expect(built, part('beginRequest'));
    expect(built.keys.toList(), [
      'version',
      'storeIdentity',
      'controllerNonce',
      'instanceNonce',
      'transactionId',
      'expectedGeneration',
      'planGeneration',
      'plan',
    ]);
    await transaction.begin();
    await transaction.commit();
    expect(calls.map((call) => call.method), [
      'policyCapabilities',
      'policyBegin',
      'policyCommit',
    ]);
    expect(calls[1].arguments, part('beginRequest'));
    expect(calls[2].arguments, part('beginRequest'));
    expect(subject.committed?.planGeneration, part('identity')['planGeneration']);
  });

  test('abort emits exactly {version, instanceNonce, transactionId}', () async {
    final calls = <MethodCallLike>[];
    final subject = channel(calls);
    await subject.discover();
    final transaction = subject.transaction(snapshot());
    await transaction.begin();
    await transaction.block();
    expect(calls.last.method, 'policyAbort');
    expect(calls.last.arguments, part('abortRequest'));
    expect(subject.receipt, isNull);
  });

  test('the six-field ACK remains authoritative for state changes', () async {
    final calls = <MethodCallLike>[];
    final subject = PolicyChannel(
      invoke: (method, arguments) async {
        calls.add(MethodCallLike(method, arguments));
        return switch (method) {
          'policyCapabilities' => part('capabilities'),
          'policyBegin' => part('beginAck'),
          'policyCommit' => {...part('commitAck'), 'unexpected': true},
          _ => null,
        };
      },
      storeIdentity: part('identity')['storeIdentity'] as String,
      controllerNonce: part('identity')['controllerNonce'] as String,
    );
    await subject.discover();
    final transaction = subject.transaction(snapshot());
    await transaction.begin();
    await expectLater(
      transaction.commit(),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_UNKNOWN'),
      ),
    );
    expect(subject.receipt, isNull);
  });
}

class MethodCallLike {
  const MethodCallLike(this.method, this.arguments);
  final String method;
  final Object? arguments;
}
