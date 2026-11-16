import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/connection_attempt.dart';
import 'package:xio/desktop_engine.dart';
import 'package:xio/engine_channel.dart';
import 'package:xio/policy_channel.dart';

/// Actual composition regression: no mock method channel, no helper launch.
/// With DesktopEngine enabled on this desktop host:
/// - valid internal policyState {version:1, instanceNonce} projects to the
///   Go read-only Method-only query and reaches the typed POLICY_UNSUPPORTED
///   guard (no helper);
/// - bad/extra/missing fields are rejected at the desktop boundary with
///   POLICY_INVALID instead of being silently stripped or forwarded;
/// - policyValidate still takes the typed policy dispatch path.
/// Response nonce binding is covered by PolicyNativeState below.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('EngineChannel projects a valid policyState query', () async {
    expect(Platform.isLinux || Platform.isWindows, isTrue);
    DesktopEngine.enabled = true;
    const channel = EngineChannel();
    try {
      await expectLater(
        channel.invokeMethod<Object?>('policyState', {
          'version': 1,
          'instanceNonce': 'c' * 32,
        }),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'POLICY_UNSUPPORTED',
          ),
        ),
        reason: 'valid query is projected; no helper means the known guard',
      );
    } finally {
      DesktopEngine.enabled = false;
    }
  });

  test('EngineChannel rejects non-exact policyState payloads', () async {
    DesktopEngine.enabled = true;
    const channel = EngineChannel();
    final bad = <String, Map<String, dynamic>>{
      'extra': {'version': 1, 'instanceNonce': 'c' * 32, 'extra': true},
      'missing': {'version': 1},
      'bad version': {'version': '1', 'instanceNonce': 'c' * 32},
      'wrong version': {'version': 2, 'instanceNonce': 'c' * 32},
      'bad nonce': {'version': 1, 'instanceNonce': 7},
      'empty nonce': {'version': 1, 'instanceNonce': ''},
    };
    try {
      for (final entry in bad.entries) {
        await expectLater(
          channel.invokeMethod<Object?>('policyState', entry.value),
          throwsA(
            isA<PlatformException>().having(
              (e) => e.code,
              'code',
              'POLICY_INVALID',
            ),
          ),
          reason: entry.key,
        );
      }
    } finally {
      DesktopEngine.enabled = false;
    }
  });

  test('policyValidate still uses the typed policy dispatch', () async {
    DesktopEngine.enabled = true;
    const channel = EngineChannel();
    try {
      await expectLater(
        channel.invokeMethod<Object?>('policyValidate', {
          'version': 1,
          'instanceNonce': 'c' * 32,
          'transactionId': 'd' * 32,
          'planGeneration': 'e' * 32,
          'validation': <String, Object?>{},
        }),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'POLICY_UNSUPPORTED',
          ),
        ),
      );
    } finally {
      DesktopEngine.enabled = false;
    }
  });

  test('a state response for another instance is still rejected', () {
    expect(
      () => PolicyNativeState.parse(
        {
          'version': 1,
          'instanceNonce': 'f' * 32,
          'state': 'blocked',
          'resourceState': 'unknown',
        },
        instance: 'c' * 32,
      ),
      throwsA(
        isA<PolicyFailure>().having((e) => e.code, 'code', 'POLICY_UNKNOWN'),
      ),
    );
  });
}
