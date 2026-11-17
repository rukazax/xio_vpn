import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_native.dart';

/// The cascade bridge scripts exist three times: `deploy/cascade/native/*.sh`
/// (what an operator runs by hand) and the same text embedded in
/// `app/lib/cascade_native.dart` (what the wizard installs). They had already
/// drifted silently — the deploy copy routed every transport while the app copy
/// still hardcoded `iif xioawg0`, so a phone-installed cascade only carried AWG
/// and the other transports kept exiting from the RU address.
///
/// This gate compares the two copies byte for byte, so a rule added to one side
/// cannot ship without the other.
void main() {
  /// Repository root from the app package directory (flutter test cwd).
  Directory repoRoot() {
    var dir = Directory.current;
    for (var i = 0; i < 4; i++) {
      if (Directory('${dir.path}/deploy/cascade/native').existsSync()) return dir;
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    fail('deploy/cascade/native not found above ${Directory.current.path}');
  }

  String deployScript(String name) =>
      File('${repoRoot().path}/deploy/cascade/native/$name').readAsStringSync();

  /// The app copy deliberately has no baked-in exit address: the wizard always
  /// supplies one. Everything else must match exactly.
  String appVariant(String script) => script.replaceFirst(
        'EXIT_HOST=\${XIO_CASCADE_EXIT_HOST:-103.102.135.124}',
        'EXIT_HOST=\${XIO_CASCADE_EXIT_HOST:?XIO_CASCADE_EXIT_HOST is required}',
      );

  test('embedded bridge up script matches deploy copy', () {
    final deploy = deployScript('xio-cascade-bridge-up.sh');
    expect(
      cascadeBridgeUpScript,
      appVariant(deploy),
      reason: 'app/lib/cascade_native.dart drifted from '
          'deploy/cascade/native/xio-cascade-bridge-up.sh',
    );
  });

  test('embedded bridge down script matches deploy copy', () {
    expect(
      cascadeBridgeDownScript,
      deployScript('xio-cascade-bridge-down.sh'),
      reason: 'app/lib/cascade_native.dart drifted from '
          'deploy/cascade/native/xio-cascade-bridge-down.sh',
    );
  });

  test('bridge scripts route every transport, not just AWG', () {
    expect(cascadeBridgeUpScript, contains('CLIENT_IFS'),
        reason: 'client interfaces must be discovered, not hardcoded');
    expect(cascadeBridgeUpScript, contains(r'name ~ /^xio/'),
        reason: 'the xio* interface filter is the discovery contract');
    expect(cascadeBridgeUpScript, contains(r'fwmark ${XIO_CASCADE_MARK:-0x518}'),
        reason: 'locally generated transport traffic needs the mark');
    // Teardown must find the rules it installed even after an interface vanished.
    expect(cascadeBridgeDownScript, contains('ip rule show'));
    expect(cascadeBridgeDownScript, contains('lookup 51888'));
    for (final script in [cascadeBridgeUpScript, cascadeBridgeDownScript]) {
      expect(script, isNot(contains('iif xioawg0 lookup 51888')),
          reason: 'a single hardcoded interface leaves RIVET/Xray out of the cascade');
    }
  });
}
