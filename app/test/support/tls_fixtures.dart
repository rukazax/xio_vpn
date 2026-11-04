import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as hashes;

/// Checked-in TLS fixtures — self-signed certificates for loopback tests.
///
/// The tests used to shell out to the `openssl` binary, which made them depend
/// on a tool the host may not have (Windows without Git-Bash/OpenSSL failed in
/// `Process.run`, so four tests were "pre-existing failures"). The certificates
/// are static now, so the suite is hermetic and needs neither `openssl` nor a
/// network.
///
/// Fixtures live in `test/fixtures/tls` and are valid 2020-01-01 … 2120-01-01,
/// i.e. a machine clock that is slightly off cannot make them "not yet valid".
/// They are test-only material: the private keys are public by construction and
/// are never used by the shipped application.
const String tlsFixtureDirectory = 'test/fixtures/tls';

/// Name of the fixture the API/HTTPS tests trust or pin.
const String localhostFixture = 'localhost';

/// Name of the fixture that no test trusts (negative handshake tests).
const String untrustedFixture = 'untrusted';

/// Absolute path of a fixture file.
///
/// `Directory.current` is the package root while `flutter test` runs; the
/// extra candidates keep the helper usable from a nested working directory.
String tlsFixturePath(String name, {String kind = 'cert'}) {
  final relative = '$tlsFixtureDirectory/$name-$kind.pem';
  for (final base in <Directory>[
    Directory.current,
    Directory.current.parent,
  ]) {
    for (final candidate in <Directory>[
      base,
      Directory('${base.path}/app'),
    ]) {
      final file = File('${candidate.path}/$relative');
      if (file.existsSync()) return file.path;
    }
  }
  throw StateError('TLS fixture "$relative" is missing');
}

/// Server-side context serving the fixture certificate.
SecurityContext tlsServerContext({String name = localhostFixture}) =>
    SecurityContext()
      ..useCertificateChain(tlsFixturePath(name))
      ..usePrivateKey(tlsFixturePath(name, kind: 'key'));

/// Client context trusting exactly one fixture certificate (and no system root).
SecurityContext tlsClientContext({String name = localhostFixture}) =>
    SecurityContext(withTrustedRoots: false)
      ..setTrustedCertificates(tlsFixturePath(name));

/// DER bytes of the fixture certificate, as sent by the server.
List<int> tlsFixtureDer({String name = localhostFixture}) {
  final pem = File(tlsFixturePath(name)).readAsStringSync();
  return base64Decode(pem.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''));
}

/// Certificate pin (`sha256` of the DER bytes) as used by `AccountAccess`.
String tlsFixturePin({String name = localhostFixture}) =>
    hashes.sha256.convert(tlsFixtureDer(name: name)).toString();
