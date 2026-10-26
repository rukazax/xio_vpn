import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/managed_service.dart';
import 'package:xio/managed_models.dart';

void main() {
  test('management key is standard Ed25519 and signs using the matching public key', () async {
    final generated = await newManagementKey();
    final pair = SSHKeyPair.fromPem(generated.$1).single;
    expect(pair.name, 'ssh-ed25519');
    expect(
      base64Encode(pair.toPublicKey().encode()),
      generated.$2.split(' ')[1],
    );
    expect(
      pair.sign(Uint8List.fromList(utf8.encode('XIO key test'))).encode(),
      isNotEmpty,
    );
  });
  test(
    'delegated bundle transports restricted key but never a root password',
    () async {
      final generated = await newManagementKey();
      final id = 'a' * 32;
      final server = ManagedServer(
        id: 'server',
        host: 'vpn.example',
        actorId: id,
        country: 'DE',
      );
      final bundle = UserBundle(
        'Admin',
        id,
        'server',
        {'awg': 'test fixture'},
        adminAccess: {
          'server': server.toJson(),
          'key': generated.$1,
          'limit': 3,
        },
      );
      final copy = UserBundle.decode(bundle.encode());
      expect(copy.adminAccess!['server']['actorId'], id);
      expect(copy.adminAccess!['limit'], 3);
      expect(copy.adminAccess!.containsKey('password'), false);
      final bad = {...copy.adminAccess!, 'password': 'not-a-real-password'};
      expect(
        () => UserBundle.decode(
          UserBundle('Bad', id, 'server', {
            'awg': 'fixture',
          }, adminAccess: bad).encode(),
        ),
        throwsFormatException,
      );
      expect(server.flag, '🇩🇪');
    },
  );
}
