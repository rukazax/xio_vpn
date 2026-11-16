import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xio/account_access.dart';
import 'package:xio/build_identity.dart';
import 'package:xio/credentials.dart';
import 'package:xio/desktop_engine.dart';
import 'package:xio/native_cascade_journal.dart';

// Explicit opt-in: run only in a disposable HOME/XDG_DATA_HOME. No channels,
// desktop application, daemon or network are involved in these real-file tests.
void main() {
  final root = Platform.environment['XIO_VAULT_TEST_ROOT'];
  final enabled = Platform.isLinux && root != null;
  late Directory folder;
  setUpAll(() {
    if (!enabled) return;
    expect(Platform.environment['HOME'], '$root/home');
    expect(Platform.environment['XDG_DATA_HOME'], '$root/data');
    folder = Directory('$root/data/$credentialProductDirectory/credentials');
  });

  test('invalid IDs reject before creating any storage', () async {
    expect(await folder.exists(), false);
    for (final id in [
      '',
      '../outside',
      '/tmp/outside',
      r'..\outside',
      'state${'a' * 63}',
      'state${'a' * 65}',
      'state${'A' * 64}',
      'other${'a' * 64}',
      'ssh${'a' * 64}\n',
      'vpn${'a' * 64}/../x',
      'state${'a' * 64}\u0000',
    ]) {
      await expectLater(
        CredentialVault.write(id, {'fake': 'test'}),
        throwsFormatException,
      );
      await expectLater(CredentialVault.read(id), throwsFormatException);
      await expectLater(CredentialVault.delete(id), throwsFormatException);
      expect(await folder.exists(), false, reason: id);
    }
  }, skip: !enabled);

  test('AccountVault real desktop roundtrip and protected modes', () async {
    const server = 'synthetic-server';
    const user = 'synthetic-user';
    final record = <String, dynamic>{
      'access': {'token': 'synthetic-token', 'serverId': server},
      'pending': {
        'id': 'synthetic-operation',
        'private': {'awg': 'synthetic-key'},
      },
    };
    final id = AccountVault.id(server, user);
    expect(id, matches(RegExp(r'^state[a-f0-9]{64}$')));
    final sibling = File(
      '${root!}/data/${clientOnlyBuild ? 'app.xio.xio' : 'app.xio.client'}/credentials/$id.bin',
    );
    await sibling.parent.create(recursive: true);
    await sibling.writeAsString('synthetic-other-product-sentinel');
    expect(await AccountVault.read(server, user), isNull);
    await AccountVault.write(server, user, record);
    expect(await AccountVault.read(server, user), record);
    final file = File('${folder.path}/$id.bin');
    final bytes = await file.readAsBytes();
    expect(
      utf8.decode(bytes, allowMalformed: true),
      isNot(contains('synthetic-token')),
    );
    expect((await folder.stat()).mode & 0x1ff, 0x1c0); // 0700
    expect((await file.stat()).mode & 0x1ff, 0x180); // 0600
    expect(
      (await File('${folder.path}/device.key').stat()).mode & 0x1ff,
      0x180,
    );
    await AccountVault.delete(server, user);
    expect(await AccountVault.read(server, user), isNull);
    expect(await file.exists(), false);
    expect(await sibling.readAsString(), 'synthetic-other-product-sentinel');
  }, skip: !enabled);

  test('existing state ciphertext remains readable and deletable unchanged', () async {
    // Seed the pre-existing format directly, independently of write validation.
    final id = AccountVault.id('legacy-server', 'legacy-user');
    final keyFile = File('${folder.path}/device.key');
    final key = await keyFile.readAsBytes();
    final record = {
      'access': {'token': 'legacy-synthetic'},
    };
    final bytes = (await AesGcm.with256bits().encrypt(
      utf8.encode(jsonEncode({'record': jsonEncode(record)})),
      secretKey: SecretKey(key),
    )).concatenation();
    final file = File('${folder.path}/$id.bin');
    await file.writeAsBytes(bytes, flush: true);
    await Process.run('chmod', ['600', file.path]);
    expect(await AccountVault.read('legacy-server', 'legacy-user'), record);
    expect(await file.readAsBytes(), bytes);
    expect(await keyFile.readAsBytes(), key);
    await AccountVault.delete('legacy-server', 'legacy-user');
    expect(await file.exists(), false);
  }, skip: !enabled);

  test(
    'all existing credential producers roundtrip without renaming',
    () async {
      for (final id in [
        CredentialVault.id('example.invalid', 22, 'test', scope: 'server'),
        NativeCascadeJournalStore.vaultId('a' * 64),
        DesktopEngine.configKey('awg123'),
        'vpn${'0' * 64}', // persisted daemon authentication
      ]) {
        final value = {'synthetic': id};
        await CredentialVault.write(id, value);
        expect(await CredentialVault.read(id), value);
        expect(await File('${folder.path}/$id.bin').exists(), true);
        await CredentialVault.delete(id);
        expect(await CredentialVault.read(id), isNull);
      }
    },
    skip: !enabled,
  );

  test(
    'corrupt ciphertext or existing key fails without replacing material',
    () async {
      const server = 'corrupt-server';
      const user = 'corrupt-user';
      await AccountVault.write(server, user, {'synthetic': 'value'});
      final file = File('${folder.path}/${AccountVault.id(server, user)}.bin');
      final keyFile = File('${folder.path}/device.key');
      final key = await keyFile.readAsBytes();
      final original = await file.readAsBytes();
      final corrupt = List<int>.from(original)..[original.length - 1] ^= 1;
      await file.writeAsBytes(corrupt);
      await expectLater(
        AccountVault.read(server, user),
        throwsA(isA<Exception>()),
      );
      expect(await file.readAsBytes(), corrupt);
      expect(await keyFile.readAsBytes(), key);
      await file.writeAsBytes(original);
      await keyFile.writeAsBytes([1, 2, 3]);
      await expectLater(AccountVault.read(server, user), throwsA(anything));
      expect(await keyFile.readAsBytes(), [1, 2, 3]);
      expect(await file.readAsBytes(), original);
      await keyFile.writeAsBytes(key);
      expect(await AccountVault.read(server, user), {'synthetic': 'value'});
      await AccountVault.delete(server, user);
    },
    skip: !enabled,
  );
}
