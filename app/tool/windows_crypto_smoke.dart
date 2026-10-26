// QA entry point only; not included in the production main library.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/widgets.dart';

import 'package:xio/windows_crypto.dart';
import 'package:xio/credentials.dart';
import 'package:xio/desktop_engine.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final proof = <String, dynamic>{
    'windowsTarget': Platform.isWindows,
    'environment': 'Wine; native Windows still required',
  };
  try {
    if (!Platform.isWindows) throw StateError('Windows target required');
    final data = utf8.encode(
      'XIO DPAPI test data, contains no production secrets',
    );
    final encrypted = windowsCrypt(data, true);
    if (utf8.decode(windowsCrypt(encrypted, false)) != utf8.decode(data)) {
      throw StateError('DPAPI round trip failed');
    }
    proof['currentUserDpapiRoundTrip'] = true;
    proof['ciphertextDiffers'] = base64Encode(encrypted) != base64Encode(data);
    final id = 'vpn${'a' * 64}';
    await CredentialVault.write(id, {'config': 'qa-only'});
    if ((await CredentialVault.read(id))?['config'] != 'qa-only') {
      throw StateError('Encrypted store round trip failed');
    }
    await CredentialVault.delete(id);
    if (await CredentialVault.read(id) != null) {
      throw StateError('Encrypted store delete failed');
    }
    proof['encryptedStorageCrud'] = true;
    await DesktopEngine.initialise();
    if (DesktopEngine.supported.length != 7) {
      throw StateError('Desktop helper missing');
    }
    proof['protocolCapabilities'] = DesktopEngine.supported.toList();
    proof['passed'] = true;
  } catch (e) {
    proof['passed'] = false;
    proof['errorType'] = e.runtimeType.toString();
    proof['error'] = e.toString();
  }
  File('dpapi-proof.json').writeAsStringSync(jsonEncode(proof));
  runApp(
    Directionality(
      textDirection: TextDirection.ltr,
      child: Center(
        child: Text(
          proof['passed'] == true ? 'XIO QA passed' : 'XIO QA failed',
        ),
      ),
    ),
  );
}
