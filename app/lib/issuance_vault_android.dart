// Android backend for the Slice B issuance journal.
//
// The native side owns the isolated AndroidKeyStore alias (`xio.issuance.v1`),
// AES-GCM with the authenticated context as AAD, file flush, rename and
// directory fsync. The lease is a Dart `flock` on an app-owned file in
// filesDir, so it covers isolates and (where applicable) processes.

import 'package:flutter/services.dart';

import 'issuance_vault.dart';
import 'issuance_vault_posix.dart';

const MethodChannel _channel = MethodChannel('app.xio/engine');

@pragma('vm:isolate-unsendable')
final class AndroidChannelVaultBackend implements IssuanceVaultBackend {
  @override
  Future<void> open() async {
    try {
      await _channel.invokeMethod<void>("issuanceJournalProvision");
    } on PlatformException catch (error) {
      throw _mapError(error);
    }
  }

  @override
  Future<Uint8List?> readSealed(String id) async {
    try {
      return await _channel.invokeMethod<Uint8List>(
        'issuanceJournalRead',
        {'id': id},
      );
    } on PlatformException catch (error) {
      throw _mapError(error);
    }
  }

  @override
  Future<void> writeSealed(String id, Uint8List sealed) async {
    if (sealed.length > issuanceVaultMaxCiphertext) {
      throw const IssuanceVaultDurabilityUnknown('Sealed record too large');
    }
    try {
      await _channel.invokeMethod<void>('issuanceJournalWrite', {
        'id': id,
        'value': sealed,
      });
    } on PlatformException catch (error) {
      throw _mapError(error);
    }
  }

  @override
  Future<Uint8List> sealSealed(
    IssuanceVaultContext context,
    Uint8List plaintext,
  ) async {
    try {
      final sealed = await _channel.invokeMethod<Uint8List>(
        'issuanceJournalSeal',
        {'id': context.vaultId, 'aad': context.aad, 'value': plaintext},
      );
      if (sealed == null) {
        throw const IssuanceVaultKeyUnavailable('Native seal returned no bytes');
      }
      return sealed;
    } on PlatformException catch (error) {
      throw _mapError(error);
    }
  }

  @override
  Future<Uint8List> openSealed(
    IssuanceVaultContext context,
    Uint8List sealed,
  ) async {
    try {
      final plain = await _channel.invokeMethod<Uint8List>(
        'issuanceJournalOpen',
        {'id': context.vaultId, 'aad': context.aad, 'value': sealed},
      );
      if (plain == null) {
        throw const IssuanceVaultCorrupt('Native open returned no bytes');
      }
      return plain;
    } on PlatformException catch (error) {
      throw _mapError(error);
    }
  }

  @override
  Future<void> close() async {}

  Exception _mapError(PlatformException error) {
    if (error.code == 'ISSUANCE_KEY_UNAVAILABLE' ||
        (error.message?.contains('KEY_UNAVAILABLE') ?? false)) {
      return const IssuanceVaultKeyUnavailable(
        'The Android issuance key is unavailable; refusing to regenerate',
      );
    }
    if (error.code == 'CORRUPT' ||
        error.message?.contains('CORRUPT') == true ||
        error.message?.contains('AEADBadTag') == true) {
      return const IssuanceVaultCorrupt(
        'Android issuance record failed authentication',
      );
    }
    return IssuanceVaultDurabilityUnknown(
      'Android issuance storage failed: ${error.code}',
    );
  }
}

Future<IssuanceJournalVault> openAndroidJournalVault(
  String storeIdentity,
) async {
  // Validate the context BEFORE any channel call or native resource.
  IssuanceVaultContext(
    version: issuanceVaultVersion,
    vaultId: IssuanceVaultContext.vaultIdFor(storeIdentity),
    storeIdentity: storeIdentity,
  );
  final leasePath = await _channel.invokeMethod<String>(
    'issuanceJournalLeasePath',
  );
  if (leasePath == null || leasePath.isEmpty) {
    throw const IssuanceVaultUnsupported(
      'Android issuance lease path is unavailable',
    );
  }
  final lease = PosixJournalLease.acquire(leasePath);
  final vault = IssuanceJournalVault(
    storeIdentity: storeIdentity,
    backend: AndroidChannelVaultBackend(),
    lease: lease,
  );
  await vault.open();
  return vault;
}
