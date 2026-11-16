// DPAPI with optional context entropy for the Slice B journal envelope.
//
// The existing `windows_crypto.dart` passes null entropy and has no id/store
// binding; this adapter is journal-specific and must not be used as a generic
// credential path.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'issuance_vault.dart';

final class _Blob extends Struct {
  @Uint32()
  external int length;
  external Pointer<Uint8> data;
}

typedef _ProtectC = Int32 Function(
  Pointer<_Blob>,
  Pointer<Utf16>,
  Pointer<_Blob>,
  Pointer<Void>,
  Pointer<Void>,
  Uint32,
  Pointer<_Blob>,
);
typedef _ProtectD = int Function(
  Pointer<_Blob>,
  Pointer<Utf16>,
  Pointer<_Blob>,
  Pointer<Void>,
  Pointer<Void>,
  int,
  Pointer<_Blob>,
);
typedef _FreeC = Pointer<Void> Function(Pointer<Void>);

const int _cryptProtectUiForbidden = 1;

Uint8List windowsProtectWithEntropy(Uint8List plaintext, Uint8List entropy) {
  return _dpapi(plaintext, entropy, encrypt: true);
}

Uint8List windowsUnprotectWithEntropy(Uint8List sealed, Uint8List entropy) {
  return _dpapi(sealed, entropy, encrypt: false);
}

Uint8List _dpapi(Uint8List inputBytes, Uint8List entropy, {required bool encrypt}) {
  final crypt = DynamicLibrary.open('crypt32.dll');
  final free = DynamicLibrary.open('kernel32.dll')
      .lookupFunction<_FreeC, Pointer<Void> Function(Pointer<Void>)>('LocalFree');
  final input = calloc<_Blob>();
  final output = calloc<_Blob>();
  final entropyBlob = calloc<_Blob>();
  final data = calloc<Uint8>(inputBytes.isEmpty ? 1 : inputBytes.length);
  final entropyData = calloc<Uint8>(entropy.isEmpty ? 1 : entropy.length);
  data.asTypedList(inputBytes.length).setAll(0, inputBytes);
  entropyData.asTypedList(entropy.length).setAll(0, entropy);
  input.ref
    ..length = inputBytes.length
    ..data = data;
  entropyBlob.ref
    ..length = entropy.length
    ..data = entropyData;
  try {
    final ok = encrypt
        ? crypt.lookupFunction<_ProtectC, _ProtectD>('CryptProtectData')(
            input,
            nullptr,
            entropyBlob,
            nullptr,
            nullptr,
            _cryptProtectUiForbidden,
            output,
          )
        : crypt.lookupFunction<_ProtectC, _ProtectD>('CryptUnprotectData')(
            input,
            nullptr,
            entropyBlob,
            nullptr,
            nullptr,
            _cryptProtectUiForbidden,
            output,
          );
    if (ok == 0) {
      throw IssuanceVaultKeyUnavailable(
        encrypt
            ? 'DPAPI could not protect the journal record'
            : 'DPAPI could not unprotect the journal record',
      );
    }
    return Uint8List.fromList(output.ref.data.asTypedList(output.ref.length));
  } finally {
    data.asTypedList(inputBytes.length).fillRange(0, inputBytes.length, 0);
    entropyData.asTypedList(entropy.length).fillRange(0, entropy.length, 0);
    if (output.ref.data != nullptr) {
      output.ref.data
          .asTypedList(output.ref.length)
          .fillRange(0, output.ref.length, 0);
      free(output.ref.data.cast<Void>());
    }
    calloc.free(data);
    calloc.free(entropyData);
    calloc.free(input);
    calloc.free(entropyBlob);
    calloc.free(output);
  }
}
