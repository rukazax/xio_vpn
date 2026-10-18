import 'dart:ffi';

import 'package:ffi/ffi.dart';

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
typedef _UnprotectC = Int32 Function(
  Pointer<_Blob>,
  Pointer<Pointer<Utf16>>,
  Pointer<_Blob>,
  Pointer<Void>,
  Pointer<Void>,
  Uint32,
  Pointer<_Blob>,
);
typedef _UnprotectD = int Function(
  Pointer<_Blob>,
  Pointer<Pointer<Utf16>>,
  Pointer<_Blob>,
  Pointer<Void>,
  Pointer<Void>,
  int,
  Pointer<_Blob>,
);
typedef _LocalFreeC = Pointer<Void> Function(Pointer<Void>);

/// Windows DPAPI, CurrentUser scope, without starting a shell or logging data.
List<int> windowsCrypt(List<int> bytes, bool encrypt) {
  final crypt = DynamicLibrary.open('crypt32.dll');
  final free = DynamicLibrary.open('kernel32.dll')
      .lookupFunction<_LocalFreeC, Pointer<Void> Function(Pointer<Void>)>(
        'LocalFree',
      );
  final input = calloc<_Blob>();
  final output = calloc<_Blob>();
  final data = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  data.asTypedList(bytes.length).setAll(0, bytes);
  input.ref.length = bytes.length;
  input.ref.data = data;
  try {
    final ok = encrypt
        ? crypt.lookupFunction<_ProtectC, _ProtectD>('CryptProtectData')(
            input,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            1,
            output,
          )
        : crypt.lookupFunction<_UnprotectC, _UnprotectD>('CryptUnprotectData')(
            input,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            1,
            output,
          );
    if (ok == 0) {
      throw StateError('Windows DPAPI could not protect the local credential');
    }
    return List<int>.from(output.ref.data.asTypedList(output.ref.length));
  } finally {
    data.asTypedList(bytes.length).fillRange(0, bytes.length, 0);
    if (output.ref.data != nullptr) {
      output.ref.data
          .asTypedList(output.ref.length)
          .fillRange(0, output.ref.length, 0);
      free(output.ref.data.cast<Void>());
    }
    calloc.free(data);
    calloc.free(input);
    calloc.free(output);
  }
}
