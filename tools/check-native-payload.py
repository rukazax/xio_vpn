#!/usr/bin/env python3
"""Compare loaded ELF sections: Gradle strips debug sections, not program code."""
from pathlib import Path
import argparse, hashlib, json, struct, zipfile

def allocated(raw):
    assert raw[:4] == b'\x7fELF' and raw[5] == 1, 'Expected little-endian ELF'
    wide = raw[4] == 2
    offset = struct.unpack_from('<Q' if wide else '<I', raw, 40 if wide else 32)[0]
    size, count, names = struct.unpack_from('<HHH', raw, 58 if wide else 46)
    fmt = '<IIQQQQIIQQ' if wide else '<IIIIIIIIII'
    entries = [struct.unpack_from(fmt, raw, offset+i*size) for i in range(count)]
    entry = entries[names]
    strings = raw[entry[4]:entry[4]+entry[5]]
    result = {}
    for entry in entries:
        name = strings[entry[0]:].split(b'\0', 1)[0].decode()
        if entry[2] & 2:
            # SHT_NOBITS represents zero-initialized memory, with no file data.
            value = b'' if entry[1] == 8 else raw[entry[4]:entry[4]+entry[5]]
            result[name] = (entry[5], hashlib.sha256(value).hexdigest())
    return result

r = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser()
p.add_argument('apk', type=Path)
a = p.parse_args()
records = []
with zipfile.ZipFile(a.apk) as apk, zipfile.ZipFile(r/'app/android/app/libs/rivet.aar') as aar:
    for name in apk.namelist():
        if not name.endswith(('/libgojni.so', '/libxio_openvpn.so')):
            continue
        _, abi, library = name.split('/')
        original = aar.read('jni/'+abi+'/'+library) if library == 'libgojni.so' else (r/'app/android/app/src/main/jniLibs'/abi/library).read_bytes()
        assert allocated(original) == allocated(apk.read(name)), 'Stale or mismatched native payload: '+name
        records.append({'abi': abi, 'library': library, 'allocatedSectionsMatch': True})
assert len(records) >= 2
print(json.dumps({'apk': a.apk.name, 'nativePayload': records}, indent=2))
