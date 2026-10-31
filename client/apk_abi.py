"""Native ABI completeness for release APKs (no device or network access)."""
ALL_ABIS = {'arm64-v8a', 'armeabi-v7a', 'x86_64'}
REQUIRED_LIBRARIES = {'libapp.so', 'libflutter.so', 'libgojni.so', 'libxio_openvpn.so', 'libc++_shared.so'}

def validate_native_abis(names, expected):
    expected = set(expected)
    if not expected or expected - ALL_ABIS:
        raise RuntimeError('Invalid expected native ABI set')
    names = list(names)
    if len(names) != len(set(names)):
        raise RuntimeError('Duplicate APK archive entries')
    actual = {}
    for name in names:
        if not name.startswith('lib/') or not name.endswith('.so'):
            continue
        parts = name.split('/')
        if len(parts) != 3:
            raise RuntimeError('Unexpected native library path')
        actual.setdefault(parts[1], set()).add(parts[2])
    if set(actual) != expected:
        raise RuntimeError('APK native ABI set differs from requested target')
    for abi in expected:
        missing = REQUIRED_LIBRARIES - actual[abi]
        if missing:
            raise RuntimeError('Incomplete native ABI '+abi+': missing '+','.join(sorted(missing)))
    return {abi: sorted(actual[abi]) for abi in sorted(actual)}
