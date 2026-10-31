import unittest
from apk_abi import ALL_ABIS, REQUIRED_LIBRARIES, validate_native_abis

def members(abis):
    return [f'lib/{abi}/{name}' for abi in abis for name in sorted(REQUIRED_LIBRARIES)]

class ApkAbiTests(unittest.TestCase):
    def test_complete_single_abi(self):
        self.assertEqual(set(validate_native_abis(members({'arm64-v8a'}), {'arm64-v8a'})), {'arm64-v8a'})
    def test_complete_universal(self):
        self.assertEqual(set(validate_native_abis(members(ALL_ABIS), ALL_ABIS)), ALL_ABIS)
    def test_foreign_abi_is_not_silently_packaged(self):
        with self.assertRaises(RuntimeError): validate_native_abis(members(ALL_ABIS), {'arm64-v8a'})
    def test_partial_extra_abi_from_aar_is_rejected(self):
        names = members({'arm64-v8a'}) + ['lib/x86_64/libgojni.so']
        with self.assertRaises(RuntimeError): validate_native_abis(names, {'arm64-v8a'})
    def test_universal_missing_flutter_abi_is_rejected(self):
        names = members(ALL_ABIS); names.remove('lib/x86_64/libapp.so')
        with self.assertRaises(RuntimeError): validate_native_abis(names, ALL_ABIS)
    def test_missing_runtime_is_rejected(self):
        names = members({'arm64-v8a'}); names.remove('lib/arm64-v8a/libgojni.so')
        with self.assertRaises(RuntimeError): validate_native_abis(names, {'arm64-v8a'})
    def test_missing_openvpn_is_rejected(self):
        names = members({'arm64-v8a'}); names.remove('lib/arm64-v8a/libxio_openvpn.so')
        with self.assertRaises(RuntimeError): validate_native_abis(names, {'arm64-v8a'})
    def test_empty_or_unknown_expected_set_is_rejected(self):
        for expected in [set(), {'mips'}]:
            with self.assertRaises(RuntimeError): validate_native_abis([], expected)
    def test_duplicate_members_are_rejected(self):
        names = members({'arm64-v8a'}); names.append(names[0])
        with self.assertRaises(RuntimeError): validate_native_abis(names, {'arm64-v8a'})

if __name__ == '__main__': unittest.main(verbosity=2)
