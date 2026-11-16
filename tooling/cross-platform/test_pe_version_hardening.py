"""Resource-only PE tests. No executable is ever launched."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('client_stamp_hardening', ROOT / 'client/build_windows_on_linux.py')
BUILD = importlib.util.module_from_spec(spec); spec.loader.exec_module(BUILD)
HELPER = BUILD.version_helper(ROOT)
FIXTURE_VERSIONS = {
    'c54b5e7591e5a144480ce247216503405a8be11e8e53161a487d4b486b25a1ea': '0.23.1+5016',
    'aded1be2514c8b3cd4b084b9aac5d62b14ead2f01ee971075847ff07793722eb': '0.23.0+5015',
}


def fresh_resource_pe(version):
    """Valid tiny PE32+ resource table, with explicitly target-sized VERSIONINFO.

    Models the allocation emitted from a freshly generated RC, not a runnable
    program/compiler provenance assertion. Manifest immediately follows version.
    """
    h = HELPER
    major, minor, patch, build = h.version_parts(version)
    ms, ls = (major << 16) | minor, (patch << 16) | build
    fixed = struct.pack('<13I', h.VS_FIXEDFILEINFO_SIGNATURE, 0x10000, ms, ls, ms, ls,
                        0x3f, 0, 0x40004, 1, 0, 0, 0)
    children = [h.Node(key=key, value_length=1, value_type=1, text=version)
                for key in ('FileVersion', 'ProductVersion')]
    root = h.Node(key='VS_VERSION_INFO', value=bytes(fixed), value_length=52,
                  children=[h.Node(key='StringFileInfo', children=[h.Node(key='040904b0', children=children)])])
    blob = h.serialize_node(root)
    manifest = b'<?xml version="1.0"?><assembly manifestVersion="1.0"/>'
    raw = 512; rva = 0x1000; payload = 160
    size = (payload + len(blob) + len(manifest) + 511) & ~511
    data = bytearray(raw + size); data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80); data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1); struct.pack_into('<H', data, 0x94, 240)
    opt = 0x98; struct.pack_into('<H', data, opt, 0x20b)
    struct.pack_into('<I', data, opt + 108, 16)
    struct.pack_into('<II', data, opt + 112 + 16, rva, size)
    section = opt + 240; data[section:section+8] = b'.rsrc\0\0\0'
    struct.pack_into('<IIII', data, section + 8, size, rva, size, raw)
    for at, entries in [(0, [(16, 0x80000020), (24, 0x80000050)]),
                        (32, [(1, 0x80000038)]), (56, [(1033, 128)]),
                        (80, [(1, 0x80000068)]), (104, [(1033, 144)])]:
        struct.pack_into('<H', data, raw + at + 14, len(entries))
        for i, pair in enumerate(entries): struct.pack_into('<II', data, raw + at + 16 + i*8, *pair)
    struct.pack_into('<IIII', data, raw + 128, rva + payload, len(blob), 1200, 0)
    struct.pack_into('<IIII', data, raw + 144, rva + payload + len(blob), len(manifest), 0, 0)
    data[raw+payload:raw+payload+len(blob)] = blob
    data[raw+payload+len(blob):raw+payload+len(blob)+len(manifest)] = manifest
    return bytes(data)


def other_resources(data):
    h = HELPER; sections = h.read_sections(data); version = h.find_version_leaf(data, sections)
    result = {}
    for at in h._data_entry_offsets(data, sections):
        rva, size = h._u32(data, at), h._u32(data, at+4)
        if rva != version.rva:
            off = h.rva_to_offset(sections, rva); result[(off, size)] = data[off:off+size]
    return result


class PeResourceBoundTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.root = Path(tmp.name)

    def assert_versions(self, result, version):
        self.assertEqual(result['FileVersion'], version); self.assertEqual(result['ProductVersion'], version)
        quad = '.'.join(map(str, HELPER.version_parts(version)))
        self.assertEqual(result['fileVersion'], quad); self.assertEqual(result['productVersion'], quad)

    def test_fresh_target_sized_resource_accepts_long_versions_both_callers(self):
        for version in ('0.24.10+5020', '0.25.0+10000', '65535.65535.65535+65535'):
            for caller in (HELPER.stamp_version, lambda p, v: BUILD.stamp_runner(p, v, HELPER)):
                with self.subTest(version=version, caller=caller):
                    original = fresh_resource_pe(version); path = self.root / 'fresh.exe'; path.write_bytes(original)
                    self.assert_versions(caller(path, version), version)
                    self.assertEqual(other_resources(path.read_bytes()), other_resources(original))
                    self.assert_versions(caller(path, version), version)  # repeated packaging stamp
                    self.assert_versions(caller(path, '1.2.3+4'), '1.2.3+4')
                    self.assert_versions(caller(path, version), version)  # explicit capacity survives shrinking
                    self.assertEqual(other_resources(path.read_bytes()), other_resources(original))

    @unittest.skipUnless(os.environ.get('XIO_CLIENT_PE_FIXTURE'), 'set XIO_CLIENT_PE_FIXTURE to known cached PE')
    def test_known_cached_pe_current_stamp_and_long_rejection_both_callers(self):
        source = Path(os.environ['XIO_CLIENT_PE_FIXTURE']); original = source.read_bytes()
        sha256 = hashlib.sha256(original).hexdigest()
        self.assertIn(sha256, FIXTURE_VERSIONS)
        self.assert_versions(HELPER.read_version(source), FIXTURE_VERSIONS[sha256])
        for caller in (HELPER.stamp_version, lambda p, v: BUILD.stamp_runner(p, v, HELPER)):
            path = self.root / 'cached.exe'; path.write_bytes(original)
            self.assert_versions(caller(path, '0.24.2+5019'), '0.24.2+5019')
            self.assertEqual(other_resources(path.read_bytes()), other_resources(original))
            for version in ('0.24.10+5020', '0.25.0+10000', '65535.65535.65535+65535'):
                with self.subTest(version=version, caller=caller):
                    path.write_bytes(original)
                    with self.assertRaises(HELPER.NoRoomError): caller(path, version)
                    self.assertEqual(path.read_bytes(), original)
                    self.assertEqual(source.read_bytes(), original)

    def test_cli_growth_rejects_with_relink_exit_without_write(self):
        original = fresh_resource_pe('0.24.2+5019'); path = self.root / 'short.exe'; path.write_bytes(original)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'tooling/cross-platform/pe-version.py'),
                                 str(path), '--stamp', '--version', '0.25.0+10000'], capture_output=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(path.read_bytes(), original)

    def test_fresh_short_allocation_rejects_growth_without_write(self):
        original = fresh_resource_pe('0.24.2+5019'); path = self.root / 'short.exe'; path.write_bytes(original)
        with self.assertRaises(HELPER.NoRoomError): HELPER.stamp_version(path, '65535.65535.65535+65535')
        self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__': unittest.main()
