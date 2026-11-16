"""Isolated delivery proofs: never run a whole bootstrap or real host command."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server/managed'))
from test_package_server import package, fixture
from test_update_ipv6 import deployment, files
import update

NATIVE = ('cascade_native.py', 'cascade_native_lifecycle.py', 'cascade_native_rpc.py')


def update_archive(raw, missing=None, extra=False):
    """Keep the complete generated installer layout, with focused test mutations."""
    result = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as src, tarfile.open(fileobj=result, mode='w:gz') as dst:
        for member in src:
            if member.name != missing:
                dst.addfile(member, src.extractfile(member))
        if extra:
            data = b'# existing optional flat runtime\n'
            member = tarfile.TarInfo('legacy_extra.py'); member.size = len(data)
            dst.addfile(member, io.BytesIO(data))
    data = result.getvalue()
    return data, hashlib.sha256(data).hexdigest()


def bootstrap_block():
    text = (ROOT / 'server/managed/bootstrap.sh').read_text()
    start, end = '# >>> native-runtime >>>', '# <<< native-runtime <<<'
    if start not in text or end not in text:
        raise AssertionError('bootstrap native-runtime safety/install block missing')
    # Execute ONLY this bounded block against owned temp paths; never the installer.
    block_start = text.index(start)
    block_end = text.index(end)
    if block_end > text.index('chmod 700 "$tmp/amneziawg-go"'):
        raise AssertionError('native completeness gate must precede managed runtime replacements')
    return text[block_start + len(start):block_end]


class NativeShippingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='xio-native-shipping-')
        cls.root = Path(cls.temporary.name)
        pin = fixture(cls.root)
        for name in (*NATIVE, 'bootstrap.sh', 'update.py'):
            (cls.root / 'server/managed' / name).write_bytes((ROOT / 'server/managed' / name).read_bytes().replace(b'\r\n', b'\n'))
        with patch.object(package, 'AWG_SHA256', pin):
            cls.manifest = package.package(cls.root, cls.root, cls.root / 'output')
        cls.raw = (cls.root / 'output/xio-server.tar.gz').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_generated_installer_archive_exact_native_bytes_modes_and_manifest(self):
        manifest = json.loads((self.root / 'output/xio-server-release.json').read_bytes())
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(manifest['sha256'], hashlib.sha256(self.raw).hexdigest())
        for source, artifact, key in (('bootstrap.sh', 'xio-bootstrap.sh', 'bootstrapSha256'), ('update.py', 'xio-server-update.py', 'updateSha256')):
            data = (self.root / 'output' / artifact).read_bytes()
            self.assertEqual(data, (ROOT / 'server/managed' / source).read_bytes().replace(b'\r\n', b'\n'))
            self.assertEqual(manifest[key], hashlib.sha256(data).hexdigest())
            self.assertEqual(manifest['artifacts'][artifact], manifest[key])
        with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as archive:
            for name in NATIVE:
                member = archive.getmember(name)
                source = (ROOT / 'server/managed' / name).read_bytes().replace(b'\r\n', b'\n')
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o600)
                self.assertEqual(archive.extractfile(member).read(), source)
                self.assertEqual(hashlib.sha256(archive.extractfile(member).read()).hexdigest(), hashlib.sha256(source).hexdigest())

    def test_missing_directory_and_linked_native_sources_fail_without_stale_fallback(self):
        for name in NATIVE:
            for kind in ('missing', 'directory', 'symlink', 'linked-parent'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder); pin = fixture(root)
                    target = root / 'server/managed' / name
                    target.unlink()
                    if kind == 'directory':
                        target.mkdir()
                    elif kind == 'symlink':
                        target.symlink_to(ROOT / 'server/managed' / name)
                    elif kind == 'linked-parent':
                        target.write_bytes(b'# fixture\n')
                        managed = target.parent
                        managed.rename(root / 'real-managed')
                        managed.symlink_to(root / 'real-managed', target_is_directory=True)
                    output = root / 'output'; output.mkdir()
                    sentinel = output / 'xio-server.tar.gz'; sentinel.write_bytes(b'old-asset')
                    with patch.object(package, 'AWG_SHA256', pin), self.assertRaisesRegex(RuntimeError, 'required managed source'):
                        package.package(root, root, output)
                    self.assertEqual(sentinel.read_bytes(), b'old-asset')
                    self.assertEqual(list(output.iterdir()), [sentinel])

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required for isolated bootstrap block')
    def test_bootstrap_installs_all_three_without_executing_them_or_activating_units(self):
        block = bootstrap_block()
        # Tight allow-list: no Python, systemctl, network tool or generated unit activation.
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                self.assertTrue(line.startswith(('for ', 'do', 'done', '[ ', 'chmod ', 'mv ')), line)
        for missing in (None, *NATIVE):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); upload = root / 'upload'; lib = root / 'managed'
                upload.mkdir(); lib.mkdir()
                with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as archive:
                    for name in NATIVE:
                        if name != missing:
                            (upload / name).write_bytes(archive.extractfile(name).read())
                            (upload / name).chmod(0o777)
                        (lib / name).write_bytes(b'old-owned-runtime')
                before = files(lib)
                result = subprocess.run(['sh', '-eu', '-c', block], env={**os.environ, 'tmp': str(upload), 'lib': str(lib)}, capture_output=True)
                if missing:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(files(lib), before)  # all sources checked BEFORE first move
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for name in NATIVE:
                        self.assertEqual((lib / name).read_bytes(), (ROOT / 'server/managed' / name).read_bytes().replace(b'\r\n', b'\n'))
                        self.assertEqual((lib / name).stat().st_mode & 0o777, 0o600)
                        self.assertFalse((upload / name).exists())

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required for isolated bootstrap block')
    def test_bootstrap_unsafe_native_source_or_destination_refuses_before_replacements(self):
        block = bootstrap_block()
        for name in NATIVE:
            for kind in ('source-directory', 'source-link', 'destination-directory', 'destination-link', 'destination-dangling-link'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder); upload = root / 'upload'; lib = root / 'managed'
                    upload.mkdir(); lib.mkdir()
                    sentinel = root / 'sentinel'; sentinel.write_bytes(b'do-not-touch')
                    for member in NATIVE:
                        (upload / member).write_bytes(b'# new module\n')
                        (lib / member).write_bytes(b'# existing module\n')
                    target = (upload if kind.startswith('source') else lib) / name
                    target.unlink()
                    if kind.endswith('directory'):
                        target.mkdir()
                    else:
                        target.symlink_to(root / 'absent' if kind.endswith('dangling-link') else sentinel)
                    before = files(lib)
                    result = subprocess.run(['sh', '-eu', '-c', block], env={**os.environ, 'tmp': str(upload), 'lib': str(lib)}, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(files(lib), before)
                    self.assertEqual(sentinel.read_bytes(), b'do-not-touch')

    def test_update_missing_each_native_module_rejects_before_maintenance_or_writes(self):
        # Construct a complete otherwise-valid runtime even against the pre-fix packer.
        base, _ = update_archive(self.raw)
        stream = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(base), mode='r:gz') as src, tarfile.open(fileobj=stream, mode='w:gz') as dst:
            names = src.getnames()
            for member in src:
                dst.addfile(member, src.extractfile(member))
            for name in NATIVE:
                if name not in names:
                    data = (ROOT / 'server/managed' / name).read_bytes()
                    member = tarfile.TarInfo(name); member.size = len(data)
                    dst.addfile(member, io.BytesIO(data))
        for missing in NATIVE:
            with self.subTest(missing=missing), deployment() as (root, _, events):
                before = files(root)
                raw, digest = update_archive(stream.getvalue(), missing=missing)
                with patch.object(update, 'atomic') as atomic, patch.object(update, 'ipv6_transaction_module', side_effect=RuntimeError('maintenance reached before completeness')) as network:
                    with self.assertRaisesRegex(RuntimeError, 'Incomplete update archive'):
                        update.update(raw, digest, 'server')
                    atomic.assert_not_called(); network.assert_not_called()
                self.assertEqual(events, [])
                self.assertEqual(files(root), before)

    def test_actual_full_generated_archive_unpacks_every_member(self):
        with tempfile.TemporaryDirectory() as folder:
            stage = Path(folder)
            update.unpack(self.raw, stage, self.manifest['sha256'])
            with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as archive:
                self.assertEqual(set(files(stage)), set(archive.getnames()))
                for member in archive:
                    self.assertEqual((stage / member.name).read_bytes(), archive.extractfile(member).read())

    def test_full_archive_layout_fences_reject_before_maintenance(self):
        cases = [('foreign/file.py', tarfile.REGTYPE), ('catalog/deeper/file.py', tarfile.REGTYPE),
                 ('/cascade/file.py', tarfile.REGTYPE), ('catalog/../file.py', tarfile.REGTYPE),
                 ('catalog//alias.py', tarfile.REGTYPE), ('./alias.py', tarfile.REGTYPE),
                 ('catalog/catalog.py', tarfile.REGTYPE), ('cascade/link', tarfile.SYMTYPE),
                 ('catalog/link', tarfile.LNKTYPE), ('cascade/', tarfile.DIRTYPE)]
        for name, kind in cases:
            with self.subTest(name=name, kind=kind), deployment() as (root, _, events):
                stream = io.BytesIO()
                with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as src, tarfile.open(fileobj=stream, mode='w:gz') as dst:
                    for entry in src:
                        dst.addfile(entry, src.extractfile(entry))
                    entry = tarfile.TarInfo(name); entry.type = kind
                    if kind == tarfile.REGTYPE:
                        entry.size = len(b'# mutation\n')
                        dst.addfile(entry, io.BytesIO(b'# mutation\n'))
                    else:
                        entry.linkname = '/unowned/target'
                        dst.addfile(entry)
                raw = stream.getvalue(); before = files(root)
                with self.assertRaisesRegex(RuntimeError, 'Invalid update archive entry'), patch.object(update, 'atomic') as atomic, patch.object(update, 'ipv6_transaction_module') as network:
                    update.update(raw, hashlib.sha256(raw).hexdigest(), 'server')
                atomic.assert_not_called(); network.assert_not_called()
                self.assertEqual(events, [])
                self.assertEqual(files(root), before)

    def test_auxiliary_destination_parent_conflicts_reject_before_maintenance(self):
        for name in ('xio_vici', 'catalog', 'cascade'):
            for kind in ('regular-file', 'symlink'):
                with self.subTest(name=name, kind=kind), deployment() as (root, _, events):
                    target = update.LIB / name
                    if kind == 'regular-file':
                        target.write_bytes(b'foreign parent file')
                    else:
                        target.symlink_to(root / 'foreign-directory', target_is_directory=True)
                    before = files(root)
                    with self.assertRaises((RuntimeError, OSError)), patch.object(update, 'atomic') as atomic, patch.object(update, 'ipv6_transaction_module') as network:
                        update.update(self.raw, self.manifest['sha256'], 'server')
                    atomic.assert_not_called(); network.assert_not_called()
                    self.assertEqual(events, [])
                    self.assertEqual(files(root), before)

    def test_auxiliary_rollback_preserves_foreign_file_in_new_directory(self):
        with deployment() as (root, _, events):
            before = files(root); original = update.atomic; failed = False
            def atomic(source, target, mode):
                nonlocal failed
                original(source, target, mode)
                if Path(target) == update.STATE and not failed:
                    failed = True
                    (update.LIB / 'cascade/foreign-note').write_bytes(b'foreign concurrent edit')
                    raise RuntimeError('injected after commit-record replacement')
            with patch.object(update, 'atomic', side_effect=atomic), self.assertRaisesRegex(RuntimeError, 'injected after'):
                update.update(self.raw, self.manifest['sha256'], 'server')
            self.assertTrue(failed)
            self.assertEqual(files(root), {**before, 'managed/cascade/foreign-note': b'foreign concurrent edit'})
            self.assertEqual(list((update.LIB / 'cascade').iterdir()), [update.LIB / 'cascade/foreign-note'])
            self.assertFalse((update.LIB / 'catalog').exists())
            self.assertFalse((update.LIB / 'xio_vici').exists())

    def test_rollback_replaced_auxiliary_parent_preserves_foreign_and_displaced_files(self):
        for dirname, member, preexisting in (('cascade', '99-xio-cascade.conf', False), ('catalog', 'catalog.py', True)):
            for replacement in ('directory', 'symlink'):
                with self.subTest(dirname=dirname, replacement=replacement), deployment() as (root, _, events):
                    owned = update.LIB / dirname
                    displaced = root / ('displaced-owned-' + dirname)
                    foreign = root / ('foreign-' + dirname)
                    if preexisting:
                        owned.mkdir()
                        (owned / member).write_bytes(b'# old owned auxiliary\n')
                    original_atomic = update.atomic; original_unlink = Path.unlink
                    injected = False; displaced_files = {}; displaced_modes = {}; foreign_writes = []; foreign_unlinks = []
                    def atomic(source, target, mode):
                        nonlocal injected, displaced_files, displaced_modes
                        target = Path(target)
                        if injected and target.resolve().is_relative_to(foreign.resolve()):
                            foreign_writes.append(str(target))
                        original_atomic(source, target, mode)
                        if target == update.STATE and not injected:
                            injected = True
                            self.assertTrue(owned.resolve().is_relative_to(root.resolve()))
                            self.assertFalse(displaced.exists())
                            owned.rename(displaced)
                            displaced_files = files(displaced)
                            displaced_modes = {p.relative_to(displaced).as_posix(): p.stat().st_mode for p in displaced.rglob('*')}
                            foreign.mkdir()
                            (foreign / member).write_bytes(b'FOREIGN same-name archive member')
                            (foreign / 'foreign-note').write_bytes(b'FOREIGN note')
                            if replacement == 'symlink':
                                owned.symlink_to(foreign, target_is_directory=True)
                            else:
                                foreign.rename(owned)
                            raise RuntimeError('injected STATE failure with displaced auxiliary parent')
                    def unlink(path, *args, **kwargs):
                        destination = foreign if replacement == 'symlink' else owned
                        if injected and path.resolve().is_relative_to(destination.resolve()):
                            foreign_unlinks.append(str(path))
                        return original_unlink(path, *args, **kwargs)
                    # For directory replacement the new foreign root is now owned's pathname.
                    def observed_atomic(source, target, mode):
                        if injected and replacement == 'directory' and Path(target).resolve().is_relative_to(owned.resolve()):
                            foreign_writes.append(str(target))
                        return atomic(source, target, mode)
                    caught = None
                    with patch.object(update, 'atomic', side_effect=observed_atomic), patch.object(Path, 'unlink', new=unlink):
                        try:
                            update.update(self.raw, self.manifest['sha256'], 'server')
                        except RuntimeError as error:
                            caught = str(error)
                    self.assertTrue(injected)
                    self.assertEqual(foreign_unlinks, [], 'rollback must not unlink through a replaced parent')
                    self.assertEqual(foreign_writes, [], 'rollback must not restore through a replaced parent')
                    replacement_root = foreign if replacement == 'symlink' else owned
                    self.assertEqual(files(replacement_root), {member: b'FOREIGN same-name archive member', 'foreign-note': b'FOREIGN note'})
                    self.assertEqual(files(displaced), displaced_files)
                    self.assertEqual({p.relative_to(displaced).as_posix(): p.stat().st_mode for p in displaced.rglob('*')}, displaced_modes)
                    self.assertEqual(owned.is_symlink(), replacement == 'symlink')
                    self.assertIsNotNone(caught)
                    self.assertIn('owner recovery', caught)
                    recovery = list(root.glob('.update-recovery-*'))
                    self.assertEqual(len(recovery), 1)
                    self.assertTrue((recovery[0] / 'backup/hashes-before.json').is_file())
                    identities = json.loads((recovery[0] / 'backup/parent-identities.json').read_bytes())
                    self.assertIn(str(owned), identities)

    def test_update_unsafe_native_destination_rejects_before_maintenance(self):
        raw, digest = update_archive(self.raw)
        for name in NATIVE:
            for kind in ('directory', 'symlink', 'dangling-link'):
                with self.subTest(name=name, kind=kind), deployment() as (root, _, events):
                    sentinel = root / 'sentinel'; sentinel.write_bytes(b'do-not-touch')
                    target = update.LIB / name
                    if kind == 'directory':
                        target.mkdir()
                    else:
                        target.symlink_to(root / 'absent' if kind == 'dangling-link' else sentinel)
                    before = files(root)
                    with self.assertRaisesRegex(RuntimeError, 'Symlink|Non-regular'), patch.object(update, 'atomic') as atomic:
                        update.update(raw, digest, 'server')
                    atomic.assert_not_called()
                    self.assertEqual(events, [])
                    self.assertEqual(files(root), before)

    def test_full_generated_archive_transactions_native_auxiliaries_and_legacy_extras_state_last(self):
        for fail_at in (None, *NATIVE, '99-xio-cascade.conf', 'catalog.py', 'deployment.json'):
            with self.subTest(fail_at=fail_at), deployment() as (root, _, events):
                # Exercise both replacement and creation rollback, including mode restoration.
                (update.LIB / NATIVE[0]).write_bytes(b'# previous native runtime\n')
                (update.LIB / NATIVE[0]).chmod(0o640)
                (update.LIB / 'catalog').mkdir()
                (update.LIB / 'catalog/catalog.py').write_bytes(b'# previous catalog copy\n')
                (update.LIB / 'catalog/catalog.py').chmod(0o640)
                (update.LIB / 'catalog/foreign-note').write_bytes(b'foreign data')
                before = files(root)
                before_dirs = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}
                raw, digest = update_archive(self.raw, extra=True)
                original = update.atomic; writes = []; failed = False
                def atomic(source, target, mode):
                    nonlocal failed
                    original(source, target, mode)
                    writes.append(Path(target).name)
                    if Path(target).name == fail_at and not failed:
                        failed = True
                        raise RuntimeError('injected failure after atomic replacement')
                with patch.object(update, 'atomic', side_effect=atomic):
                    if fail_at:
                        with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                            update.update(raw, digest, 'server')
                        self.assertTrue(failed)
                        self.assertEqual(files(root), before)
                        self.assertEqual((update.LIB / NATIVE[0]).stat().st_mode & 0o777, 0o640)
                        self.assertEqual((update.LIB / 'catalog/catalog.py').stat().st_mode & 0o777, 0o640)
                        self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}, before_dirs)
                    else:
                        self.assertTrue(update.update(raw, digest, 'server')['updated'])
                        self.assertEqual(writes[-1], 'deployment.json')
                        for name in NATIVE:
                            self.assertEqual((update.LIB / name).read_bytes(), (ROOT / 'server/managed' / name).read_bytes().replace(b'\r\n', b'\n'))
                            self.assertEqual((update.LIB / name).stat().st_mode & 0o777, 0o600)
                        self.assertEqual((update.LIB / 'legacy_extra.py').read_bytes(), b'# existing optional flat runtime\n')
                        with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as archive:
                            for member in archive:
                                target = update.LIB / member.name
                                self.assertEqual(target.read_bytes(), archive.extractfile(member).read())
                                self.assertEqual(target.stat().st_mode & 0o777, 0o755 if member.name in update.RUNTIMES else 0o600)
                        self.assertEqual((update.LIB / 'catalog/foreign-note').read_bytes(), b'foreign data')
                self.assertTrue(all(event[0] == 'systemctl' and event[1] in {'is-active', 'stop', 'start'} and event[-1] in update.UNITS for event in events), events)
                self.assertFalse(any(any('cascade' in str(arg) or 'Rootnet' in str(arg) for arg in event) for event in events))


if __name__ == '__main__':
    unittest.main()
