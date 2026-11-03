import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('package_server', Path(__file__).with_name('package-server.py'))
package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)


def fixture(root):
    managed = root / 'server/managed'; (managed / 'xio_vici').mkdir(parents=True)
    for name in ['dualstack.py','client_api.py','admin.py','stack.py','network_stack.py','mesh_stack.py','rivet-setup.py','update.py','readiness.py','xio-ready.service']:
        (managed / name).write_text('RECIPE = 26\n' if name in ['admin.py','update.py'] else '# fixture\n')
    (managed / 'mesh-pins.json').write_text('{}')
    (managed / 'bootstrap.sh').write_bytes(b'set -eu\n')
    (managed / 'xio_vici/__init__.py').write_text('# vici fixture\n')
    (managed / 'xio_vici/LICENSE').write_text('fixture-license\nsecond line\n')
    catalog_dir = root / 'server/catalog'; catalog_dir.mkdir(parents=True)
    for name in ['catalog.py','lint_catalog.py','whitelist-pins.json','README.md','xio-catalog.service','xio-catalog.timer']:
        (catalog_dir / name).write_bytes(b'# catalog fixture\n')
    (root / 'tools').mkdir(exist_ok=True)
    (root / 'tools/xio-peer.py').write_bytes(b'# peer fixture\n')
    cascade = root / 'deploy/cascade'; cascade.mkdir(parents=True)
    (cascade / 'xio-cascade-tunnel.sh').write_bytes(b'# tunnel fixture\n')
    (cascade / 'xio-cascade.service').write_bytes(b'# unit fixture\n')
    (cascade / 'xio-cascade-exit.sh').write_bytes(b'# exit fixture\n')
    (cascade / 'xio-cascade-exit.service').write_bytes(b'# exit unit fixture\n')
    (cascade / 'README.md').write_bytes(b'# cascade readme fixture\n')
    (cascade / '99-xio-cascade.conf').write_bytes(b'# sysctl fixture\n')
    (cascade / 'xio-awg-uapi.conf').write_bytes(b'# tmpfiles fixture\n')
    (root / 'vendor-server').mkdir()
    for name in ['amneziawg-go-linux-amd64','xio-rivet-linux-amd64','xio-xray-linux-amd64','xio-cloak-linux-amd64']:
        (root / 'vendor-server' / name).write_bytes(('not-an-executable-unit-fixture-' + name).encode())
    aar = root / 'app/android/app/libs/rivet.aar'; aar.parent.mkdir(parents=True); aar.write_bytes(b'not-an-aar-unit-fixture')
    native = root / 'protocol/rivet'; native.mkdir(parents=True)
    (native / 'go.mod').write_text('module fixture\n'); (native / 'go.sum').write_text('')
    metadata = {'serverSha256':package.sha256(root / 'vendor-server/xio-rivet-linux-amd64'),
                'xrayServerSha256':package.sha256(root / 'vendor-server/xio-xray-linux-amd64'),
                'cloakServerSha256':package.sha256(root / 'vendor-server/xio-cloak-linux-amd64'),
                'androidAarSha256':package.sha256(aar), 'sourceSha256':package.fingerprint(root)}
    (root / 'vendor-metadata').mkdir(); (root / 'vendor-metadata/rivet-build.json').write_text(json.dumps(metadata))
    return package.sha256(root / 'vendor-server/amneziawg-go-linux-amd64')


class PackageGuardTests(unittest.TestCase):
    def test_missing_inputs_refuse_before_any_output_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'app/assets'; output.mkdir(parents=True)
            sentinel = output / 'xio-server.tar.gz'; sentinel.write_bytes(b'old-owned-asset')
            with self.assertRaisesRegex(RuntimeError, 'missing pinned inputs'):
                package.package(root, root, output)
            self.assertEqual(sentinel.read_bytes(), b'old-owned-asset')
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_each_pinned_input_and_native_source_digest_is_required(self):
        for target in ['vendor-server/amneziawg-go-linux-amd64','vendor-server/xio-rivet-linux-amd64',
                       'vendor-server/xio-xray-linux-amd64','vendor-server/xio-cloak-linux-amd64',
                       'app/android/app/libs/rivet.aar','protocol/rivet/go.mod']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); pin = fixture(root)
                (root / target).write_bytes(b'changed-fixture')
                output = root / 'isolated-output'
                with patch.object(package, 'AWG_SHA256', pin), self.assertRaisesRegex(RuntimeError, 'digest mismatch|Native sources changed'):
                    package.package(root, root, output)
                self.assertFalse(output.exists())

    def test_recipe_coherence_and_check_mode_never_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin = fixture(root); output = root / 'output'
            with patch.object(package, 'AWG_SHA256', pin):
                self.assertEqual(package.package(root, root, output, check=True)['recipeVersion'], 26)
                self.assertFalse(output.exists())
                (root / 'server/managed/admin.py').write_text('RECIPE = 24\n')
                with self.assertRaisesRegex(RuntimeError, 'Recipe mismatch'):
                    package.package(root, root, output)
                self.assertFalse(output.exists())

    def test_deterministic_fixture_archive_members_mirrors_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin = fixture(root)
            one = root / 'out-one'; two = root / 'out-two'
            with patch.object(package, 'AWG_SHA256', pin):
                first = package.package(root, root, one)
                for source, _ in package.sources(root):
                    os.utime(source, (1700000000,1700000000)); source.chmod(0o644)
                second = package.package(root, root, two)
            self.assertEqual(first, second)
            self.assertEqual((one / 'xio-server.tar.gz').read_bytes(), (two / 'xio-server.tar.gz').read_bytes())
            self.assertEqual(first['sha256'], hashlib.sha256((one / 'xio-server.tar.gz').read_bytes()).hexdigest())
            self.assertEqual(json.loads((one / 'xio-server-release.json').read_bytes()), first)
            with tarfile.open(one / 'xio-server.tar.gz','r:gz') as tar:
                for source, name in package.sources(root):
                    self.assertEqual(tar.extractfile(name).read(), package.member_payload(source, name))
                    entry = tar.getmember(name)
                    self.assertEqual((entry.uid,entry.gid,entry.mtime),(0,0,0))
                    self.assertEqual(entry.mode, 0o755 if name in package.BINARY_MEMBERS else 0o600)
            for source, target in package.MIRRORS:
                self.assertEqual((one / target).read_bytes(), (root / 'server/managed' / source).read_bytes())

    def test_crlf_and_lf_sources_produce_the_same_archive(self):
        """Windows checkouts use CRLF; Linux CI uses LF. The archive must not depend on that."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin = fixture(root)
            one = root / 'out-lf'; two = root / 'out-crlf'
            with patch.object(package, 'AWG_SHA256', pin):
                first = package.package(root, root, one)
            # Every text member the packer claims to normalise, taken from the packer's
            # own rule: a suffix list alone missed the vendored LICENSE and shipped CRLF.
            for source, name in package.sources(root):
                if package.is_text_member(name):
                    source.write_bytes(source.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
            with patch.object(package, 'AWG_SHA256', pin):
                second = package.package(root, root, two)
            self.assertEqual(first['sha256'], second['sha256'])
            self.assertEqual((one / 'xio-server.tar.gz').read_bytes(), (two / 'xio-server.tar.gz').read_bytes())
            # The LICENSE is published next to the tarball as well as packed inside it.
            published = (two / 'xio_vici/LICENSE').read_bytes()
            self.assertNotIn(b'\r\n', published)
            with tarfile.open(two / 'xio-server.tar.gz', 'r:gz') as tar:
                self.assertEqual(tar.extractfile('xio_vici/LICENSE').read(), published)

    def test_real_canonical_recipe_constants_match_without_importing_or_packaging(self):
        import ast
        root = Path(__file__).resolve().parent.parent
        for name in ['admin.py','update.py']:
            tree = ast.parse((root / 'server/managed' / name).read_bytes())
            value = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id == 'RECIPE' for t in n.targets))
            self.assertEqual(value, package.RECIPE)

    def test_every_bootstrap_move_is_shipped_in_the_archive(self):
        """bootstrap.sh extracts the archive and moves each file out of it.

        A missing member aborts the install with exit 1 (this shipped in 0.24.0:
        readiness.py and xio-ready.service were moved but never packed). The test
        keeps the two sides in sync by parsing the real bootstrap script.
        """
        import re
        root = Path(__file__).resolve().parent.parent
        bootstrap = root / 'server/managed/bootstrap.sh'
        if not bootstrap.is_file():
            self.skipTest('bootstrap.sh is not present in this tree')
        packed = [name for _, name in package.sources(root)]
        missing = []
        # `mv "$tmp/xio_vici/"*` yields "xio_vici/", a directory move; a plain
        # `mv "$tmp/readiness.py"` yields an exact member name.
        for target in re.findall(r'mv "\$tmp/([^"]+)"', bootstrap.read_text()):
            if target.endswith('/'):
                if not any(name.startswith(target) for name in packed):
                    missing.append(target + '*')
            elif target not in packed:
                missing.append(target)
        self.assertEqual(sorted(missing), [],
                         'bootstrap moves files the archive does not ship: ' + ', '.join(sorted(missing)))


if __name__ == '__main__':
    unittest.main()
