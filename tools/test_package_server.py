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
    for name in ['dualstack.py','client_api.py','admin.py','stack.py','network_stack.py','mesh_stack.py','rivet-setup.py','update.py']:
        (managed / name).write_text('RECIPE = 25\n' if name in ['admin.py','update.py'] else '# fixture\n')
    (managed / 'mesh-pins.json').write_text('{}')
    (managed / 'bootstrap.sh').write_text('set -eu\n')
    (managed / 'xio_vici/__init__.py').write_text('# vici fixture\n')
    (managed / 'xio_vici/LICENSE').write_text('fixture-license')
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
                self.assertEqual(package.package(root, root, output, check=True)['recipeVersion'], 25)
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
                    self.assertEqual(tar.extractfile(name).read(), source.read_bytes())
                    entry = tar.getmember(name)
                    self.assertEqual((entry.uid,entry.gid,entry.mtime),(0,0,0))
                    self.assertEqual(entry.mode, 0o755 if name in package.BINARY_MEMBERS else 0o600)
            for source, target in package.MIRRORS:
                self.assertEqual((one / target).read_bytes(), (root / 'server/managed' / source).read_bytes())

    def test_real_canonical_recipe_constants_match_without_importing_or_packaging(self):
        import ast
        root = Path(__file__).resolve().parent.parent
        for name in ['admin.py','update.py']:
            tree = ast.parse((root / 'server/managed' / name).read_bytes())
            value = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id == 'RECIPE' for t in n.targets))
            self.assertEqual(value, package.RECIPE)


if __name__ == '__main__':
    unittest.main()
