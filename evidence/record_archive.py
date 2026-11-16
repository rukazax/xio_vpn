"""Retain a clearly labelled TEST FIXTURE, never a release or authoritative asset."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from test_native_shipping import NativeShippingTests, NATIVE

output = Path(sys.argv[1]).resolve()
if not output.is_relative_to(Path('/srv/archives/agent-native-shipping-20261105').resolve()):
    raise RuntimeError('Evidence output must remain in the owned Debian scratch tree')
output.mkdir(parents=True, exist_ok=True)
NativeShippingTests.setUpClass()
try:
    case = NativeShippingTests
    for name in ('xio-server.tar.gz', 'xio-server-release.json', 'xio-bootstrap.sh', 'xio-server-update.py'):
        shutil.copyfile(case.root / 'output' / name, output / name)
    with tarfile.open(fileobj=io.BytesIO(case.raw), mode='r:gz') as archive:
        members = [{'name': item.name, 'sha256': hashlib.sha256(archive.extractfile(item).read()).hexdigest(),
                    'mode': oct(item.mode)} for item in archive]
    proof = {'kind': 'TEST-FIXTURE-NOT-A-RELEASE',
             'note': 'Real canonical native3/bootstrap/update bytes, other sources and pinned binaries are unit fixtures; no production pin override.',
             'fixtureInstallerSha256': case.manifest['sha256'],
             'manifest': case.manifest, 'members': members,
             'nativeSourceSha256': {name: hashlib.sha256((ROOT / 'server/managed' / name).read_bytes()).hexdigest() for name in NATIVE}}
    (output / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof, indent=2))
finally:
    NativeShippingTests.tearDownClass()
