#!/usr/bin/env python3
"""Inspect the shipped client APKs; never contacts an Android device or server."""
from pathlib import Path
import hashlib
import argparse
import json
import re
import struct
import subprocess
import sys
import zipfile

from apk_abi import ALL_ABIS, validate_native_abis

ROOT = Path(__file__).resolve().parents[1]
import os
SDK = Path(os.environ.get('XIO_ANDROID_BUILD_TOOLS') or (Path.home() / 'Android/Sdk/build-tools/36.0.0'))
AAPT = 'aapt.exe' if os.name == 'nt' else 'aapt'
APKSIGNER = 'apksigner.bat' if os.name == 'nt' else 'apksigner'
parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', type=Path)
parser.add_argument('--android-build-tools', type=Path, help='Explicit installed build-tools path')
parser.add_argument('--architectures', default='arm64-v8a,armeabi-v7a,x86_64,universal', help='Exact expected candidate set; default still requires all four APKs')
parser.add_argument('--native-aar', type=Path, default=ROOT/'app/android/app/libs/rivet.aar')
args = parser.parse_args()
RELEASE = '0.23.1'
VERSION_CODE = '5016'
if args.android_build_tools:
    SDK = args.android_build_tools
expected_architectures = args.architectures.split(',')
if not expected_architectures or len(set(expected_architectures)) != len(expected_architectures) or set(expected_architectures) - {'arm64-v8a','armeabi-v7a','x86_64','universal'}:
    raise RuntimeError('Invalid expected architecture set')
OUTPUT = args.output_dir or ROOT / f'releases/client-{RELEASE}'
OUTPUT.mkdir(parents=True, exist_ok=True)
records = []
expected_files = {f'XIO-Client-{RELEASE}-android-{abi}.apk' for abi in expected_architectures}
if {path.name for path in OUTPUT.glob('*.apk')} != expected_files:
    raise RuntimeError('Missing or unexpected APKs in the explicitly requested candidate set')


def call(args):
    return subprocess.check_output(list(map(str, args)), text=True)


for path in sorted(OUTPUT.glob('*.apk')):
    badging = call([SDK / AAPT, 'dump', 'badging', path])
    assert "name='app.xio.client'" in badging
    assert f"versionCode='{VERSION_CODE}'" in badging and f"versionName='{RELEASE}'" in badging
    assert "sdkVersion:'26'" in badging and "targetSdkVersion:'36'" in badging
    assert "application-label:'XIO Client'" in badging
    assert 'android.permission.REQUEST_INSTALL_PACKAGES' not in badging
    manifest = call([SDK / AAPT, 'dump', 'xmltree', path, 'AndroidManifest.xml'])
    for blocked in ['.UpdateJob', '.UpdateCleanupReceiver', '.updates"']:
        assert blocked not in manifest, blocked
    assert 'app.xio.xio.MainActivity' in manifest
    assert 'app.xio.xio.XioVpnService' in manifest
    blocks = [b for b in re.split(r'^      E: ', manifest, flags=re.M)
              if b.startswith('activity-alias ')]
    assert len(blocks) == 16
    expected = {f'app.xio.client.launcher.{c}_{b}_{n}'
                for c in ('green', 'white') for b in ('dark', 'clear')
                for n in (0, 90, 180, 270)}
    actual = {re.search(r'android:name[^=]*="([^"]+)"', b)[1] for b in blocks}
    assert actual == expected
    assert sum('android:enabled(0x0101000e)=(type 0x12)0xffffffff' in b for b in blocks) == 1
    signature = call([SDK / APKSIGNER, 'verify', '--verbose', '--print-certs', path])
    assert 'Verified using v2 scheme (APK Signature Scheme v2): true' in signature
    cert = re.search(r'Signer #1 certificate SHA-256 digest: (\w+)', signature)[1]
    call([SDK / 'zipalign', '-c', '-P', '16', '4', path])
    native = json.loads(call([sys.executable, ROOT / 'tools/check-native-payload.py', path, '--aar', args.native_aar]))
    libraries = []
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        architecture = path.name[len(f'XIO-Client-{RELEASE}-android-'):-4]
        native_abis = validate_native_abis(names, ALL_ABIS if architecture == 'universal' else {architecture})
        assets = [n for n in names if n.startswith('assets/flutter_assets/assets/')]
        assert assets
        for name in assets:
            assert any(name.startswith('assets/flutter_assets/assets/' + d + '/')
                       for d in ['help', 'licenses', 'l10n', 'security', 'fonts']), name
        assert not any('CJKsc' in name for name in assets)
        # The slim Dart entrypoint must not retain SSH administration or telemetry.
        for name in names:
            if name.endswith('/libapp.so'):
                raw = apk.read(name)
                for forbidden in [b'ssh-known-hosts.json', b'ipapi.co', b'xio-server-update.py',
                                  b'xio-bootstrap.sh', b'vpn-sharing.sh']:
                    assert forbidden not in raw, (name, forbidden)
            if not name.endswith('.so'):
                continue
            raw = apk.read(name)
            wide = raw[4] == 2
            offset = struct.unpack_from('<Q' if wide else '<I', raw, 32 if wide else 28)[0]
            size, count = struct.unpack_from('<HH', raw, 54 if wide else 42)
            fmt = '<IIQQQQQQ' if wide else '<IIIIIIII'
            aligns = [struct.unpack_from(fmt, raw, offset + i * size)[-1]
                      for i in range(count)
                      if struct.unpack_from('<I', raw, offset + i * size)[0] == 1]
            assert min(aligns) >= (16384 if wide else 4096), name
            libraries.append({'name': name, 'minLoadAlignment': min(aligns)})
    records.append({'file': path.name, 'bytes': path.stat().st_size,
                    'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'certificateSha256': cert, 'minSdk': 26, 'targetSdk': 36,
                    'signatureVerified': True, 'zipalign16KiB': True,
                    'nativePayload': native['nativePayload'], 'nativeAbiComplete': True, 'nativeAbis': native_abis, 'libraries': libraries})
assert len(records) == len(expected_files), 'Need the complete explicitly requested APK set'
report = {'appId': 'app.xio.client', 'version': RELEASE + '+5016',
          'artifacts': records, 'expectedArchitectures': expected_architectures, 'allFourArtifactSet': len(expected_files) == 4, 'physicalAndroidTestedByVerifier': False,
          'realServerConnectionTested': False,
          'limits': ['Local build/unit/widget/artifact checks only; no device or server contacted.']}
(OUTPUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
(OUTPUT / 'SHA256SUMS').write_text(''.join(f"{r['sha256']}  {r['file']}\n" for r in records))
print(json.dumps({'artifacts': len(records), 'verified': True,
                  'report': str(OUTPUT / 'verification.json')}, indent=2))
