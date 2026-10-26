#!/usr/bin/env python3
"""Inspect the shipped client APKs; never contacts an Android device or server."""
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
import os
SDK = Path(os.environ.get('XIO_ANDROID_BUILD_TOOLS') or (Path.home() / 'Android/Sdk/build-tools/36.0.0'))
AAPT = 'aapt.exe' if os.name == 'nt' else 'aapt'
APKSIGNER = 'apksigner.bat' if os.name == 'nt' else 'apksigner'
OUTPUT = ROOT / 'releases/client-0.22.5'
OUTPUT.mkdir(parents=True, exist_ok=True)
records = []


def call(args):
    return subprocess.check_output(list(map(str, args)), text=True)


for path in sorted(OUTPUT.glob('*.apk')):
    badging = call([SDK / AAPT, 'dump', 'badging', path])
    assert "name='app.xio.client'" in badging
    assert "versionCode='5014'" in badging and "versionName='0.22.5'" in badging
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
    native = json.loads(call([sys.executable, ROOT / 'tools/check-native-payload.py', path]))
    libraries = []
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
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
                    'nativePayload': native['nativePayload'], 'libraries': libraries})
assert len(records) == 4, 'Need universal and three architecture APKs'
report = {'appId': 'app.xio.client', 'version': '0.22.5+5014',
          'artifacts': records, 'physicalAndroidTestedByVerifier': False,
          'realServerConnectionTested': False,
          'limits': ['Local build/unit/widget/artifact checks only; no device or server contacted.']}
(OUTPUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
(OUTPUT / 'SHA256SUMS').write_text(''.join(f"{r['sha256']}  {r['file']}\n" for r in records))
print(json.dumps({'artifacts': len(records), 'verified': True,
                  'report': str(OUTPUT / 'verification.json')}, indent=2))
