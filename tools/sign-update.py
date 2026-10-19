#!/usr/bin/env python3
"""Sign an XIO update envelope. Private key must remain outside source/release archives."""
from pathlib import Path
import argparse,base64,hashlib,json,re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
r=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--key',type=Path,required=True);p.add_argument('--notes',type=Path,required=True);args=p.parse_args()
version,build=re.search(r'^version: ([0-9.]+)\+(\d+)',(r/'app/pubspec.yaml').read_text(),re.M).groups()
assets={}
for platform,suffix in [('android-arm64-v8a','android-arm64-v8a.apk'),('android-armeabi-v7a','android-armeabi-v7a.apk'),('android-x86_64','android-x86_64.apk'),('linux-x64','ubuntu-amd64.deb'),('windows-x64','windows-x64.zip')]:
 name=f'XIO-{version}-{suffix}';f=r/'releases'/name
 if not f.is_file():raise SystemExit(f'Missing {name}')
 assets[platform]={'url':f'https://github.com/rukazax/xio_vpn/releases/download/v{version}/{name}','size':f.stat().st_size,'sha256':hashlib.file_digest(f.open('rb'),'sha256').hexdigest()}
key=Ed25519PrivateKey.from_private_bytes(args.key.read_bytes())
public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
assert public==(r/'app/assets/security/update-ed25519.pub').read_text().strip(),'Signing key does not match the pinned application key'
payload=json.dumps({'schema':1,'tag':f'v{version}','version':version,'build':int(build),'notes':args.notes.read_text().strip(),'assets':assets},ensure_ascii=False,separators=(',',':')).encode()
envelope={'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(key.sign(payload)).decode()}
(r/'releases/XIO-update.json').write_text(json.dumps(envelope,separators=(',',':'))+'\n')
print('Signed update manifest prepared; no private key exported')
