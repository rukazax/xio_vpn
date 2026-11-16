#!/usr/bin/env python3
"""Fail-closed local candidate inspection. Never signs, installs, runs apps or publishes."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'tooling/cross-platform'), str(ROOT / 'client'), str(ROOT / 'tools')]
import linux_provenance as assets
from apk_abi import ALL_ABIS, validate_native_abis
from native_fingerprint import fingerprint

CONFIG = json.loads((Path(__file__).with_name('current-targets.json')).read_text())


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        return value.hexdigest()


def run(command, cwd=ROOT):
    # SDK tools never receive passwords; do not use this for signing commands.
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True, text=True)
    require(result.returncode == 0, f'Verification tool failed: {Path(str(command[0])).name}')
    return result.stdout + result.stderr


def staged_server_fresh(root):
    # Reuse the authoritative packager's member list/canonicalization, without needing
    # untracked vendor-server binaries or executing/rebuilding any server payload.
    spec = importlib.util.spec_from_file_location('ci_server_packager', ROOT / 'tools/package-server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    metadata = json.loads((root / 'vendor-metadata/rivet-build.json').read_text())
    pins = {'amneziawg-go': module.AWG_SHA256, 'rivet': metadata['serverSha256'],
            'xraygateway': metadata['xrayServerSha256'], 'cloak': metadata['cloakServerSha256']}
    expected = module.sources(root)
    with tarfile.open(root / 'app/assets/xio-server.tar.gz', 'r:gz') as archive:
        entries = archive.getmembers()
        members = {member.name: member for member in entries}
        if len(members) != len(entries) or set(members) != {name for _, name in expected}:
            return False
        for source, name in expected:
            member = members[name]
            if not member.isfile() or member.size > assets.MAX_MEMBER:
                return False
            data = archive.extractfile(member).read()
            if (assets.digest(data) != pins[name] if name in pins else data != module.member_payload(source, name)):
                return False
    manifest = json.loads((root / 'app/assets/xio-server-release.json').read_text())
    if manifest['recipeVersion'] != module.RECIPE:
        return False
    for source, target in module.MIRRORS:
        data = (root / 'server/managed' / source).read_bytes()
        if source.endswith('.sh'):
            data = data.replace(b'\r\n', b'\n')
        if data != (root / 'app/assets' / target).read_bytes():
            return False
    return True


def capture(root, source_sha):
    require(re.fullmatch('[0-9a-f]{40}', source_sha) is not None, 'Require immutable full source SHA')
    require(run(['git', 'rev-parse', 'HEAD'], root).strip() == source_sha, 'Checkout SHA mismatch')
    require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], root).strip(),
            'Tracked checkout inputs are dirty')
    full = assets.capture(root / 'app', 'full')
    metadata = json.loads((root / 'vendor-metadata/rivet-build.json').read_text())
    inputs = ['app/pubspec.yaml', 'app/android/app/libs/rivet.aar', 'vendor-metadata/rivet-build.json']
    inputs += [p.relative_to(root).as_posix() for p in
               sorted((root / 'app/android/app/src/main/jniLibs').rglob('*.so'))]
    native = fingerprint(root)
    return {'schema': 1, 'sourceSha': source_sha, 'version': full['appVersion'], 'assets': full,
            'matrix': CONFIG, 'inputs': {name: sha(root / name) for name in inputs},
            'nativeSourceSha256': native, 'stagedServerSourceFresh': staged_server_fresh(root),
            'nativeSourceFresh': native == metadata['sourceSha256'],
            'nativeAarMatchesMetadata': sha(root / 'app/android/app/libs/rivet.aar') == metadata['androidAarSha256']}


def client_snapshot(lock):
    full = lock['assets']
    return {**full, 'flavor': 'client', 'recipeVersion': None,
            'files': {name: value for name, value in full['files'].items() if name.startswith('l10n/')}}


def contract(target, version):
    result = {}
    for flavor, kinds in CONFIG[target].items():
        for kind in kinds:
            if target == 'android':
                name = f'XIO-{flavor.title()}-{version}-android-{kind}.apk'
            elif target == 'ubuntu':
                brand = 'XIO' if flavor == 'full' else 'XIO-Client'
                name = f'{brand}-{version}-ubuntu-' + ('amd64.deb' if kind == 'deb' else 'x64.tar.gz')
            else:
                name = f'XIO-{flavor.title()}-{version}-windows-x64.zip'
            result[name] = (flavor, kind)
    require(bool(result), 'Empty artifact contract')
    return result


def artifact_set(directory, target, expected):
    found = {}
    for path in sorted(directory.rglob('*')):
        if not path.is_file():
            continue
        selected = (path.suffix == '.apk' if target == 'android' else
                    path.suffix == '.zip' if target == 'windows' else
                    path.suffix == '.deb' or ('ubuntu' in path.name and path.name.endswith('.tar.gz')))
        if not selected:
            continue
        require(not path.is_symlink() and path.name not in found, 'Linked/duplicate artifact')
        found[path.name] = path
    require(set(found) == set(expected),
            f'Artifact set mismatch: missing={sorted(set(expected)-set(found))}; unexpected={sorted(set(found)-set(expected))}')
    return found


def zip_payload(path, prefix, snapshot):
    payload, files, folded = {}, {}, set()
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            name = assets.safe_name(member.filename)
            require(name.lower() not in folded, f'Duplicate/case-colliding ZIP member: {name}')
            folded.add(name.lower())
            require((member.external_attr >> 16) & 0o170000 != 0o120000, 'Linked ZIP member')
            if member.is_dir():
                continue
            files[name] = member
            if snapshot['flavor'] == 'client':
                require(not assets.client_path(name), f'Client contains server payload: {name}')
            if name.startswith(prefix):
                relative = name[len(prefix):]
                if snapshot['flavor'] == 'client':
                    require(relative.split('/')[0] in assets.CLIENT_ASSET_DIRS, 'Unexpected Client asset root')
                if relative in snapshot['files'] or relative.startswith('l10n/'):
                    require(member.file_size <= assets.MAX_MEMBER, 'Oversized provenance asset')
                    payload[relative] = archive.read(member)
    assets.check_payload(payload, snapshot)
    return files


def sdk_tool(sdk, name):
    suffix = '.bat' if os.name == 'nt' and name == 'apksigner' else '.exe' if os.name == 'nt' else ''
    path = sdk / (name + suffix)
    require(path.is_file(), f'Required Android verification tool absent: {name}')
    return path


def android_identity(badging, flavor, version, build):
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    require(package is not None and package.groups() ==
            ('app.xio.xio' if flavor == 'full' else 'app.xio.client', build, version), 'APK identity/version mismatch')
    label = 'XIO' if flavor == 'full' else 'XIO Client'
    require(f"application-label:'{label}'" in badging, 'APK label mismatch')
    require("sdkVersion:'26'" in badging and "targetSdkVersion:'36'" in badging, 'Unexpected APK SDK contract')
    if flavor == 'client':
        require('android.permission.REQUEST_INSTALL_PACKAGES' not in badging, 'Client has updater install permission')


def android(path, flavor, architecture, lock, sdk):
    version, build = lock['version'].split('+')
    android_identity(run([sdk_tool(sdk, 'aapt'), 'dump', 'badging', path]), flavor, version, build)
    signature = run([sdk_tool(sdk, 'apksigner'), 'verify', '--verbose', '--print-certs', path])
    require('Verified using v2 scheme (APK Signature Scheme v2): true' in signature, 'APK v2 signature required')
    certs = re.findall(r'Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})', signature)
    require(len(certs) == 1 and certs[0].lower() == CONFIG['certificateSha256'], 'Unexpected APK signing certificate')
    run([sdk_tool(sdk, 'zipalign'), '-c', '-P', '16', '4', path])
    manifest = run([sdk_tool(sdk, 'aapt'), 'dump', 'xmltree', path, 'AndroidManifest.xml'])
    for required in ['app.xio.xio.MainActivity', 'app.xio.xio.XioVpnService']:
        require(required in manifest, 'APK missing native activity/VPN service')
    if flavor == 'client':
        require(not any(blocked in manifest for blocked in ['.UpdateJob', '.UpdateCleanupReceiver', '.updates"']),
                'Client manifest retains updater')
    snapshot = lock['assets'] if flavor == 'full' else client_snapshot(lock)
    zip_payload(path, 'assets/flutter_assets/assets/', snapshot)
    with zipfile.ZipFile(path) as archive:
        native = validate_native_abis(archive.namelist(), ALL_ABIS if architecture == 'universal' else {architecture})
        for abi, libraries in native.items():
            for library in libraries:
                member = archive.getinfo(f'lib/{abi}/{library}')
                require(member.file_size <= assets.MAX_MEMBER, 'Oversized native Android payload')
                raw = archive.read(member)
                require(raw[:4] == b'\x7fELF' and raw[5] == 1, 'Require little-endian native ELF')
                wide = raw[4] == 2
                expected_machine = {'arm64-v8a': 183, 'armeabi-v7a': 40, 'x86_64': 62}[abi]
                require(struct.unpack_from('<H', raw, 18)[0] == expected_machine, 'Wrong native ELF machine')
                offset = struct.unpack_from('<Q' if wide else '<I', raw, 32 if wide else 28)[0]
                size, count = struct.unpack_from('<HH', raw, 54 if wide else 42)
                fmt = '<IIQQQQQQ' if wide else '<IIIIIIII'
                aligns = [struct.unpack_from(fmt, raw, offset + i * size)[-1] for i in range(count)
                          if struct.unpack_from('<I', raw, offset + i * size)[0] == 1]
                require(aligns and min(aligns) >= (16384 if wide else 4096), 'Unsupported native ELF load alignment')
    sections = json.loads(run([sys.executable, '-I', ROOT / 'tools/check-native-payload.py', path,
                               '--aar', ROOT / 'app/android/app/libs/rivet.aar']))
    require({(row['abi'], row['library']) for row in sections['nativePayload']} ==
            {(abi, lib) for abi in native for lib in ['libgojni.so', 'libxio_openvpn.so']},
            'Incomplete allocated-section native comparison')
    return {'certificateSha256': certs[0].lower(), 'nativeAbis': native, 'nativeSections': sections}


def pe_module():
    spec = importlib.util.spec_from_file_location('current_targets_pe', ROOT / 'tooling/cross-platform/pe-version.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pe_identity(path, flavor, version):
    module = pe_module()
    actual = module.read_version(path)
    quad = '.'.join(map(str, module.version_parts(version)))
    require(actual['fileVersion'] == quad and actual['productVersion'] == quad, 'Stale PE fixed VERSIONINFO')
    require(actual['FileVersion'] == version and actual['ProductVersion'] == version, 'Stale PE string VERSIONINFO')
    raw = path.read_bytes()
    sections = module.read_sections(raw)
    leaf = module.find_version_leaf(raw, sections)
    offset = module.rva_to_offset(sections, leaf.rva)
    node = module.parse_node(raw, offset, offset + leaf.size)
    table = node.child('StringFileInfo')
    require(table is not None and bool(table.children), 'Missing PE identity table')
    for block in table.children:
        identity = {item.key: item.text for item in block.children}
        require(identity.get('ProductName') in (('XIO',) if flavor == 'full' else ('XIOClient', 'XIO Client')),
                'Wrong PE product identity')
        require(identity.get('OriginalFilename') == ('XIO.exe' if flavor == 'full' else 'XIOClient.exe'),
                'Wrong PE original executable identity')
    require(raw[:2] == b'MZ' and struct.unpack_from('<H', raw, struct.unpack_from('<I', raw, 0x3c)[0] + 4)[0] == 0x8664,
            'Require Windows AMD64 PE')
    return actual


def windows(path, flavor, lock, reference):
    brand = 'XIO' if flavor == 'full' else 'XIOClient'
    snapshot = lock['assets'] if flavor == 'full' else client_snapshot(lock)
    # Exact supported layout: one top-level branded directory; never an ambiguous flat/mixed archive.
    files = zip_payload(path, brand + '/data/flutter_assets/assets/', snapshot)
    require(all(name.startswith(brand + '/') for name in files), 'Unexpected Windows archive root')
    required = [brand + '/' + name for name in [brand + '.exe', 'flutter_windows.dll', 'data/app.so',
                'data/icudtl.dat', 'libexec/xio-tunnel.exe', 'libexec/wintun.dll', 'libexec/WINTUN-LICENSE.txt']]
    require(set(required) <= set(files), 'Incomplete Windows native/runtime bundle')
    with tempfile.TemporaryDirectory() as scratch, zipfile.ZipFile(path) as archive:
        executable = Path(scratch) / (brand + '.exe')
        require(files[required[0]].file_size <= assets.MAX_MEMBER, 'Oversized PE executable')
        executable.write_bytes(archive.read(required[0]))
        identity = pe_identity(executable, flavor, lock['version'])
        for name in required[4:6]:
            require(files[name].file_size <= assets.MAX_MEMBER, 'Oversized native Windows payload')
            data = archive.read(name)
            require(data[:2] == b'MZ', 'Invalid Windows helper/driver payload')
            require(assets.digest(data) == sha(reference / Path(name).name), 'Windows helper/driver differs from job native reference')
    return {'versionInfo': identity, 'nativePayloadPresent': True, 'driverLoaded': False, 'authenticodeVerified': False}


def linux_identity(path, flavor, version, reference):
    brand = 'XIO' if flavor == 'full' else 'XIOClient'
    prefix = ('opt/xio/' if flavor == 'full' else 'opt/xio-client/') if path.suffix == '.deb' else brand + '/'
    required = {prefix + name for name in [brand, 'lib/libflutter_linux_gtk.so', 'libexec/xio-tunnel',
                                           'data/icudtl.dat', 'data/flutter_assets/AssetManifest.bin']}
    with tarfile.open(fileobj=assets.deb_data(path) if path.suffix == '.deb' else None,
                      name=None if path.suffix == '.deb' else str(path), mode='r:*') as archive:
        found = {assets.safe_name(member.name): member for member in archive if member.isfile()}
        require(required <= set(found), 'Incomplete Linux native/runtime payload')
        executable = archive.extractfile(found[prefix + brand]).read(20)
        require(executable[:6] == b'\x7fELF\x02\x01' and executable[18:20] == b'\x3e\x00', 'Require Linux AMD64 ELF')
        helper = found[prefix + 'libexec/xio-tunnel']
        require(helper.size <= assets.MAX_MEMBER, 'Oversized native helper')
        require(assets.digest(archive.extractfile(helper).read()) == sha(reference / 'xio-tunnel'),
                'Linux helper differs from job native reference')
    if path.suffix == '.deb':
        # dpkg is required for control metadata, never for payload extraction/installation.
        control = run(['dpkg-deb', '--field', path])
        expected_package = 'xio' if flavor == 'full' else 'xio-client'
        for field, value in [('Package', expected_package), ('Version', version), ('Architecture', 'amd64')]:
            require(re.search(r'^' + field + ': ' + re.escape(value) + r'\s*$', control, re.M), 'DEB control identity/version mismatch')
    return {'nativePayloadPresent': True, 'appExecuted': False}


def verify(root, lock, directory, target, source_sha, sdk=None, reference=None):
    require(lock == capture(root, source_sha), 'Staged source, matrix or native references changed after capture')
    require(lock['stagedServerSourceFresh'], 'Staged server assets NOT_READY: regenerate from current reviewed source')
    require(lock['nativeSourceFresh'] and lock['nativeAarMatchesMetadata'],
            'Native source/AAR provenance NOT_READY: rebuild reviewed native inputs (Full embeds server engines too)')
    if target != 'android':
        require(reference is not None and reference.is_dir(), 'Fresh same-job desktop native reference required')
    expected = contract(target, lock['version'].split('+')[0])
    candidates = artifact_set(directory, target, expected)
    rows = []
    for name, (flavor, kind) in expected.items():
        path = candidates[name]
        if target == 'android':
            require(sdk is not None, 'Android build-tools required, no signature/native-verification bypass')
            details = android(path, flavor, kind, lock, sdk)
        elif target == 'ubuntu':
            assets.verify_package(path, lock['assets'] if flavor == 'full' else client_snapshot(lock))
            details = linux_identity(path, flavor, lock['version'].split('+')[0], reference)
        else:
            details = windows(path, flavor, lock, reference)
        rows.append({'file': name, 'bytes': path.stat().st_size, 'sha256': sha(path), 'flavor': flavor, **details})
    return {'schema': 1, 'sourceSha': source_sha, 'sourceLockSha256': assets.digest(json.dumps(lock, sort_keys=True).encode()),
            'target': target, 'candidateArtifactsAccepted': True, 'artifacts': rows,
            'physicalDeviceAccepted': False, 'realDriverGuiAccepted': False, 'published': False}


def compile_proof(root, lock, source_sha, target, full, client, sdk=None):
    require(lock == capture(root, source_sha), 'Compile inputs changed after source capture')
    rows = []
    for flavor, path in [('full', full), ('client', client)]:
        snapshot = lock['assets'] if flavor == 'full' else client_snapshot(lock)
        if target == 'android':
            require(path.is_file(), 'Missing required Full/Client debug APK')
            require(sdk is not None, 'Android build-tools required')
            android_identity(run([sdk_tool(sdk, 'aapt'), 'dump', 'badging', path]), flavor, *lock['version'].split('+'))
            zip_payload(path, 'assets/flutter_assets/assets/', snapshot)
            executable = path
        else:
            require(path.is_dir(), 'Missing required Full/Client debug bundle')
            assets.verify_bundle(path, snapshot)
            executable = path / (('XIO' if flavor == 'full' else 'XIOClient') + ('.exe' if target == 'windows' else ''))
            require(executable.is_file(), 'Missing required compiled executable')
            magic = executable.read_bytes()[:4]
            require(magic[:2] == b'MZ' if target == 'windows' else magic == b'\x7fELF', 'Invalid compiled executable')
        rows.append({'flavor': flavor, 'file': str(executable), 'sha256': sha(executable)})
    return {'schema': 1, 'sourceSha': source_sha, 'target': target, 'compileOnly': True,
            'candidateArtifactsAccepted': False, 'nativeSourceFresh': lock['nativeSourceFresh'],
            'stagedServerSourceFresh': lock['stagedServerSourceFresh'],
            'physicalDeviceAccepted': False, 'realDriverGuiAccepted': False, 'published': False,
            'compiledOutputs': rows}


def receipt_check(lock, receipt, target, source_sha, directory=None, candidate=False):
    require(receipt.get('sourceSha') == source_sha and receipt.get('target') == target, 'Receipt source/target mismatch')
    require(receipt.get('candidateArtifactsAccepted') is candidate, 'Receipt is not the requested acceptance mode')
    if candidate:
        require(receipt.get('sourceLockSha256') == assets.digest(json.dumps(lock, sort_keys=True).encode()), 'Receipt source-lock digest mismatch')
        expected = contract(target, lock['version'].split('+')[0])
        rows = receipt.get('artifacts', [])
        require(len(rows) == len(expected) and {row['file'] for row in rows} == set(expected), 'Receipt artifact set incomplete')
        require(directory is not None, 'Receipt artifact directory required')
        paths = artifact_set(directory, target, expected)
        for row in rows:
            require(sha(paths[row['file']]) == row['sha256'] and paths[row['file']].stat().st_size == row['bytes'],
                    'Artifact changed/missing after verification')
    else:
        rows = receipt.get('compiledOutputs', [])
        require(receipt.get('compileOnly') is True and len(rows) == 2 and
                {row['flavor'] for row in rows} == {'full', 'client'}, 'Full AND Client compile receipt required')
        for row in rows:
            require(Path(row['file']).is_file() and sha(row['file']) == row['sha256'], 'Compiled output changed/missing')
    require(receipt.get('physicalDeviceAccepted') is False and receipt.get('realDriverGuiAccepted') is False and
            receipt.get('published') is False, 'Receipt overclaims runtime/publication acceptance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['capture', 'verify', 'compile-proof', 'receipt-check'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--source-lock', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--target', choices=['android', 'ubuntu', 'windows'])
    parser.add_argument('--build-tools', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--full', type=Path)
    parser.add_argument('--client', type=Path)
    parser.add_argument('--desktop-reference', type=Path)
    parser.add_argument('--candidate', action='store_true')
    args = parser.parse_args()
    if args.action == 'capture':
        result = capture(args.root, args.source_sha)
        args.source_lock.parent.mkdir(parents=True, exist_ok=True)
        args.source_lock.write_text(json.dumps(result, indent=2) + '\n')
    elif args.action == 'receipt-check':
        require(args.target and args.report and args.report.is_file(), 'Required success receipt missing')
        lock = json.loads(args.source_lock.read_text())
        require(lock == capture(args.root, args.source_sha), 'Receipt inputs differ from locked source')
        receipt_check(lock, json.loads(args.report.read_text()), args.target, args.source_sha, args.artifacts, args.candidate)
    else:
        require(args.target and args.report, 'Verification requires target/report')
        require(not args.report.exists(), 'Refuse existing success receipt: use a fresh output directory')
        lock = json.loads(args.source_lock.read_text())
        if args.action == 'compile-proof':
            require(args.full and args.client, 'Compile proof requires Full AND Client outputs')
            result = compile_proof(args.root, lock, args.source_sha, args.target, args.full, args.client, args.build_tools)
        else:
            require(args.artifacts, 'Verification requires artifacts directory')
            result = verify(args.root, lock, args.artifacts, args.target, args.source_sha, args.build_tools, args.desktop_reference)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'sourceSha': args.source_sha, 'action': args.action, 'target': args.target}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, assets.ProvenanceError, OSError, ValueError, KeyError, zipfile.BadZipFile,
            tarfile.TarError, struct.error) as error:
        print(f'Current-target verification FAILED: {error}', file=sys.stderr)
        sys.exit(1)
