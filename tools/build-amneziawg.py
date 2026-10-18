#!/usr/bin/env python3
"""Build the pinned AWG JNI bridge with an installed Go toolchain and Android NDK.

Uses a private patched copy of Go; never edits the user's toolchain. No root.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parent.parent
source = root / 'vendor/amneziawg/go'
go = Path(os.environ.get('X1O_GO_ROOT', root / '.build-support/go'))
ndk = Path(os.environ.get('ANDROID_NDK_HOME', Path.home() / 'Android/Sdk/ndk/30.0.16248370'))
version = (go / 'VERSION').read_text().splitlines()[0]
if version != 'go1.27.2':
    raise SystemExit('This recipe pins Go 1.27.2; review runtime changes before changing the pin')
if 'Pkg.Revision = 30.0.16248370' not in (ndk / 'source.properties').read_text():
    raise SystemExit('This recipe pins Android NDK 30.0.16248370')
patched = root / '.build-support/go-awg'
if not (patched / '.x1o-patched').exists():
    if patched.exists():
        raise SystemExit('Incomplete private Go copy; inspect/remove .build-support/go-awg before retrying')
    shutil.copytree(go, patched)
    # Apply upstream CLOCK_BOOTTIME semantics to the architectures we ship.
    # Fail on changed assembly rather than silently losing suspend timer behavior.
    replacements = {
        'amd64': [('MOVL\t$1, DI // CLOCK_MONOTONIC', 'MOVL\t$7, DI // CLOCK_BOOTTIME')],
        'arm64': [('#define CLOCK_MONOTONIC 1', '#define CLOCK_BOOTTIME 7'),
                  ('$CLOCK_MONOTONIC, R0', '$CLOCK_BOOTTIME, R0')],
        'arm': [('#define CLOCK_MONOTONIC\t1', '#define CLOCK_BOOTTIME\t7'),
                ('$CLOCK_MONOTONIC, R0', '$CLOCK_BOOTTIME, R0')],
    }
    for arch, edits in replacements.items():
        path = patched / f'src/runtime/sys_linux_{arch}.s'
        text = path.read_text()
        for before, after in edits:
            if text.count(before) != 1:
                raise SystemExit(f'Go runtime changed: review {arch} CLOCK_BOOTTIME patch')
            text = text.replace(before, after)
        path.write_text(text)
    (patched / '.x1o-patched').write_text('CLOCK_BOOTTIME on arm/arm64/amd64\n')

targets = [('arm64-v8a', 'arm64', 'aarch64-linux-android26-clang'),
           ('armeabi-v7a', 'arm', 'armv7a-linux-androideabi26-clang'),
           ('x86_64', 'amd64', 'x86_64-linux-android26-clang')]
requested = os.environ.get('X1O_AWG_ABIS', '').split(',')
hashes = {}
for abi, arch, compiler in targets:
    if requested != [''] and abi not in requested:
        continue
    out = root / f'vendor/amneziawg/jniLibs/{abi}/libx1o-awg.so'
    out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOROOT=str(patched), GOOS='android', GOARCH=arch,
               GOARM='7', CGO_ENABLED='1', GOTOOLCHAIN='local',
               CC=str(ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin' / compiler),
               CGO_LDFLAGS='-Wl,-soname=libx1o-awg.so -Wl,-z,max-page-size=16384')
    subprocess.run([str(patched / 'bin/go'), 'build', '-mod=readonly', '-tags', 'linux',
                    '-trimpath', '-buildvcs=false', '-ldflags=-buildid=',
                    '-buildmode=c-shared', '-o', str(out), '.'], cwd=source, env=env, check=True)
    out.with_suffix('.h').unlink(missing_ok=True)
    hashes[abi] = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f'{abi}: built', flush=True)
metadata = root / 'vendor-metadata/amneziawg-native.json'
previous = json.loads(metadata.read_text()) if metadata.exists() else {}
previous.update(hashes)
metadata.write_text(json.dumps(previous, indent=2)+'\n')
