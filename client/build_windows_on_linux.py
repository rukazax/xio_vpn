#!/usr/bin/env python3
"""Cross-build Client only; Wine does not prove native Windows networking.

Package names, generated resources and final PE VERSIONINFO derive from the
source app/pubspec.yaml. Shared client preparation retains its reviewed base pin.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def version_helper(root):
    """Reuse the audited Full PE helper without changing its implementation."""
    spec = importlib.util.spec_from_file_location(
        'xio_client_pe_version', root / 'tooling/cross-platform/pe-version.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves its defining module
    spec.loader.exec_module(module)
    return module


def client_resource(version, helper):
    quad = ','.join(map(str, helper.version_parts(version)))
    return f'''#include <windows.h>
101 ICON "xio.ico"
1 RT_MANIFEST "windows.manifest"
1 VERSIONINFO
FILEVERSION {quad}
PRODUCTVERSION {quad}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "CompanyName", "Konstantin Eryomin\\0"
   VALUE "FileDescription", "XIO VPN Client\\0"
   VALUE "FileVersion", "{version}\\0"
   VALUE "ProductVersion", "{version}\\0"
   VALUE "ProductName", "XIO Client\\0"
   VALUE "OriginalFilename", "XIOClient.exe\\0"
   VALUE "LegalCopyright", "Copyright 2026 Konstantin Eryomin; GPL-3.0-only\\0"
  END
 END
 BLOCK "VarFileInfo" BEGIN VALUE "Translation", 0x409, 1200 END
END
'''


def stamp_runner(exe, version, helper):
    # Unconditional, even if a compiler/cache returns an older runner. Never
    # modify runtime-template input binaries or trust their embedded version.
    helper.stamp_version(exe, version)
    seen = helper.read_version(exe)
    quad = '.'.join(map(str, helper.version_parts(version)))
    expected = {'FileVersion': version, 'ProductVersion': version,
                'fileVersion': quad, 'productVersion': quad}
    if any(seen.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f'Client runner VERSIONINFO mismatch: {seen!r}; expected {expected!r}')
    return seen


def run(cmd, **kwargs):
    return subprocess.run(list(map(str, cmd)), check=True, **kwargs)


def build(args, root=ROOT):
    helper = version_helper(root)
    version = helper.pubspec_version(root / 'app/pubspec.yaml')
    helper.version_parts(version)  # Reject unrepresentable versions before writes/processes.
    release = version.split('+', 1)[0]
    stage = root / '.build-support/client-windows'
    app = stage / 'app'
    build_dir = stage / 'cross'
    run([sys.executable, root / 'client/prepare_platform.py', 'windows'])
    # Preparation may have a reviewed version pin, but may not silently produce
    # assets for a different release than the version on the executable.
    if helper.pubspec_version(app / 'pubspec.yaml') != version:
        raise RuntimeError('Prepared Client pubspec version differs from source')
    build_dir.mkdir(parents=True, exist_ok=True)
    run(['flutter', 'pub', 'get', '--offline'], cwd=app)
    assets = build_dir / 'assets'
    run(['flutter', 'build', 'bundle', '--release', '--no-pub',
         '--target-platform=windows-x64', '--target=lib/client_main.dart',
         '--dart-define=XIO_CLIENT_ONLY=true', '--asset-dir=' + str(assets)], cwd=app)
    dill = max((app / '.dart_tool/flutter_build').glob('*/app.dill'),
               key=lambda path: path.stat().st_mtime)
    bundle = build_dir / 'XIOClient'
    bundle.mkdir(exist_ok=True)
    data = bundle / 'data'
    data.mkdir(exist_ok=True)
    shutil.rmtree(data / 'flutter_assets', ignore_errors=True)
    shutil.copytree(assets, data / 'flutter_assets')
    shutil.copy2(args.runtime_template / 'data/icudtl.dat', data / 'icudtl.dat')
    for path in args.runtime_template.glob('*.dll'):
        shutil.copy2(path, bundle / path.name)
    for path in args.runtime_template.glob('*LICENSE*'):
        shutil.copy2(path, bundle / path.name)
    shutil.copy2(root / 'client/brand/client-windows.ico', build_dir / 'xio.ico')
    shutil.copy2(root / 'tooling/cross-platform/windows.manifest', build_dir / 'windows.manifest')
    source = (root / 'tooling/cross-platform/windows_runner.cpp').read_text(encoding='utf-8')
    source = source.replace('L"XIO"', 'L"XIO Client"')
    source = re.sub(r'L"XIOClient[0-9]+"', 'L"XIOClient"', source)
    (build_dir / 'runner.cpp').write_text(source, encoding='utf-8')
    (build_dir / 'windows.rc').write_text(client_resource(version, helper), encoding='utf-8')
    run(['x86_64-w64-mingw32-windres', 'windows.rc', 'windows-res.o'], cwd=build_dir)
    exe = bundle / 'XIOClient.exe'
    run(['x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-municode', '-mwindows',
         '-static-libgcc', '-static-libstdc++', '-I' + str(args.engine_cache / 'release'),
         'runner.cpp', 'windows-res.o', args.engine_cache / 'libflutter_windows.a',
         '-lole32', '-lshell32', '-o', exe], cwd=build_dir)
    stamp_runner(exe, version, helper)
    # Private compiler prefix prevents interference with another Wine session.
    env = dict(os.environ, WINEPREFIX=str(args.wine_prefix.resolve()),
               WINEDEBUG='-all', WINEDLLOVERRIDES='mscoree,mshtml=')
    win = lambda path: 'Z:' + str(path.resolve()).replace('/', '\\')
    run(['xvfb-run', '-a', 'wine', args.engine_cache / 'debug/gen_snapshot.exe',
         '--deterministic', '--snapshot_kind=app-aot-elf', '--elf=' + win(data / 'app.so'),
         '--strip', win(dill)], env=env, timeout=180)
    (bundle / 'libexec').mkdir(exist_ok=True)
    run([args.go, 'build', '-trimpath', '-ldflags=-s -w', '-o',
         bundle / 'libexec/xio-tunnel.exe', './cmd/xio-desktop'], cwd=root / 'protocol/rivet',
        env=dict(os.environ, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0'))
    for name in ['wintun.dll', 'WINTUN-LICENSE.txt']:
        shutil.copy2(args.runtime_template / 'libexec' / name, bundle / 'libexec' / name)
    for name in ['LICENSE', 'COPYRIGHT', 'THIRD-PARTY-0.22.md']:
        shutil.copy2(root / name, bundle / name)
    for lang in ['ru', 'en']:
        shutil.copy2(root / f'client/README.{lang}.md', bundle / f'README.{lang}.md')
    # A final readback gates packaging too (not just compilation).
    seen = stamp_runner(exe, version, helper)
    out = root / f'releases/client-{release}'
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f'XIO-Client-{release}-windows-x64.zip'
    part = archive.with_suffix('.zip.part')
    with zipfile.ZipFile(part, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for path in sorted(bundle.rglob('*')):
            if path.is_file():
                zipped.write(path, 'XIOClient/' + path.relative_to(bundle).as_posix())
    part.replace(archive)
    print(f'Windows Client {seen["FileVersion"]} packaged: {archive}. '
          'Native Windows/driver acceptance NOT_EXECUTED.')
    return archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine-cache', type=Path, required=True)
    parser.add_argument('--runtime-template', type=Path, required=True)
    parser.add_argument('--wine-prefix', type=Path, required=True)
    parser.add_argument('--go', default='go')
    build(parser.parse_args(argv))


if __name__ == '__main__':
    main()
