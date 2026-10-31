#!/usr/bin/env python3
"""Build the Android-only client from the current app, never the stale Git HEAD.

The isolated staging tree has its own pubspec, package ID, manifest and outputs.
No source asset/manifest/pubspec in the full application is rewritten.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLUTTER = 'flutter.bat' if os.name == 'nt' else 'flutter'
RELEASE = '0.23.1'
VERSION = RELEASE + '+5016'

STAGE = ROOT / '.build-support/client'
APP = STAGE / 'app'


def prepare():
    # Review version changes before any staging writes or refresh/removal.
    source = (ROOT / 'app/pubspec.yaml').read_text()
    if re.findall(r'(?m)^version: ([^\r\n]+)', source) != [VERSION]:
        raise RuntimeError('Review the client version before using a different base')
    stage = STAGE.resolve()
    if stage in {ROOT.resolve(), (ROOT / 'app').resolve()} or APP.is_symlink():
        raise RuntimeError('Unsafe client staging path')
    owner = STAGE / '.xio-client-stage.json'
    if owner.exists():
        record = json.loads(owner.read_text())
        if record.get('owner') != 'xio-client-staging-v1' or record.get('sourceRoot') != str(ROOT.resolve()):
            raise RuntimeError('Foreign staging tree preserved')
    elif APP.exists():
        raise RuntimeError('Unowned staging tree preserved; choose a fresh --stage')
    STAGE.mkdir(parents=True, exist_ok=True)
    owner.write_text(json.dumps({'owner': 'xio-client-staging-v1', 'sourceRoot': str(ROOT.resolve()), 'version': VERSION}) + '\n')
    # Reuse Gradle caches and outputs, refreshing source inputs each time.
    for name in ['lib', 'android', 'assets']:
        target = APP / name
        if target.exists():
            shutil.rmtree(target)
    APP.mkdir(exist_ok=True)
    for name in ['lib', 'android']:
        shutil.copytree(ROOT / 'app' / name, APP / name,
                        ignore=shutil.ignore_patterns('.gradle', 'build', '.cxx'))
    for name in ['pubspec.lock', 'analysis_options.yaml']:
        shutil.copy2(ROOT / 'app' / name, APP / name)
    for name in ['vendor', '.signing']:
        link = STAGE / name
        if (ROOT / name).exists() and not link.exists():
            link.symlink_to(ROOT / name, target_is_directory=True)
    assets = APP / 'assets'
    for name in ['help', 'licenses', 'l10n', 'security']:
        shutil.copytree(ROOT / 'app/assets' / name, assets / name)
    for lang in ['ru', 'en']:
        for document in ['privacy', 'legal']:
            shutil.copy2(ROOT / f'client/{document}.{lang}.txt', assets / f'help/{document}.{lang}.txt')
    (assets/'fonts').mkdir(exist_ok=True)
    shutil.copy2(ROOT/'app/assets/fonts/NotoSans-Regular.ttf',assets/'fonts/NotoSans-Regular.ttf')
    # System fonts handle scripts: do not bundle the 16 MB CJK font or server tools.
    source = source[:source.index('  assets:')] + '''  assets:
    - assets/help/
    - assets/licenses/
    - assets/l10n/
    - assets/security/
  fonts:
    - family: X1oSans
      fonts:
        - asset: assets/fonts/NotoSans-Regular.ttf
'''
    source = source.replace('"XIO вЂ” X in, 1 out. VPN, mesh and network laboratory."',
                            '"XIO Client вЂ” connect to existing VPN servers."')
    source = re.sub(r'(?m)^description:.*$', 'description: "XIO Client - connect to existing VPN servers."', source, count=1)
    (APP / 'pubspec.yaml').write_text(source)
    manifest = APP / 'android/app/src/main/AndroidManifest.xml'
    import xml.etree.ElementTree as ET
    ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
    ns = '{http://schemas.android.com/apk/res/android}'
    tree = ET.parse(manifest)
    root = tree.getroot()
    for child in list(root):
        if child.tag == 'uses-permission' and child.get(ns + 'name') == '${installPermission}':
            root.remove(child)
    application = root.find('application')
    for child in list(application):
        if child.get(ns + 'name') in ['.UpdateJob', '.UpdateCleanupReceiver'] or child.get(ns + 'authorities') in ['${applicationId}.updates']:
            application.remove(child)
    for child in root.iter():
        if child.get(ns + 'label') == 'XIO':
            child.set(ns + 'label', 'XIO Client')
        # Relative names resolve against applicationId, not the Kotlin namespace.
        for attr in ['name', 'targetActivity']:
            value = child.get(ns + attr, '')
            if value.startswith('.'):
                child.set(ns + attr, ('app.xio.client' if value.startswith('.launcher.') else 'app.xio.xio') + value)
    # Verification task expects the original relative alias targets. Fully qualify
    # components only in the manifest, and adapt its target assertion in staging.
    gradle = APP / 'android/app/build.gradle.kts'
    gradle.write_text(gradle.read_text().replace('== ".MainActivity"', '== "app.xio.xio.MainActivity"').replace('".launcher.', '"app.xio.client.launcher.'))
    tree.write(manifest, encoding='unicode', xml_declaration=True)
    subprocess.run([os.sys.executable, ROOT / 'client/generate_icons.py', '--android-app', APP], check=True)
    inputs = {}
    for base in [APP / 'lib', APP / 'android/app/src/main', assets]:
        for path in sorted(base.rglob('*')):
            if path.is_file() and path.name != 'GeneratedPluginRegistrant.java':
                inputs[str(path.relative_to(APP))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ['pubspec.yaml', 'pubspec.lock', 'android/app/build.gradle.kts',
                 'android/build.gradle.kts', 'android/settings.gradle.kts', 'android/gradle.properties',
                 'android/app/libs/rivet.aar']:
        inputs[name] = hashlib.sha256((APP / name).read_bytes()).hexdigest()
    for path in sorted((ROOT / 'vendor/amneziawg/android').rglob('*')):
        if path.is_file() and not any(part in {'.gradle', 'build', '.cxx'} for part in path.parts):
            inputs[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    (STAGE / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--stage', type=Path, help='Fresh, owned staging root; source tree is never changed')
    parser.add_argument('--output-dir', type=Path, help='Separate artifact directory')
    args = parser.parse_args()
    if args.stage:
        STAGE = args.stage.resolve()
        APP = STAGE / 'app'
    prepare()
    if not args.prepare_only:
        env = os.environ.copy()
        env.setdefault('ANDROID_HOME', str(Path.home() / 'Android/Sdk'))
        subprocess.run([FLUTTER, 'pub', 'get', '--offline'], cwd=APP, env=env, check=True)
        for split in [['--split-per-abi'], []]:
            subprocess.run([FLUTTER, 'build', 'apk', '--no-pub', '--release', *split,
                            '--target', 'lib/client_main.dart',
                            '--dart-define=XIO_CLIENT_ONLY=true'], cwd=APP, env=env, check=True)
        output = args.output_dir or ROOT / f'releases/client-{RELEASE}'
        output.mkdir(parents=True, exist_ok=True)
        packages = APP / 'build/app/outputs/flutter-apk'
        for abi in ['arm64-v8a', 'armeabi-v7a', 'x86_64']:
            shutil.copy2(packages / f'app-{abi}-release.apk',
                         output / f'XIO-Client-{RELEASE}-android-{abi}.apk')
        shutil.copy2(packages / 'app-release.apk', output / 'XIO-Client-0.23.0-android-universal.apk')
        shutil.copy2(STAGE / 'source-inputs.json', output / 'source-inputs.json')
        for name in ['README.ru.md', 'README.en.md']:
            shutil.copy2(ROOT / 'client' / name, output / name)
        subprocess.run([os.sys.executable, ROOT / 'client/verify.py', '--output-dir', output], cwd=ROOT, check=True)
        print(output)
