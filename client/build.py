#!/usr/bin/env python3
"""Build the Android-only client from the current app, never the stale Git HEAD.

The isolated staging tree has its own pubspec, package ID, manifest and outputs.
No source asset/manifest/pubspec in the full application is rewritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.build-support/client'
APP = STAGE / 'app'


def prepare():
    STAGE.mkdir(parents=True, exist_ok=True)
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
        if not link.exists():
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
    source = (ROOT / 'app/pubspec.yaml').read_text()
    assert 'version: 0.22.3+5012' in source, 'Review the client version before using a newer base'
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
    source = source.replace('"XIO — X in, 1 out. VPN, mesh and network laboratory."',
                            '"XIO Client — connect to existing VPN servers."')
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
                child.set(ns + attr, ('app.x1o.client' if value.startswith('.launcher.') else 'app.x1o.x1o') + value)
    # Verification task expects the original relative alias targets. Fully qualify
    # components only in the manifest, and adapt its target assertion in staging.
    gradle = APP / 'android/app/build.gradle.kts'
    gradle.write_text(gradle.read_text().replace('== ".MainActivity"', '== "app.x1o.x1o.MainActivity"').replace('".launcher.', '"app.x1o.client.launcher.'))
    tree.write(manifest, encoding='unicode', xml_declaration=True)
    inputs = {}
    for base in [APP / 'lib', APP / 'android/app/src/main', assets]:
        for path in sorted(base.rglob('*')):
            if path.is_file() and path.name != 'GeneratedPluginRegistrant.java':
                inputs[str(path.relative_to(APP))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ['pubspec.yaml', 'pubspec.lock', 'android/app/build.gradle.kts',
                 'android/build.gradle.kts', 'android/settings.gradle.kts']:
        inputs[name] = hashlib.sha256((APP / name).read_bytes()).hexdigest()
    (STAGE / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    prepare()
    if not args.prepare_only:
        env = os.environ.copy()
        env.setdefault('ANDROID_HOME', str(Path.home() / 'Android/Sdk'))
        subprocess.run(['flutter', 'pub', 'get', '--offline'], cwd=APP, env=env, check=True)
        for split in [['--split-per-abi'], []]:
            subprocess.run(['flutter', 'build', 'apk', '--no-pub', '--release', *split,
                            '--target', 'lib/client_main.dart',
                            '--dart-define=XIO_CLIENT_ONLY=true'], cwd=APP, env=env, check=True)
        output = ROOT / 'releases/client-0.22.3'
        output.mkdir(parents=True, exist_ok=True)
        packages = APP / 'build/app/outputs/flutter-apk'
        for abi in ['arm64-v8a', 'armeabi-v7a', 'x86_64']:
            shutil.copy2(packages / f'app-{abi}-release.apk',
                         output / f'XIO-Client-0.22.3-{abi}.apk')
        shutil.copy2(packages / 'app-release.apk', output / 'XIO-Client-0.22.3-universal.apk')
        shutil.copy2(STAGE / 'source-inputs.json', output / 'source-inputs.json')
        for name in ['README.ru.md', 'README.en.md']:
            shutil.copy2(ROOT / 'client' / name, output / name)
        subprocess.run([os.sys.executable, ROOT / 'client/verify.py'], cwd=ROOT, check=True)
        print(output)
