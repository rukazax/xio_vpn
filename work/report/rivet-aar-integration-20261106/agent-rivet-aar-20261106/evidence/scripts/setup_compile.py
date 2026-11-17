#!/usr/bin/env python3
"""Prepare the owned compile tree: Flutter SDK facade, plugin metadata, Gradle cache copy.

Only reads shared toolchains; every writable path is inside the owned tree.
"""
from pathlib import Path
import shutil, json, hashlib

B = Path('/srv/archives/agent-rivet-aar-20261106')
S = B / 'src'
OLD_AAR_SHA = 'cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7'
NEW_AAR_SHA = 'PLACEHOLDER'
STALE = B / 'artifacts/stale-rivet-cfc336c9.aar'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


aar = S / 'app/android/app/libs/rivet.aar'
assert sha(aar) == OLD_AAR_SHA, f'unexpected committed AAR {sha(aar)}'
# Preserve the exact committed stale AAR for the negative control, then never touch it again.
if not STALE.exists():
    shutil.copy2(aar, STALE)
assert sha(STALE) == OLD_AAR_SHA

# Gradle dependency cache: upstream host cache, copied (never shared/written).
gc = B / 'gradle/caches'
for rel in ['modules-2', '9.3.1/generated-gradle-jars']:
    src = Path('/root/.gradle/caches') / rel
    dst = gc / rel
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst)

# Flutter SDK facade: writable Gradle tooling copied, SDK resources referenced read-only.
f = B / 'flutter'
if not f.exists():
    f.mkdir()
    for p in Path('/opt/flutter').iterdir():
        if p.name != 'packages':
            (f / p.name).symlink_to(p, target_is_directory=p.is_dir())
    (f / 'packages').mkdir()
    for p in Path('/opt/flutter/packages').iterdir():
        if p.name != 'flutter_tools':
            (f / 'packages' / p.name).symlink_to(p, target_is_directory=p.is_dir())
    ft = f / 'packages/flutter_tools'
    ft.mkdir()
    for p in Path('/opt/flutter/packages/flutter_tools').iterdir():
        if p.name != 'gradle':
            (ft / p.name).symlink_to(p, target_is_directory=p.is_dir())
    shutil.copytree('/opt/flutter/packages/flutter_tools/gradle', ft / 'gradle',
                    ignore=shutil.ignore_patterns('build', '.gradle', '.kotlin'))

# Real SDK integration_test package, copied so the Flutter build cannot write into /opt/flutter.
it = B / 'integration_test'
if not it.exists():
    shutil.copytree('/opt/flutter/packages/integration_test', it,
                    ignore=shutil.ignore_patterns('build', '.gradle', '.dart_tool'))

meta = {
    'info': 'This is a generated file; do not edit or check into version control.',
    'plugins': {
        'ios': [{'name': 'integration_test', 'path': str(it) + '/', 'native_build': True, 'dependencies': [], 'dev_dependency': True}],
        'android': [{'name': 'integration_test', 'path': str(it) + '/', 'native_build': True, 'dependencies': [], 'dev_dependency': True}],
        'macos': [], 'linux': [], 'windows': [], 'web': [],
    },
    'dependencyGraph': [{'name': 'integration_test', 'dependencies': []}],
    'date_created': '2026-11-06 05:00:00.000000',
    'version': '3.47.7',
    'swift_package_manager_enabled': {'ios': False, 'macos': False},
}
(S / 'app/.flutter-plugins-dependencies').write_text(json.dumps(meta))
(S / 'app/android/local.properties').write_text(
    f'sdk.dir=/opt/android-sdk\nflutter.sdk={f}\nflutter.versionName=0.24.2\nflutter.versionCode=5019\n')

report = {
    'tree': str(S),
    'staleAarSha256': sha(STALE),
    'committedAarSha256': sha(aar),
    'flutterSdkFacade': str(f),
    'gradleCaches': str(gc),
    'integrationTest': str(it),
    'pluginMetadataSha256': sha(S / 'app/.flutter-plugins-dependencies'),
    'localProperties': (S / 'app/android/local.properties').read_text(),
}
(B / 'logs/setup.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
