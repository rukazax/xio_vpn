#!/usr/bin/env python3
"""Assemble machine-readable provenance for the fresh rivet.aar."""
from pathlib import Path
import hashlib, json

B = Path('/srv/archives/agent-rivet-aar-20261106')
L = B / 'logs'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


inputs = json.loads((L / 'inputs.json').read_text())
surface = json.loads((L / 'aar-surface.json').read_text())
integrity = json.loads((L / 'final-integrity.json').read_text())


def run(name):
    return {
        'exit': int((L / f'{name}-exit.txt').read_text().strip()),
        'durationSeconds': int((L / f'{name}-duration.txt').read_text().strip().rstrip('s')),
        'aarSha256': (L / f'{name}-aar.txt').read_text().split()[-1],
        'audit': json.loads((L / f'{name}-audit.txt').read_text()) if (L / f'{name}-audit.txt').exists() else None,
    }


prov = {
    'schema': 1,
    'commit': '595def6ab24590002458c0a5fa4f8020d5c8a86f',
    'commitSubjects': 'merge: independently accepted bounded WebUI contract repair (C6+C7+D10 at c946c920 plus S3 server-only WebUI repair)',
    'sourceArchive': {'path': str(B / 'source-main-595def6a.tar'),
                      'sha256': sha(B / 'source-main-595def6a.tar'),
                      'bytes': (B / 'source-main-595def6a.tar').stat().st_size,
                      'command': "git archive --format=tar 595def6ab24590002458c0a5fa4f8020d5c8a86f app client CONTRIBUTING.md docs legal patches protocol tooling tools vendor vendor-metadata",
                      'producedOn': 'Windows work/repo-merge (authorized source of MAIN), transferred by scp, hash re-verified on host'},
    'gitTreeIds': {'app': '7854a372a7f0148e6890645171baf8e48a19984f',
                   'client': 'f14d5f23685b6eb47c5382228312df3676afd767',
                   'protocol': '31f1a7d461bddf5e912e9de27a7a4a3141972522',
                   'tooling': 'c8ca36cf3fb268518219d4fde67a94840642fff3',
                   'tools': '24386867c9b5baecc7f77730c9f20bdad1a06647',
                   'vendor': 'c32b7204e067669841f7554cf2a66b1dc7a29515'},
    'gomobileInputs': {
        'roots': inputs['gomobileInputRoots'],
        'fileCount': inputs['gomobileInputFileCount'],
        'aggregateSha256': inputs['gomobileInputAggregateSha256'],
        'byteIdenticalToHistoricalEA891Inputs': inputs['inputsIdenticalToHistoricalEA891'],
        'goModSha256': inputs['goModSha256'],
        'goSumSha256': inputs['goSumSha256'],
        'pubspecLockSha256': inputs['pubspecLockSha256'],
        'verifiedAgainAfterCompiles': integrity['gomobileInputsStillMatchInputsJson'],
    },
    'recipe': {
        'origin': 'tools/build-rivet.py:20-23 (project canonical AAR recipe), private Go from tools/prepare-mobile-go.py',
        'cwd': 'src/protocol/rivet',
        'command': ('gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 '
                    "-trimpath '-ldflags=-s -w' -javapkg app.xio -o <out>/rivet.aar ./mobile"),
        'abis': ['arm64-v8a', 'armeabi-v7a', 'x86_64'],
        'androidApi': 26,
        'gomobileBinaries': {'gomobileSha256': sha('/root/go/bin/gomobile'),
                             'gobindSha256': sha('/root/go/bin/gobind'),
                             'module': 'golang.org/x/mobile v0.0.0-20261011034528-197770444867'},
        'privateGoPatch': 'CLOCK_BOOTTIME on arm/arm64/amd64 (tools/prepare-mobile-go.py)',
    },
    'toolchain': {'go': 'go1.27.3 linux/amd64', 'gomobileModule': 'golang.org/x/mobile v0.0.0-20261011034528-197770444867',
                  'jdk': 'OpenJDK 21.0.13+9-1-deb13u2', 'gradle': '9.3.1', 'agp': '9.1.0',
                  'kotlinAndroidPlugin': '2.4.0', 'androidSdk': 36, 'ndk': '30.0.16248370 (r30)',
                  'flutter': '3.47.7 revision abaf9c523780a608bd46686fd5e53740a07077f8', 'dart': '3.13.5'},
    'artifact': {
        'path': str(B / 'artifacts/rivet-fresh-595def6a-allabi.aar'),
        'canonicalCopy': str(B / 'fresh-binding/rivet.aar'),
        'sha256': surface['fresh']['aarSha256'],
        'bytes': surface['fresh']['aarBytes'],
        'classesJarSha256': surface['fresh']['classesJarSha256'],
        'classesJarIdenticalToHistoricalArm64Build': True,
        'abis': surface['fresh']['abis'],
        'nativeLibs': {k: v for k, v in surface['fresh']['nativeLibs'].items()},
        'javap': str(B / 'artifacts/surface/fresh/fresh-javap.txt'),
        'elfHeaders': str(B / 'artifacts/elf/'),
        'methodsRequired': surface['methods'],
        'methodsPresent': surface['fresh']['methodPresent'],
        'androidManifest': '<manifest package="go.mobile.gojni"><uses-sdk android:minSdkVersion="26"/></manifest>',
    },
    'compiles': {
        'command': ('gradle --offline --no-daemon --no-build-cache --max-workers=1 '
                    '-Dorg.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=512m '
                    '-Pkotlin.daemon.jvmargs=-Xmx1024m :app:compileDebugKotlin :app:compileDebugJavaWithJavac '
                    '-Ptarget-platform=android-arm64 -x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets'),
        'fresh-full': run('fresh-full'),
        'fresh-client': run('fresh-client'),
    },
    'negativeControl': {
        'aarSha256': surface['stale']['aarSha256'],
        'methodsPresent': surface['stale']['methodPresent'],
        'stale-full': run('stale-full'),
        'stale-client': run('stale-client'),
    },
    'integrity': {
        'archiveUnchanged': integrity['archiveUnchanged'],
        'onlyArchivedFileChanged': integrity['changedArchivedFiles'],
        'addedFilesAreGeneratedOnlyCount': len(integrity['addedFilesAreGeneratedOnly']),
        'aarArtifactUnchangedAfterCompiles': integrity['aarArtifactUnchanged'],
        'aarInTreeSha256': integrity['aarInTreeSha256'],
    },
    'reproducibility': {
        'classesJar': 'byte-identical to the historical EA891 arm64 binding',
        'nativeLibraries': ('NOT byte-identical to the historical arm64-only AAR. Different build roots are a '
                            'CONFIRMED CONTRIBUTOR: Go records replace-directive absolute paths in build info, and the '
                            'fresh libs embed /srv/archives/agent-rivet-aar-20261106/src/... while the historical ones '
                            'embed /srv/archives/agent-android-compile-preflight-20261106/src/... . Complete binary '
                            'equivalence/reproducibility of the .so was NOT established; this non-identity is '
                            'specific to this pair of builds and is not a general claim.'),
        'historicalArm64SoSha256': '777c70cfb803222a69a66289668d912769edfaecee52b01072986c2b4a4a8bac',
        'freshArm64SoSha256': surface['fresh']['nativeLibs']['jni/arm64-v8a/libgojni.so']['sha256'],
    },
    'limits': [
        'Compiler proof only: no APK/AAB, no signing, no install, no device, no runtime or route/VPN behaviour.',
        'Dart compilation and asset merging were excluded (-x :app:compileFlutterBuildDebug -x :app:mergeDebugAssets); app/pubspec.lock and Dart/assets untouched.',
        'Only the three ABIs actually built are claimed (arm64-v8a, armeabi-v7a, x86_64). No other ABI is claimed.',
        'The bundled AAR in the repository was NOT replaced and nothing was committed or pushed.',
        'OpenVPN/AmneziaWG JNI payloads, separate Client manifest/assets staging and macOS/iOS remain out of scope.',
    ],
}
(B / 'artifacts/provenance.json').write_text(json.dumps(prov, indent=2) + '\n')
print(json.dumps({k: prov[k] for k in ('artifact', 'compiles', 'negativeControl', 'integrity')}, indent=2))
