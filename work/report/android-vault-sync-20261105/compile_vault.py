"""Offline standalone Kotlin compile using only explicitly located existing cache inputs."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

WORK = Path('/srv/archives/agent-vault-compile-20261105')
CACHE = Path('/root/.gradle/caches/modules-2/files-2.1')
JARS = {
    'compiler': 'org.jetbrains.kotlin/kotlin-compiler-embeddable/2.4.0/f1a24af8bd111a83950236b1aec7a6d72a97e92c/kotlin-compiler-embeddable-2.4.0.jar',
    'stdlib': 'org.jetbrains.kotlin/kotlin-stdlib/2.4.0/4e9f4b531dce5c7dee58ed2de9a8b9a763c8dc6c/kotlin-stdlib-2.4.0.jar',
    'script-runtime': 'org.jetbrains.kotlin/kotlin-script-runtime/2.4.0/1de03f0ef3e208ab5f97ee6a587e9b8480447df6/kotlin-script-runtime-2.4.0.jar',
    'build-tools-api': 'org.jetbrains.kotlin/kotlin-build-tools-api/2.4.0/46429d5887df2d02f33fe11a0c8444c5be5fd8da/kotlin-build-tools-api-2.4.0.jar',
    'daemon-embeddable': 'org.jetbrains.kotlin/kotlin-daemon-embeddable/2.4.0/1ecabef3a8ba6a8e25654573d54edb7e4136e903/kotlin-daemon-embeddable-2.4.0.jar',
    'reflect': 'org.jetbrains.kotlin/kotlin-reflect/1.6.10/1cbe9c92c12a94eea200d23c2bbaedaf3daf5132/kotlin-reflect-1.6.10.jar',
    'coroutines': 'org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.0/ac1dc37a30a93150b704022f8d895ee1bd3a36b3/kotlinx-coroutines-core-jvm-1.8.0.jar',
    'annotations': 'org.jetbrains/annotations/13.0/919f0dfe192fb4e063e7dacadee7f8bb9a2672a9/annotations-13.0.jar',
}
SDK = Path('/opt/android-sdk/platforms/android-36/android.jar')
API_XML = SDK.parent / 'data/api-versions.xml'
JAVA = Path('/usr/lib/jvm/java-21-openjdk-amd64/bin/java')
JAVAP = JAVA.with_name('javap')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def call(command, output):
    process = subprocess.run(list(map(str, command)), cwd=WORK, capture_output=True, text=True)
    (WORK / output).write_text(process.stdout + process.stderr)
    return process.returncode


def main():
    global WORK
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--round', required=True)
    args = parser.parse_args()
    base = WORK
    if Path(args.round).name != args.round or args.round in {'.', '..'}:
        raise RuntimeError('Unsafe evidence round name')
    source_bytes = (base / 'ConfigVault.kt').read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != args.expected_sha256:
        raise RuntimeError('Copied source SHA mismatch')
    WORK = base / args.round
    WORK.mkdir()
    source = WORK / 'ConfigVault.kt'
    source.write_bytes(source_bytes)
    paths = {name: CACHE / relative for name, relative in JARS.items()}
    for path in [*paths.values(), SDK, API_XML, JAVA, JAVAP]:
        if not path.is_file():
            raise RuntimeError('Required existing dependency absent: ' + str(path))
    evidence = {'source': {'path': str(source), 'sha256': sha(source)},
                'inputs': {name: {'path': str(path), 'sha256': sha(path)} for name, path in paths.items()},
                'androidJar': {'path': str(SDK), 'sha256': sha(SDK)},
                'apiHistory': {'path': str(API_XML), 'sha256': sha(API_XML)}}
    classes = WORK / 'classes'
    temporary = WORK / 'tmp'
    classes.mkdir()
    temporary.mkdir()
    java = [JAVA, '-Djava.io.tmpdir=' + str(temporary), '-cp', ':'.join(map(str, paths.values())),
            'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler']
    evidence['javaVersionExit'] = call([JAVA, '-version'], 'java-version.log')
    evidence['compilerVersionExit'] = call([*java, '-no-stdlib', '-no-reflect', '-no-jdk', '-version'], 'kotlin-version.log')
    command = [*java, '-no-stdlib', '-no-reflect', '-no-jdk', '-jvm-target', '17', '-classpath',
               ':'.join(map(str, [SDK, paths['stdlib'], paths['annotations']])), '-d', classes, source]
    evidence['compilerCommand'] = list(map(str, command))
    evidence['compilerExit'] = call(command, 'compile.log')
    evidence['sourceAfterSha256'] = sha(source)
    if evidence['compilerExit'] == 0:
        evidence['outputs'] = [{'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}
                               for path in sorted(classes.rglob('*')) if path.is_file()]
        evidence['javapExit'] = call([JAVAP, '-classpath', classes, '-c', '-p', '-verbose', 'app.xio.xio.ConfigVault'], 'javap.log')
    history = ET.parse(API_XML).getroot()
    checks = {
        'android/system/Os': [('method', 'open(Ljava/lang/String;II)Ljava/io/FileDescriptor;'),
                              ('method', 'fsync(Ljava/io/FileDescriptor;)V'), ('method', 'close(Ljava/io/FileDescriptor;)V'),
                              ('method', 'fstat(Ljava/io/FileDescriptor;)Landroid/system/StructStat;')],
        'android/system/OsConstants': [('field', 'O_RDONLY'), ('method', 'S_ISDIR(I)Z')] +
                                      ([('field', 'O_DIRECTORY')] if b'O_DIRECTORY' in source_bytes else []),
        'android/system/StructStat': [('field', 'st_mode')],
        'android/content/Context': [('method', 'getNoBackupFilesDir()Ljava/io/File;')],
        'android/security/keystore/KeyGenParameterSpec': [],
        'android/security/keystore/KeyProperties': [],
        'javax/crypto/spec/GCMParameterSpec': [],
        'java/io/FileDescriptor': [('method', 'sync()V')],
    }
    api_records = []
    for name, members in checks.items():
        node = history.find("class[@name='" + name + "']")
        if node is None:
            raise RuntimeError('SDK API history class absent: ' + name)
        api_records.append({'symbol': name, 'since': int(node.get('since', '1'))})
        for kind, member in members:
            child = node.find(kind + "[@name='" + member + "']")
            if child is None:
                api_records.append({'symbol': name + '.' + member, 'missingInPublicSdk': True})
                continue
            api_records.append({'symbol': name + '.' + member, 'since': int(child.get('since', node.get('since', '1')))})
    evidence['apiHistoryRecords'] = api_records
    evidence['reviewedMinSdk'] = 26
    evidence['apiSymbolsAvailableByMin26'] = all(not row.get('missingInPublicSdk') and row['since'] <= 26 for row in api_records)
    (WORK / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')
    if evidence['compilerExit'] or evidence.get('javapExit') or evidence['sourceAfterSha256'] != args.expected_sha256:
        return 1
    if not evidence.get('outputs') or not evidence['apiSymbolsAvailableByMin26']:
        return 1
    print(json.dumps({'compiled': True, 'sourceSha256': args.expected_sha256, 'classes': evidence['outputs'],
                      'min26ApiSymbols': evidence['apiSymbolsAvailableByMin26']}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
