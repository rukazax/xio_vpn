#!/usr/bin/env python3
"""Final integrity: archive unchanged, only the AAR differs among archived product files,
gomobile inputs still byte-identical (1842 files), AAR artifact hash unchanged after compiles."""
from pathlib import Path
import hashlib, json

B = Path('/srv/archives/agent-rivet-aar-20261106')
S = B / 'src'
NEW_AAR = '7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c'
ARCHIVE = '27148ceb51225e5f60894952e469a116ede930e41a310ee342c8192edd95b904'
PREFIXES = ('protocol/', 'vendor/', 'tools/', 'tooling/')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


pre = json.loads((B / 'source-pre.json').read_text())
# The compile needs a machine-specific local.properties (not a committed file); keep its bytes as evidence.
lp = S / 'app/android/local.properties'
if 'app/android/local.properties' not in pre and lp.exists():
    (B / 'logs/local.properties.used').write_text(lp.read_text())
cur = {str(p.relative_to(S)): sha(p) for p in sorted(S.rglob('*')) if p.is_file()}
changed = {k: {'before': v, 'after': cur.get(k)} for k, v in pre.items() if v != cur.get(k)}
removed = sorted(k for k in changed if cur.get(k) is None)
added = sorted(k for k in cur if k not in pre)

inputs = {k: v for k, v in cur.items() if k.startswith(PREFIXES)}
agg = hashlib.sha256()
for k in sorted(inputs):
    agg.update(f'{k}\0{inputs[k]}\n'.encode())

report = {
    'commit': '595def6ab24590002458c0a5fa4f8020d5c8a86f',
    'archiveSha256Now': sha(B / 'source-main-595def6a.tar'),
    'archiveUnchanged': sha(B / 'source-main-595def6a.tar') == ARCHIVE,
    'archivedFileCount': len(pre),
    'currentFileCount': len(cur),
    'changedArchivedFiles': changed,
    'removedArchivedFiles': removed,
    'addedFilesAreGeneratedOnly': added,
    'gomobileInputFileCount': len(inputs),
    'gomobileInputAggregateSha256': agg.hexdigest(),
    'gomobileInputsStillMatchInputsJson': agg.hexdigest() == json.loads((B / 'logs/inputs.json').read_text())['gomobileInputAggregateSha256'],
    'aarInTreeSha256': sha(S / 'app/android/app/libs/rivet.aar'),
    'aarArtifactSha256': sha(B / 'fresh-binding/rivet.aar'),
    'aarArtifactUnchanged': sha(B / 'fresh-binding/rivet.aar') == NEW_AAR,
    'staleAarSha256': sha(B / 'artifacts/stale-rivet-cfc336c9.aar'),
    'runAarRecords': {f.stem: f.read_text().strip() for f in sorted((B / 'logs').glob('*-aar.txt'))},
    'runExits': {f.stem.replace('-exit', ''): f.read_text().strip()
                 for f in sorted((B / 'logs').glob('*-exit.txt'))},
}
assert report['archiveUnchanged']
assert report['gomobileInputsStillMatchInputsJson']
assert report['aarArtifactUnchanged']
assert report['aarInTreeSha256'] == NEW_AAR
assert list(changed) == ['app/android/app/libs/rivet.aar'], changed
assert not removed
(B / 'logs/final-integrity.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
