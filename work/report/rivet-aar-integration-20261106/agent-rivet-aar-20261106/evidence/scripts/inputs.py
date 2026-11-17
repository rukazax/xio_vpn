#!/usr/bin/env python3
"""Hash the exact gomobile inputs fed from the MAIN snapshot; compare to historical EA891 inputs."""
from pathlib import Path
import hashlib, json

B = Path('/srv/archives/agent-rivet-aar-20261106')
S = B / 'src'
OLD = Path('/srv/archives/agent-android-compile-preflight-20261106')
PREFIXES = ('protocol/', 'vendor/', 'tools/', 'tooling/')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


files = {str(p.relative_to(S)): sha(p) for p in sorted(S.rglob('*')) if p.is_file()}
(B / 'source-pre.json').write_text(json.dumps(files, indent=2))

inputs = {k: v for k, v in files.items() if k.startswith(PREFIXES)}
# Deterministic aggregate over the exact input set (path + content hash).
agg = hashlib.sha256()
for k in sorted(inputs):
    agg.update(f'{k}\0{inputs[k]}\n'.encode())

old_pre = json.loads((OLD / 'source-pre.json').read_text())
old_inputs = {k: v for k, v in old_pre.items() if k.startswith(PREFIXES)}

report = {
    'commit': '595def6ab24590002458c0a5fa4f8020d5c8a86f',
    'archiveSha256': sha(B / 'source-main-595def6a.tar'),
    'archiveBytes': (B / 'source-main-595def6a.tar').stat().st_size,
    'extractedFileCount': len(files),
    'gomobileInputRoots': list(PREFIXES),
    'gomobileInputFileCount': len(inputs),
    'gomobileInputAggregateSha256': agg.hexdigest(),
    'historicalInputFileCount': len(old_inputs),
    'inputsIdenticalToHistoricalEA891': old_inputs == inputs,
    'mobilePackageFiles': {k: v for k, v in inputs.items() if k.startswith('protocol/rivet/mobile/')},
    'goModSha256': files.get('protocol/rivet/go.mod'),
    'goSumSha256': files.get('protocol/rivet/go.sum'),
    'pubspecLockSha256': files.get('app/pubspec.lock'),
    'javaKotlinSourceCounts': {
        'kotlin': len([k for k in files if k.endswith('.kt')]),
        'java': len([k for k in files if k.endswith('.java')]),
    },
}
(B / 'logs/inputs.json').write_text(json.dumps(report, indent=2) + '\n')
if not report['inputsIdenticalToHistoricalEA891']:
    only_new = sorted(set(inputs) - set(old_inputs))
    only_old = sorted(set(old_inputs) - set(inputs))
    changed = sorted(k for k in set(inputs) & set(old_inputs) if inputs[k] != old_inputs[k])
    report['differences'] = {'onlyInMain': only_new, 'onlyInHistorical': only_old, 'contentChanged': changed}
    (B / 'logs/inputs.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'mobilePackageFiles'}, indent=2))
