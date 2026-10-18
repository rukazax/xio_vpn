#!/usr/bin/env python3
"""Package sources and evidence, excluding credentials, SDKs and build caches."""
from pathlib import Path
import zipfile
import re
import argparse

root = Path(__file__).resolve().parent.parent
excluded = {'publishing', 'output', 'tmp', '.build-support', '.signing', 'releases', '.dart_tool', 'build', '.gradle', '.cxx', '.git', '__pycache__', '.idea', 'ephemeral', '.plugin_symlinks'}
excluded_names = {'local.properties', '.flutter-plugins-dependencies', 'GeneratedPluginRegistrant.java', 'Generated.xcconfig', 'flutter_export_environment.sh'}
version = re.search(r'^version: ([0-9.]+)', (root/'app/pubspec.yaml').read_text(), re.M).group(1)
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path)
args = parser.parse_args()
out = args.output or root/f'releases/XIO-{version}-source.zip'
out.parent.mkdir(exist_ok=True)
temporary = out.with_name(out.name + '.part')
with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.name.startswith('release-archive-audit'):
            continue
        relative = path.relative_to(root)
        # Publish only this release's verification; retain older evidence locally.
        if relative.parts[0] == 'verification' and not path.name.startswith('VERIFICATION-') and not any(('0'+version.split('.')[1]) in part or ('.'.join(version.split('.')[:2])) in part for part in relative.parts):
            continue
        if path.name.startswith(('archive-audit-', 'source-package-', 'release-audit-')):
            continue
        is_vendor = 'vendor' in relative.parts
        if any(part in excluded and not (is_vendor and part in {'build', 'tmp', 'output'}) for part in relative.parts) or path.name in excluded_names:
            continue
        if relative.as_posix() not in {'app/assets/security/probe-roots.pem', 'app/android/app/src/main/res/raw/xio_probe_roots.pem'} and not is_vendor and path.suffix in {'.p12','.jks','.pem','.key','.jar'} and not (path.name == 'gradle-wrapper.jar'):
            continue
        if relative.parts[0] == 'vendor-metadata' and path.suffix == '.java':
            continue
        archive.write(path, 'XIO-source/XIO/'+relative.as_posix())
    for name in ['RIVET-1-ARCHITECTURE.ru.md','AMNEZIA-TECHNICAL-REVIEW.ru.md','TAILSCALE-DOCUMENTATION-REVIEW.ru.md']:
        archive.write(root.parent/name,'XIO-source/'+name)
with zipfile.ZipFile(temporary) as archive:
    assert archive.testzip() is None, 'Source archive integrity failed'
temporary.replace(out)
print(out)
