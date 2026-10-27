#!/usr/bin/env python3
"""Check local links in the maintained English/Russian GitHub pages."""
from pathlib import Path
import json,re,sys
r=Path(__file__).resolve().parents[1]
pages=[r/'README.md',r/'README.ru.md',r/'SECURITY.md',r/'CONTRIBUTING.md',r/'CHANGELOG.md',*(r/'docs/en').glob('*.md'),*(r/'docs/ru').glob('*.md')]
failures=[];count=0
for page in pages:
 text=page.read_text(encoding="utf-8")
 for url in [*re.findall(r'\]\(([^)]+)\)',text),*re.findall(r'src="([^"]+)"',text)]:
  if re.match(r'^[a-z]+:',url) or url.startswith('#'):continue
  target=(page.parent/url.split('#',1)[0]).resolve();count+=1
  if not target.exists():failures.append((str(page.relative_to(r)),url))
# A filename in a code span is not a download link. Keep both README tables
# and download pages linked to every published application in the release manifest.
version=re.search(r'^version:\s*(\d+\.\d+\.\d+)',(r/'app/pubspec.yaml').read_text(encoding='utf-8'),re.M).group(1)
manifest=json.loads((r/f'verification/{version}-release.json').read_text(encoding='utf-8'))
release_root=f'https://github.com/rukazax/xio_vpn/releases/download/{manifest["tag"]}/'
app_files=[a['file'] for a in manifest['artifacts'] if a['file'].startswith(('XIO-Client-','XIO-Full-'))]
download_pages=[r/'README.md',r/'README.ru.md',r/'docs/en/downloads.md',r/'docs/ru/downloads.md']
for page in download_pages:
 text=page.read_text(encoding='utf-8')
 targets=set(re.findall(r'\]\(([^)]+)\)',text))
 for name in app_files:
  if release_root+name not in targets:failures.append((str(page.relative_to(r)),'missing direct download: '+name))
 # GitHub's latest endpoint excludes pre-releases. Versioned download pages
 # must stay usable even when there is no stable release.
 if 'https://github.com/rukazax/xio_vpn/releases/latest' in text:
  failures.append((str(page.relative_to(r)),'use the tagged release, not /releases/latest'))
 # Shields expects include_prereleases as a bare flag; =true renders an error SVG.
 if re.search(r'https://img\.shields\.io/github/v/release/[^\" )]*[?&]include_prereleases=',text):
  failures.append((str(page.relative_to(r)),'Shields include_prereleases must be a bare flag'))
if failures:
 for p,url in failures:print(p+': '+url)
 sys.exit(1)
print(f'{len(pages)} pages, {count} local links; {len(download_pages)} download pages x {len(app_files)} application links: passed')
