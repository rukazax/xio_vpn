#!/usr/bin/env python3
"""Check local links in the maintained English/Russian GitHub pages."""
from pathlib import Path
import re,sys
r=Path(__file__).resolve().parents[1]
pages=[r/'README.md',r/'README.ru.md',r/'SECURITY.md',r/'CONTRIBUTING.md',r/'CHANGELOG.md',*(r/'docs/en').glob('*.md'),*(r/'docs/ru').glob('*.md')]
failures=[];count=0
for page in pages:
 text=page.read_text()
 for url in [*re.findall(r'\]\(([^)]+)\)',text),*re.findall(r'src="([^"]+)"',text)]:
  if re.match(r'^[a-z]+:',url) or url.startswith('#'):continue
  target=(page.parent/url.split('#',1)[0]).resolve();count+=1
  if not target.exists():failures.append((str(page.relative_to(r)),url))
if failures:
 for p,url in failures:print(p+': '+url)
 sys.exit(1)
print(f'{len(pages)} pages, {count} local links: passed')
