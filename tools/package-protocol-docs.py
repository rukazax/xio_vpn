#!/usr/bin/env python3
"""Build a portable bilingual HTML/Markdown documentation edition. Requires markdown."""
from pathlib import Path
import base64,hashlib,json,re,zipfile,subprocess
import markdown
R=Path(__file__).resolve().parents[1];D=R/'docs/protocols'; RELEASE=R/'releases';RELEASE.mkdir(exist_ok=True)
css='''body{margin:0;background:#0d111b;color:#e8efdf;font:17px/1.65 system-ui,sans-serif}main{max-width:1080px;margin:auto;padding:36px 24px}h1,h2,h3{line-height:1.25;color:#b9ec70}h1{font-size:2.2em;border-bottom:1px solid #354257;padding-bottom:24px}h2{margin-top:2em}a{color:#70c6ed}img{max-width:100%;height:auto}table{display:block;overflow:auto;border-collapse:collapse;font-size:.9em}th,td{border:1px solid #354257;padding:9px 12px;min-width:90px}pre{padding:16px;background:#192233;overflow:auto;font-size:14px}code{overflow-wrap:anywhere}nav{padding:16px;background:#192233;border-radius:12px}article{margin-bottom:90px} .meta{color:#a5b1c3} @media(max-width:600px){main{padding:20px 14px}body{font-size:16px}h1{font-size:1.65em}}@media print{body{background:white;color:#172031;font-size:10pt}h1,h2,h3{color:#213c22}a{color:#164c75}article{break-before:page}pre{white-space:pre-wrap}table{display:table;font-size:8pt}img{max-height:180mm;object-fit:contain}nav{display:none}}'''
for lang in ['ru','en']:
 sections=[]
 for p in sorted((D/lang).glob('*.md')):
  s=p.read_text()
  def image(m):
   path=(p.parent/m[2]).resolve();b=base64.b64encode(path.read_bytes()).decode();return f'![{m[1]}](data:image/png;base64,{b})'
  s=re.sub(r'!\[([^]]*)\]\(([^)]+)\)',image,s)
  def link(m):
   t=m[2]
   if t.startswith(('https:','http:','mailto:','data:','#')):return m[0]
   resolved=(p.parent/t).resolve()
   try: relative=resolved.relative_to(R).as_posix()
   except ValueError:return m[0]
   return f'[{m[1]}](https://github.com/rukazax/xio_vpn/blob/main/{relative})'
  s=re.sub(r'(?<!!)\[([^]]*)\]\(([^)]+)\)',link,s)
  sections.append('<article>'+markdown.markdown(s,extensions=['tables','fenced_code','toc'])+'</article>')
 title='RIVET — устройство, безопасность и испытания' if lang=='ru' else 'RIVET — architecture, security and testing'
 html=f'<!doctype html><html lang="{lang}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>{css}</style><main><nav>XIO · RIVET/1 · Documentation 1.0 · 2026-10-18<br>RU / EN · <a href="https://github.com/rukazax/xio_vpn/tree/main/docs/protocols">GitHub</a></nav>'+''.join(sections)+'</main></html>'
 (RELEASE/f'XIO-RIVET-docs-1.0-{lang}.html').write_text(html)
paths=sorted([p for p in D.rglob('*') if p.is_file()]+[R/'docs/blog/2026-10-18-rivet.md',R/'tools/render-protocol-figures.py',R/'tools/package-protocol-docs.py'])
archive=RELEASE/'XIO-RIVET-docs-1.0.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in paths:z.write(p,p.relative_to(R).as_posix())
 for lang in ['ru','en']:
  p=RELEASE/f'XIO-RIVET-docs-1.0-{lang}.html';z.write(p,p.name)
assets=[archive]+[RELEASE/f'XIO-RIVET-docs-1.0-{l}.html' for l in ['ru','en']]
(RELEASE/'SHA256SUMS-rivet-docs-1.0').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in assets))
print(json.dumps({p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in assets},indent=2))
