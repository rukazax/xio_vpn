#!/usr/bin/env python3
"""Check the packaged manifest, including disabled icon variants, not just sources."""
from pathlib import Path
import argparse,os,subprocess,re,json
p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--aapt',type=Path);a=p.parse_args()
if a.aapt is None:
 sdk=Path(os.environ.get('ANDROID_HOME',Path.home()/'Android/Sdk'))
 a.aapt=sorted((sdk/'build-tools').glob('*/aapt'))[-1]
def run(*args):return subprocess.check_output([str(a.aapt),*args],text=True)
badging=run('dump','badging',str(a.apk));tree=run('dump','xmltree',str(a.apk),'AndroidManifest.xml')
# aapt badging omits activity-alias launchers; inspect the compiled XML tree.
blocks=[b for b in re.split(r'^      E: ',tree,flags=re.M) if b.startswith('activity-alias ')]
assert len(blocks)==16, 'APK lost icon alternatives during manifest merge'
expected={f'app.xio.xio.launcher.{c}_{b}_{n}' for c in ('green','white') for b in ('dark','clear') for n in (0,90,180,270)}
names=set();enabled=[]
for block in blocks:
 name=re.search(r'^        A: android:name[^=]*="([^\"]+)"',block,re.M).group(1)
 names.add(name)
 assert 'android.intent.action.MAIN' in block and 'android.intent.category.LAUNCHER' in block
 assert 'android:targetActivity' in block and '="app.xio.xio.MainActivity"' in block
 assert re.search(r'android:exported[^=]*=\(type 0x12\)0xffffffff',block)
 if re.search(r'android:enabled[^=]*=\(type 0x12\)0xffffffff',block):enabled.append(name)
assert names==expected and enabled==['app.xio.xio.launcher.green_dark_0'], 'APK has no valid unique default launcher'
assert "name='app.xio.xio'" in badging
print(json.dumps({'apk':a.apk.name,'defaultLauncher':enabled[0],'packagedIconAliases':16,'validated':True},indent=2))
