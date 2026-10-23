#!/usr/bin/env python3
"""Generate client icons from the repository's vector geometry, never edit main icons."""
from pathlib import Path
from PIL import Image,ImageDraw
import ast,math,json,argparse,shutil,copy
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--android-app',type=Path);a=p.parse_args()
paths=next(ast.literal_eval(n.value) for n in ast.parse((ROOT/'tools/generate-icons.py').read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='paths' for t in n.targets))
out=ROOT/'client/brand';out.mkdir(exist_ok=True)
def render(size,angle=0,pale=False,clear=False):
 scale=size/256;im=Image.new('RGBA',(size,size));d=ImageDraw.Draw(im)
 if not clear:d.rounded_rectangle((0,0,size-1,size-1),radius=60*scale,fill='#211a10')
 def transform(point):
  x,y=point[0]-128,point[1]-128;t=math.radians(angle);return ((128+x*math.cos(t)-y*math.sin(t))*scale,(128+x*math.sin(t)+y*math.cos(t))*scale)
 for i,path in enumerate(paths):
  pts=[transform(x) for x in path];color='#ffe1a6' if pale else ('#ffdc82' if i==3 else '#ffb547')
  for width,ink in [(23*scale,'#362000'),(17*scale,color)]:
   d.line(pts,fill=ink,width=round(width),joint='curve')
   for x,y in pts:d.ellipse((x-width/2,y-width/2,x+width/2,y+width/2),fill=ink)
 return im
render(1024).save(out/'client-1024.png');render(1024).resize((256,256),Image.Resampling.LANCZOS).save(out/'client-linux.png')
render(256).save(out/'client-windows.ico',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
# Keep existing launcher IDs so Android icon selections survive an update.
if a.android_app:
 res=a.android_app/'android/app/src/main/res'
 for palette in ['green','white']:
  for background in ['dark','clear']:
   for angle in [0,90,180,270]:
    name=f'{palette}_{background}_{angle}'
    for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
     folder=res/f'mipmap-{density}';folder.mkdir(exist_ok=True);render(size*4,angle,palette=='white',background=='clear').resize((size,size),Image.Resampling.LANCZOS).save(folder/f'xio_{name}.png')
    vector=res/'drawable'/f'xio_{name}_foreground.xml';s=vector.read_text().replace('#c0f57b','#ffb547').replace('#e7efde','#ffdc82').replace('#ffffff','#ffe1a6')
    ET.register_namespace('android','http://schemas.android.com/apk/res/android');root=ET.fromstring(s);group=root.find('group');ns='{http://schemas.android.com/apk/res/android}'
    for index,node in reversed(list(enumerate(list(group)))):
     outline=copy.deepcopy(node);outline.set(ns+'strokeColor','#362000');outline.set(ns+'strokeWidth','23');group.insert(index,outline)
    vector.write_text(ET.tostring(root,encoding='unicode'))
 (res/'values/xio_icons.xml').write_text('<resources><color name="xio_icon_dark">#211a10</color><color name="xio_icon_clear">#00000000</color></resources>\n')
 # Legacy launchers must also use client colors if any manifest names them.
 for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
  for p in (res/f'mipmap-{density}').glob('ic_launcher*.png'):render(size*4).resize((size,size),Image.Resampling.LANCZOS).save(p)
# Distinct Apple asset catalog prepared for an actual Xcode build/signing host.
ios=out/'AppIcon.appiconset';ios.mkdir(exist_ok=True);contents=json.loads((ROOT/'app/ios/Runner/Assets.xcassets/AppIcon.appiconset/Contents.json').read_text())
for spec in contents['images']:
 name=spec.get('filename')
 if name:
  size=round(float(spec['size'].split('x')[0])*float(spec['scale'].rstrip('x')));mark=render(size);opaque=Image.new('RGB',(size,size),'#211a10');opaque.paste(mark,mask=mark.getchannel('A'));opaque.save(ios/name)
(ios/'Contents.json').write_text(json.dumps(contents,indent=2)+'\n')
print('Client amber icons generated from vector geometry; full-app icons untouched')
