#!/usr/bin/env python3
"""Render the existing vector mark at four rotations in two palettes/backgrounds."""
from pathlib import Path
from PIL import Image, ImageDraw
import math, re
r=Path(__file__).resolve().parent.parent
assets=r/'app/assets/icons'; assets.mkdir(exist_ok=True)
res=r/'app/android/app/src/main/res'
(res/'values'/'xio_icons.xml').write_text('<resources><color name="xio_icon_dark">#0c1119</color><color name="xio_icon_clear">#00000000</color></resources>\n')
variants=[]
paths=[[(43,53),(119,128),(211,128)],[(43,203),(119,128)],[(182,99),(211,128),(182,157)],[(43,128),(78,128)]]
for palette in ['green','white']:
 for background in ['dark','clear']:
  for angle in [0,90,180,270]:
   name=f'{palette}_{background}_{angle}'; variants.append(name)
   def point(p):
    x,y=p[0]-128,p[1]-128
    t=math.radians(angle)
    return (128+x*math.cos(t)-y*math.sin(t),128+x*math.sin(t)+y*math.cos(t))
   transformed=[[point(p) for p in path] for path in paths]
   def render(size):
    scale=size/256; im=Image.new('RGBA',(size,size)); d=ImageDraw.Draw(im)
    if background=='dark': d.rounded_rectangle((0,0,size-1,size-1),radius=60*scale,fill='#0c1119')
    for i,points in enumerate(transformed):
     color='#ffffff' if palette=='white' else ('#e7efde' if i==3 else '#c0f57b')
     pts=[(x*scale,y*scale) for x,y in points]; w=17*scale
     d.line(pts,fill=color,width=round(w),joint='curve')
     for x,y in pts:d.ellipse((x-w/2,y-w/2,x+w/2,y+w/2),fill=color)
    return im
   render(1024).resize((256,256),Image.Resampling.LANCZOS).save(assets/f'{name}.png')
   for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    folder=res/f'mipmap-{density}';folder.mkdir(exist_ok=True)
    render(size*4).resize((size,size),Image.Resampling.LANCZOS).save(folder/f'xio_{name}.png')
   vector='<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="108dp" android:height="108dp" android:viewportWidth="256" android:viewportHeight="256"><group android:scaleX="0.65" android:scaleY="0.65" android:translateX="44.8" android:translateY="44.8">'
   for idx,points in enumerate(transformed):
    color='#ffffff' if palette=='white' else ('#e7efde' if idx==3 else '#c0f57b')
    path='M'+' L'.join(f'{x:.3f},{y:.3f}' for x,y in points)
    vector+=f'<path android:pathData="{path}" android:fillColor="@android:color/transparent" android:strokeColor="{color}" android:strokeWidth="17" android:strokeLineCap="round" android:strokeLineJoin="round"/>'
   vector+='</group></vector>'
   (res/'drawable'/f'xio_{name}_foreground.xml').write_text(vector+'\n')
   adaptive=res/'mipmap-anydpi-v26';adaptive.mkdir(exist_ok=True)
   (adaptive/f'xio_{name}.xml').write_text(f'<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android"><background android:drawable="@color/xio_icon_{background}"/><foreground android:drawable="@drawable/xio_{name}_foreground"/></adaptive-icon>\n')
   svg='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">'
   if background=='dark':svg+='<rect width="256" height="256" rx="60" fill="#0c1119"/>'
   for i,points in enumerate(transformed):
    color='#ffffff' if palette=='white' else ('#e7efde' if i==3 else '#c0f57b')
    svg+=f'<polyline points="'+ ' '.join(f'{x:.1f},{y:.1f}' for x,y in points)+f'" fill="none" stroke="{color}" stroke-width="17" stroke-linecap="round" stroke-linejoin="round"/>'
   svg+='</svg>'
   (r/'brand'/f'{name}.svg').write_text(svg)
# Native aliases preserve package/data identity while offering real launcher switching.
from launcher_manifest import install_aliases
p=r/'app/android/app/src/main/AndroidManifest.xml'
p.write_text(install_aliases(p.read_text()))
# Review sheet with transparent icons on a neutral checker pattern.
sheet=Image.new('RGB',(1024,1104),'#313941');d=ImageDraw.Draw(sheet)
for i,name in enumerate(variants):
 x=(i%4)*256;y=(i//4)*276
 for a in range(0,256,16):
  for b in range(0,256,16):
   d.rectangle((x+a,y+b,x+a+15,y+b+15),fill='#555d65' if (a+b)//16%2 else '#424a52')
 im=Image.open(assets/f'{name}.png');sheet.paste(im,(x,y),im)
 d.text((x+8,y+258),name,fill='white')
sheet.save(r/'verification/XIO-icons-0.15.png')
print(f'{len(variants)} vector variants generated')
