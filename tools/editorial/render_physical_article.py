#!/usr/bin/env python3
"""Reproducible article diagrams. These are illustrations, not phone screenshots.
Requires Pillow; emits editable SVG and matching PNG without private device data.
"""
from pathlib import Path
from html import escape
from PIL import Image, ImageDraw, ImageFont
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'docs/images/physical-2026-10-21'
BG='#0c1119';CARD='#172130';TEXT='#e7efde';MUTED='#a6b5c6';LIME='#c0f57b';CYAN='#6dd8e8';ORANGE='#ffb38c'
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD=FONT.replace('.ttf','-Bold.ttf')
class Canvas:
 def __init__(self,h):
  self.w=1500;self.h=h;self.im=Image.new('RGB',(self.w,h),BG);self.d=ImageDraw.Draw(self.im);self.svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="{h}" viewBox="0 0 1500 {h}" role="img"><rect width="1500" height="{h}" fill="{BG}"/>']
 def box(self,x,y,w,h,fill=CARD,r=22):
  self.d.rounded_rectangle((x,y,x+w,y+h),radius=r,fill=fill);self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}"/>')
 def text(self,x,y,s,size=24,color=TEXT,bold=False,maxw=None):
  font=ImageFont.truetype(BOLD if bold else FONT,size)
  width=self.d.textlength(s,font=font)
  assert x+width<1480,(s,width)
  if maxw is not None:assert width<=maxw,(s,width,maxw)
  self.d.text((x,y),s,font=font,fill=color,anchor='lt');self.svg.append(f'<text x="{x}" y="{y}" font-family="DejaVu Sans,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}" dominant-baseline="text-before-edge">{escape(s)}</text>')
 def line(self,x1,y1,x2,y2,color=LIME,width=4):
  self.d.line((x1,y1,x2,y2),fill=color,width=width);self.svg.append(f'<path d="M{x1},{y1} L{x2},{y2}" fill="none" stroke="{color}" stroke-width="{width}"/>')
 def arrow(self,x,y,w=30,color=LIME):
  self.line(x,y,x+w,y,color);self.line(x+w-9,y-8,x+w,y,color);self.line(x+w-9,y+8,x+w,y,color)
 def save(self,name):
  self.svg.append('</svg>');OUT.mkdir(parents=True,exist_ok=True);(OUT/(name+'.svg')).write_text('\n'.join(self.svg));self.im.save(OUT/(name+'.png'),optimize=True)
def hero(lang):
 ru=lang=='ru';c=Canvas(760)
 c.box(50,45,290,52,fill='#273a28',r=26);c.text(74,58,'XIO / 21.10.2026',23,LIME,True)
 c.text(55,137,'XIO на реальном' if ru else 'XIO on a real',68,bold=True)
 c.text(55,222,'Android' if ru else 'Android phone',78,LIME,True)
 c.text(59,339,'Пять протоколов. Найденная ошибка.' if ru else 'Five protocols. One discovered bug.',29,maxw=1330)
 c.text(59,390,'Исправление. Повторная проверка.' if ru else 'A fix. A repeatable result.',29,CYAN)
 for i,(num,label) in enumerate([('5','протоколов' if ru else 'protocols'),('1','телефон' if ru else 'phone'),('1','сеть' if ru else 'network'),('20','ревизия VPS' if ru else 'VPS revision')]):
  x=55+i*355;c.box(x,492,330,146);c.text(x+24,510,num,53,LIME,True);c.text(x+24,581,label,23,MUTED)
 c.text(59,688,'POCO X6 5G · Android 16 · 0.22.0 → 0.22.1 · HTTP 200 ≠ аудит безопасности' if ru else 'POCO X6 5G · Android 16 · 0.22.0 → 0.22.1 · HTTP 200 ≠ security audit',23,MUTED)
 c.save('hero-'+lang)
def matrix(lang):
 ru=lang=='ru';c=Canvas(860)
 c.text(55,40,'Что прошло проверку' if ru else 'What passed the check',44,bold=True)
 c.text(58,105,'HTTPS: example.com · отдельный приоритет каждого протокола' if ru else 'HTTPS: example.com · each protocol selected as first priority',25,MUTED)
 c.text(80,178,'ПРОТОКОЛ' if ru else 'PROTOCOL',20,MUTED,True)
 c.text(650,178,'РЕЗУЛЬТАТ' if ru else 'RESULT',20,MUTED,True)
 c.text(965,178,'КОНТЕКСТ' if ru else 'CONTEXT',20,MUTED,True)
 for i,p in enumerate(['Xray / REALITY','RIVET / S1','RIVET / H3','AmneziaWG 3.1','OpenVPN / Cloak']):
  y=225+i*95;c.box(55,y,1390,79);c.box(73,y+19,8,40,LIME,4);c.text(100,y+23,p,27,bold=True)
  c.text(650,y+23,'HTTP 200',27,LIME,True)
  c.text(965,y+27,('0.22.0' if i<4 else ('исправление + 0.22.1' if ru else 'fix + 0.22.1')),23,CYAN)
 c.text(58,731,'Пять наблюдаемых результатов, а не процент надёжности.' if ru else 'Five observed outcomes, not a reliability percentage.',24,MUTED)
 c.text(58,779,'Cloak повторно проверен после обновления APK и сервера.' if ru else 'Cloak rechecked after updating both APK and server.',24,MUTED)
 c.save('matrix-'+lang)
def bug(lang):
 ru=lang=='ru';c=Canvas(875)
 c.text(55,38,'Почему Cloak не пускал нового пользователя' if ru else 'Why Cloak rejected a new user',39,bold=True)
 c.text(58,106,'Ошибка порядка активации. Криптографические алгоритмы не менялись.' if ru else 'Activation order bug. Cryptographic algorithms were unchanged.',24,MUTED)
 rows=[(190,ORANGE,'ДО' if ru else 'BEFORE', [('Создать','пользователя'),('Применить','список без UID'),('Выдать','Cloak UID'),('Доступ','отклонён')] if ru else [('Create','user'),('Apply','list without UID'),('Generate','Cloak UID'),('Access','rejected')]),(495,LIME,'ПОСЛЕ' if ru else 'AFTER',[('Создать','пользователя'),('Сформировать','профили и UID'),('Применить','список с UID'),('HTTPS','HTTP 200')] if ru else [('Create','user'),('Generate','profiles and UID'),('Apply','list with UID'),('HTTPS','HTTP 200')])]
 for y,color,label,boxes in rows:
  c.text(59,y,label,24,color,True)
  for i,(a,b) in enumerate(boxes):
   x=55+i*355;c.box(x,y+56,325,140);c.text(x+23,y+83,a,25,bold=True,maxw=279);c.text(x+23,y+128,b,23,color,maxw=279)
   if i<3:c.arrow(x+329,y+126,22,color)
 c.text(58,781,'Регрессионный тест + новый пользователь на VPS + проверка на телефоне' if ru else 'Regression test + new VPS user + physical phone check',24,MUTED)
 c.save('cloak-order-'+lang)
if __name__=='__main__':
 for lang in ['ru','en']:
  hero(lang);matrix(lang);bug(lang)
 print('Generated six SVGs and six matching PNGs; no screenshots or private data used.')
