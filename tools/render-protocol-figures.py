#!/usr/bin/env python3
"""Reproduce bilingual RIVET figures from cleaned, versioned evidence. Requires matplotlib."""
from pathlib import Path
import json,statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
ROOT=Path(__file__).resolve().parents[1]; D=ROOT/'docs/protocols'; OUT=D/'images'
BG='#0d111b'; PANEL='#192233'; WHITE='#e8efdf'; MUTED='#a5b1c3'; GREEN='#b9ec70'; BLUE='#70c6ed'; ORANGE='#f1b976'
plt.rcParams.update({'font.family':'DejaVu Sans','text.color':WHITE,'axes.labelcolor':WHITE,'xtick.color':MUTED,'ytick.color':MUTED,'axes.edgecolor':MUTED,'axes.facecolor':BG,'figure.facecolor':BG,'font.size':11,'savefig.facecolor':BG})
def save(fig,name):
 fig.savefig(OUT/(name+'.png'),dpi=150,bbox_inches='tight',pad_inches=.25);plt.close(fig)
def base(title,sub,h=5.8):
 fig,ax=plt.subplots(figsize=(12,h));ax.set(xlim=(0,12),ylim=(0,h));ax.axis('off');ax.text(0,h-.16,title,fontsize=21,fontweight='bold',va='top');ax.text(0,h-.7,sub,color=MUTED,fontsize=10,va='top');return fig,ax
def box(ax,x,y,w,h,title,desc,color=GREEN):
 ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.08,rounding_size=.12',edgecolor=color,facecolor=PANEL,linewidth=1.2));ax.text(x+w/2,y+h-.27,title,ha='center',va='top',fontsize=14,color=color,fontweight='bold');ax.text(x+w/2,y+h/2-.1,desc,ha='center',va='center',fontsize=10,linespacing=1.5)
def arrow(ax,a,b,color=GREEN):ax.add_patch(FancyArrowPatch(a,b,arrowstyle='-|>',mutation_scale=15,color=color,linewidth=1.5))
for lang in ['ru','en']:
 ru=lang=='ru'
 fig,ax=base('RIVET/1 · два транспорта, один внутренний сеанс' if ru else 'RIVET/1 · two carriers, one inner session','Схема реализации 0.2 · общий VPS доверенный · не независимая анонимная сеть' if ru else 'Implementation profile 0.2 · shared VPS trusted · not an independent anonymity network')
 box(ax,.1,2.4,2.8,1.55,'XIO / TUN','IPv4 · MTU 1280\nK_device + pin')
 box(ax,4.1,2.4,2.8,1.55,'ENTRY','Внешний TLS / H3\nТокен допуска' if ru else 'Outer TLS / H3\nAdmission token',BLUE)
 box(ax,8.1,2.4,2.8,1.55,'GATEWAY','Внутренний TLS / QUIC\nHMAC → TUN → NAT' if ru else 'Inner TLS / QUIC\nHMAC → TUN → NAT')
 arrow(ax,(3,3.2),(3.95,3.2),BLUE);arrow(ax,(7,3.2),(7.95,3.2),BLUE);arrow(ax,(11,3.2),(11.9,3.2))
 ax.text(3.5,4.2,'H3: CONNECT-UDP / UDP\nS1: WSS / TCP',ha='center',color=BLUE,fontsize=11)
 ax.plot([.3,10.7],[1.65,1.65],color=GREEN,lw=3);ax.text(5.5,1.25,'Внутренний защищённый канал: клиент ↔ Gateway' if ru else 'Inner authenticated channel: client ↔ Gateway',ha='center',color=GREEN)
 ax.text(7.5,.5,'Entry и Gateway: разные процессы и пользователи ОС на одном VPS' if ru else 'Entry and Gateway: separate processes and OS accounts on one VPS',ha='center',color=MUTED,fontsize=10)
 save(fig,'architecture-'+lang)
 fig,ax=base('Подключение: от TLS до первого IP-пакета' if ru else 'Establishment: from TLS to the first IP packet','Схема сообщений, не временная шкала измерений' if ru else 'Message diagram, not a measured timing chart',h=8)
 for x,title in [(1.4,'CLIENT'),(6,'ENTRY'),(10.5,'GATEWAY')]:
  ax.text(x,6.8,title,ha='center',color=GREEN,fontweight='bold');ax.plot([x,x],[.6,6.5],color=MUTED,alpha=.4)
 lines=[(1.4,6,'Outer TLS + token / CONNECT-UDP or WSS',BLUE),(1.4,10.5,'Inner TLS 1.3 + SPKI pin',GREEN),(10.5,1.4,'CHALLENGE: gatewayId + nonce',ORANGE),(1.4,10.5,'AUTH: userId + params + HMAC',GREEN),(10.5,1.4,'AUTH_OK: sessionId',ORANGE),(10.5,1.4,'CONFIG: exact canonical CBOR',ORANGE),(1.4,10.5,'CONFIG_ACK: SHA256(CONFIG)',GREEN),(1.4,10.5,'IP_PACKET / DATAGRAM',GREEN)]
 for i,(a,b,label,col) in enumerate(lines):
  y=6.15-i*.66;arrow(ax,(a,y),(b,y),col);ax.text((a+b)/2,y+.12,label,ha='center',fontsize=10,color=col)
 ax.text(6,.2,'До CONFIG_ACK пользовательский трафик не маршрутизируется' if ru else 'No user traffic is routed before CONFIG_ACK',ha='center',color=MUTED)
 save(fig,'session-'+lang)
 fig,ax=base('Форматы RIVET внутри защищённого канала' if ru else 'RIVET formats inside the authenticated channel','Все целые заголовков — big-endian · внешний TLS/QUIC здесь не показан' if ru else 'Header integers are big-endian · outer TLS/QUIC are not shown',h=5.4)
 for y,title,fields in [(2.9,'Stream · 6 B header',[('type\n1 B',1.4),('flags=0\n1 B',1.6),('length\n4 B',2.3),('body\n≤ 4096 B',5.3)]),(1.1,'H3 DATAGRAM · 15 B header',[('type=16\n1 B',1.6),('packetId\n8 B',2.3),('total\n2 B',1.6),('offset\n2 B',1.6),('length\n2 B',1.6),('fragment\nsender ≤ 1000 B',2.5)])]:
  ax.text(.1,y+1.0,title,color=GREEN,fontsize=13,fontweight='bold');x=.1
  for label,w in fields:
   ax.add_patch(FancyBboxPatch((x,y),w-.06,.8,boxstyle='round,pad=0.02',facecolor=PANEL,edgecolor=BLUE));ax.text(x+(w-.06)/2,y+.4,label,ha='center',va='center',fontsize=10);x+=w
 ax.text(.1,.3,'IP_PACKET ≤ 1280 B · AUTH body = 59 B · H3 1280 B packet → 1000 + 280 B' ,color=MUTED,fontsize=10)
 save(fig,'wire-'+lang)
 probe=json.loads((D/'data/probe.json').read_text())
 fig,ax=plt.subplots(figsize=(10.5,5.6));fig.subplots_adjust(top=.8,bottom=.17)
 for i,row in enumerate(probe['results']):
  vals=row['elapsedMs'];med=statistics.median(vals);col=BLUE if i==0 else GREEN
  ax.scatter(vals,[i+(j-4.5)*.027 for j in range(len(vals))],s=55,color=col,alpha=.85,zorder=3)
  ax.plot([med,med],[i-.28,i+.28],lw=3,color=WHITE);ax.text(med,i+.34,f'{med:.2f} ms',ha='center',color=WHITE)
 ax.set_yticks([0,1],['S1 · n=10','H3 · n=10']);ax.set_ylim(-.5,1.6);ax.set_xlabel('Полное время CLI-пробы, мс' if ru else 'Complete CLI probe duration, ms');ax.grid(axis='x',alpha=.18)
 fig.suptitle('Сохранённые пробы VPS: точки и медианы' if ru else 'Historical VPS probes: observations and medians',fontsize=19,fontweight='bold',y=.96)
 fig.text(.12,.87,'Handshake + аутентификация + DNS-ответ; не скорость загрузки' if ru else 'Handshake + authentication + DNS response; not download throughput',color=MUTED)
 fig.text(.12,.04,'Один VPS · малые выборки · не тест стран · данные 0.16, публикация 18.10.2026' if ru else 'One VPS · small samples · no country comparison · 0.16 evidence, published 2026-10-18',fontsize=9,color=MUTED)
 save(fig,'probe-'+lang)
 ndpi=json.loads((D/'data/ndpi.json').read_text());a=ndpi['beforeALPNFix'];b=ndpi['afterALPNFix'];keys=['missingALPNWarnings','notHTTPSWarnings','nonstandardPortWarnings']
 fig,ax=plt.subplots(figsize=(10.5,5.8));fig.subplots_adjust(top=.8,bottom=.24)
 xs=range(3);ax.bar([x-.18 for x in xs],[a[k] for k in keys],width=.35,color=ORANGE,label='До: 22 потока' if ru else 'Before: 22 flows');ax.bar([x+.18 for x in xs],[b[k] for k in keys],width=.35,color=GREEN,label='После: 20 потоков' if ru else 'After: 20 flows')
 for i,k in enumerate(keys):
  for off,v in [(-.18,a[k]),(.18,b[k])]:ax.text(i+off,v+.4,str(v),ha='center')
 ax.set_xticks(list(xs),['Нет ALPN','Не HTTPS','Нестандартный порт'] if ru else ['Missing ALPN','Not HTTPS','Nonstandard port']);ax.set_ylabel('Предупреждения, шт.' if ru else 'Warning count');ax.set_ylim(0,25);ax.legend(facecolor=PANEL,labelcolor=WHITE);ax.grid(axis='y',alpha=.15)
 fig.suptitle('nDPI: что изменило исправление ALPN' if ru else 'nDPI: effect of correcting ALPN',fontsize=19,fontweight='bold',y=.96)
 fig.text(.12,.87,'Разные короткие захваты · абсолютные счётчики, не вероятность обнаружения' if ru else 'Different short captures · counts, not detection probability',color=MUTED,fontsize=10)
 fig.text(.12,.07,'20/20 потоков после: 10 QUIC + 10 TLS; нестандартный порт остался заметен.' if ru else 'After: 10 QUIC + 10 TLS; the nonstandard port remained observable.',fontsize=10,color=MUTED)
 fig.text(.12,.025,'Классификация TLS/QUIC не доказывает неотличимость.' if ru else 'TLS/QUIC classification does not establish indistinguishability.',fontsize=10,color=MUTED)
 save(fig,'dpi-'+lang)
print('Rendered',len(list(OUT.glob('*.png'))),'figures')
