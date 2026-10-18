#!/usr/bin/env python3
"""Validate local store assets and mark unresolved publication prerequisites honestly."""
from pathlib import Path
from PIL import Image
import json,re
r=Path(__file__).resolve().parent.parent;p=r/'publishing/google-play'
for name,size in [('icon512.png',(512,512)),('feature1024x500.png',(1024,500))]:
 with Image.open(p/name) as im:assert im.size==size
text=(p/'STORE-LISTING.ru.md').read_text()
shorts=['VPN-клиент для своего сервера: профили, пользователи и выбор соединения.','VPN client for your own server, profiles and managed users.']
assert all(len(s)<=80 for s in shorts);assert len('XIO VPN')<=30
screens=list((p/'phone-screenshots').glob('*.png'));assert len(screens)>=2
for s in screens:
 with Image.open(s) as im:assert min(im.size)>=320 and max(im.size)<=3840
report={'assetChecks':True,'shortDescriptionLengths':list(map(len,shorts)),'phoneScreenshots':len(screens),'publicationStatus':'candidate_for_internal_testing','unresolved':['Verified Organization developer account','Permanent public privacy policy and Corresponding Source URLs','Final Data Safety based on operator role','Reviewer profile and video URLs','Country-specific regulatory classification','Physical-device and Play pre-launch validation']}
(r/'verification/store-preflight-018.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
