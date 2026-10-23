#!/usr/bin/env python3
"""Inspect declared native engines. A profile codec test is not tunnel parity."""
from pathlib import Path
import re,json,argparse
r=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('--require-complete',action='store_true');a=p.parse_args()
android=(r/'app/android/app/src/main/kotlin/app/x1o/x1o/MainActivity.kt').read_text()
desktop=(r/'protocol/rivet/internal/desktop/runtime.go').read_text()
ios=(r/'app/ios/Runner/XIOEngine.swift').read_text()
required={'awg','rivet-h3','rivet-s1','xray','cloak'}
def quoted(s):return set(re.findall(r'"([a-z0-9-]+)"',s))
sets={'android':quoted(re.search(r'"supportedProtocols".*?listOf\((.*?)\)',android).group(1)),'windows':quoted(re.search(r'var Protocols = \[\]string\{(.*?)\}',desktop).group(1)),'ubuntu':quoted(re.search(r'var Protocols = \[\]string\{(.*?)\}',desktop).group(1)),'ios':quoted(re.search(r'case "supportedProtocols": result\(\[(.*?)\]\)',ios).group(1))}
# Keep the Dart capability registry tied to actual native declarations.
dart=(r/'app/lib/protocol_compatibility.dart').read_text()
for name,values in sets.items():
 m=re.search(r'ClientPlatform\.'+name+r':\s*(universalProtocolIds|\{[^}]*\})',dart);assert m,name
 expected=required if m.group(1)=='universalProtocolIds' else set(re.findall(r"'([^']+)'",m.group(1)))
 assert expected==values,(name,expected,values)
report={'schema':1,'requiredProtocols':sorted(required),'wireContainer':'shared xio:// schema1; schema3 for restricted account capability','platforms':{name:{'nativeDeclared':sorted(v),'missingNative':sorted(required-v),'nativeAllProtocolsAccepted':False} for name,v in sets.items()},'complete':all(v==required for v in sets.values()),'scope':'Source-declared engines, not native runtime verification; Apple build/device unavailable'}
(r/'docs/compatibility/protocol-status.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if a.require_complete and not report['complete']:raise SystemExit(2)
