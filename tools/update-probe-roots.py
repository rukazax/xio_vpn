#!/usr/bin/env python3
"""Build the narrow legacy trust subset from an authenticated CA snapshot.
Build-time only; never changes the operating system or downloads runtime trust.
Requires Python cryptography. Changing anchors or the expected digest requires review.
"""
from pathlib import Path
import argparse,hashlib,json,re
from cryptography import x509
from cryptography.x509.oid import NameOID
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args()
r=Path(__file__).resolve().parent.parent;raw=a.source.read_bytes();assert hashlib.sha256(raw).hexdigest()==a.sha256,'CA snapshot digest mismatch'
wanted={'GTS Root R1','GTS Root R3','GTS Root R4','SSL.com Root Certification Authority ECC'};roots=[]
for block in re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',raw,re.S):
 c=x509.load_pem_x509_certificate(block);cn=c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
 if cn and cn[0].value in wanted:
  assert c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
  roots.append(block+b'\n')
assert len(roots)==len(wanted),'Expected anchors absent from current reviewed snapshot'
for path in ['app/assets/security/probe-roots.pem','app/android/app/src/main/res/raw/xio_probe_roots.pem']:(r/path).write_bytes(b''.join(roots))
print('Verified snapshot; regenerated four public anchors. TLS and hostname checks remain enabled.')
