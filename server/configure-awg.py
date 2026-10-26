#!/usr/bin/env python3
"""Configure only xioawg0 using root-private UAPI; no key material in argv/logs."""
from pathlib import Path
import socket, subprocess, sys, time

INTERFACE = 'xioawg0'
COMMENT = 'xio-awg-test'

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

def rules(delete=False):
    ipv4 = [
        ['FORWARD','-i',INTERFACE,'-s','10.78.0.0/24','-m','comment','--comment',COMMENT,'-j','ACCEPT'],
        ['FORWARD','-o',INTERFACE,'-d','10.78.0.0/24','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','comment','--comment',COMMENT,'-j','ACCEPT'],
    ]
    interface = Path('/etc/xio/outbound-interface').read_text().strip()
    import re
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface): raise RuntimeError('Invalid outbound interface')
    tables = [('iptables',[],r) for r in ipv4] + [
        ('iptables',['-t','nat'],['POSTROUTING','-s','10.78.0.0/24','-o',interface,'-m','comment','--comment',COMMENT,'-j','MASQUERADE']),
        ('ip6tables',[],['FORWARD','-i',INTERFACE,'-m','comment','--comment',COMMENT,'-j','DROP'])]
    for command, table, rule in tables:
        exists = subprocess.run([command,'-w','5',*table,'-C',*rule], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if delete and exists: run(command,'-w','5',*table,'-D',*rule)
        elif not delete and not exists: run(command,'-w','5',*table,'-I',*rule)

if sys.argv[1:] == ['down']:
    rules(delete=True)
    raise SystemExit(0)
for _ in range(100):
    if Path('/run/amneziawg/xioawg0.sock').exists(): break
    time.sleep(.1)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(10)
    sock.connect('/run/amneziawg/xioawg0.sock')
    sock.sendall(b'set=1\n'+Path('/etc/xio/awg.uapi').read_bytes().rstrip(b'\n')+b'\n\n')
    data=b''
    while b'\n\n' not in data: data+=sock.recv(4096)
    if data != b'errno=0\n\n': raise RuntimeError('AWG configuration rejected')
run('ip','address','replace','10.78.0.1/24','dev',INTERFACE)
run('ip','-6','address','replace','fd78:1::1/64','dev',INTERFACE)
run('ip','link','set','dev',INTERFACE,'mtu','1280','up')
rules()
