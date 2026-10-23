#!/usr/bin/env python3
"""Owned RIVET installation; entry and gateway are separate unprivileged users."""
import json,os,subprocess,shutil,sys,ipaddress,socket,time,shlex,re
from pathlib import Path
ROOT=Path('/etc/xio-rivet'); LIB=Path('/usr/local/lib/xio-rivet'); RECEIPT=ROOT/'install-receipt.json'
def run(*args,data=None):
 p=subprocess.run(args,input=data,capture_output=True,text=True)
 if p.returncode:raise RuntimeError('RIVET setup command failed: '+args[0])
 return p.stdout.strip()
def write(path,text,mode=0o644):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.new');tmp.write_text(text);tmp.chmod(mode);tmp.replace(p)
def rule(args,remove=False):
 exists=subprocess.run(['iptables','-w','5','-C',*args],capture_output=True).returncode==0
 if remove and exists:run('iptables','-w','5','-D',*args)
 elif not remove and not exists:run('iptables','-w','5','-I',*args)
def managed_firewall(receipt,remove=False):
 f=receipt.get('firewall')
 if not f:
  if subprocess.run(['systemctl','is-active','--quiet','firewalld'],capture_output=True).returncode==0:
   assert run('firewall-cmd','--permanent','--zone=trusted','--get-target')=='ACCEPT','Modified trusted zone'
   assert re.search(r'(?m)^\s*target: ACCEPT\s*$',run('firewall-cmd','--zone=trusted','--list-all')),'Modified trusted zone'
   zone=subprocess.run(['firewall-cmd','--get-zone-of-interface='+receipt['outbound']],capture_output=True,text=True).stdout.strip()
   if not zone or zone=='no zone':zone=run('firewall-cmd','--get-default-zone')
   assert re.fullmatch('[A-Za-z0-9_-]+',zone)
   f={'kind':'firewalld','zone':zone,'added':[]}
  elif shutil.which('ufw') and 'Status: active' in run('env','LC_ALL=C','ufw','status'):f={'kind':'ufw','added':[]}
  else:f={'kind':'iptables'}
  receipt['firewall']=f;write(RECEIPT,json.dumps(receipt),0o600)
 if f['kind']=='firewalld':
  items=f.get('added',[]) if remove else [dict(args=(['--permanent'] if permanent else [])+['--zone='+zone],option=option,value=value) for zone,option,value in [('trusted','interface','xiorivet'),(f['zone'],'port','8443/tcp'),(f['zone'],'port','8443/udp'),(f['zone'],'rich-rule','rule family="ipv4" source address="10.79.0.0/24" masquerade')] for permanent in [False,True]]
  for item in items:
   args=item['args'];option=item['option'];value=item['value'];exists=subprocess.run(['firewall-cmd',*args,'--query-'+option+'='+value],capture_output=True).returncode==0
   if remove and exists:run('firewall-cmd',*args,'--remove-'+option+'='+value)
   elif not remove and not exists:
    if item not in f['added']:f['added'].append(item);write(RECEIPT,json.dumps(receipt),0o600)
    run('firewall-cmd',*args,'--add-'+option+'='+value)
 elif f['kind']=='ufw':
  existing=[shlex.split(line)[1:] for line in run('ufw','show','added').splitlines() if line.startswith('ufw ')]
  items=f.get('added',[]) if remove else [['allow','in','on',receipt['outbound'],'to','any','port','8443','proto',proto] for proto in ['tcp','udp']]+[['route','allow','in','on','xiorivet','out','on',receipt['outbound'],'from','10.79.0.0/24']]
  for item in items:
   if remove and item in existing:
    if item[0]=='route':run('ufw','--force','route','delete',*item[1:])
    else:run('ufw','--force','delete',*item)
   elif not remove and item not in existing:
    if item not in f['added']:f['added'].append(item);write(RECEIPT,json.dumps(receipt),0o600)
    run('ufw',*item)

def outbound_device():
 for family in ['-4','-6']:
  routes=json.loads(run('ip','-j',family,'route','show','default'))
  if routes:return min(routes,key=lambda r:r.get('metric',0))['dev']
 raise RuntimeError('No IPv4 or IPv6 default route')
def main():
 action=sys.argv[1];binary=str(LIB/'rivet')
 if action=='install':
  req=json.loads(sys.stdin.read(65537));assert len(json.dumps(req))<=65536
  if RECEIPT.exists():
   receipt=json.loads(RECEIPT.read_text());assert receipt.get('owner')=='xio-rivet-v1','Unowned RIVET receipt'
   assert receipt.get('phase')=='ready','Incomplete RIVET installation; remove before retry'
   managed_firewall(receipt)
   unit=Path('/etc/systemd/system/xio-rivet-gateway.service');text=unit.read_text();post='ExecStartPost=+'+shutil.which('ip')+' link set dev xiorivet up\n'
   if post not in text:
    assert 'ExecStart=/usr/local/bin/xio-rivet gateway ' in text,'Unowned gateway service'
    write(unit,text.replace('ExecStopPost=',post+'ExecStopPost='));run('systemctl','daemon-reload');run('systemctl','restart','xio-rivet-gateway','xio-rivet-entry')
   run('systemctl','start','xio-rivet-gateway','xio-rivet-entry')
   run('systemctl','is-active','--quiet','xio-rivet-gateway','xio-rivet-entry')
   return
  assert not ROOT.exists(),'Unowned RIVET directory'
  assert not run('ss','-H','-lntu','sport = :8443'),'RIVET port in use'
  cert=Path(req['cert']) if req.get('cert') else None;key=Path(req['key']) if req.get('key') else None;name=req['serverName'];assert (cert is None and key is None) or (cert.is_absolute() and key.is_absolute() and cert.is_file() and key.is_file())
  assert len(name)<=253 and name and not any(c in name for c in '/\\\r\n\x00')
  before=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip();outbound=outbound_device()
  assert outbound.replace('-','').replace('.','').isalnum()
  # Fail before creating accounts if namespace names are already in use.
  for user in ['xio-entry','xio-rivet']:
   assert subprocess.run(['id',user],capture_output=True).returncode!=0,'Unowned service account'
  for path in ['/usr/local/bin/xio-rivet','/var/lib/xio-rivet','/etc/systemd/system/xio-rivet-entry.service','/etc/systemd/system/xio-rivet-gateway.service','/sys/class/net/xiorivet']:
   assert not Path(path).exists(),'Unowned RIVET installation path'
  for route in json.loads(run('ip','-j','-4','route')):
   if route.get('dst','default')!='default':assert not ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network('10.79.0.0/24')),'RIVET subnet conflict'
  ROOT.mkdir(mode=0o700)
  receipt={'binaryOwned':True,'owner':'xio-rivet-v1','oldForward':before,'outbound':outbound,'serverName':name,'users':['xio-entry','xio-rivet'],'phase':'installing'}
  write(RECEIPT,json.dumps(receipt),0o600)
  for user in receipt['users']:run('useradd','--system','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',user)
  shutil.copyfile(binary,'/usr/local/bin/xio-rivet');Path('/usr/local/bin/xio-rivet').chmod(0o755)
  if shutil.which('restorecon'):run('restorecon','/usr/local/bin/xio-rivet')
  public=json.loads(run(binary,'init'))
  if cert is None:
   generated=json.loads(run(binary,'outer','--name',name));public['outerCA']=generated['outerCA']
  else:
   shutil.copyfile(cert,ROOT/'outer.crt');shutil.copyfile(key,ROOT/'outer.key')
  # A normal local landing page for ordinary requests; no VPN-specific banner.
  write(ROOT/'index.html','<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Service</title><body><main><h1>Service</h1><p>Secure connection service.</p></main></body></html>')
  public.update(endpoint=name+':8443',serverName=name);write(ROOT/'public.json',json.dumps(public),0o644)
  ROOT.chmod(0o755)
  for filename in ['gateway.json','users.json','seal.key','inner.crt','inner.key']:
   run('chown','root:xio-rivet',str(ROOT/filename));(ROOT/filename).chmod(0o640)
  for filename in ['entry.json','tokens.json','outer.crt','outer.key']:
   run('chown','root:xio-entry',str(ROOT/filename));(ROOT/filename).chmod(0o640)
  stats=Path('/var/lib/xio-rivet');stats.mkdir(mode=0o750);run('chown','xio-rivet:xio-rivet',str(stats))
  write(LIB/'network-up',f'''#!/bin/sh
set -eu
if ! ip link show dev xiorivet >/dev/null 2>&1; then ip tuntap add dev xiorivet mode tun user xio-rivet; fi
ip address replace 10.79.0.1/24 dev xiorivet
ip link set xiorivet mtu 1280 up
sysctl -q -w net.ipv4.ip_forward=1
python3 {LIB}/setup.py network
if [ -f /usr/local/lib/x1o-managed/dualstack.py ]; then python3 /usr/local/lib/x1o-managed/dualstack.py apply; fi
''',0o755)
  common='''NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryMax=256M
TasksMax=128
LimitNOFILE=2048
Restart=on-failure
RestartSec=2
UMask=0077
'''
  write('/etc/systemd/system/xio-rivet-gateway.service',f'''[Unit]
Description=XIO RIVET gateway
After=network-online.target firewalld.service ufw.service
Wants=network-online.target
[Service]
Type=simple
User=xio-rivet
Group=xio-rivet
ExecStartPre=+{LIB}/network-up
ExecStart=/usr/local/bin/xio-rivet gateway --config {ROOT}/gateway.json
ExecStartPost=+{shutil.which('ip')} link set dev xiorivet up
ExecStopPost=+{shutil.which('ip')} link delete dev xiorivet
ReadWritePaths=/var/lib/xio-rivet
{common}[Install]
WantedBy=multi-user.target
''')
  write('/etc/systemd/system/xio-rivet-entry.service',f'''[Unit]
Description=XIO RIVET HTTPS and HTTP3 entry
After=network-online.target xio-rivet-gateway.service
Wants=network-online.target
[Service]
Type=simple
User=xio-entry
Group=xio-entry
ExecStart=/usr/local/bin/xio-rivet entry --config {ROOT}/entry.json
{common}[Install]
WantedBy=multi-user.target
''')
  receipt['rules']=[['INPUT','-p','tcp','--dport','8443','-m','comment','--comment','XIO-RIVET','-j','ACCEPT'],['INPUT','-p','udp','--dport','8443','-m','comment','--comment','XIO-RIVET','-j','ACCEPT'],['INPUT','-i','xiorivet','-m','comment','--comment','XIO-RIVET','-j','DROP'],['FORWARD','-i','xiorivet','-m','comment','--comment','XIO-RIVET','-j','DROP'],['FORWARD','-o','xiorivet','-m','comment','--comment','XIO-RIVET','-j','DROP'],['FORWARD','-i','xiorivet','-o',outbound,'-s','10.79.0.0/24','-m','comment','--comment','XIO-RIVET','-j','ACCEPT'],['FORWARD','-o','xiorivet','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-m','comment','--comment','XIO-RIVET','-j','ACCEPT']]
  write(RECEIPT,json.dumps(receipt),0o600)
  managed_firewall(receipt)
  for args in receipt['rules']:rule(args)
  nat=['POSTROUTING','-s','10.79.0.0/24','-o',outbound,'-m','comment','--comment','XIO-RIVET','-j','MASQUERADE'];receipt['nat']=nat;write(RECEIPT,json.dumps(receipt),0o600)
  if subprocess.run(['iptables','-w','5','-t','nat','-C',*nat],capture_output=True).returncode:run('iptables','-w','5','-t','nat','-A',*nat)
  run('systemctl','daemon-reload');run('systemctl','enable','--now','xio-rivet-gateway','xio-rivet-entry')
  time.sleep(1);run('systemctl','is-active','--quiet','xio-rivet-gateway','xio-rivet-entry');receipt['phase']='ready';write(RECEIPT,json.dumps(receipt),0o600)
 elif action=='network':
  receipt=json.loads(RECEIPT.read_text());assert receipt['owner']=='xio-rivet-v1'
  managed_firewall(receipt)
  for args in receipt.get('rules',[]):rule(args)
  nat=receipt.get('nat')
  if nat and subprocess.run(['iptables','-w','5','-t','nat','-C',*nat],capture_output=True).returncode:run('iptables','-w','5','-t','nat','-A',*nat)
 elif action=='remove':
  if not RECEIPT.exists():return
  receipt=json.loads(RECEIPT.read_text());assert receipt['owner']=='xio-rivet-v1'
  for unit in ['xio-rivet-entry','xio-rivet-gateway']:subprocess.run(['systemctl','disable','--now',unit],capture_output=True)
  if receipt.get('firewall'):managed_firewall(receipt,True)
  for args in receipt.get('rules',[]):rule(args,True)
  nat=receipt.get('nat')
  if nat:subprocess.run(['iptables','-w','5','-t','nat','-D',*nat],capture_output=True)
  for name in ['entry','gateway']:Path('/etc/systemd/system/xio-rivet-'+name+'.service').unlink(missing_ok=True)
  subprocess.run(['ip','link','delete','xiorivet'],capture_output=True)
  run('systemctl','daemon-reload');shutil.rmtree('/var/lib/xio-rivet',ignore_errors=True)
  for user in receipt.get('users',[]):subprocess.run(['userdel',user],capture_output=True)
  # Original shared forwarding state is retained if another VPN remains.
  if not any(p.name in ['x1o0','x1oawg0'] for p in Path('/sys/class/net').iterdir()):run('sysctl','-q','-w','net.ipv4.ip_forward='+receipt['oldForward'])
  if receipt.get('binaryOwned'):Path('/usr/local/bin/xio-rivet').unlink(missing_ok=True)
  shutil.rmtree(ROOT);shutil.rmtree(LIB)
 else:raise ValueError('Unknown operation')
if __name__=='__main__':
 try:main()
 except Exception as e:
  # Roll back only an installation carrying our receipt, never unknown files.
  if len(sys.argv)>1 and sys.argv[1]=='install' and RECEIPT.exists():
   try:
    receipt=json.loads(RECEIPT.read_text())
    if receipt.get('owner')=='xio-rivet-v1' and receipt.get('phase')=='installing':
     subprocess.run([sys.executable,__file__,'remove'],capture_output=True)
   except Exception:pass
  print(str(e),file=sys.stderr);sys.exit(1)
