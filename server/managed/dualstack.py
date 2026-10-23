#!/usr/bin/env python3
"""Owned IPv6 forwarding additions, with an explicit reversible receipt.

No provider addresses/routes are invented, no firewall is flushed, and no
packages are installed. Existing IPv4 rules and server credentials are retained.
"""
import json,os,re,socket,subprocess,sys
from pathlib import Path
STATE=Path('/etc/x1o-managed/deployment.json')
RECEIPT=Path('/etc/x1o-managed/dualstack-receipt.json')
CONFIG_DIR=Path('/etc/xio-stack')
NETWORK_UP=Path('/usr/local/lib/xio-rivet/network-up')
SUBNETS=(('x1oawg0','fd78:1::/64','fd78:1::1/64'),('xiorivet','fd79:1::/64','fd79:1::1/64'),('xioovpn1','fd80:1::/64','fd80:1::1/64'))
def call(*args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if check and p.returncode:raise RuntimeError('IPv6 network operation failed: '+args[0])
 return p

def routes(family):
 p=call('ip','-j',family,'route','show','default',check=False)
 try:items=json.loads(p.stdout) if p.returncode==0 else []
 except ValueError:items=[]
 return sorted((x for x in items if x.get('dev') and x.get('type','unicast')=='unicast'),key=lambda x:x.get('metric',0))
def outbound():
 for family in ['-4','-6']:
  items=routes(family)
  if items:
   value=items[0]['dev'];assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',value);return value
 raise RuntimeError('No IPv4 or IPv6 default route')
def ipv6_ready():return bool(routes('-6'))
def listener():
 try:
  with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:s.bind(('::1',0))
  return '::'
 except OSError:return '0.0.0.0'
def save(receipt):
 RECEIPT.parent.mkdir(parents=True,exist_ok=True);p=RECEIPT.with_suffix('.new');p.write_text(json.dumps(receipt));p.chmod(0o600);p.replace(RECEIPT)
def apply():
 assert os.geteuid()==0,'Owner root access required'
 state=json.loads(STATE.read_text());assert state.get('owner')=='x1o-managed-v1','Unowned deployment'
 if not ipv6_ready():return {'ipv6Forwarding':False,'reason':'No IPv6 default route'}
 dev=routes('-6')[0]['dev'];assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',dev)
 receipt=json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'owner':'xio-dualstack-v1','oldForward':Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip(),'rules':[],'addresses':[]}
 assert receipt['owner']=='xio-dualstack-v1'
 save(receipt) # Save intent before every network effect.
 # Forwarding can suppress RA acceptance. Retain RA on the physical uplink when
 # it was the source of the existing default route; restore only our own change.
 accept=Path('/proc/sys/net/ipv6/conf')/dev/'accept_ra'
 if routes('-6')[0].get('protocol')=='ra' and accept.exists() and accept.read_text().strip()!='2':
  receipt.setdefault('acceptRa',{}).setdefault(dev,accept.read_text().strip());save(receipt);accept.write_text('2\n')
 # Open only ports of the installed owned services; never a blanket policy.
 ports=[]
 if state.get('rivet'):ports += [(8443,'tcp'),(8443,'udp')]
 if Path('/etc/xio-stack/receipt.json').exists():ports += [(4443,'tcp'),(9443,'tcp')]
 if state.get('clientApiSystemUserOwned'):ports += [(9444,'tcp')]
 for port,protocol in ports:
  rule=['INPUT','-i',dev,'-p',protocol,'--dport',str(port),'-m','comment','--comment','xio-dualstack-v1-input','-j','ACCEPT']
  if call('ip6tables','-w','5','-C',*rule,check=False).returncode:
   record=[[],rule]
   if record not in receipt['rules']:receipt['rules'].append(record);save(receipt)
   call('ip6tables','-w','5','-I',*rule)
 for interface,subnet,address in SUBNETS:
  if not Path('/sys/class/net',interface).exists():continue
  entries=json.loads(call('ip','-j','-6','address','show','dev',interface).stdout)
  if not any(x.get('local')==address.split('/')[0] for e in entries for x in e.get('addr_info',[])):
   item=[interface,address]
   if item not in receipt['addresses']:receipt['addresses'].append(item);save(receipt)
   call('ip','-6','address','add',address,'dev',interface)
  comment='xio-dualstack-v1-'+interface
  rules=[([],['INPUT','-i',dev,'-p','udp','--dport','51821','-m','comment','--comment',comment,'-j','ACCEPT'])] if interface=='x1oawg0' else []
  rules += [([],['FORWARD','-i',interface,'-o',dev,'-s',subnet,'-m','comment','--comment',comment,'-j','ACCEPT']),([],['FORWARD','-o',interface,'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','comment','--comment',comment,'-j','ACCEPT']),(['-t','nat'],['POSTROUTING','-s',subnet,'-o',dev,'-m','comment','--comment',comment,'-j','MASQUERADE'])]
  for table,rule in rules:
   if call('ip6tables','-w','5',*table,'-C',*rule,check=False).returncode:
    record=[table,rule]
    if record not in receipt['rules']:receipt['rules'].append(record);save(receipt)
    call('ip6tables','-w','5',*table,'-I',*rule)
 call('sysctl','-q','-w','net.ipv6.conf.all.forwarding=1')
 return {'ipv6Forwarding':True}
def configure():
 assert os.geteuid()==0 and json.loads(STATE.read_text()).get('owner')=='x1o-managed-v1','Unowned deployment'
 family=listener();ready=ipv6_ready()
 state=json.loads(STATE.read_text())
 # Old recipes deliberately blocked IPv6 on the owned AWG interface. Remove
 # only rules recorded as ours, retaining enough information for rollback.
 firewall=state.get('firewall',{})
 if ready and firewall.get('kind')=='firewalld':
  receipt=json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'owner':'xio-dualstack-v1','oldForward':Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip(),'rules':[],'addresses':[]}
  assert receipt['owner']=='xio-dualstack-v1'
  for item in firewall.get('added',[]):
   if item.get('option')!='rich-rule' or item.get('value')!='rule family="ipv6" source address="fd78:1::/64" drop':continue
   args=item['args'];value=item['value']
   if call('firewall-cmd',*args,'--query-rich-rule='+value,check=False).returncode==0:
    removed=receipt.setdefault('removedLegacyRules',[])
    if item not in removed:removed.append(item);save(receipt)
    call('firewall-cmd',*args,'--remove-rich-rule='+value)
 def replace(path,value):
  p=Path(path);q=p.with_suffix(p.suffix+'.dualstack-new');q.write_text(value);q.chmod(p.stat().st_mode&0o777);q.replace(p)
 p=(CONFIG_DIR/'config.json')
 if p.exists():
  value=json.loads(p.read_text())
  for inbound in value.get('inbounds',[]):
   if inbound.get('listen') in ['0.0.0.0','::']:inbound['listen']=family
  replace(p,json.dumps(value))
 p=(CONFIG_DIR/'cloak.json')
 if p.exists():
  value=json.loads(p.read_text());value['BindAddr']=[('[::]:9443' if family=='::' else '0.0.0.0:9443') if a in ['0.0.0.0:9443','[::]:9443'] else a for a in value['BindAddr']];replace(p,json.dumps(value))
 p=(CONFIG_DIR/'tcp.ovpn')
 if p.exists() and ready:
  value=p.read_text()
  if 'server-ipv6 ' not in value:value+='\nserver-ipv6 fd80:1::/64\npush "redirect-gateway ipv6"\npush "dhcp-option DNS6 2620:fe::fe"\n'
  replace(p,value)
 p=NETWORK_UP
 if p.exists() and 'dualstack.py apply' not in p.read_text():replace(p,p.read_text()+'\npython3 /usr/local/lib/x1o-managed/dualstack.py apply\n')
 return {'ipv6Listener':family=='::','ipv6DefaultRoute':ready}
def remove(restore_legacy=False):
 if not RECEIPT.exists():return
 receipt=json.loads(RECEIPT.read_text());assert receipt.get('owner')=='xio-dualstack-v1'
 if restore_legacy:
  for item in receipt.get('removedLegacyRules',[]):
   if call('firewall-cmd',*item['args'],'--query-rich-rule='+item['value'],check=False).returncode!=0:call('firewall-cmd',*item['args'],'--add-rich-rule='+item['value'])
 for table,rule in reversed(receipt['rules']):
  if call('ip6tables','-w','5',*table,'-C',*rule,check=False).returncode==0:call('ip6tables','-w','5',*table,'-D',*rule)
 for interface,address in receipt['addresses']:call('ip','-6','address','del',address,'dev',interface,check=False)
 for dev,value in receipt.get('acceptRa',{}).items():
  path=Path('/proc/sys/net/ipv6/conf')/dev/'accept_ra'
  if path.exists() and path.read_text().strip()=='2':path.write_text(value+'\n')
 # Do not disable forwarding when a later unrelated VPN/bridge may depend on it.
 others=[p.name for p in Path('/sys/class/net').iterdir() if p.name not in {'lo','x1o0','x1oawg0','xiorivet','xioovpn1'} and (p/'tun_flags').exists()]
 if not others and Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip()=='1':call('sysctl','-q','-w','net.ipv6.conf.all.forwarding='+receipt['oldForward'])
 RECEIPT.unlink()
if __name__=='__main__':
 assert sys.argv[1:] in [['apply'],['remove'],['configure'],['rollback']]
 result={'apply':apply,'configure':configure,'remove':remove,'rollback':lambda:remove(True)}[sys.argv[1]]()
 print(json.dumps(result or {'removed':True}))
