#!/usr/bin/env python3
"""Owned IPv6 forwarding additions, with an explicit reversible receipt.

No provider addresses/routes are invented, no firewall is flushed, and no
packages are installed. Existing IPv4 rules and server credentials are retained.
"""
import json,os,re,socket,stat,subprocess,sys
from pathlib import Path
STATE=Path('/etc/xio-managed/deployment.json')
RECEIPT=Path('/etc/xio-managed/dualstack-receipt.json')
CONFIG_DIR=Path('/etc/xio-stack')
NETWORK_UP=Path('/usr/local/lib/xio-rivet/network-up')
TUN=Path('/dev/net/tun')
PROCESS_STATUS=Path('/proc/self/status')
SYS_NET=Path('/sys/class/net')
IPV6_SYS=Path('/proc/sys/net/ipv6/conf')
FORWARDING=IPV6_SYS/'all/forwarding'
SUBNETS=(('xio0','fd77:1::/64','fd77:1::1/64'),('xioawg0','fd78:1::/64','fd78:1::1/64'),('xiorivet','fd79:1::/64','fd79:1::1/64'),('xioovpn0','fd80:0::/64','fd80:0::1/64'),('xioovpn1','fd80:1::/64','fd80:1::1/64'))
def call(*args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if check and p.returncode:raise RuntimeError('IPv6 network operation failed: '+args[0])
 return p

def routes(family):
 try:p=call('ip','-j',family,'route','show','default',check=False)
 except OSError:return []
 try:items=json.loads(p.stdout) if p.returncode==0 else []
 except ValueError:items=[]
 return sorted((x for x in items if re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',x.get('dev','')) and x.get('type','unicast')=='unicast'),key=lambda x:x.get('metric',0))

def outbounds():
 result={}
 for name,family in [('ipv4','-4'),('ipv6','-6')]:
  items=routes(family)
  if items:
   value=items[0]['dev'];assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',value);result[name]=value
 return result
def outbound():
 values=outbounds()
 for family in ['ipv4','ipv6']:
  if family in values:return values[family]
 raise RuntimeError('No IPv4 or IPv6 default route')
def ipv6_ready():return bool(routes('-6'))

def capabilities():
 values=outbounds()
 return {'outboundByFamily':values,'ipv4DefaultRoute':'ipv4' in values,'ipv6DefaultRoute':'ipv6' in values,
         'dns64':'notProbed','nat64':'notProbed','endToEnd':'notProbed',
         'ipv4LiteralEgress':'notProbed' if 'ipv4' in values else 'requiresExplicitTranslation',
         'note':'Routes are observations, not connectivity tests. DNS64 does not translate IPv4 literals or IPv4 tunnel packets; no NAT64/CLAT is configured by XIO.'}

def preflight():
 # No interface, ioctl, firewall, route, module, cgroup or sysctl changes here.
 # An open probe detects device-policy denial but does NOT prove TUNSETIFF.
 try:info=TUN.stat()
 except OSError as error:raise RuntimeError('TUN preflight: /dev/net/tun (10:200) unavailable; the host/provider must expose and permit the device. No device or security bypass is attempted.') from error
 if not stat.S_ISCHR(info.st_mode) or (os.major(info.st_rdev),os.minor(info.st_rdev))!=(10,200):raise RuntimeError('TUN preflight: /dev/net/tun is not character device 10:200')
 try:
  fields=dict(line.split(':',1) for line in PROCESS_STATUS.read_text().splitlines() if ':' in line)
  for field in ['CapEff','CapBnd']:
   mask=int(fields[field].strip(),16)
   for name,bit in [('CAP_NET_ADMIN',12),('CAP_NET_RAW',13)]:
    if not mask & (1<<bit):raise RuntimeError('Network preflight: '+name+' absent from '+field+'; container host delegation is required, not guest security changes')
 except (OSError,KeyError,ValueError) as error:raise RuntimeError('Network preflight: cannot verify effective/bounding capabilities') from error
 try:
  descriptor=os.open(TUN,os.O_RDWR|getattr(os,'O_CLOEXEC',0));os.close(descriptor)
 except OSError as error:raise RuntimeError('TUN preflight: device open denied/unavailable; check host device/cgroup/LSM delegation. Root or sysfs visibility is not sufficient.') from error
 result=capabilities()
 if not result['outboundByFamily']:raise RuntimeError('Network preflight: no usable IPv4 or IPv6 default route')
 return dict(result,tunOpen=True,tunSetIff='notProbed',wireguardCreation='notProbed',netfilterWrites='notProbed')
def listener():
 try:
  with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:s.bind(('::1',0))
  return '::'
 except OSError:return '0.0.0.0'
def _digest(raw):
 import hashlib
 return hashlib.sha256(raw).hexdigest()

def _regular(path,missing=False):
 if any(p.is_symlink() for p in (path,*path.parents)):raise RuntimeError('Linked IPv6 transaction path')
 if not path.exists():
  if missing:return
  raise RuntimeError('Missing IPv6 transaction file')
 if not path.is_file():raise RuntimeError('Non-regular IPv6 transaction file')

def _raw_receipt():
 _regular(RECEIPT,True)
 return RECEIPT.read_bytes() if RECEIPT.exists() else None

def _sha_receipt():
 raw=_raw_receipt();return _digest(raw) if raw is not None else None

def _fence_path():return RECEIPT.with_name('.dualstack-update.json')

def _put(path,raw,mode=0o600):
 import tempfile
 _regular(path,True)
 descriptor,name=tempfile.mkstemp(prefix='.ipv6-new-',dir=path.parent)
 temporary=Path(name)
 try:
  with os.fdopen(descriptor,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
  temporary.chmod(mode);temporary.replace(path)
 finally:temporary.unlink(missing_ok=True)

def _json_put(path,value):
 if path==_fence_path():
  value={k:v for k,v in value.items() if k!='journalSha'}
  value['journalSha']=_digest(json.dumps(value,sort_keys=True).encode())
 _put(path,json.dumps(value,sort_keys=True).encode())

def _fence():
 path=_fence_path()
 if not path.exists() and not path.is_symlink():return None
 _regular(path);value=json.loads(path.read_bytes())
 if value.get('journalSha')!=_digest(json.dumps({k:v for k,v in value.items() if k!='journalSha'},sort_keys=True).encode()):raise RuntimeError('IPv6 intent journal hash mismatch')
 if value.get('owner')!='xio-ipv6-update-v1' or value.get('receiptSha')!=_sha_receipt():raise RuntimeError('Foreign or raced IPv6 transaction receipt')
 return value

def _lock():
 import contextlib,fcntl
 @contextlib.contextmanager
 def locked():
  path=RECEIPT.with_name('.dualstack.lock');_regular(path,True)
  with path.open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX);yield
 return locked()

def delta_begin(folder):
 import secrets
 with _lock():
  if _fence_path().exists() or _fence_path().is_symlink():raise RuntimeError('Existing IPv6 update fence; owner recovery required')
  raw=_raw_receipt()
  if raw is not None and json.loads(raw).get('owner')!='xio-dualstack-v1':raise RuntimeError('Foreign IPv6 receipt')
  _regular(FORWARDING);forward=FORWARDING.read_text().strip()
  if forward not in ['0','1']:raise RuntimeError('Invalid IPv6 forwarding snapshot')
  accept={}
  for directory in IPV6_SYS.iterdir():
   path=directory/'accept_ra'
   if re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',directory.name) and path.is_file():
    _regular(path);value=path.read_text().strip()
    if value not in ['0','1','2']:raise RuntimeError('Invalid IPv6 RA snapshot')
    accept[directory.name]=value
  value={'owner':'xio-ipv6-update-v1','id':secrets.token_hex(16),'receiptSha':_digest(raw) if raw is not None else None,
         'receiptRaw':raw.hex() if raw is not None else None,'receiptMode':RECEIPT.stat().st_mode&0o777 if raw is not None else 0o600,
         'forward':forward,'acceptRa':accept}
  path=Path(folder)/'ipv6-before.json';_json_put(path,value)
  plan={'path':str(path),'sha256':_digest(path.read_bytes()),'id':value['id']}
  _json_put(_fence_path(),{'owner':value['owner'],'id':value['id'],'snapshotSha':plan['sha256'],'receiptSha':value['receiptSha'],'effects':[],'forward':forward,'acceptRa':accept})
  return plan

def _effect(kind,value,action):
 fence=_fence()
 if fence is not None:
  if kind=='ra' and (value not in fence['acceptRa'] or (IPV6_SYS/value/'accept_ra').read_text().strip()!=fence['acceptRa'][value]):raise RuntimeError('Raced IPv6 RA state before write')
  if kind=='forward' and FORWARDING.read_text().strip()!=fence['forward']:raise RuntimeError('Raced IPv6 forwarding state before write')
  effect={'kind':kind,'value':value}
  if effect not in fence['effects']:fence['effects'].append(effect)
  _json_put(_fence_path(),fence) # Intent precedes the kernel effect.
 return action()

def save(receipt):
 fence=_fence();_json_put(RECEIPT,receipt)
 if fence is not None:
  fence['receiptSha']=_sha_receipt();_json_put(_fence_path(),fence)

def _delta_load(plan):
 path=Path(plan['path']);_regular(path)
 if _digest(path.read_bytes())!=plan['sha256']:raise RuntimeError('IPv6 rollback snapshot hash mismatch')
 before=json.loads(path.read_bytes());fence=_fence()
 if fence is None or fence.get('id')!=plan['id'] or fence.get('snapshotSha')!=plan['sha256'] or before.get('id')!=plan['id']:raise RuntimeError('IPv6 transaction ownership/hash mismatch')
 if before.get('owner')!='xio-ipv6-update-v1':raise RuntimeError('Foreign IPv6 snapshot')
 if fence.get('forward')!=before['forward'] or fence.get('acceptRa')!=before['acceptRa']:raise RuntimeError('Changed IPv6 sysctl snapshot fence')
 raw=_raw_receipt()
 if raw is not None and json.loads(raw).get('owner')!='xio-dualstack-v1':raise RuntimeError('Foreign IPv6 receipt during rollback')
 return before,fence

def delta_commit(plan):
 with _lock():
  _delta_load(plan);_fence_path().unlink()

def _owned_rule(record,devices):
 for dev in devices:
  for port,proto in [(8443,'tcp'),(8443,'udp'),(4443,'tcp'),(9443,'tcp'),(9444,'tcp')]:
   if record==[[],['INPUT','-i',dev,'-p',proto,'--dport',str(port),'-m','comment','--comment','xio-dualstack-v1-input','-j','ACCEPT']]:return True
  for interface,subnet,_ in SUBNETS:
   comment=['-m','comment','--comment','xio-dualstack-v1-'+interface]
   candidates=[[[],['FORWARD','-i',interface,'-o',dev,'-s',subnet,*comment,'-j','ACCEPT']],[[],['FORWARD','-o',interface,'-m','conntrack','--ctstate','RELATED,ESTABLISHED',*comment,'-j','ACCEPT']],[['-t','nat'],['POSTROUTING','-s',subnet,'-o',dev,*comment,'-j','MASQUERADE']]]
   port={'xio0':'51820','xioawg0':'51821','xioovpn0':'1194'}.get(interface)
   if port:candidates.append([[],['INPUT','-i',dev,'-p','udp','--dport',port,*comment,'-j','ACCEPT']])
   if record in candidates:return True
 return False

def delta_rollback(plan):
 with _lock():
  before,fence=_delta_load(plan)
  # Validate ALL intent/snapshot ownership and sysctl fences before any deletion.
  for effect in fence['effects']:
   kind,value=effect['kind'],effect['value']
   if kind=='rule':
    table,rule=value
    if not _owned_rule(value,before['acceptRa']):raise RuntimeError('Foreign IPv6 rule intent')
   elif kind=='address':
    if value not in [[i,a] for i,_,a in SUBNETS]:raise RuntimeError('Foreign IPv6 address intent')
   elif kind=='ra':
    if value not in before['acceptRa'] or (IPV6_SYS/value/'accept_ra').read_text().strip() not in [before['acceptRa'][value],'2']:raise RuntimeError('Raced IPv6 RA state')
   elif kind=='forward':
    if FORWARDING.read_text().strip() not in [before['forward'],'1']:raise RuntimeError('Raced IPv6 forwarding state')
   elif kind=='legacy-rule':
    if value.get('option')!='rich-rule' or value.get('value') not in ['rule family="ipv6" source address="'+s+'" drop' for s in ['fd77:1::/64','fd78:1::/64']]:raise RuntimeError('Foreign legacy rule intent')
   else:raise RuntimeError('Unknown IPv6 effect intent')
  for effect in reversed(fence['effects']):
   _delta_load(plan) # Recheck the receipt/hash fence before each kernel change.
   kind,value=effect['kind'],effect['value']
   if kind=='rule':
    table,rule=value
    if call('ip6tables','-w','5',*table,'-C',*rule,check=False).returncode==0:call('ip6tables','-w','5',*table,'-D',*rule)
   elif kind=='address':
    interface,address=value
    if (SYS_NET/interface).exists():
     entries=json.loads(call('ip','-j','-6','address','show','dev',interface).stdout)
     if any(x.get('local')==address.split('/')[0] and x.get('prefixlen')==int(address.split('/')[1]) for e in entries for x in e.get('addr_info',[])):call('ip','-6','address','del',address,'dev',interface)
   elif kind=='ra':(IPV6_SYS/value/'accept_ra').write_text(before['acceptRa'][value]+'\n')
   elif kind=='forward':call('sysctl','-q','-w','net.ipv6.conf.all.forwarding='+before['forward'])
   elif kind=='legacy-rule':
    if call('firewall-cmd',*value['args'],'--query-rich-rule='+value['value'],check=False).returncode!=0:call('firewall-cmd',*value['args'],'--add-rich-rule='+value['value'])
  if before['receiptRaw'] is None:RECEIPT.unlink(missing_ok=True)
  else:_put(RECEIPT,bytes.fromhex(before['receiptRaw']),before['receiptMode'])
  _fence_path().unlink()

def apply():
 with _lock():return _apply()

def _apply():
 assert os.geteuid()==0,'Owner root access required'
 state=json.loads(STATE.read_text());assert state.get('owner')=='xio-managed-v1','Unowned deployment'
 if not ipv6_ready():return {'ipv6Forwarding':False,'reason':'No IPv6 default route'}
 dev=routes('-6')[0]['dev'];assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',dev)
 receipt=json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'owner':'xio-dualstack-v1','oldForward':FORWARDING.read_text().strip(),'rules':[],'addresses':[]}
 assert receipt['owner']=='xio-dualstack-v1'
 save(receipt) # Save intent before every network effect.
 # Forwarding can suppress RA acceptance. Retain RA on the physical uplink when
 # it was the source of the existing default route; restore only our own change.
 accept=IPV6_SYS/dev/'accept_ra'
 if routes('-6')[0].get('protocol')=='ra' and accept.exists() and accept.read_text().strip()!='2':
  receipt.setdefault('acceptRa',{}).setdefault(dev,accept.read_text().strip());save(receipt);_effect('ra',dev,lambda:accept.write_text('2\n'))
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
   _effect('rule',[[],rule],lambda:call('ip6tables','-w','5','-I',*rule))
 for interface,subnet,address in SUBNETS:
  if not (SYS_NET/interface).exists():continue
  entries=json.loads(call('ip','-j','-6','address','show','dev',interface).stdout)
  if not any(x.get('local')==address.split('/')[0] for e in entries for x in e.get('addr_info',[])):
   item=[interface,address]
   if item not in receipt['addresses']:receipt['addresses'].append(item);save(receipt)
   _effect('address',[interface,address],lambda:call('ip','-6','address','add',address,'dev',interface))
  comment='xio-dualstack-v1-'+interface
  port={'xio0':'51820','xioawg0':'51821','xioovpn0':'1194'}.get(interface)
  rules=[([],['INPUT','-i',dev,'-p','udp','--dport',port,'-m','comment','--comment',comment,'-j','ACCEPT'])] if port else []
  rules += [([],['FORWARD','-i',interface,'-o',dev,'-s',subnet,'-m','comment','--comment',comment,'-j','ACCEPT']),([],['FORWARD','-o',interface,'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','comment','--comment',comment,'-j','ACCEPT']),(['-t','nat'],['POSTROUTING','-s',subnet,'-o',dev,'-m','comment','--comment',comment,'-j','MASQUERADE'])]
  for table,rule in rules:
   if call('ip6tables','-w','5',*table,'-C',*rule,check=False).returncode:
    record=[table,rule]
    if record not in receipt['rules']:receipt['rules'].append(record);save(receipt)
    _effect('rule',[table,rule],lambda:call('ip6tables','-w','5',*table,'-I',*rule))
 if FORWARDING.read_text().strip()!='1':_effect('forward',None,lambda:call('sysctl','-q','-w','net.ipv6.conf.all.forwarding=1'))
 return {'ipv6Forwarding':True}
def configure():
 with _lock():return _configure()

def _configure():
 assert os.geteuid()==0 and json.loads(STATE.read_text()).get('owner')=='xio-managed-v1','Unowned deployment'
 family=listener();ready=ipv6_ready()
 state=json.loads(STATE.read_text())
 # Old recipes deliberately blocked IPv6 on the owned AWG interface. Remove
 # only rules recorded as ours, retaining enough information for rollback.
 firewall=state.get('firewall',{})
 if ready and firewall.get('kind')=='firewalld':
  receipt=json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'owner':'xio-dualstack-v1','oldForward':FORWARDING.read_text().strip(),'rules':[],'addresses':[]}
  assert receipt['owner']=='xio-dualstack-v1'
  for item in firewall.get('added',[]):
   if item.get('option')!='rich-rule' or item.get('value') not in ['rule family="ipv6" source address="'+subnet+'" drop' for subnet in ['fd77:1::/64','fd78:1::/64']]:continue
   args=item['args'];value=item['value']
   if call('firewall-cmd',*args,'--query-rich-rule='+value,check=False).returncode==0:
    removed=receipt.setdefault('removedLegacyRules',[])
    if item not in removed:removed.append(item);save(receipt)
    _effect('legacy-rule',item,lambda:call('firewall-cmd',*args,'--remove-rich-rule='+value))
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
 if p.exists() and 'dualstack.py apply' not in p.read_text():replace(p,p.read_text()+'\npython3 /usr/local/lib/xio-managed/dualstack.py apply\n')
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
  path=IPV6_SYS/dev/'accept_ra'
  if path.exists() and path.read_text().strip()=='2':path.write_text(value+'\n')
 # Do not disable forwarding when a later unrelated VPN/bridge may depend on it.
 others=[p.name for p in SYS_NET.iterdir() if p.name not in {'lo',*[i for i,_,_ in SUBNETS]} and (p/'tun_flags').exists()]
 if not others and FORWARDING.read_text().strip()=='1':call('sysctl','-q','-w','net.ipv6.conf.all.forwarding='+receipt['oldForward'])
 RECEIPT.unlink()
if __name__=='__main__':
 assert sys.argv[1:] in [['apply'],['remove'],['configure'],['rollback']]
 result={'apply':apply,'configure':configure,'remove':remove,'rollback':lambda:remove(True)}[sys.argv[1]]()
 print(json.dumps(result or {'removed':True}))
