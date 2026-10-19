#!/usr/bin/env python3
"""x1o owned WG/AWG deployment; JSON stdin/stdout, no client private keys."""
import base64,fcntl,hashlib,ipaddress,json,os,re,secrets,shlex,socket,subprocess,sys,time,uuid,shutil
from pathlib import Path
ROOT=Path('/etc/x1o-managed'); LIB=Path('/usr/local/lib/x1o-managed'); OWNER='x1o-managed-v1'

def run(*args,input=None):
 p=subprocess.run(args,input=input,text=True,capture_output=True)
 if p.returncode: raise RuntimeError('Command failed: '+args[0])
 return p.stdout.strip()
def write(p,text):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);tmp=Path(str(p)+'.tmp');tmp.write_text(text);tmp.chmod(0o600);os.replace(tmp,p)
def load():
 d=json.loads((ROOT/'deployment.json').read_text());assert d['owner']==OWNER;return d
def save(d):write(ROOT/'deployment.json',json.dumps(d))
def platform_info(text=None):
 values={}
 for line in (text if text is not None else Path('/etc/os-release').read_text()).splitlines():
  if '=' in line:
   k,v=line.split('=',1);values[k]=v.strip().strip('"').strip("'")
 name=values.get('ID','');version=values.get('VERSION_ID','');major=version.split('.')[0]
 if name=='debian' and major in ['12','13'] or name=='ubuntu' and version in ['22.04','24.04','26.04']:manager='apt'
 elif name in ['centos','rocky','almalinux','rhel'] and major in ['9','10']:manager='rpm'
 else:raise RuntimeError('Unsupported OS; see supported server systems in XIO')
 return {'id':name,'version':version,'manager':manager}
def installed_packages(manager):
 if manager=='apt':
  text=run('dpkg-query','-W','-f=${binary:Package} ${db:Status-Status}\n')
  return {line.split()[0].removesuffix(':amd64') for line in text.splitlines() if line.endswith(' installed')}
 return set(run('rpm','-qa','--qf','%{NAME}\n').splitlines())
def packages_install(d):
 manager=d['platform']['manager'];before=LIB/'packages-before'
 if 'packagesBefore' not in d:d['packagesBefore']=sorted({p.removesuffix(':amd64') for p in before.read_text().splitlines()} if before.exists() else installed_packages(manager))
 save(d);env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',LC_ALL='C')
 commands=[['apt-get','update'],['apt-get','install','-y','--no-install-recommends','wireguard-tools','iptables','iproute2','ca-certificates']] if manager=='apt' else [['dnf','--setopt=install_weak_deps=False','install','-y','wireguard-tools','iptables','iproute','ca-certificates']]
 try:
  with (ROOT/'install.log').open('a') as log:
   for cmd in commands:subprocess.run(cmd,env=env,stdout=log,stderr=log,check=True)
 finally:
  d['packagesAdded']=sorted(installed_packages(manager)-set(d['packagesBefore']));save(d)
def purge_packages(d):
 manager=d.get('platform',{}).get('manager','apt')
 owned=set(d.get('packagesAdded', ['wireguard-tools'] if d.get('packageOwned') else []))
 # An interrupted bootstrap may have installed packages before init saved its receipt.
 if 'packagesBefore' in d:owned |= installed_packages(manager)-set(d['packagesBefore']) if d.get('phase')=='installing' else set()
 assert all(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9+_.:-]*',p) for p in owned),'Invalid package receipt'
 owned &= installed_packages(manager);removed=[]
 # Existing WireGuard configurations make the tooling shared, even without declared package dependencies.
 protected={'wireguard-tools'} if d.get('preserveWireGuardTools') or list(Path('/etc/wireguard').glob('*.conf')) else set()
 candidates=owned-protected
 if manager=='apt' and candidates:
  def plan(names):
   text=run('apt-get','-s','purge',*sorted(names))
   return {line.split()[1].removesuffix(':amd64') for line in text.splitlines() if line.startswith(('Remv ','Purg '))}
  chosen=candidates
  if not plan(chosen)<=candidates:
   chosen={p for p in candidates if plan([p])<=candidates}
  if chosen and plan(chosen)<=candidates:
   actual=plan(chosen)
   run('env','DEBIAN_FRONTEND=noninteractive','apt-get','purge','-y',*sorted(chosen));removed=sorted(actual)
 elif manager=='rpm':
  # rpm --test refuses reverse dependencies; never use --nodeps or erase foreign packages.
  pending=set(candidates)
  while pending:
   batch=sorted(pending)
   if subprocess.run(['rpm','-e','--test',*batch],capture_output=True).returncode==0:
    run('rpm','-e',*batch);removed+=batch;break
   progress=False
   for package in sorted(pending):
    if subprocess.run(['rpm','-e','--test',package],capture_output=True).returncode==0:
     run('rpm','-e',package);removed.append(package);pending.remove(package);progress=True
   if not progress:break
 return {'packagesRemoved':removed,'packagesRetained':sorted(owned-set(removed))}
def firewall_prepare(d):
 active=lambda unit:subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0
 if active('firewalld'):
  assert re.search(r'(?m)^\s*target: ACCEPT\s*$',run('firewall-cmd','--zone=trusted','--list-all')),'Modified trusted zone; firewall setup required'
  assert run('firewall-cmd','--permanent','--zone=trusted','--get-target')=='ACCEPT','Modified permanent trusted zone; firewall setup required'
  zone=subprocess.run(['firewall-cmd','--get-zone-of-interface='+d['outbound']],capture_output=True,text=True).stdout.strip()
  if not zone or zone=='no zone':zone=run('firewall-cmd','--get-default-zone')
  assert re.fullmatch('[A-Za-z0-9_-]+',zone),'Invalid firewall zone'
  d['firewall']={'kind':'firewalld','zone':zone,'added':[]}
 elif shutil.which('ufw') and 'Status: active' in run('env','LC_ALL=C','ufw','status'):
  d['firewall']={'kind':'ufw','added':[]}
 else:d['firewall']={'kind':'iptables'}
 save(d)
def firewall_managed(d,remove=False):
 f=d.get('firewall',{'kind':'iptables'});kind=f['kind']
 if kind=='iptables':return False
 if kind=='firewalld':
  if remove:
   for item in reversed(f['added']):
    args=item['args']
    if subprocess.run(['firewall-cmd',*args,'--query-'+item['option']+'='+item['value']],capture_output=True).returncode==0:run('firewall-cmd',*args,'--remove-'+item['option']+'='+item['value'])
  else:
   items=[('trusted','interface',i) for i in ['x1o0','x1oawg0']]+[(f['zone'],'port',str(p)+'/udp') for p in [51820,51821]]
   items += [(f['zone'],'rich-rule','rule family="ipv4" source address="'+n+'" masquerade') for n in ['10.77.0.0/24','10.78.0.0/24']]
   items += [('trusted','rich-rule','rule family="ipv6" source address="'+n+'" drop') for n in ['fd77:1::/64','fd78:1::/64']]
   for zone,option,value in items:
    for permanent in [False,True]:
     args=(['--permanent'] if permanent else [])+['--zone='+zone]
     if subprocess.run(['firewall-cmd',*args,'--query-'+option+'='+value],capture_output=True).returncode!=0:
      item={'args':args,'option':option,'value':value}
      if item not in f['added']:f['added'].append(item);save(d)
      run('firewall-cmd',*args,'--add-'+option+'='+value)
 elif kind=='ufw':
  if remove:
   existing=[shlex.split(line)[1:] for line in run('ufw','show','added').splitlines() if line.startswith('ufw ')]
   for rule in reversed(f['added']):
    if rule in existing:
     if rule[0]=='route':run('ufw','--force','route','delete',*rule[1:])
     else:run('ufw','--force','delete',*rule)
   if f.get('profileOwned'):Path('/etc/ufw/applications.d/xio-vpn').unlink(missing_ok=True)
  else:
   profile=Path('/etc/ufw/applications.d/xio-vpn')
   if not f.get('profileOwned'):
    assert not profile.exists(),'Existing XIO UFW application profile'
    f['profileOwned']=True;save(d)
   write(profile,'[XIO VPN]\ntitle=XIO VPN\ndescription=XIO managed VPN ports\nports=51820,51821/udp\n')
   rules=[['allow','in','on',d['outbound'],'to','any','app','XIO VPN']]
   rules += [['route','allow','in','on',i,'out','on',d['outbound'],'from',n] for i,n in [('x1o0','10.77.0.0/24'),('x1oawg0','10.78.0.0/24')]]
   existing=[]
   for line in run('ufw','show','added').splitlines():
    if line.startswith('ufw '):existing.append(shlex.split(line)[1:])
   for rule in rules:
    if rule in existing:continue
    if rule not in f['added']:f['added'].append(rule);save(d)
    run('ufw',*rule)
 return kind=='firewalld'
def key():
 private=base64.b64encode(secrets.token_bytes(32)).decode();return private,run('wg','pubkey',input=private+'\n')
def rules(d,remove=False):
 if firewall_managed(d,remove):return
 for proto,iface,subnet in [('wireguard','x1o0','10.77.0.0/24'),('awg','x1oawg0','10.78.0.0/24')]:
  comment=OWNER+'-'+proto
  for cmd,table,rule in [
   ('iptables',[],['INPUT','-i',d['outbound'],'-p','udp','--dport','51820' if proto=='wireguard' else '51821','-m','comment','--comment',comment,'-j','ACCEPT']),
   ('ip6tables',[],['INPUT','-i',d['outbound'],'-p','udp','--dport','51820' if proto=='wireguard' else '51821','-m','comment','--comment',comment,'-j','ACCEPT']),
   ('iptables',[],['FORWARD','-i',iface,'-m','comment','--comment',comment,'-j','ACCEPT']),
   ('iptables',[],['FORWARD','-o',iface,'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','comment','--comment',comment,'-j','ACCEPT']),
   ('iptables',['-t','nat'],['POSTROUTING','-s',subnet,'-o',d['outbound'],'-m','comment','--comment',comment,'-j','MASQUERADE']),
   ('ip6tables',[],['FORWARD','-i',iface,'-m','comment','--comment',comment,'-j','DROP'])]:
   if not shutil.which(cmd):continue
   exists=subprocess.run([cmd,'-w','5',*table,'-C',*rule],capture_output=True).returncode==0
   if remove and exists:run(cmd,'-w','5',*table,'-D',*rule)
   elif not remove and not exists:run(cmd,'-w','5',*table,'-I',*rule)
def awg_uapi(lines):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.settimeout(5);s.connect('/run/amneziawg/x1oawg0.sock');s.sendall(('set=1\n'+lines+'\n\n').encode());data=b''
  while b'\n\n' not in data:
   part=s.recv(4096)
   if not part:raise RuntimeError('AWG closed UAPI')
   data+=part
  if data!=b'errno=0\n\n':raise RuntimeError('AWG configuration rejected')
def render(d):
 lines=['[Interface]','PrivateKey = '+(ROOT/'wg.key').read_text().strip(),'Address = 10.77.0.1/24, fd77:1::1/64','ListenPort = 51820','MTU = 1280']
 for user in d['users'].values():
  if not user.get('revoked'):lines+=['','[Peer]','PublicKey = '+user['keys']['wireguard'],'AllowedIPs = 10.77.0.%d/32, fd77:1::%x/128'%(user['slot'],user['slot'])]
 write('/etc/wireguard/x1o0.conf','\n'.join(lines)+'\n')
def apply(d):
 render(d)
 # No user-controlled command interpolation; stdin is wg config without addresses.
 text=run('wg-quick','strip','x1o0');run('wg','syncconf','x1o0','/dev/stdin',input=text+'\n')
 lines=[]
 for u in d['users'].values():
  if u.get('revoked'):
   lines+=['public_key='+base64.b64decode(u['keys']['awg']).hex(),'remove=true'];continue
  lines+=['public_key='+base64.b64decode(u['keys']['awg']).hex(),'replace_allowed_ips=true','allowed_ip=10.78.0.%d/32'%u['slot'],'allowed_ip=fd78:1::%x/128'%u['slot']]
 awg_uapi('\n'.join(lines))
def start_awg(d):
 for _ in range(100):
  if Path('/run/amneziawg/x1oawg0.sock').exists():break
  time.sleep(.1)
 lines=['private_key='+base64.b64decode((ROOT/'awg.key').read_text().strip()).hex(),'listen_port=51821']+[k.lower()+'='+str(v) for k,v in d['awg'].items()]
 awg_uapi('\n'.join(lines));run('ip','address','replace','10.78.0.1/24','dev','x1oawg0');run('ip','-6','address','replace','fd78:1::1/64','dev','x1oawg0');run('ip','link','set','dev','x1oawg0','mtu','1280','up');apply(d);rules(d)
def counters():
 result={}
 for protocol,iface in [('wireguard','x1o0'),('awg','x1oawg0')]:
  if protocol=='wireguard':
   text=run('wg','show',iface,'dump');rows=text.splitlines()[1:]
   for row in rows:
    v=row.split('\t');result[(protocol,v[0])]=(int(v[5]),int(v[6]),int(v[4]))
  else:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
    s.settimeout(5);s.connect('/run/amneziawg/x1oawg0.sock');s.sendall(b'get=1\n\n');data=b''
    while b'\n\n' not in data:
     part=s.recv(65536)
     if not part:break
     data+=part
   peer=None;v={}
   for line in data.decode().splitlines():
    if '=' not in line:continue
    k,value=line.split('=',1)
    if k=='public_key':
     if peer:result[('awg',peer)]=(int(v.get('rx_bytes',0)),int(v.get('tx_bytes',0)),int(v.get('last_handshake_time_sec',0)))
     peer=base64.b64encode(bytes.fromhex(value)).decode();v={}
    else:v[k]=value
   if peer:result[('awg',peer)]=(int(v.get('rx_bytes',0)),int(v.get('tx_bytes',0)),int(v.get('last_handshake_time_sec',0)))
 return result
def country():
 try:
  import urllib.request
  with urllib.request.urlopen('https://ipapi.co/country/',timeout=5) as response:
   value=response.read(16).decode().strip()
  return value if re.fullmatch('[A-Z]{2}',value) else ''
 except Exception:return ''

def delegation_key(uid,public=None):
 path=Path('/root/.ssh/authorized_keys');marker='xio-delegate:'+uid
 existing=path.read_text().splitlines() if path.exists() else []
 lines=[line for line in existing if not line.endswith(' '+marker)]
 if public:
  assert re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]{64,80}',public),'Invalid management public key'
  blob=base64.b64decode(public.split()[1],validate=True)
  assert len(blob)==51 and blob[:19]==b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20','Invalid management key'
  lines.append('restrict,command="/usr/bin/python3 /usr/local/lib/x1o-managed/admin.py --delegate '+uid+'" '+public+' '+marker)
 path.parent.mkdir(mode=0o700,exist_ok=True)
 write(path,'\n'.join(lines)+'\n')

def authority(d,actor,action,req):
 if actor is None:return
 u=d['users'].get(actor)
 assert u and not u.get('revoked') and u.get('role')=='admin','Admin access revoked'
 assert action in ['inspect','status','add','revoke'],'Operation not permitted'
 if action=='add':
  assert not req.get('admin',False),'Only owner may create admins'
  children=sum(not x.get('revoked') and x.get('createdBy')==actor for x in d['users'].values())
  assert children < u.get('userLimit',0),'User quota exceeded'
 if action=='revoke':
  target=d['users'].get(req.get('id'),{})
  assert target.get('createdBy')==actor,'Cannot revoke another admin user'

def stats(d):
 current=counters();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 # Generation also changes on service restart even within the same boot.
 generations={p:boot+':'+run('systemctl','show',unit,'--property=InvocationID','--value') for p,unit in [('wireguard','wg-quick@x1o0'),('awg','x1o-managed-awg')]}
 for u in d['users'].values():
  for p,pub in u['keys'].items():
   rx,tx,hs=current.get((p,pub),(0,0,0));s=u.setdefault('stats',{}).setdefault(p,{'rx':0,'tx':0,'lastRx':0,'lastTx':0})
   if u.get('revoked'):continue
   reset=s.get('generation')!=generations[p]
   dr=rx if reset or rx<s['lastRx'] else rx-s['lastRx'];dt=tx if reset or tx<s['lastTx'] else tx-s['lastTx']
   s['rx']+=dr;s['tx']+=dt;s.update(lastRx=rx,lastTx=tx,handshake=hs,generation=generations[p])
   month=time.strftime('%Y-%m',time.gmtime());months=u.setdefault('monthly',{});months[month]=months.get(month,0)+dr+dt
  u['month']=time.strftime('%Y-%m',time.gmtime());u['monthBytes']=u.get('monthly',{}).get(u['month'],0)
  u['online']=not u.get('revoked') and any(0<=time.time()-v.get('handshake',0)<=180 for v in u.get('stats',{}).values())
  u.setdefault('trackingSince',int(time.time()))
 save(d);return {'server':public(d),'users':[dict(id=k,**v) for k,v in d['users'].items()],'sampledAt':int(time.time()),'statisticsNote':'Server counters; sampled every 30s. Unsampled traffic before a service crash may be lost.'}
def public(d):return {**{k:d[k] for k in ['id','host','protocols','publicKeys','awg']},'country':d.get('country',''),'platform':d.get('platform',{}),'recipeVersion':d.get('recipeVersion',13)}
def init(req):
 if (ROOT/'deployment.json').exists():
  existing=load()
  if existing.get('phase')!='ready':raise RuntimeError('Incomplete installation; remove before retry')
  return {'server':public(existing),'existing':True}
 platform=platform_info()
 assert Path('/run/systemd/system').is_dir(),'systemd required'
 if run('uname','-m')!='x86_64':raise RuntimeError('amd64 VPS required')
 links=json.loads(run('ip','-j','link'));assert not any(i['ifname'] in ['x1o0','x1oawg0'] for i in links),'Existing VPN; remove it first'
 assert not Path('/etc/wireguard/x1o0.conf').exists(),'Existing x1o0 configuration'
 ports=run('ss','-H','-lun');assert not any(line.split()[3].endswith((':51820',':51821')) for line in ports.splitlines()),'VPN ports busy'
 for route in json.loads(run('ip','-j','-4','route')):
  if route.get('dst','default')!='default':assert not any(ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network(n)) for n in ['10.77.0.0/24','10.78.0.0/24']),'Subnet conflict'
 for route in json.loads(run('ip','-j','-6','route')):
  if route.get('dst','default')!='default':assert not any(ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network(n)) for n in ['fd77:1::/64','fd78:1::/64']),'IPv6 subnet conflict'
 host=req['host'];assert re.fullmatch(r'[a-zA-Z0-9.:-]{1,253}',host)
 installed='wireguard-tools' in installed_packages(platform['manager'])
 d={'owner':OWNER,'id':str(uuid.uuid4()),'host':host,'protocols':['wireguard','awg'],'users':{},'publicKeys':{},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40,'H1':secrets.randbelow(100000)+100000,'H2':secrets.randbelow(100000)+200000,'H3':secrets.randbelow(100000)+300000,'H4':secrets.randbelow(100000)+400000},'outbound':json.loads(run('ip','-j','route','show','default'))[0]['dev'],'oldForward':run('sysctl','-n','net.ipv4.ip_forward'),'packageOwned':not installed,'platform':platform,'recipeVersion':14,'phase':'installing','country':country()}
 assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',d['outbound']);save(d)
 packages_install(d);firewall_prepare(d)
 binary=Path('/usr/local/bin/xio-amneziawg-go');assert not binary.exists(),'Existing XIO binary path'
 d['binaryOwned']=True;save(d);shutil.copyfile(LIB/'amneziawg-go',binary);binary.chmod(0o700)
 if shutil.which('restorecon'):run('restorecon',str(binary))
 for p in d['protocols']:
  private,pub=key();write(ROOT/('wg.key' if p=='wireguard' else 'awg.key'),private+'\n');d['publicKeys'][p]=pub
 save(d);render(d);write('/etc/sysctl.d/91-x1o-managed.conf','net.ipv4.ip_forward=1\n');run('sysctl','-q','-w','net.ipv4.ip_forward=1')
 unit='''[Unit]
Description=x1o managed AmneziaWG
After=network-online.target wg-quick@x1o0.service
Requires=wg-quick@x1o0.service
[Service]
Type=simple
UMask=0077
Environment=WG_PROCESS_FOREGROUND=1
Environment=GOMAXPROCS=2
Environment=LOG_LEVEL=error
ExecStart=/usr/local/bin/xio-amneziawg-go -f x1oawg0
ExecStartPost=/usr/bin/python3 /usr/local/lib/x1o-managed/admin.py start
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
'''
 write('/etc/systemd/system/x1o-managed-awg.service',unit)
 write('/etc/systemd/system/x1o-managed-stats.service','[Unit]\nDescription=x1o counters\nAfter=x1o-managed-awg.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/lib/x1o-managed/admin.py sample\n')
 write('/etc/systemd/system/x1o-managed-stats.timer','[Unit]\nDescription=x1o periodic counters\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\n[Install]\nWantedBy=timers.target\n')
 run('systemctl','daemon-reload');run('systemctl','enable','--now','wg-quick@x1o0');run('systemctl','enable','--now','x1o-managed-awg');run('systemctl','enable','--now','x1o-managed-stats.timer');d=load();d['phase']='ready';save(d);return {'server':public(d),'existing':False}
def remove(d):
 for uid,u in d['users'].items():
  if u.get('role')=='admin':delegation_key(uid)
 # Only owned units/config/rules. No journal wiping, shared package removal or global firewall restore.
 for unit in ['x1o-managed-stats.timer','x1o-managed-stats.service','x1o-managed-awg','wg-quick@x1o0']:subprocess.run(['systemctl','disable','--now',unit],capture_output=True)
 rules(d,True)
 for iface in ['x1o0','x1oawg0']:
  if subprocess.run(['ip','link','show',iface],capture_output=True).returncode==0:run('ip','link','delete',iface)
 for path in ['/etc/wireguard/x1o0.conf','/etc/sysctl.d/91-x1o-managed.conf',*['/etc/systemd/system/'+u for u in ['x1o-managed-awg.service','x1o-managed-stats.service','x1o-managed-stats.timer']]]:Path(path).unlink(missing_ok=True)
 # Restore global forwarding only if no additional virtual network has appeared.
 links=json.loads(run('ip','-j','link'));other=[i['ifname'] for i in links if i.get('linkinfo',{}).get('info_kind') in ['wireguard','tun','bridge','veth']]
 restored=False
 if not other and run('sysctl','-n','net.ipv4.ip_forward')=='1':run('sysctl','-q','-w','net.ipv4.ip_forward='+d['oldForward']);restored=True
 # Remove runtime sockets and install-only temporary data; preserve global package/journal history.
 for socket_path in ['/run/amneziawg/x1oawg0.sock','/run/wireguard/x1o0.sock']:Path(socket_path).unlink(missing_ok=True)
 d['preserveWireGuardTools']=any(i.get('linkinfo',{}).get('info_kind')=='wireguard' for i in links)
 if d.get('binaryOwned'):Path('/usr/local/bin/xio-amneziawg-go').unlink(missing_ok=True)
 package_result=purge_packages(d)
 shutil.rmtree(ROOT);shutil.rmtree(LIB);run('systemctl','daemon-reload')
 Path('/run/lock/x1o-managed.lock').unlink(missing_ok=True)
 return {'removed':True,'ownedPackageRemoved':'wireguard-tools' in package_result['packagesRemoved'],**package_result,'forwardingRestored':restored,'otherVirtualInterfaces':other}
def dispatch(req,actor=None):
 action=req['action']
 if action=='init':
  assert actor is None,'Operation not permitted'
  return init(req)
 d=load()
 authority(d,actor,action,req)
 if action=='inspect':return {'server':public(d),'phase':d['phase']}
 assert req.get('serverId')==d['id'],'Server identity changed; reopen setup'
 if action=='status':
  result=stats(d)
  if actor:result['users']=[u for u in result['users'] if u['id']==actor or u.get('createdBy')==actor]
  return result
 if action=='remove':return remove(d)
 if action=='add':
  name=req['name'];assert isinstance(name,str) and 0<len(name.strip())<=80,'Invalid name'
  uid=req['id'];assert re.fullmatch('[a-f0-9]{32}',uid),'Invalid user id'
  keys=req['publicKeys'];assert set(keys)==set(d['protocols'])
  for k in keys.values():assert isinstance(k,str) and len(base64.b64decode(k,validate=True))==32,'Invalid public key'
  if uid in d['users']:raise RuntimeError('User id already exists')
  assert not any(set(keys.values()) & set(u['keys'].values()) for u in d['users'].values()),'Duplicate key'
  used={u['slot'] for u in d['users'].values() if not u.get('revoked')};slot=next((i for i in range(2,255) if i not in used),None);assert slot,'User limit reached'
  admin=req.get('admin',False);limit=req.get('userLimit',0)
  assert isinstance(admin,bool) and type(limit) is int and 0<=limit<=250,'Invalid admin limit'
  assert len(d['users'])<10000,'History limit reached'
  if admin:delegation_key(uid,req.get('adminPublicKey',''))
  d['users'][uid]={'name':name.strip(),'slot':slot,'keys':keys,'revoked':False,'createdAt':int(time.time()),'role':'admin' if admin else 'user','userLimit':limit if admin else 0,'createdBy':actor,'monthly':{}}
  try:save(d);apply(d)
  except Exception:
   d['users'].pop(uid,None);save(d)
   if admin:delegation_key(uid)
   apply(d);raise
  return {'user':dict(id=uid,**d['users'][uid]),'server':public(d)}
 if action=='revoke':
  stats(d);uid=req['id'];assert uid in d['users'],'Unknown user'
  targets=[uid]+[k for k,u in d['users'].items() if u.get('createdBy')==uid]
  for target in targets:
   d['users'][target]['revoked']=True
   if d['users'][target].get('role')=='admin':delegation_key(target)
  save(d);apply(d);return {'revoked':uid}
 raise RuntimeError('Unknown operation')
if __name__=='__main__':
 os.umask(0o077)
 try:
  assert os.geteuid()==0,'root required'
  if sys.argv[1:]==['start']:
   start_awg(load());sys.exit(0)
  with open('/run/lock/x1o-managed.lock','a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX)
   if sys.argv[1:]==['sample']:stats(load())
   else:
    actor=None
    if sys.argv[1:]:
     assert len(sys.argv)==3 and sys.argv[1]=='--delegate' and re.fullmatch('[a-f0-9]{32}',sys.argv[2]),'Invalid invocation'
     actor=sys.argv[2]
    raw=sys.stdin.buffer.read(32769);assert len(raw)<=32768,'Request too large'
    print(json.dumps({'ok':True,**dispatch(json.loads(raw),actor)}))
 except Exception as e:
  # Only our explicit errors; subprocess errors never echo command input or keys.
  print(json.dumps({'ok':False,'error':str(e) if isinstance(e,(AssertionError,RuntimeError)) else 'Server operation failed; inspect root-only install log'}));sys.exit(1)
