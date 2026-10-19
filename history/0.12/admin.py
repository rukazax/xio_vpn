#!/usr/bin/env python3
"""x1o owned WG/AWG deployment; JSON stdin/stdout, no client private keys."""
import base64,fcntl,hashlib,ipaddress,json,os,re,secrets,shlex,socket,subprocess,sys,time,uuid
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
def key():
 private=base64.b64encode(secrets.token_bytes(32)).decode();return private,run('wg','pubkey',input=private+'\n')
def rules(d,remove=False):
 for proto,iface,subnet in [('wireguard','x1o0','10.77.0.0/24'),('awg','x1oawg0','10.78.0.0/24')]:
  comment=OWNER+'-'+proto
  for cmd,table,rule in [
   ('iptables',[],['FORWARD','-i',iface,'-m','comment','--comment',comment,'-j','ACCEPT']),
   ('iptables',[],['FORWARD','-o',iface,'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','comment','--comment',comment,'-j','ACCEPT']),
   ('iptables',['-t','nat'],['POSTROUTING','-s',subnet,'-o',d['outbound'],'-m','comment','--comment',comment,'-j','MASQUERADE']),
   ('ip6tables',[],['FORWARD','-i',iface,'-m','comment','--comment',comment,'-j','DROP'])]:
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
def stats(d):
 current=counters();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 # Generation also changes on service restart even within the same boot.
 generations={p:boot+':'+run('systemctl','show',unit,'--property=InvocationID','--value') for p,unit in [('wireguard','wg-quick@x1o0'),('awg','x1o-managed-awg')]}
 for u in d['users'].values():
  for p,pub in u['keys'].items():
   rx,tx,hs=current.get((p,pub),(0,0,0));s=u.setdefault('stats',{}).setdefault(p,{'rx':0,'tx':0,'lastRx':0,'lastTx':0})
   if u.get('revoked'):continue
   reset=s.get('generation')!=generations[p]
   s['rx']+=rx if reset or rx<s['lastRx'] else rx-s['lastRx'];s['tx']+=tx if reset or tx<s['lastTx'] else tx-s['lastTx'];s.update(lastRx=rx,lastTx=tx,handshake=hs,generation=generations[p])
 save(d);return {'server':public(d),'users':[dict(id=k,**v) for k,v in d['users'].items()],'sampledAt':int(time.time()),'statisticsNote':'Server counters; sampled every 30s. Unsampled traffic before a service crash may be lost.'}
def public(d):return {k:d[k] for k in ['id','host','protocols','publicKeys','awg']}
def init(req):
 if (ROOT/'deployment.json').exists():
  existing=load()
  if existing.get('phase')!='ready':raise RuntimeError('Incomplete installation; remove before retry')
  return {'server':public(existing),'existing':True}
 osinfo=Path('/etc/os-release').read_text()
 if not ('ID=debian' in osinfo and 'VERSION_ID="12"' in osinfo):raise RuntimeError('This recipe requires Debian 12 amd64')
 if run('uname','-m')!='x86_64':raise RuntimeError('amd64 VPS required')
 links=json.loads(run('ip','-j','link'));assert not any(i['ifname'] in ['x1o0','x1oawg0'] for i in links),'Existing VPN; remove it first'
 assert not Path('/etc/wireguard/x1o0.conf').exists(),'Existing x1o0 configuration'
 ports=run('ss','-H','-lun');assert not any(line.split()[3].endswith((':51820',':51821')) for line in ports.splitlines()),'VPN ports busy'
 for route in json.loads(run('ip','-j','-4','route')):
  if route.get('dst','default')!='default':assert not any(ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network(n)) for n in ['10.77.0.0/24','10.78.0.0/24']),'Subnet conflict'
 for route in json.loads(run('ip','-j','-6','route')):
  if route.get('dst','default')!='default':assert not any(ipaddress.ip_network(route['dst'],strict=False).overlaps(ipaddress.ip_network(n)) for n in ['fd77:1::/64','fd78:1::/64']),'IPv6 subnet conflict'
 if subprocess.run(['sh','-c','command -v ufw >/dev/null && ufw status | grep -q "^Status: active"'],capture_output=True).returncode==0:raise RuntimeError('Active UFW requires separate setup')
 host=req['host'];assert re.fullmatch(r'[a-zA-Z0-9.:-]{1,253}',host)
 installed=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}','wireguard-tools'],capture_output=True,text=True).stdout=='installed'
 d={'owner':OWNER,'id':str(uuid.uuid4()),'host':host,'protocols':['wireguard','awg'],'users':{},'publicKeys':{},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40,'H1':secrets.randbelow(100000)+100000,'H2':secrets.randbelow(100000)+200000,'H3':secrets.randbelow(100000)+300000,'H4':secrets.randbelow(100000)+400000},'outbound':json.loads(run('ip','-j','route','show','default'))[0]['dev'],'oldForward':run('sysctl','-n','net.ipv4.ip_forward'),'packageOwned':not installed,'phase':'installing'}
 assert re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',d['outbound']);save(d)
 env=os.environ.copy();env['DEBIAN_FRONTEND']='noninteractive'
 with (ROOT/'install.log').open('a') as log:
  subprocess.run(['apt-get','update'],env=env,stdout=log,stderr=log,check=True)
  subprocess.run(['apt-get','install','-y','--no-install-recommends','wireguard-tools','iptables'],env=env,stdout=log,stderr=log,check=True)
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
ExecStart=/usr/local/lib/x1o-managed/amneziawg-go -f x1oawg0
ExecStartPost=/usr/bin/python3 /usr/local/lib/x1o-managed/admin.py start
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
'''
 write('/etc/systemd/system/x1o-managed-awg.service',unit)
 write('/etc/systemd/system/x1o-managed-stats.service','[Unit]\nDescription=x1o counters\nAfter=x1o-managed-awg.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/lib/x1o-managed/admin.py sample\n')
 write('/etc/systemd/system/x1o-managed-stats.timer','[Unit]\nDescription=x1o periodic counters\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\n[Install]\nWantedBy=timers.target\n')
 run('systemctl','daemon-reload');run('systemctl','enable','--now','wg-quick@x1o0');run('systemctl','enable','--now','x1o-managed-awg');run('systemctl','enable','--now','x1o-managed-stats.timer');d['phase']='ready';save(d);return {'server':public(d),'existing':False}
def remove(d):
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
 packageRemoved=False
 if d['packageOwned']:
  configs=list(Path('/etc/wireguard').glob('*.conf'));plan=run('apt-get','-s','purge','wireguard-tools')
  removals=[line.split()[1] for line in plan.splitlines() if line.startswith(('Remv ','Purg '))]
  if not configs and removals==['wireguard-tools']:run('apt-get','purge','-y','wireguard-tools');packageRemoved=True
 import shutil
 shutil.rmtree(ROOT);shutil.rmtree(LIB);run('systemctl','daemon-reload')
 return {'removed':True,'ownedPackageRemoved':packageRemoved,'forwardingRestored':restored,'otherVirtualInterfaces':other}
def dispatch(req):
 action=req['action']
 if action=='init':return init(req)
 d=load()
 if action=='inspect':return {'server':public(d),'phase':d['phase']}
 assert req.get('serverId')==d['id'],'Server identity changed; reopen setup'
 if action=='status':return stats(d)
 if action=='remove':return remove(d)
 if action=='add':
  name=req['name'];assert isinstance(name,str) and 0<len(name.strip())<=80,'Invalid name'
  uid=req['id'];assert re.fullmatch('[a-f0-9]{32}',uid),'Invalid user id'
  keys=req['publicKeys'];assert set(keys)==set(d['protocols'])
  for k in keys.values():assert isinstance(k,str) and len(base64.b64decode(k,validate=True))==32,'Invalid public key'
  if uid in d['users']:raise RuntimeError('User id already exists')
  assert not any(set(keys.values()) & set(u['keys'].values()) for u in d['users'].values()),'Duplicate key'
  used={u['slot'] for u in d['users'].values()};slot=next((i for i in range(2,255) if i not in used),None);assert slot,'User limit reached'
  d['users'][uid]={'name':name.strip(),'slot':slot,'keys':keys,'revoked':False,'createdAt':int(time.time())};save(d);apply(d)
  return {'user':dict(id=uid,**d['users'][uid]),'server':public(d)}
 if action=='revoke':
  stats(d);uid=req['id'];assert uid in d['users'],'Unknown user';d['users'][uid]['revoked']=True;save(d);apply(d);return {'revoked':uid}
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
   else:print(json.dumps({'ok':True,**dispatch(json.load(sys.stdin))}))
 except Exception as e:
  # Only our explicit errors; subprocess errors never echo command input or keys.
  print(json.dumps({'ok':False,'error':str(e) if isinstance(e,(AssertionError,RuntimeError)) else 'Server operation failed; inspect root-only install log'}));sys.exit(1)
