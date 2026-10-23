#!/usr/bin/env python3
"""Owned Xray/SS deployment, called only by the SSH-authorized manager."""
import base64,ipaddress,json,os,secrets,shutil,socket,subprocess,uuid
from pathlib import Path
ROOT=Path('/etc/xio-stack');STATE=Path('/var/lib/xio-stack');LIB=Path('/usr/local/lib/x1o-managed');OWNER='xio-stack-v1'
import importlib.util
_ns=importlib.util.spec_from_file_location("xio_network_stack",str(Path(__file__).with_name("network_stack.py")))
network=importlib.util.module_from_spec(_ns);_ns.loader.exec_module(network)
_ms=importlib.util.spec_from_file_location('xio_mesh_stack',str(Path(__file__).with_name('mesh_stack.py')))
mesh=importlib.util.module_from_spec(_ms);_ms.loader.exec_module(mesh)
def run(*args,input=None):
 p=subprocess.run(args,input=input,capture_output=True)
 if p.returncode:raise RuntimeError('Stack operation failed: '+(' '.join(args[:3]) if args[0]=='systemctl' else args[0]))
 return p.stdout
def write(path,data,mode=0o600):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);p=path.with_name(path.name+'.new');p.write_text(data);p.chmod(mode);p.replace(path)
def receipt():
 r=json.loads((ROOT/'receipt.json').read_text());assert r['owner']==OWNER;return r
def firewall(r,remove=False):
 f=r.get('firewall')
 ports=['4443/tcp','8388/tcp','8388/udp','1194/udp','9443/tcp','500/udp','4500/udp','18443/tcp','3478/udp','41641/udp']
 if r.get('restrictedNetwork'):ports=['4443/tcp','9443/tcp']
 if not f:
  if subprocess.run(['systemctl','is-active','--quiet','firewalld'],capture_output=True).returncode==0:
   f={'kind':'firewalld','zone':run('firewall-cmd','--get-default-zone').decode().strip(),'added':[]}
  elif shutil.which('ufw') and 'Status: active' in run('env','LC_ALL=C','ufw','status').decode():f={'kind':'ufw','added':[]}
  else:f={'kind':'iptables','added':[]}
  r['firewall']=f;write(ROOT/'receipt.json',json.dumps(r))
 if f['kind']=='firewalld':
  for item in (f['added'][:] if remove else [(p,permanent) for p in ports for permanent in [False,True]]):
   port,permanent=item;args=['--zone='+f['zone']]+(['--permanent'] if permanent else [])
   exists=subprocess.run(['firewall-cmd',*args,'--query-port='+port],capture_output=True).returncode==0
   if remove and exists:run('firewall-cmd',*args,'--remove-port='+port)
   elif not remove and not exists:
    f['added'].append(list(item));write(ROOT/'receipt.json',json.dumps(r));run('firewall-cmd',*args,'--add-port='+port)
 elif f['kind']=='ufw':
  existing=run('ufw','show','added').decode()
  for port in f['added'][:] if remove else ports:
   if remove:run('ufw','--force','delete','allow',port)
   elif 'ufw allow '+port not in existing:
    if port not in f['added']:f['added'].append(port);write(ROOT/'receipt.json',json.dumps(r))
    run('ufw','allow',port)
 else:
  for tool in ['iptables','ip6tables']:
   if not shutil.which(tool):continue
   for port in ports:
    number,proto=port.split('/');args=['INPUT','-p',proto,'--dport',number,'-m','comment','--comment','xio-stack-v1','-j','ACCEPT']
    exists=subprocess.run([tool,'-w','5','-C',*args],capture_output=True).returncode==0
    if remove and exists:run(tool,'-w','5','-D',*args)
    elif not remove and not exists:run(tool,'-w','5','-I',*args)

def config(d):
 r=receipt();users=[(uid,u['stack']) for uid,u in d['users'].items() if not u.get('revoked') and u.get('stack')]
 clients=[{'id':u['uuid'],'email':uid+'@xio','flow':'xtls-rprx-vision','level':0} for uid,u in users]
 ssclients=[{'password':u['ssKey'],'email':uid+'@xio','level':0} for uid,u in users]
 if not ssclients:ssclients=[{'password':r['inactiveKey'],'email':'inactive@xio'}]
 j={'log':{'loglevel':'none'},'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'statsUserOnline':True,'handshake':10,'connIdle':180}}},'inbounds':[{'listen':network.dualstack().listener(),'port':4443,'protocol':'vless','settings':{'clients':clients,'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'target':r['target'],'xver':0,'serverNames':[r['serverName']],'privateKey':r['privateKey'],'shortIds':[r['shortId']]}}},{'listen':network.dualstack().listener(),'port':8388,'protocol':'shadowsocks','settings':{'method':'2022-blake3-aes-256-gcm','password':r['ssKey'],'clients':ssclients,'network':'tcp,udp'}}],'outbounds':[{'protocol':'freedom'}]}
 if d.get('restrictedNetwork'):j['inbounds']=[inbound for inbound in j['inbounds'] if inbound['protocol']!='shadowsocks']
 write(ROOT/'config.json',json.dumps(j))
def apply(d):
 config(d)
 if (ROOT/'swanctl.conf').exists():network.ike_config(d);network.load_ike()
 if (ROOT/'cloak.json').exists():network.cloak_config(d);subprocess.run(['systemctl','reset-failed','xio-cloak'],capture_output=True);run('systemctl','restart','xio-cloak');run('systemctl','is-active','--quiet','xio-cloak')
 subprocess.run(['systemctl','reset-failed','xio-stack'],capture_output=True);run('systemctl','restart','xio-stack');run('systemctl','is-active','--quiet','xio-stack')
def install(d):
 if (ROOT/'receipt.json').exists():r=receipt()
 else:
  assert not ROOT.exists(),'Unowned Xray directory'
  for port,kind in [(4443,socket.SOCK_STREAM),(8388,socket.SOCK_STREAM),(8388,socket.SOCK_DGRAM)]:
   s=socket.socket(socket.AF_INET,kind)
   try:s.bind(('0.0.0.0',port))
   finally:s.close()
  assert not Path('/etc/systemd/system/xio-stack.service').exists(),'Unowned Xray service'
  der=run('openssl','genpkey','-algorithm','X25519','-outform','DER');pub=run('openssl','pkey','-inform','DER','-pubout','-outform','DER',input=der)
  name=d.get('rivet',{}).get('serverName','')
  try:ipaddress.ip_address(name);name='www.microsoft.com'
  except ValueError:pass
  if not name:name='www.microsoft.com'
  r={'owner':OWNER,'privateKey':base64.urlsafe_b64encode(der[-32:]).decode().rstrip('='),'publicKey':base64.urlsafe_b64encode(pub[-32:]).decode().rstrip('='),'shortId':secrets.token_hex(8),'serverName':name,'target':name+':443','ssKey':base64.b64encode(secrets.token_bytes(32)).decode(),'inactiveKey':base64.b64encode(secrets.token_bytes(32)).decode()}
  ROOT.mkdir(mode=0o700);write(ROOT/'receipt.json',json.dumps(r))
 dest=Path('/usr/local/bin/xio-stack');src=LIB/'xraygateway';tmp=dest.with_suffix('.new');shutil.copyfile(src,tmp);tmp.chmod(0o755);tmp.replace(dest)
 if shutil.which('restorecon'):run('restorecon',str(dest))
 network.STATE.mkdir(mode=0o700,exist_ok=True);network.RUN.mkdir(mode=0o700,exist_ok=True);network.selinux_setup()
 r['restrictedNetwork']=d.get('restrictedNetwork',False);write(ROOT/'receipt.json',json.dumps(r))
 firewall(r)
 config(d)
 write('/etc/systemd/system/xio-stack.service','''[Unit]
Description=XIO Xray and Shadowsocks gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
DynamicUser=yes
StateDirectory=xio-stack
StateDirectoryMode=0700
LoadCredential=config:/etc/xio-stack/config.json
ExecStart=/usr/local/bin/xio-stack %d/config /var/lib/xio-stack/stats.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
''',0o644)
 run('systemctl','daemon-reload');subprocess.run(['systemctl','reset-failed','xio-stack'],capture_output=True);run('systemctl','enable','--now','xio-stack');run('systemctl','restart','xio-stack');run('systemctl','is-active','--quiet','xio-stack')
 network.install(d);network.cloak_install(d)
 if not d.get('restrictedNetwork'):network.ike_install(d);mesh.install(d)
 d['stack']={'protocols':(['xray','cloak'] if d.get('restrictedNetwork') else ['xray','shadowsocks','openvpn','cloak','ikev2']),'publicKey':r['publicKey'],'shortId':r['shortId'],'serverName':r['serverName']}
def create(d,uid):
 u={'uuid':str(uuid.uuid4()),'ssKey':base64.b64encode(secrets.token_bytes(32)).decode()};d['users'][uid]['stack']=u;configs=network.create(d,uid)
 if not d.get('restrictedNetwork'):configs.update(network.ike_profile(d,uid))
 configs.update(network.cloak_profile(d,uid,configs['openvpn']))
 if d.get('restrictedNetwork'):configs.pop('openvpn',None)
 if d.get('mesh'):configs.update(mesh.create(d,uid))
 # Activate credentials only after every profile, including Cloak UID, exists.
 apply(d)
 return dict(profiles(d,uid),**configs)
def profiles(d,uid):
 r=receipt();u=d['users'][uid]['stack'];host=d['host']
 return {p:json.dumps({'protocol':p,'outbound':out}) for p,out in {'xray':{'protocol':'vless','settings':{'vnext':[{'address':host,'port':4443,'users':[{'id':u['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':r['serverName'],'fingerprint':'chrome','publicKey':r['publicKey'],'shortId':r['shortId']}}},'shadowsocks':{'protocol':'shadowsocks','settings':{'servers':[{'address':host,'port':8388,'method':'2022-blake3-aes-256-gcm','password':r['ssKey']+':'+u['ssKey']}]}}}.items() if not d.get('restrictedNetwork') or p!='shadowsocks'}
def stats():
 try:return json.loads((STATE/'stats.json').read_text())
 except FileNotFoundError:return {}
def remove(d):
 if not (ROOT/'receipt.json').exists():return
 r=receipt();mesh.remove();network.remove(d);subprocess.run(['systemctl','disable','--now','xio-stack'],capture_output=True);firewall(r,True)
 Path('/etc/systemd/system/xio-stack.service').unlink(missing_ok=True);Path('/usr/local/bin/xio-stack').unlink(missing_ok=True)
 shutil.rmtree(ROOT);shutil.rmtree(STATE,ignore_errors=True);shutil.rmtree('/var/lib/private/xio-stack',ignore_errors=True);run('systemctl','daemon-reload')
