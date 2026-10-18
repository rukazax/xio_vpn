#!/usr/bin/env python3
"""Private Headscale + owned Tailscale exit node; pinned verified upstream bins."""
import hashlib,io,ipaddress,json,os,secrets,shutil,socket,ssl,subprocess,tarfile,time,urllib.request
from pathlib import Path
ROOT=Path('/etc/xio-mesh');LIB=Path('/usr/local/lib/xio-mesh');STATE=Path('/var/lib/xio-mesh');RUN=Path('/run/xio-mesh');PKI=Path('/etc/xio-stack/pki');OWNER='xio-mesh-v1'
def run(*args,input=None):
 p=subprocess.run(args,input=input,capture_output=True,timeout=60)
 if p.returncode:raise RuntimeError('Mesh operation failed: '+args[0])
 return p.stdout
def write(p,text,mode=0o600):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.new');t.write_text(text);t.chmod(mode);t.replace(p)
def hs(*args):return json.loads(run(str(LIB/'headscale'),'-c',str(ROOT/'config.yaml'),'-o','json',*args))
def ts(*args):return run(str(LIB/'tailscale'),'--socket='+str(RUN/'tailscaled.sock'),*args)
def download(item,destination):
 temp=destination.with_suffix('.download');h=hashlib.sha256();total=0
 with urllib.request.urlopen(urllib.request.Request(item['url'],headers={'User-Agent':'XIO-installer/0.17'}),timeout=60) as response,temp.open('wb') as f:
  while data:=response.read(1024*1024):
   total+=len(data);assert total<=200*1024*1024,'Oversized upstream binary';h.update(data);f.write(data)
 assert h.hexdigest()==item['sha256'],'Upstream binary checksum mismatch';return temp

def binaries():
 pins=json.loads(Path(__file__).with_name('mesh-pins.json').read_text());record=ROOT/'binaries.json'
 try:installed=json.loads(record.read_text())
 except FileNotFoundError:installed={}
 for kind,item in pins.items():
  names=['headscale'] if kind=='headscale' else ['tailscale','tailscaled']
  if all((LIB/name).is_file() and installed.get(name)==hashlib.sha256((LIB/name).read_bytes()).hexdigest() for name in names):continue
  downloaded=download(item,LIB/kind)
  if kind=='headscale':downloaded.chmod(0o755);downloaded.replace(LIB/'headscale')
  else:
   with tarfile.open(downloaded) as tar:
    for name in names:
     member=next(m for m in tar.getmembers() if m.isfile() and Path(m.name).name==name);data=tar.extractfile(member).read();assert len(data)<150*1024*1024;temp=LIB/(name+'.new');temp.write_bytes(data);temp.chmod(0o755);temp.replace(LIB/name)
   downloaded.unlink()
  for name in names:installed[name]=hashlib.sha256((LIB/name).read_bytes()).hexdigest()
  write(record,json.dumps(installed))

def service(unit,start,extra=''):
 p=Path('/etc/systemd/system/'+unit+'.service')
 if p.exists():assert 'Description=XIO owned '+unit in p.read_text(),'Unowned mesh service'
 write(p,f'''[Unit]
Description=XIO owned {unit}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart={start}
Restart=on-failure
RestartSec=2
UMask=0077
RuntimeDirectory=xio-mesh
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/xio-mesh /run/xio-mesh
{extra}
[Install]
WantedBy=multi-user.target
''',0o644)

def install(d):
 if (ROOT/'receipt.json').exists():assert json.loads((ROOT/'receipt.json').read_text())['owner']==OWNER
 else:
  for p in [ROOT,LIB,STATE]:assert not p.exists(),'Unowned mesh directory'
  assert not Path('/var/run/tailscale/tailscaled.sock').exists(),'Existing Tailscale installation'
  for port,kind in [(18443,socket.SOCK_STREAM),(3478,socket.SOCK_DGRAM),(41641,socket.SOCK_DGRAM)]:
   sock=socket.socket(socket.AF_INET,kind)
   try:sock.bind(('0.0.0.0',port))
   finally:sock.close()
  for p in [ROOT,LIB,STATE]:p.mkdir(mode=0o700)
  write(ROOT/'receipt.json',json.dumps({'owner':OWNER}))
 binaries()
 RUN.mkdir(mode=0o700,exist_ok=True)
 if shutil.which('restorecon'):
  for path in [ROOT,STATE,RUN,LIB/'tailscaled']:run('restorecon','-RF',str(path))
 host=d['host'];host='['+host+']' if ':' in host else host;url='https://'+host+':18443'
 derp={'enabled':True,'region_id':999,'region_code':'xio','region_name':'XIO private relay','verify_clients':True,'stun_listen_addr':'0.0.0.0:3478','private_key_path':str(STATE/'derp.key'),'automatically_add_embedded_derp_region':True}
 try:
  ip=ipaddress.ip_address(d['host']);derp['ipv4' if ip.version==4 else 'ipv6']=str(ip)
 except ValueError:pass
 cfg={'server_url':url,'listen_addr':'0.0.0.0:18443','metrics_listen_addr':'127.0.0.1:18445','grpc_listen_addr':'127.0.0.1:18446','grpc_allow_insecure':False,'noise':{'private_key_path':str(STATE/'noise.key')},'prefixes':{'v4':'100.64.0.0/10','v6':'fd7a:115c:a1e0::/48','allocation':'sequential'},'derp':{'server':derp,'urls':[],'paths':[],'auto_update_enabled':False},'disable_check_updates':True,'database':{'type':'sqlite','sqlite':{'path':str(STATE/'db.sqlite'),'write_ahead_log':True}},'tls_cert_path':str(PKI/'server.crt'),'tls_key_path':str(PKI/'server.key'),'policy':{'mode':'file','path':str(ROOT/'policy.hujson')},'dns':{'magic_dns':False,'base_domain':'xio.internal','override_local_dns':False,'nameservers':{'global':[]}},'unix_socket':str(RUN/'headscale.sock'),'unix_socket_permission':'0600','log':{'format':'text','level':'error'}}
 write(ROOT/'config.yaml',json.dumps(cfg));write(ROOT/'policy.hujson',json.dumps({'acls':[{'action':'accept','src':['*'],'dst':['autogroup:internet:*']}]}))
 service('xio-headscale',str(LIB/'headscale')+' -c /etc/xio-mesh/config.yaml serve','CapabilityBoundingSet=\n')
 service('xio-tailscaled',str(LIB/'tailscaled')+' --state=/var/lib/xio-mesh/tailscaled.state --socket=/run/xio-mesh/tailscaled.sock --tun=xio-tailnet --port=41641','Environment=TS_NO_LOGS_NO_SUPPORT=true\nEnvironment=TS_LOGS_DIR=/var/lib/xio-mesh\nEnvironment=SSL_CERT_FILE=/etc/xio-stack/pki/ca.crt\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n')
 run('systemctl','daemon-reload')
 for unit in ['xio-headscale','xio-tailscaled']:run('systemctl','enable','--now',unit);run('systemctl','restart',unit)
 for i in range(100):
  try:users=hs('users','list') or [];break
  except Exception:
   if i==99:raise
   time.sleep(.2)
 owner=next((u for u in users if u['name']=='xio-exit'),None)
 if owner is None:owner=hs('users','create','xio-exit')
 status=json.loads(ts('status','--json'))
 if status.get('BackendState')!='Running':
  key=hs('preauthkeys','create','--user',str(owner['id']),'--expiration','1h')
  path=RUN/'exit.auth';write(path,key['key'])
  try:ts('up','--login-server='+url,'--auth-key=file:'+str(path),'--advertise-exit-node','--accept-dns=false','--accept-routes=false','--hostname=xio-exit','--reset','--timeout=25s')
  finally:path.unlink(missing_ok=True)
 nodes=hs('nodes','list') or [];node=next(n for n in nodes if int(n['user']['id'])==int(owner['id']))
 hs('nodes','approve-routes','--identifier',str(node['id']),'--routes','0.0.0.0/0,::/0')
 status=json.loads(ts('status','--json'));exit_ip=next(ip for ip in status['TailscaleIPs'] if ':' not in ip)
 d['mesh']={'controlURL':url,'exitNode':exit_ip}

def create(d,uid):
 user=hs('users','create','xio-'+uid);key=hs('preauthkeys','create','--user',str(user['id']),'--reusable','--expiration','8760h')
 d['users'][uid]['mesh']={'userId':user['id'],'keyId':key['id']}
 return {'tailscale':json.dumps({'protocol':'tailscale','controlURL':d['mesh']['controlURL'],'controlCA':(PKI/'ca.crt').read_text(),'exitNode':d['mesh']['exitNode'],'authKey':key['key'],'hostname':'xio-'+uid[:12]})}
def revoke(d,uid):
 user=d['users'][uid].get('mesh')
 if not user:return
 hs('preauthkeys','expire','--id',str(user['keyId']))
 for node in hs('nodes','list') or []:
  if int(node['user']['id'])==int(user['userId']):hs('nodes','delete','--identifier',str(node['id']),'--force')
 hs('users','destroy','--identifier',str(user['userId']),'--force')
def stats(d):
 path=ROOT/'statistics.json'
 try:state=json.loads(path.read_text())
 except FileNotFoundError:state={}
 status=json.loads(ts('status','--json'));generation=run('systemctl','show','xio-tailscaled','--property=InvocationID','--value').decode().strip();now=int(time.time());month=time.strftime('%Y-%m',time.gmtime())
 for uid,user in d['users'].items():
  if not user.get('mesh') or user.get('revoked'):continue
  peers=[p for p in (status.get('Peer') or {}).values() if int(p.get('UserID',-1))==int(user['mesh']['userId'])];rx=sum(p.get('RxBytes',0) for p in peers);tx=sum(p.get('TxBytes',0) for p in peers)
  s=state.setdefault(uid,{'rx':0,'tx':0});dr=rx if s.get('generation')!=generation or rx<s.get('lastRx',0) else rx-s.get('lastRx',0);dt=tx if s.get('generation')!=generation or tx<s.get('lastTx',0) else tx-s.get('lastTx',0)
  if s.get('month')!=month:s['month']=month;s['monthBytes']=0
  s['rx']+=dr;s['tx']+=dt;s['monthBytes']+=dr+dt;s.update(lastRx=rx,lastTx=tx,generation=generation,online=any(p.get('Online') for p in peers),sampledAt=now)
 write(path,json.dumps(state));return state

def remove():
 if not (ROOT/'receipt.json').exists():return
 assert json.loads((ROOT/'receipt.json').read_text())['owner']==OWNER
 try:ts('down')
 except Exception:pass
 for unit in ['xio-headscale','xio-tailscaled']:
  subprocess.run(['systemctl','disable','--now',unit],capture_output=True);Path('/etc/systemd/system/'+unit+'.service').unlink(missing_ok=True)
 subprocess.run([str(LIB/'tailscaled'),'--cleanup'],capture_output=True)
 for p in [ROOT,LIB,STATE,RUN]:shutil.rmtree(p,ignore_errors=True)
 run('systemctl','daemon-reload')
