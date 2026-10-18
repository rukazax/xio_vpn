# Disposable VM-only packet test; never run against the user's live VPS.
import importlib.util,subprocess,json,socket,time,base64,os
assert socket.gethostname().startswith('xio014-')
spec=importlib.util.spec_from_file_location('a','/usr/local/lib/x1o-managed/admin.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);d=m.load()
def run(*args,input=None):
 p=subprocess.run(args,input=input,text=True,capture_output=True);assert p.returncode==0,(args[0],p.stderr[:300]);return p.stdout.strip()
private={p:run('wg','genkey') for p in ['wireguard','awg']};pub={p:run('wg','pubkey',input=k+'\n') for p,k in private.items()}
result=m.dispatch({'action':'add','serverId':d['id'],'id':'14'*16,'name':'QA lab','publicKeys':pub});slot=result['user']['slot'];server=result['server'];endpoint=run('ip','-4','-o','addr','show','dev',d['outbound']).split()[3].split('/')[0];web=socket.gethostbyname('example.com');child=None
run('ip','netns','add','xio-qa');run('ip','link','add','qt-host','type','veth','peer','name','qt-client');run('ip','link','set','qt-client','netns','xio-qa');run('ip','addr','add','172.31.25.1/24','dev','qt-host');run('ip','link','set','qt-host','up')
ns=['ip','netns','exec','xio-qa'];run(*ns,'ip','addr','add','172.31.25.2/24','dev','qt-client');run(*ns,'ip','link','set','qt-client','up');run(*ns,'ip','link','set','lo','up');run(*ns,'ip','route','add',endpoint+'/32','via','172.31.25.1')
# A temporary allow only on the isolated test veth; the public XIO port rules are untouched.
rule=['INPUT','-i','qt-host','-p','udp','-m','multiport','--dports','51820,51821','-m','comment','--comment','xio-qa-lab','-j','ACCEPT'];run('iptables','-I',*rule)
results={}
try:
 for proto in ['wireguard','awg']:
  iface='wgqa' if proto=='wireguard' else 'awgqa'
  if proto=='wireguard':
   run(*ns,'ip','link','add',iface,'type','wireguard');run(*ns,'wg','set',iface,'private-key','/dev/stdin','peer',server['publicKeys'][proto],'endpoint',endpoint+':51820','allowed-ips','0.0.0.0/0',input=private[proto]+'\n')
  else:
   child=subprocess.Popen(ns+['/usr/local/bin/xio-amneziawg-go','-f',iface],env=dict(os.environ,LOG_LEVEL='error'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   path='/run/amneziawg/'+iface+'.sock'
   for _ in range(50):
    if os.path.exists(path):break
    time.sleep(.1)
   lines=['set=1','private_key='+base64.b64decode(private[proto]).hex()]+[k.lower()+'='+str(v) for k,v in server['awg'].items()]+['public_key='+base64.b64decode(server['publicKeys'][proto]).hex(),'endpoint='+endpoint+':51821','allowed_ip=0.0.0.0/0','persistent_keepalive_interval=25']
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
    sock.connect(path);sock.sendall(('\n'.join(lines)+'\n\n').encode());assert b'errno=0' in sock.recv(1024)
  subnet='77' if proto=='wireguard' else '78';run(*ns,'ip','addr','add',f'10.{subnet}.0.{slot}/32','dev',iface);run(*ns,'ip','link','set',iface,'mtu','1280','up');run(*ns,'ip','route','add','default','dev',iface)
  code=run(*ns,'curl','--max-time','20','--resolve','example.com:443:'+web,'-s','-o','/dev/null','-w','%{http_code}','https://example.com');assert code=='200',code
  stats=m.counters()[(proto,pub[proto])];assert stats[0]>0 and stats[1]>0 and stats[2]>0;results[proto]={'http':int(code),'rx':stats[0],'tx':stats[1],'handshake':stats[2]}
  run(*ns,'ip','link','delete',iface)
  if child:child.terminate();child.wait(timeout=5);child=None
finally:
 if child:child.terminate();child.wait(timeout=5)
 run('ip','netns','delete','xio-qa');run('ip','link','delete','qt-host');run('iptables','-D',*rule)
print(json.dumps(results))
