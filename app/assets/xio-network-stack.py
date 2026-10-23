#!/usr/bin/env python3
"""Owned OpenVPN/Cloak/IPsec services. No existing daemons or PKI modified."""
import base64,ipaddress,json,os,re,secrets,shutil,socket,subprocess,tempfile,time
from pathlib import Path
ROOT=Path('/etc/xio-stack');PKI=ROOT/'pki';RUN=Path('/run/xio-openvpn');STATE=Path('/var/lib/xio-network')
def dualstack():
 import importlib.util
 spec=importlib.util.spec_from_file_location('xio_dualstack',str(Path(__file__).with_name('dualstack.py')))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def run(*args,input=None):
 p=subprocess.run(args,input=input,capture_output=True)
 if p.returncode:raise RuntimeError('Network stack operation failed: '+args[0])
 return p.stdout
def write(p,text,mode=0o600):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.new');t.write_text(text);t.chmod(mode);t.replace(p)
def pki(d):
 if (PKI/'ca.crt').exists():return
 PKI.mkdir(mode=0o700);(PKI/'certs').mkdir(mode=0o700);(PKI/'index').write_text('');(PKI/'serial').write_text('1000\n');(PKI/'crlnumber').write_text('1000\n')
 write(PKI/'ca.cnf',f'''[ca]
default_ca = xio
[xio]
dir = {PKI}
database = $dir/index
new_certs_dir = $dir/certs
certificate = $dir/ca.crt
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 730
default_crl_days = 365
policy = policy
unique_subject = no
[policy]
commonName = supplied
[client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = {('IP:' if _is_ip(d['host']) else 'DNS:')+d['host']}
''')
 run('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',str(PKI/'ca.key'))
 run('openssl','req','-new','-x509','-sha256','-days','3650','-key',str(PKI/'ca.key'),'-out',str(PKI/'ca.crt'),'-subj','/CN=XIO private VPN CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
 run('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',str(PKI/'server.key'))
 run('openssl','req','-new','-key',str(PKI/'server.key'),'-out',str(PKI/'server.csr'),'-subj','/CN=XIO VPN server')
 run('openssl','ca','-batch','-notext','-config',str(PKI/'ca.cnf'),'-extensions','server','-in',str(PKI/'server.csr'),'-out',str(PKI/'server.crt'))
 run('openssl','ca','-batch','-config',str(PKI/'ca.cnf'),'-gencrl','-out',str(PKI/'crl.pem'))
 (PKI/'server.csr').unlink()
def _is_ip(s):
 try:ipaddress.ip_address(s);return True
 except ValueError:return False
def firewall(d,remove=False):
 for subnet,tun in [('10.80.0.0/24','xioovpn0'),('10.81.0.0/24','xioovpn1'),('10.82.0.0/24',None)]:
  rules=[['-t','nat','POSTROUTING','-s',subnet,'-o',d['outbound'],'-m','comment','--comment','xio-stack-net-v1','-j','MASQUERADE'],['FORWARD','-s',subnet,'-o',d['outbound'],'-m','comment','--comment','xio-stack-net-v1','-j','ACCEPT'],['FORWARD','-d',subnet,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-m','comment','--comment','xio-stack-net-v1','-j','ACCEPT']]
  for rule in rules:
   table=[]
   if rule[:2]==['-t','nat']:table=rule[:2];rule=rule[2:]
   exists=subprocess.run(['iptables','-w','5',*table,'-C',*rule],capture_output=True).returncode==0
   if remove and exists:run('iptables','-w','5',*table,'-D',*rule)
   elif not remove and not exists:run('iptables','-w','5',*table,'-I',*rule)
def openvpn_configs():
 for transport,proto,subnet,device in [('udp','udp','10.80.0.0','xioovpn0'),('tcp','tcp-server','10.81.0.0','xioovpn1')]:
  v6=transport=='tcp' and dualstack().ipv6_ready()
  v6push='push \"redirect-gateway ipv6\"\npush \"dhcp-option DNS6 2620:fe::fe\"' if v6 else ''
  write(ROOT/(transport+'.ovpn'),f'''port {1194 if transport=='udp' else 1195}
proto {proto}
{'local 127.0.0.1' if transport=='tcp' else ''}
dev {device}
dev-type tun
topology subnet
server {subnet} 255.255.255.0
{('server-ipv6 fd80:1::/64' if v6 else '')}
ca {PKI}/ca.crt
cert {PKI}/server.crt
key {PKI}/server.key
dh none
crl-verify {PKI}/crl.pem
tls-crypt-v2 {ROOT}/tls-crypt-v2.key
tls-version-min 1.2
remote-cert-tls client
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
allow-compression no
keepalive 10 60
persist-key
persist-tun
push "redirect-gateway def1"
push "dhcp-option DNS 9.9.9.9"
{v6push}
status {STATE}/openvpn-{transport}.status 5
status-version 3
management {RUN}/{transport}.sock unix
verb 0
''')
def service(name,exec_start,extra=''):
 write('/etc/systemd/system/'+name+'.service',f'''[Unit]
Description=XIO managed {name}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=2
UMask=0077
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/xio-network /run/xio-openvpn
RuntimeDirectory=xio-openvpn
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
{extra}
[Install]
WantedBy=multi-user.target
''',0o644)
def apparmor(remove=False):
 if not shutil.which('apparmor_parser'):return
 begin='# BEGIN XIO STACK\n';end='# END XIO STACK\n'
 rules=' /etc/xio-stack/ r,\n /etc/xio-stack/** r,\n /var/lib/xio-network/ rw,\n /var/lib/xio-network/** rwk,\n /run/xio-openvpn/ rw,\n /run/xio-openvpn/** rw,\n'
 for name in ['usr.lib.ipsec.charon','usr.sbin.swanctl','usr.sbin.openvpn']:
  base=Path('/etc/apparmor.d')/name;local=Path('/etc/apparmor.d/local')/name
  if not base.exists() or '<local/'+name+'>' not in base.read_text():continue
  text=local.read_text() if local.exists() else ''
  if begin in text:
   assert text.count(begin)==1 and text.count(end)==1,'Unrecognized XIO AppArmor marker'
   text=text[:text.index(begin)]+text[text.index(end)+len(end):]
  if not remove:text+=('\n' if text and not text.endswith('\n') else '')+begin+rules+end
  write(local,text,0o644);run('apparmor_parser','-r',str(base))

def selinux_setup(remove=False):
 if not shutil.which('getenforce') or run('getenforce').decode().strip()=='Disabled':return
 receipt=ROOT/'receipt.json';r=json.loads(receipt.read_text())
 specs=[('/etc/xio-stack(/.*)?','xio_stack_etc_t'),('/var/lib/xio-network(/.*)?','xio_stack_state_t'),('/var/run/xio-openvpn(/.*)?','xio_stack_run_t'),('/etc/xio-mesh(/.*)?','xio_stack_etc_t'),('/var/lib/xio-mesh(/.*)?','xio_stack_state_t'),('/var/run/xio-mesh(/.*)?','xio_stack_run_t'),('/usr/local/lib/xio-mesh/tailscaled','openvpn_exec_t')]
 if remove:
  if not r.get('selinuxModule'):return
  for path in r.get('selinuxFcontexts',[item[0] for item in specs] if not r.get('selinuxReceiptVersion') else []):run('semanage','fcontext','-d',path)
  if r.get('selinuxPort',not r.get('selinuxReceiptVersion')):run('semanage','port','-d','-p','tcp','1195')
  for path in [ROOT,STATE,RUN]:
   if path.exists():run('restorecon','-RF',str(path))
  run('semodule','-r','xio_stack');return
 policy='''module xio_stack 1.0;
require {
 type init_t;
 type iptables_t;
 type iptables_exec_t;
 type sysctl_fs_t;
 type sysctl_t;
 type etc_t;
 type NetworkManager_etc_t;
 type bin_t;
 type binfmt_misc_fs_t;
 type sysctl_net_t;
 type openvpn_t;
 type ipsec_t;
 type ipsec_mgmt_t;
 attribute file_type;
 attribute port_type;
 class dir { read write getattr search open add_name remove_name mounton watch watch_reads };
 class file { create read write getattr setattr lock append unlink open rename ioctl map execute };
 class lnk_file { getattr read };
 class sock_file { create read write getattr setattr unlink open };
 class unix_stream_socket { connectto };
 class tcp_socket { name_bind };
 class process2 { nnp_transition };
 class process { transition };
 class fifo_file {read write open getattr ioctl};
 class netlink_generic_socket {create bind read write getattr getopt setopt ioctl};
 class netlink_netfilter_socket {create bind read write getattr getopt setopt ioctl};
}
type xio_stack_etc_t;
typeattribute xio_stack_etc_t file_type;
type xio_stack_state_t;
typeattribute xio_stack_state_t file_type;
type xio_stack_run_t;
typeattribute xio_stack_run_t file_type;
type xio_stack_port_t;
typeattribute xio_stack_port_t port_type;
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_etc_t:dir {read getattr search open};
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_etc_t:file {read getattr open ioctl};
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_etc_t:lnk_file {getattr read};
allow {init_t openvpn_t ipsec_t} xio_stack_state_t:dir {read write getattr search open add_name remove_name};
allow {init_t openvpn_t ipsec_t} xio_stack_state_t:file {create read write getattr setattr lock append unlink open rename ioctl map};
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_run_t:dir {read write getattr search open add_name remove_name};
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_run_t:file {create read write getattr setattr lock append unlink open rename ioctl};
allow {init_t openvpn_t ipsec_t ipsec_mgmt_t} xio_stack_run_t:sock_file {create read write getattr setattr unlink open};
allow ipsec_mgmt_t ipsec_t:unix_stream_socket connectto;
allow openvpn_t xio_stack_port_t:tcp_socket name_bind;
allow init_t {openvpn_t ipsec_t ipsec_mgmt_t}:process2 nnp_transition;
allow openvpn_t iptables_t:process2 nnp_transition;
allow openvpn_t iptables_t:process transition;
type_transition openvpn_t iptables_exec_t:process iptables_t;
allow openvpn_t iptables_exec_t:file {read open getattr execute};
allow openvpn_t self:netlink_generic_socket {create bind read write getattr getopt setopt ioctl};
allow openvpn_t self:netlink_netfilter_socket {create bind read write getattr getopt setopt ioctl};
allow openvpn_t {sysctl_fs_t sysctl_t}:dir {read search open getattr};
allow openvpn_t sysctl_fs_t:file {read open getattr};
allow openvpn_t {etc_t bin_t}:dir {watch watch_reads};
allow openvpn_t NetworkManager_etc_t:dir {getattr search read open watch watch_reads};
allow openvpn_t binfmt_misc_fs_t:dir search;
allow openvpn_t sysctl_net_t:file {read write open getattr};
allow iptables_t openvpn_t:fifo_file {read write open getattr ioctl};
allow init_t {xio_stack_run_t xio_stack_state_t xio_stack_etc_t}:dir {read write getattr search open add_name remove_name mounton};
allow init_t xio_stack_run_t:file {create read write getattr setattr lock append unlink open rename ioctl};
'''
 write(ROOT/'xio_stack.te',policy);run('checkmodule','-M','-m','-o',str(ROOT/'xio_stack.mod'),str(ROOT/'xio_stack.te'));run('semodule_package','-o',str(ROOT/'xio_stack.pp'),'-m',str(ROOT/'xio_stack.mod'));run('semodule','-i',str(ROOT/'xio_stack.pp'))
 if not r.get('selinuxModule'):
  r.update(selinuxModule=True,selinuxReceiptVersion=2,selinuxFcontexts=[],selinuxPort=False);write(receipt,json.dumps(r))
 if r.get('selinuxReceiptVersion')==2:
  for path,kind in specs:
   if path not in r['selinuxFcontexts']:
    existing=run('semanage','fcontext','-l','-C').decode()
    if not any(line.split() and line.split()[0]==path and ':'+kind+':' in line for line in existing.splitlines()):run('semanage','fcontext','-a','-t',kind,path)
    r['selinuxFcontexts'].append(path);write(receipt,json.dumps(r))
  if not r.get('selinuxPort'):
   existing=run('semanage','port','-l','-C').decode()
   if not any(line.split()[:2]==['xio_stack_port_t','tcp'] and '1195' in line.split()[2:] for line in existing.splitlines()):run('semanage','port','-a','-t','xio_stack_port_t','-p','tcp','1195')
   r['selinuxPort']=True;write(receipt,json.dumps(r))
 for path in [ROOT,STATE,RUN]:run('restorecon','-RF',str(path))

def install(d):
 apparmor()
 if 'strongswan-starter' in d.get('packagesAdded',[]):subprocess.run(['systemctl','disable','--now','strongswan-starter'],capture_output=True)
 STATE.mkdir(mode=0o700,exist_ok=True);RUN.mkdir(mode=0o700,exist_ok=True);selinux_setup()
 for port,kind,unit in [(1194,socket.SOCK_DGRAM,'xio-openvpn-udp'),(1195,socket.SOCK_STREAM,'xio-openvpn-tcp'),(500,socket.SOCK_DGRAM,'xio-ikev2'),(4500,socket.SOCK_DGRAM,'xio-ikev2'),(9443,socket.SOCK_STREAM,'xio-cloak')]:
  if d.get('restrictedNetwork') and unit not in ['xio-openvpn-tcp','xio-cloak']:continue
  service_file=Path('/etc/systemd/system/'+unit+'.service')
  if service_file.exists():assert 'Description=XIO managed '+unit in service_file.read_text(),'Unowned VPN service'
  else:
   sock=socket.socket(socket.AF_INET,kind)
   try:sock.bind(('0.0.0.0',port))
   finally:sock.close()
 pki(d)
 if not (ROOT/'tls-crypt-v2.key').exists():run('openvpn','--genkey','tls-crypt-v2-server',str(ROOT/'tls-crypt-v2.key'))
 openvpn_configs()
 for transport in (['tcp'] if d.get('restrictedNetwork') else ['udp','tcp']):service('xio-openvpn-'+transport,shutil.which('openvpn')+' --config '+str(ROOT/(transport+'.ovpn')),'ExecStartPre=+'+shutil.which('python3')+' /usr/local/lib/x1o-managed/network_stack.py firewall\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n')
 firewall(d);run('systemctl','daemon-reload')
 for unit in (['xio-openvpn-tcp'] if d.get('restrictedNetwork') else ['xio-openvpn-udp','xio-openvpn-tcp']):run('systemctl','enable','--now',unit);run('systemctl','restart',unit);run('systemctl','is-active','--quiet',unit)
def create(d,uid):
 pki(d)
 with tempfile.TemporaryDirectory(prefix='client-',dir=ROOT) as temp:
  temp=Path(temp);key=temp/'key.pem';csr=temp/'request.pem';cert=temp/'cert.pem';tls=temp/'tls.key'
  run('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',str(key))
  run('openssl','req','-new','-key',str(key),'-out',str(csr),'-subj','/CN='+uid)
  run('openssl','ca','-batch','-notext','-config',str(PKI/'ca.cnf'),'-extensions','client','-in',str(csr),'-out',str(cert))
  run('openvpn','--tls-crypt-v2',str(ROOT/'tls-crypt-v2.key'),'--genkey','tls-crypt-v2-client',str(tls))
  # Keep only the public certificate for CRL revocation. Client key is returned
  # once over SSH, then deleted with the private temporary directory.
  write(ROOT/(uid+'.crt'),cert.read_text())
  cfg=f'''client
dev tun
proto udp
remote {d['host']} 1194
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM
allow-compression no
<ca>
{(PKI/'ca.crt').read_text()}</ca>
<cert>
{cert.read_text()}</cert>
<key>
{key.read_text()}</key>
<tls-crypt-v2>
{tls.read_text()}</tls-crypt-v2>
'''
  d['users'][uid]['stack']['openvpn']=True
  return {'openvpn':json.dumps({'protocol':'openvpn','config':cfg,'username':'','password':''})}
def revoke(d,uid):
 if d['users'][uid].get('stack',{}).get('ikePassword'):
  for sa in ike_sas():
   if ike_identity(sa)==uid+'@xio':run('swanctl','--terminate','--ike-id',str(int(sa['uniqueid'])),'--uri','unix://'+str(RUN/'charon.vici'))

 cert=ROOT/(uid+'.crt')
 if cert.exists():
  run('openssl','ca','-batch','-config',str(PKI/'ca.cnf'),'-revoke',str(cert));run('openssl','ca','-batch','-config',str(PKI/'ca.cnf'),'-gencrl','-out',str(PKI/'crl.pem'));cert.unlink()
 for transport in ['udp','tcp']:
  path=RUN/(transport+'.sock')
  if not path.exists():continue
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2)
  try:s.connect(str(path));s.sendall(('kill '+uid+'\nquit\n').encode());s.recv(4096)
  except OSError:pass
  finally:s.close()
def ike_sas():
 import importlib.util,sys
 path=Path(__file__).with_name('xio_vici')
 if 'xio_vici' not in sys.modules:
  spec=importlib.util.spec_from_file_location('xio_vici',path/'__init__.py',submodule_search_locations=[str(path)]);module=importlib.util.module_from_spec(spec);sys.modules['xio_vici']=module;spec.loader.exec_module(module)
 import xio_vici
 sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(2)
 try:
  sock.connect(str(RUN/'charon.vici'));session=xio_vici.Session(sock);return [sa for event in session.list_sas() for sa in event.values()]
 finally:sock.close()
def ike_identity(sa):
 value=sa.get('remote-eap-id',sa.get('remote-id',b''))
 return value.decode() if isinstance(value,bytes) else str(value)
def ike_sample(d,state,month,now):
 try:sas=ike_sas()
 except (OSError,ValueError):return
 generation=run('systemctl','show','xio-ikev2','--property=InvocationID','--value').decode().strip()
 for sa in sas:
  identity=ike_identity(sa);uid=identity.removesuffix('@xio');u=d['users'].get(uid)
  if identity!=uid+'@xio' or not u or u.get('revoked') or sa.get('state')!=b'ESTABLISHED':continue
  record=state.setdefault(uid,{'rx':0,'tx':0});samples=record.setdefault('ikeSamples',{})
  if record.get('month')!=month:record['month']=month;record['monthBytes']=0
  for child in sa.get('child-sas',{}).values():
   key=generation+':'+str(sa.get('uniqueid'))+':'+str(child.get('uniqueid'));rx=int(child.get('bytes-in',0));tx=int(child.get('bytes-out',0));old=samples.get(key,{})
   dr=rx-old.get('rx',0) if rx>=old.get('rx',0) else rx;dt=tx-old.get('tx',0) if tx>=old.get('tx',0) else tx
   record['rx']+=dr;record['tx']+=dt;record['monthBytes']+=dr+dt;samples[key]={'rx':rx,'tx':tx,'seen':now}
  record['online']=True;record['sampledAt']=now
  record['ikeSamples']={k:v for k,v in samples.items() if now-v.get('seen',0)<86400}

def stats(d):
 path=ROOT/'network-statistics.json'
 try:state=json.loads(path.read_text())
 except FileNotFoundError:state={}
 month=time.strftime('%Y-%m',time.gmtime());now=int(time.time())
 for record in state.values():record['online']=False
 for transport in ['udp','tcp']:
  p=STATE/('openvpn-'+transport+'.status')
  if not p.exists() or time.time()-p.stat().st_mtime>20:continue
  generation=run('systemctl','show','xio-openvpn-'+transport,'--property=InvocationID','--value').decode().strip()
  header=None
  for line in p.read_text().splitlines():
   fields=line.split('\t')
   if fields[:2]==['HEADER','CLIENT_LIST']:header=fields[2:]
   if fields[0]!='CLIENT_LIST' or not header:continue
   data=dict(zip(header,fields[1:]));uid=data.get('Common Name','');u=d['users'].get(uid)
   if not u or u.get('revoked'):continue
   record=state.setdefault(uid,{'rx':0,'tx':0});old=record.setdefault(transport,{})
   session=generation+':'+data.get('Connected Since (time_t)',data.get('Connected Since',''))
   rx=int(data.get('Bytes Received',0));tx=int(data.get('Bytes Sent',0))
   dr=rx if old.get('generation')!=session or rx<old.get('rx',0) else rx-old.get('rx',0);dt=tx if old.get('generation')!=session or tx<old.get('tx',0) else tx-old.get('tx',0)
   if record.get('month')!=month:record['month']=month;record['monthBytes']=0
   record['rx']+=dr;record['tx']+=dt;record['monthBytes']+=dr+dt;record['online']=True;record['sampledAt']=now;record[transport]={'generation':session,'rx':rx,'tx':tx}
 ike_sample(d,state,month,now)
 write(path,json.dumps(state));return state
def ike_config(d):
 if not (PKI/'ike-server.crt').exists():
  run('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(PKI/'ike-server.key'))
  run('openssl','req','-new','-key',str(PKI/'ike-server.key'),'-out',str(PKI/'ike-server.csr'),'-subj','/CN=XIO IKEv2 server')
  run('openssl','ca','-batch','-notext','-config',str(PKI/'ca.cnf'),'-extensions','server','-in',str(PKI/'ike-server.csr'),'-out',str(PKI/'ike-server.crt'))
  (PKI/'ike-server.csr').unlink()
 for directory,name,target in [('private','ike-server.pem',PKI/'ike-server.key'),('x509','ike-server.pem',PKI/'ike-server.crt'),('x509ca','ca.pem',PKI/'ca.crt')]:
  path=ROOT/directory;path.mkdir(mode=0o700,exist_ok=True);link=path/name
  if not link.exists():link.symlink_to(target)
 secrets_text='\n'.join(' eap-'+uid+' {\n  id = "'+uid+'@xio"\n  secret = "'+u['stack']['ikePassword']+'"\n }' for uid,u in d['users'].items() if not u.get('revoked') and u.get('stack',{}).get('ikePassword'))
 write(ROOT/'strongswan.conf','''charon {
 load_modular = no
 load = random nonce x509 pubkey pkcs1 pkcs8 pem openssl sha2 hmac kdf aes gcm kernel-netlink socket-default vici eap-identity eap-mschapv2
 plugins {
  include '''+('/etc/strongswan.d/charon/*.conf' if Path('/etc/strongswan.d/charon').exists() else '/etc/strongswan/strongswan.d/charon/*.conf')+'''

  vici {
   socket = unix:///run/charon.vici
  }
 }
 interfaces_use = '''+d['outbound']+'''
 syslog {
  daemon {
   default = 0
  }
  auth {
   default = 0
  }
 }
}
''')
 write(ROOT/'swanctl.conf',f'''connections {{
 xio {{
  version = 2
  local_addrs = 0.0.0.0
  pools = xio
  proposals = aes256gcm16-prfsha384-ecp384,aes128gcm16-prfsha256-ecp256,aes256-sha256-modp2048
  send_cert = always
  fragmentation = yes
  mobike = yes
  dpd_delay = 30s
  local {{
   auth = pubkey
   id = {d['host']}
   certs = {PKI}/ike-server.crt
  }}
  remote {{
   auth = eap-mschapv2
   eap_id = %any
   id = %any
  }}
  children {{
   internet {{
    local_ts = 0.0.0.0/0
    remote_ts = dynamic
    esp_proposals = aes256gcm16,aes128gcm16,aes256-sha256
    dpd_action = clear
    rekey_time = 1h
   }}
  }}
 }}
}}
pools {{
 xio {{
  addrs = 10.82.0.2-10.82.0.254
  dns = 9.9.9.9
 }}
}}
authorities {{
 xio {{
  cacert = {PKI}/ca.crt
 }}
}}
secrets {{
{secrets_text}
}}
''')
def load_ike():
 socket_path=Path('/run/charon.vici') if os.environ.get('XIO_IKE_NAMESPACE')=='1' else RUN/'charon.vici'
 for i in range(30):
  if socket_path.exists():break
  time.sleep(.1)
 run('swanctl','--load-creds','--clear','--file',str(ROOT/'swanctl.conf'),'--uri','unix://'+str(socket_path))
 run('swanctl','--load-all','--file',str(ROOT/'swanctl.conf'),'--uri','unix://'+str(socket_path))
def ike_install(d):
 # RPM packages compile charon with /run/strongswan, Debian uses /run.
 (RUN/"strongswan").mkdir(mode=0o700,exist_ok=True)
 if shutil.which("restorecon"):run("restorecon","-RF",str(RUN))
 ike_config(d)
 charon=next((p for p in ['/usr/lib/ipsec/charon','/usr/libexec/strongswan/charon'] if Path(p).exists()),None)
 assert charon,'StrongSwan daemon missing'
 service('xio-ikev2',charon,'Environment=STRONGSWAN_CONF=/etc/xio-stack/strongswan.conf\nEnvironment=XIO_IKE_NAMESPACE=1\nBindPaths=/run/xio-openvpn:/run\nReadWritePaths=/run\nExecStartPost='+shutil.which('python3')+' /usr/local/lib/x1o-managed/network_stack.py load-ike\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_IPC_LOCK CAP_DAC_OVERRIDE CAP_AUDIT_WRITE\n')
 run('systemctl','daemon-reload');run('systemctl','enable','--now','xio-ikev2');run('systemctl','restart','xio-ikev2');run('systemctl','is-active','--quiet','xio-ikev2')
def ike_profile(d,uid):
 u=d['users'][uid]['stack'];u['ikePassword']=secrets.token_urlsafe(32);ike_config(d);load_ike()
 return {'ikev2':json.dumps({'protocol':'ikev2','server':d['host'],'identity':uid+'@xio','username':uid+'@xio','password':u['ikePassword'],'ca':(PKI/'ca.crt').read_text()})}

def cloak_config(d):
 receipt=ROOT/'receipt.json';r=json.loads(receipt.read_text())
 if 'cloakPrivateKey' not in r:
  der=run('openssl','genpkey','-algorithm','X25519','-outform','DER');pub=run('openssl','pkey','-inform','DER','-pubout','-outform','DER',input=der)
  r['cloakPrivateKey']=base64.b64encode(der[-32:]).decode();r['cloakPublicKey']=base64.b64encode(pub[-32:]).decode();write(receipt,json.dumps(r))
 cfg={'ProxyBook':{'openvpn':['tcp','127.0.0.1:1195']},'BindAddr':['[::]:9443' if dualstack().listener()=='::' else '0.0.0.0:9443'],'BypassUID':[u['stack']['cloakUID'] for u in d['users'].values() if not u.get('revoked') and u.get('stack',{}).get('cloakUID')],'PrivateKey':r['cloakPrivateKey'],'RedirAddr':r['target']}
 write(ROOT/'cloak.json',json.dumps(cfg))
def cloak_install(d):
 cloak_config(d);dest=Path('/usr/local/bin/xio-cloak');temp=dest.with_suffix('.new');shutil.copyfile('/usr/local/lib/x1o-managed/cloak',temp);temp.chmod(0o755);temp.replace(dest)
 if shutil.which('restorecon'):run('restorecon',str(dest))
 service('xio-cloak',str(dest)+' -c /etc/xio-stack/cloak.json -verbosity error','CapabilityBoundingSet=\n')
 run('systemctl','daemon-reload');subprocess.run(['systemctl','reset-failed','xio-cloak'],capture_output=True);run('systemctl','enable','--now','xio-cloak');run('systemctl','restart','xio-cloak');run('systemctl','is-active','--quiet','xio-cloak')
def cloak_profile(d,uid,openvpn):
 u=d['users'][uid]['stack'];u['cloakUID']=base64.b64encode(secrets.token_bytes(16)).decode();r=json.loads((ROOT/'receipt.json').read_text());p=json.loads(openvpn)
 p.update(protocol='cloak',cloak={'UID':u['cloakUID'],'PublicKey':r['cloakPublicKey'],'ServerName':r['serverName'],'RemoteHost':d['host'],'RemotePort':'9443','ProxyMethod':'openvpn','EncryptionMethod':'aes-gcm','Transport':'direct','BrowserSig':'chrome','NumConn':1})
 p['config']=p['config'].replace('proto udp\n','proto tcp-client\n').replace('remote '+d['host']+' 1194\n','remote '+d['host']+' 9443\n')
 # The enclosing committed stack.apply activates this user once.
 return {'cloak':json.dumps(p)}

def remove(d):
 for unit in ['xio-openvpn-udp','xio-openvpn-tcp','xio-cloak','xio-ikev2']:
  p=Path('/etc/systemd/system/'+unit+'.service')
  if p.exists():subprocess.run(['systemctl','disable','--now',unit],capture_output=True);p.unlink()
 Path('/usr/local/bin/xio-cloak').unlink(missing_ok=True)
 apparmor(True);selinux_setup(True)
 firewall(d,True);shutil.rmtree(RUN,ignore_errors=True);shutil.rmtree(STATE,ignore_errors=True);run('systemctl','daemon-reload')

if __name__=='__main__':
 import sys
 if sys.argv[1:]==['load-ike']:load_ike()
 elif sys.argv[1:]==['firewall']:firewall(json.loads(Path('/etc/x1o-managed/deployment.json').read_text()))
