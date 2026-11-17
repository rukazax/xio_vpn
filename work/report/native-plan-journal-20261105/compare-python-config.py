import base64,hashlib,importlib.util,json,sys
from pathlib import Path
p=Path(sys.argv[1]) if len(sys.argv)>1 else Path(r'C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-native-connector-20261105\server\managed\cascade_native.py')
s=importlib.util.spec_from_file_location('tested_connector',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
b64=lambda x:base64.b64encode(bytes.fromhex(x)).decode()
publics={'bridge':b64('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'),'exit':b64('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')}
hops={'bridge':{'ipv4':'10.204.241.2','ipv6':'fd42:204:241::2'},'exit':{'ipv4':'10.204.241.1','ipv6':'fd42:204:241::1'}}
result={}
for role in ['bridge','exit']:
    peer='exit' if role=='bridge' else 'bridge'
    config={'schema':1,'enabled':True,'ownerOptIn':True,'role':role,'backend':'userspace','interface':'xiocascade0','ingresses':{'awg':{'interface':'xioawg0','ipv4':'10.78.0.0/24','ipv6':'fd78:1::/64'},'rivet':{'interface':'xiorivet','ipv4':'10.79.0.0/24','ipv6':'fd79:1::/64'}},'innerFamilies':['ipv4','ipv6'],'sourceMode':'hop-snat','localAddresses':hops[role],'peerAddresses':hops[peer],'peer':{'publicKey':publics[peer],**({'host':'2001:db8::20','port':9443} if role=='bridge' else {})},'listenPort':0 if role=='bridge' else 9443,'exitInterfaces':{} if role=='bridge' else {'ipv4':'eth0','ipv6':'eth0'}}
    normalized=m.validate_config(config)
    assert normalized==config
    result[role]={'config':config,'sha256':m.digest(normalized)}
output={'connectorSourceSha256':hashlib.sha256(p.read_bytes()).hexdigest(),'cases':result}
(Path(__file__).parent/'native-plan-python-hashes.json').write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps({k:v['sha256'] for k,v in result.items()},indent=2))
