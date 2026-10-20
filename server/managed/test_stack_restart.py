import unittest,tempfile,json,base64
from pathlib import Path
from unittest.mock import patch
import network_stack as network
import stack
class CloakAdministrationTests(unittest.TestCase):
 def test_profile_generation_does_not_restart_before_user_commit(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'receipt.json').write_text(json.dumps({'cloakPublicKey':'public','serverName':'vpn.example'}))
   data={'host':'vpn.example','users':{'u':{'stack':{}}}}
   with patch.object(network,'ROOT',root),patch.object(network,'run') as command:
    result=network.cloak_profile(data,'u',json.dumps({'protocol':'openvpn','config':'proto udp\nremote vpn.example 1194\n'}))
   command.assert_not_called();profile=json.loads(result['cloak']);self.assertEqual(len(base64.b64decode(profile['cloak']['UID'])),16);self.assertIn('9443',profile['config'])
 def test_committed_admin_update_resets_only_owned_unit_before_restart(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'cloak.json').write_text('{}');events=[]
   with patch.object(stack,'ROOT',root),patch.object(stack,'config'),patch.object(stack.network,'cloak_config'),patch.object(stack,'run',side_effect=lambda *args,**kw:events.append(args)),patch.object(stack.subprocess,'run',side_effect=lambda args,**kw:events.append(tuple(args))):stack.apply({})
   reset=events.index(('systemctl','reset-failed','xio-cloak'));restart=events.index(('systemctl','restart','xio-cloak'));self.assertLess(reset,restart)
   self.assertIn(('systemctl','is-active','--quiet','xio-cloak'),events)
if __name__=='__main__':unittest.main()

class RestrictedInstallTests(unittest.TestCase):
 def test_restricted_profiles_exclude_bare_shadowsocks(self):
  fixture={'host':'vpn.example','restrictedNetwork':True,'users':{'u':{'stack':{'uuid':'00000000-0000-0000-0000-000000000001','ssKey':'fixture'}}}}
  with patch.object(stack,'receipt',return_value={'publicKey':'fixture','shortId':'aabb','serverName':'vpn.example','ssKey':'fixture'}):
   self.assertEqual(set(stack.profiles(fixture,'u')),{'xray'})
 def test_restricted_gateway_has_no_shadowsocks_listener(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   fixture={'host':'vpn.example','restrictedNetwork':True,'users':{}}
   with patch.object(stack,'ROOT',root),patch.object(stack,'receipt',return_value={'inactiveKey':'fixture','target':'vpn.example:443','serverName':'vpn.example','privateKey':'fixture','shortId':'aabb','ssKey':'fixture'}):stack.config(fixture)
   self.assertEqual([v['protocol'] for v in json.loads((root/'config.json').read_text())['inbounds']],['vless'])

class UserActivationTests(unittest.TestCase):
 def test_new_cloak_user_is_authorized_before_first_gateway_activation(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'receipt.json').write_text(json.dumps({'cloakPublicKey':'public','serverName':'vpn.example'}))
   data={'host':'vpn.example','restrictedNetwork':True,'users':{'u':{}}};activated=[]
   def activate(current):
    activated.append(current['users']['u']['stack'].get('cloakUID'))
   with patch.object(stack.network,'ROOT',root),patch.object(stack.network,'create',return_value={'openvpn':json.dumps({'protocol':'openvpn','config':'proto udp\nremote vpn.example 1194\n'})}),patch.object(stack,'apply',side_effect=activate),patch.object(stack,'profiles',return_value={}):
    result=stack.create(data,'u')
   uid=json.loads(result['cloak'])['cloak']['UID']
   self.assertEqual(activated,[uid])
