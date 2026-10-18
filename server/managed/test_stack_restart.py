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
