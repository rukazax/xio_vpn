import importlib.util,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('managed',Path(__file__).with_name('admin.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Синтетический FakeTLS-секрет: настоящий в репозиторий не попадает.
SECRET='ee000102030405060708090a0b0c0d0e0f6578616d706c652e6f7267'
class MtprotoStateTests(unittest.TestCase):
 def state(self,folder,host='vpn.example.org'):
  with patch.object(m,'MTPROTO_ETC',Path(folder)):
   return m.mtproto_state({'host':host})
 def test_missing_secret_reports_not_installed(self):
  with tempfile.TemporaryDirectory() as folder:
   self.assertEqual(self.state(folder),{'installed':False,'host':'vpn.example.org','port':8444,'secret':None,'link':None})
 def test_installer_files_produce_the_print_link_equivalent(self):
  with tempfile.TemporaryDirectory() as folder:
   etc=Path(folder);(etc/'secret').write_text('secret='+SECRET+'\ndomain=79e.ru\n');(etc/'port').write_text('8444\n');(etc/'domain').write_text('81.177.142.37\n')
   state=self.state(folder)
   self.assertTrue(state['installed']);self.assertEqual(state['host'],'81.177.142.37');self.assertEqual(state['port'],8444)
   self.assertEqual(state['secret'],SECRET)
   self.assertEqual(state['link'],'tg://proxy?server=81.177.142.37&port=8444&secret='+SECRET)
 def test_bare_secret_and_unusable_port_fall_back(self):
  with tempfile.TemporaryDirectory() as folder:
   etc=Path(folder);(etc/'secret').write_text(SECRET+'\n');(etc/'port').write_text('99999\n')
   state=self.state(folder)
   self.assertTrue(state['installed']);self.assertEqual(state['port'],8444);self.assertEqual(state['host'],'vpn.example.org')
 def test_non_fake_tls_secret_is_not_a_working_proxy(self):
  for bad in ['ee1234','secret=zzzz','not-a-secret','ff'+SECRET[2:]]:
   with tempfile.TemporaryDirectory() as folder:
    Path(folder,'secret').write_text(bad+'\n')
    state=self.state(folder)
    self.assertFalse(state['installed'],bad);self.assertIsNone(state['link']);self.assertIsNone(state['secret'])
 def test_ipv6_host_is_bracketed_only_in_the_link(self):
  with tempfile.TemporaryDirectory() as folder:
   etc=Path(folder);(etc/'secret').write_text(SECRET+'\n');(etc/'port').write_text('443\n')
   state=self.state(folder,'2a0c:b641:1a0:800::2a2')
   self.assertEqual(state['host'],'2a0c:b641:1a0:800::2a2')
   self.assertTrue(state['link'].startswith('tg://proxy?server=[2a0c:b641:1a0:800::2a2]&port=443&secret='))
class MtprotoDispatchTests(unittest.TestCase):
 def test_action_needs_no_server_id_and_never_writes(self):
  deployment={'id':'srv','host':'vpn.example.org','phase':'ready','protocols':[],'users':{}}
  with tempfile.TemporaryDirectory() as folder:
   etc=Path(folder);(etc/'secret').write_text(SECRET+'\n')
   with patch.object(m,'MTPROTO_ETC',etc),patch.object(m,'load',return_value=deployment),patch.object(m,'save',side_effect=AssertionError('mtproto wrote state')):
    answer=m.dispatch({'action':'mtproto'})
  self.assertTrue(answer['installed']);self.assertEqual(answer['port'],8444)
  self.assertEqual(answer['link'],'tg://proxy?server=vpn.example.org&port=8444&secret='+SECRET)
 def test_delegated_admin_does_not_receive_the_secret(self):
  d={'id':'srv','host':'vpn.example.org','users':{'a'*32:{'role':'admin','revoked':False}}}
  with patch.object(m,'load',return_value=d):
   with self.assertRaises(AssertionError):m.dispatch({'action':'mtproto'},'a'*32)
if __name__=='__main__':unittest.main()
