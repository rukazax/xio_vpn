import importlib.util,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('managed',Path(__file__).with_name('admin.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PolicyTests(unittest.TestCase):
 def test_scoped_quota_and_roles(self):
  d={'users':{'a':{'role':'admin','userLimit':1,'revoked':False},'b':{'createdBy':'a','revoked':False}}}
  for action,req in [('add',{}),('init',{}),('remove',{}),('revoke',{'id':'a'})]:
   with self.assertRaises(AssertionError):m.authority(d,'a',action,req)
  d['users']['b']['revoked']=True;m.authority(d,'a','add',{})
  with self.assertRaises(AssertionError):m.authority(d,'a','add',{'admin':True})
  m.authority(d,'a','status',{})
  d['users']['a']['revoked']=True
  with self.assertRaises(AssertionError):m.authority(d,'a','inspect',{})
 def test_monthly_delta_reset_and_rollover(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(m,'ROOT',Path(directory)),patch.object(m,'run',return_value='generation-1'):
   d={'owner':m.OWNER,'id':'s','host':'example','protocols':['wireguard','awg'],'publicKeys':{},'awg':{},'users':{'u':{'keys':{'wireguard':'pub'},'revoked':False}}}
   with patch.object(m,'counters',return_value={('wireguard','pub'):(10,20,1000)}),patch.object(m.time,'time',return_value=1001),patch.object(m.time,'strftime',return_value='2026-10'):
    m.stats(d);self.assertEqual(d['users']['u']['monthBytes'],30);self.assertTrue(d['users']['u']['online'])
   with patch.object(m,'counters',return_value={('wireguard','pub'):(15,25,1000)}),patch.object(m.time,'time',return_value=2000),patch.object(m.time,'strftime',return_value='2026-11'):
    m.stats(d);self.assertEqual(d['users']['u']['monthBytes'],10);self.assertFalse(d['users']['u']['online'])
   with patch.object(m,'counters',return_value={('wireguard','pub'):(2,3,2000)}),patch.object(m.time,'strftime',return_value='2026-11'):
    m.stats(d);self.assertEqual(d['users']['u']['monthBytes'],15)
class RivetStatisticsTests(unittest.TestCase):
 def test_rivet_snapshot_not_double_counted_and_stale_online_rejected(self):
  import io,json
  original=Path.read_text
  snapshot={'u':{'rx':40,'tx':50,'month':'2026-10','monthBytes':90,'online':True,'sampledAt':1000}}
  def read(path,*args,**kwargs):
   return json.dumps(snapshot) if str(path)=='/var/lib/xio-rivet/stats.json' else original(path,*args,**kwargs)
  with tempfile.TemporaryDirectory() as directory,patch.object(m,'ROOT',Path(directory)),patch.object(m,'run',return_value='generation-1'),patch.object(Path,'read_text',read),patch.object(m,'counters',return_value={}),patch.object(m.time,'strftime',return_value='2026-10'),patch.object(m.time,'time',return_value=1001):
   d={'owner':m.OWNER,'id':'s','host':'example','protocols':['wireguard','awg'],'publicKeys':{},'awg':{},'users':{'u':{'keys':{},'rivet':True,'revoked':False}}}
   m.stats(d);m.stats(d);self.assertEqual(d['users']['u']['monthBytes'],90);self.assertTrue(d['users']['u']['online'])
   snapshot['u']['sampledAt']=900;m.stats(d);self.assertFalse(d['users']['u']['online'])

class InstallerTests(unittest.TestCase):
 def test_supported_and_rejected_platforms(self):
  for name,version,manager in [('debian','12','apt'),('debian','13','apt'),('ubuntu','24.04','apt'),('centos','9','rpm'),('rocky','9.6','rpm'),('almalinux','10.0','rpm')]:
   self.assertEqual(m.platform_info('ID="'+name+'"\nVERSION_ID="'+version+'"')['manager'],manager)
  for text in ['ID=centos\nVERSION_ID="7"','ID=ubuntu\nVERSION_ID="18.04"','ID=alpine\nVERSION_ID="3.22"']:
   with self.assertRaises(RuntimeError):m.platform_info(text)
 def test_shared_dependencies_not_purged(self):
  calls=[]
  def command(*args,**kwargs):
   calls.append(args)
   if args[:3]==('apt-get','-s','purge'):
    return '\n'.join('Purg '+p for p in args[3:])+('\nRemv foreign-app' if 'shared-lib' in args else '')
   return ''
  with patch.object(m,'installed_packages',return_value={'wireguard-tools','shared-lib','foreign-app'}),patch.object(m,'run',side_effect=command):
   result=m.purge_packages({'platform':{'manager':'apt'},'packagesAdded':['wireguard-tools','shared-lib']})
  self.assertEqual(result['packagesRemoved'],['wireguard-tools']);self.assertEqual(result['packagesRetained'],['shared-lib'])
  self.assertFalse(any('foreign-app' in args for args in calls))
 def test_foreign_wireguard_configuration_protects_tools(self):
  with patch.object(m,'installed_packages',return_value={'wireguard-tools'}),patch.object(m,'run') as command:
   result=m.purge_packages({'platform':{'manager':'apt'},'packagesAdded':['wireguard-tools'],'preserveWireGuardTools':True})
  self.assertEqual(result['packagesRetained'],['wireguard-tools']);command.assert_not_called()
 def test_firewalld_cleanup_only_recorded_rules(self):
  from types import SimpleNamespace
  d={'firewall':{'kind':'firewalld','added':[{'args':['--zone=public'],'option':'port','value':'51820/udp'}]}}
  with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0)),patch.object(m,'run') as command:
   self.assertTrue(m.firewall_managed(d,True));command.assert_called_once_with('firewall-cmd','--zone=public','--remove-port=51820/udp')
 def test_ufw_removes_only_owned_route_with_valid_syntax(self):
  rule=['route','allow','in','on','x1o0','out','on','eth0','from','10.77.0.0/24']
  d={'firewall':{'kind':'ufw','added':[rule]}}
  def command(*args,**kwargs):
   return 'ufw allow 22/tcp\nufw '+' '.join(rule) if args==('ufw','show','added') else ''
  with patch.object(m,'run',side_effect=command) as calls:
   self.assertFalse(m.firewall_managed(d,True))
  self.assertIn(unittest.mock.call('ufw','--force','route','delete',*rule[1:]),calls.call_args_list)
  self.assertEqual(len(calls.call_args_list),2)
if __name__=='__main__':unittest.main()
