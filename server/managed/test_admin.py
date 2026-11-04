import importlib.util,io,json,tempfile,time,unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('managed',Path(__file__).with_name('admin.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
_read_text=Path.read_text
def fixture_read(path,*args,**kwargs):
 if path.as_posix()=='/proc/sys/kernel/random/boot_id':return 'unit-fixture-boot'
 return _read_text(path,*args,**kwargs)
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
  with tempfile.TemporaryDirectory() as directory,patch.object(Path,'read_text',fixture_read),patch.object(m,'ROOT',Path(directory)),patch.object(m,'run',return_value='generation-1'):
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
   return json.dumps(snapshot) if path.as_posix()=='/var/lib/xio-rivet/stats.json' else fixture_read(path,*args,**kwargs)
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
  rule=['route','allow','in','on','xio0','out','on','eth0','from','10.77.0.0/24']
  d={'firewall':{'kind':'ufw','added':[rule]}}
  def command(*args,**kwargs):
   return 'ufw allow 22/tcp\nufw '+' '.join(rule) if args==('ufw','show','added') else ''
  with patch.object(m,'run',side_effect=command) as calls:
   self.assertFalse(m.firewall_managed(d,True))
  self.assertIn(unittest.mock.call('ufw','--force','route','delete',*rule[1:]),calls.call_args_list)
  self.assertEqual(len(calls.call_args_list),2)

class RestrictedPolicyTests(unittest.TestCase):
 def setUp(self):
  # public() now consults the live cascade probe; keep this unit test off the network.
  patcher=patch.object(m,'cascade_status',return_value={'alive':False,'reason':'no-ipv6-default-route','probe':'route'})
  self.addCleanup(patcher.stop);patcher.start()
 def test_public_profiles_advertise_only_restricted_candidates(self):
  d={'id':'s','host':'vpn.example','publicKeys':{},'awg':{},'protocols':['wireguard','awg'],'restrictedNetwork':True,'rivet':{'serverName':'vpn.example'},'stack':{'protocols':['xray','cloak']}}
  self.assertEqual(set(m.public(d)['protocols']),{'awg','xray','cloak','rivet-h3','rivet-s1'})
 def test_counters_skip_absent_interfaces(self):
  # Restricted installs run without xio0; `wg show xio0 dump` fails and used to
  # take the stats timer and `status` down with it.
  with patch.object(m.Path,'exists',return_value=False),patch.object(m,'run') as called:
   self.assertEqual(m.counters(),{})
   called.assert_not_called()


class StatsGenerationTests(unittest.TestCase):
 def test_protocol_without_unit_does_not_fail_sample(self):
  # Restricted installs run AWG only, but user keys still carry 'wireguard'.
  # generations[p] used to raise KeyError and took the stats timer and
  # status down with it; the sample must stay green.
  d={'id':'s','phase':'ready','restrictedNetwork':True,'protocols':['wireguard','awg'],'publicKeys':{},'awg':{},
     'users':{'u':{'keys':{'wireguard':'k1','awg':'k2'},'stats':{},'monthly':{}}}}
  with patch.object(m,'counters',return_value={}),patch.object(m,'run',return_value='gen'),\
       patch.object(m,'save'),patch.object(m,'public',return_value={'id':'s'}),\
       patch.object(m.Path,'read_text',side_effect=lambda *a,**k:'unit-fixture-boot'):
   result=m.stats(d)
  self.assertEqual(result['sampledAt']>0,True)
  self.assertEqual(d['users']['u']['stats']['wireguard']['generation'],None)
  self.assertEqual(d['users']['u']['stats']['awg']['generation'],'unit-fixture-boot:gen')

class StatsTests(unittest.TestCase):
 def test_restricted_install_tolerates_keys_without_a_running_unit(self):
  # restrictedNetwork installs run no kernel WireGuard, but a user may still carry a
  # wireguard key from an earlier recipe; the whole sample must not fail on it.
  with tempfile.TemporaryDirectory() as directory,patch.object(Path,'read_text',fixture_read),patch.object(m,'ROOT',Path(directory)):
   d={'owner':m.OWNER,'id':'s','host':'example','restrictedNetwork':True,'protocols':['wireguard','awg'],'publicKeys':{},'awg':{},'users':{'u':{'keys':{'wireguard':'w','awg':'a'},'revoked':False}}}
   with patch.object(m,'counters',return_value={('awg','a'):(5,7,1000)}),patch.object(m,'run',return_value='inv'),patch.object(m.time,'time',return_value=1001),patch.object(m.time,'strftime',return_value='2026-10'):
    m.stats(d)
   self.assertEqual(d['users']['u']['stats']['awg']['rx'],5)
   self.assertEqual(d['users']['u']['stats']['wireguard']['rx'],0)

class CrossServiceStatisticsTests(unittest.TestCase):
 """Snapshots written by other services must never take the sample down.

 xio-stack is a DynamicUser and writes its snapshot with an explicit 0600; xio-rivet runs as
 xio-rivet with UMask=0077. Reading either needs CAP_DAC_READ_SEARCH, which a narrowed
 CapabilityBoundingSet removes, and the EACCES used to kill the stats timer and `status`.
 The counters this manager owns (wg dump, AWG UAPI) are independent of those files.
 """
 boot='/proc/sys/kernel/random/boot_id'
 def deployment(self):
  return {'owner':m.OWNER,'id':'s','host':'example','restrictedNetwork':True,'protocols':['wireguard','awg'],
          'publicKeys':{},'awg':{},'stack':{'protocols':['xray']},
          'users':{'u':{'keys':{'awg':'a'},'stats':{},'monthly':{},'rivet':True,'stack':{'uuid':'x'}}}}
 def sample(self,read_text,stack_snapshot):
  """Run one sample with the given snapshot reader and stack module behaviour."""
  stack=SimpleNamespace(stats=stack_snapshot,network=SimpleNamespace(stats=lambda d:{}),mesh=SimpleNamespace(stats=lambda d:{}))
  d=self.deployment()
  with tempfile.TemporaryDirectory() as directory,patch.object(m,'stack',stack),patch.object(Path,'read_text',read_text),\
       patch.object(m,'ROOT',Path(directory)),patch.object(m,'save'),patch.object(m,'public',return_value={'id':'s'}),\
       patch.object(m,'run',return_value='generation-1'),patch.object(m,'counters',return_value={('awg','a'):(5,7,1000)}),\
       redirect_stderr(io.StringIO()) as logged:
   return m.stats(d),d,logged.getvalue()
 def readable(self,snapshots):
  def read_text(path,*args,**kwargs):
   key=path.as_posix()
   if key==self.boot:return 'unit-fixture-boot'
   if key in snapshots:return json.dumps(snapshots[key])
   raise FileNotFoundError(2,'No such file or directory')
  return read_text
 def test_unreadable_snapshots_are_reported_and_the_sample_survives(self):
  def denied(path,*args,**kwargs):
   if path.as_posix()==self.boot:return 'unit-fixture-boot'
   raise PermissionError(13,'Permission denied')
  def unreadable():raise PermissionError(13,'Permission denied')
  result,d,logged=self.sample(denied,unreadable)
  named={item['source']:item for item in result['statisticsUnavailable']}
  self.assertEqual(set(named),{'stack','rivet'})
  self.assertEqual(named['stack']['path'],'/var/lib/xio-stack/stats.json')
  self.assertEqual(named['rivet']['path'],'/var/lib/xio-rivet/stats.json')
  self.assertEqual({item['reason'] for item in result['statisticsUnavailable']},{'PermissionError'})
  self.assertIn('CAP_DAC_READ_SEARCH',result['statisticsNote'])
  self.assertIn('statistics unavailable',logged)
  # The sample is still a real sample: our own counter moved.
  self.assertEqual(d['users']['u']['stats']['awg']['rx'],5)
 def test_readable_snapshots_are_counted_without_a_warning(self):
  month=time.strftime('%Y-%m',time.gmtime())
  snapshots={m.STATISTICS_FILES['rivet']:{'u':{'rx':40,'tx':50,'month':month,'monthBytes':90,'online':True,'sampledAt':1000}}}
  result,d,logged=self.sample(self.readable(snapshots),lambda:{'u':{'rx':1,'tx':2,'month':month,'monthBytes':3,'online':False,'sampledAt':1000}})
  self.assertNotIn('statisticsUnavailable',result)
  self.assertEqual(logged,'')
  self.assertEqual(d['users']['u']['monthBytes'],5+7+90+3)
  self.assertEqual(d['users']['u']['stats']['stack'],{'rx':1,'tx':2})
 def test_absent_snapshot_is_zero_not_a_warning(self):
  # A service that is not installed must stay silent: only EACCES/invalid JSON is named.
  def absent():raise FileNotFoundError(2,'No such file or directory')
  result,d,logged=self.sample(self.readable({}),absent)
  self.assertNotIn('statisticsUnavailable',result)
  self.assertNotIn('statistics unavailable',logged)
  self.assertEqual(d['users']['u']['stats']['awg']['rx'],5)


class CatalogTests(unittest.TestCase):
 def test_catalog_action_refuses_a_request_without_server_identity(self):
  """The action is dispatched, not called directly: the identity check runs first.

  catalog_state() alone is read-only and harmless, so a test that calls it never sees
  the guard. A client that forgets serverId gets 'Server identity changed; reopen setup'
  for every press, which is what the masking screen did before this case existed.
  """
  d={'id':'server-1','phase':'ready','users':{},'owner':m.OWNER}
  with tempfile.TemporaryDirectory() as directory:
   with patch.object(m,'CATALOG_DIR',Path(directory)),patch.object(m,'load',lambda:d):
    with self.assertRaisesRegex(AssertionError,'identity'):
     m.dispatch({'action':'catalog'},None)
    state=m.dispatch({'action':'catalog','serverId':'server-1'},None)
    self.assertFalse(state['available'])
    self.assertIn('timer',state['reason'])

 def test_missing_catalog_reports_unavailable(self):
  with tempfile.TemporaryDirectory() as directory:
   with patch.object(m,'CATALOG_DIR',Path(directory)):
    state=m.catalog_state()
   self.assertFalse(state['available'])
   self.assertIn('timer',state['reason'])

 def test_catalog_lists_only_eligible_entries(self):
  """Read the artifact exactly as the builder publishes it, not a hand-made manifest."""
  import sys as _sys
  _sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'catalog'))
  import catalog
  document={'schema':catalog.SCHEMA,'contentSha256':'c'*64,
            'source':{'commit':'e61be51b','fetchedAt':'2026-11-03T06:00:00Z'},
            'probe':{'country':'BE'},'counts':{'unique':2},
            'entries':[{'fqdn':'a.ru','eligible':True,'certNotAfter':'2027','tlsRttMs':10},
                       {'fqdn':'b.ru','eligible':False,'tlsRttMs':None}]}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   catalog.publish(root,'whitelist-20261103.json',catalog.dumps(document))
   with patch.object(m,'CATALOG_DIR',root):
    state=m.catalog_state()
   self.assertTrue(state['available'])
   reference=json.loads((root/'whitelist-state.json').read_text())['current']
   self.assertEqual(state['sha256'],reference['sha256'])
   self.assertEqual([entry['fqdn'] for entry in state['entries']],['a.ru'])
   self.assertEqual(state['eligible'],1)
   self.assertEqual(state['contentSha256'],'c'*64)
   self.assertEqual(state['fetchedAt'],'2026-11-03T06:00:00Z')

 def test_unreadable_state_is_an_explicit_error(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   (root/'whitelist-state.json').write_text(json.dumps({'current':{'file':'missing.json'}}))
   with patch.object(m,'CATALOG_DIR',root),self.assertRaisesRegex(RuntimeError,'Catalog unreadable'):
    m.catalog_state()

class StaticAwgTests(unittest.TestCase):
 def setUp(self):
  # The profile's DNS line depends on the live cascade probe; pin it off the network.
  patcher=patch.object(m,'cascade_status',return_value={'alive':False,'reason':'no-ipv6-default-route','probe':'route'})
  self.addCleanup(patcher.stop);patcher.start()
 def deployment(self):
  return {'owner':m.OWNER,'id':'srv','host':'203.0.113.9','phase':'ready','protocols':['wireguard','awg'],
          'users':{},'publicKeys':{'awg':'SERVERPUBKEY'},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40,
          'H1':1,'H2':2,'H3':3,'H4':4}}
 def test_add_awg_returns_profile_and_marks_transport(self):
  d=self.deployment(); saved={}
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x: saved.update(x)),patch.object(m,'apply',return_value=None):
   answer=m.dispatch({'action':'add-awg','serverId':'srv','name':'router','id':'a'*32,'publicKey':'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='})
  user=answer['user']; self.assertEqual(user['transports'],['awg']); self.assertEqual(user['slot'],2)
  conf=answer['config']
  self.assertIn('Endpoint = 203.0.113.9:51821',conf)
  self.assertIn('PublicKey = SERVERPUBKEY',conf)
  self.assertIn('Jc = 4',conf)
  self.assertIn('MTU = 1280',conf)
  self.assertNotIn('S3 =',conf)  # not present in this deployment, so not invented
  self.assertIn('10.78.0.2/24',conf)
  self.assertEqual(d['users']['a'*32]['keys'],{'awg':'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='})

 def test_add_awg_rejects_short_key(self):
  d=self.deployment()
  with patch.object(m,'load',return_value=d),patch.object(m,'save',return_value=None),patch.object(m,'apply',return_value=None):
   with self.assertRaises(AssertionError):
    m.dispatch({'action':'add-awg','serverId':'srv','name':'router','id':'b'*32,'publicKey':'AAAA'})

class StaticAwgGuardTests(unittest.TestCase):
 KEY='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
 ZERO='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
 def setUp(self):
  patcher=patch.object(m,'cascade_status',return_value={'alive':False,'reason':'no-ipv6-default-route','probe':'route'})
  self.addCleanup(patcher.stop);patcher.start()
 def deployment(self):
  return {'owner':m.OWNER,'id':'srv','host':'2001:db8::1','phase':'ready','protocols':['wireguard','awg'],
          'users':{},'publicKeys':{'awg':'SERVERPUBKEY'},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40,
          'H1':1,'H2':2,'H3':3,'H4':4}}
 def dispatch(self,d,**extra):
  request={'action':'add-awg','serverId':'srv','name':'router','id':'a'*32,'publicKey':self.KEY}
  request.update(extra)
  return m.dispatch(request)

 def test_failed_apply_removes_the_peer_from_disk_state(self):
  d=self.deployment(); saved={}
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x: saved.update(x)),patch.object(m,'apply',side_effect=RuntimeError('uapi down')):
   with self.assertRaises(RuntimeError): self.dispatch(d)
  self.assertEqual(saved['users'],{})

 def test_ipv6_host_endpoint_is_bracketed(self):
  d=self.deployment()
  with patch.object(m,'load',return_value=d),patch.object(m,'save',return_value=None),patch.object(m,'apply',return_value=None):
   answer=self.dispatch(d)
  self.assertIn('Endpoint = [2001:db8::1]:51821',answer['config'])

 def test_zero_key_and_server_key_are_rejected(self):
  d=self.deployment()
  with patch.object(m,'load',return_value=d),patch.object(m,'save',return_value=None),patch.object(m,'apply',return_value=None):
   with self.assertRaises(AssertionError): self.dispatch(d,publicKey=self.ZERO)
   with self.assertRaises(AssertionError): self.dispatch(d,publicKey='SERVERPUBKEY')

 def test_static_peer_does_not_appear_in_wireguard_config(self):
  d=self.deployment()
  with patch.object(m,'load',return_value=d),patch.object(m,'save',return_value=None),patch.object(m,'apply',return_value=None):
   self.dispatch(d)
  self.assertNotIn('wireguard',d['users']['a'*32]['keys'])



class IsolationRulesTests(unittest.TestCase):
 def payload(self):
  return {'restrictedNetwork':True,'outbound':'eth0','users':{},'firewall':{'kind':'iptables'}}

 def test_ipv4_chain_order_and_removal(self):
  calls=[]
  fake=type('R',(),{'returncode':1})()
  with patch.object(m,'run',side_effect=lambda *a,**k: calls.append(a)), \
       patch.object(m,'shutil') as sh, patch.object(m,'stack') as st, \
       patch.object(m.subprocess,'run',return_value=fake):
   sh.which.return_value='/usr/bin/iptables'
   st.network.dualstack.return_value.outbounds.return_value={'ipv6':'eth0'}
   m.rules(self.payload())
  inserts=[c for c in calls if c[0]=='iptables' and 'FORWARD' in c and '-I' in c and 'xio-managed-v1-awg' in c]
  targets=[c[c.index('-j')+1] for c in inserts if '-j' in c]
  self.assertEqual(targets[0],'DROP','the drop is inserted first so it ends up below the accepts')
  self.assertEqual(targets[-1],'ACCEPT')
  joined=' '.join(' '.join(c) for c in inserts)
  self.assertIn('RELATED',joined)
  self.assertIn('-o eth0',joined)

 def test_remove_deletes_the_forward_rules(self):
  calls=[]
  fake=type('R',(),{'returncode':0})()
  with patch.object(m,'run',side_effect=lambda *a,**k: calls.append(a)), \
       patch.object(m,'shutil') as sh, patch.object(m,'stack') as st, \
       patch.object(m.subprocess,'run',return_value=fake):
   sh.which.return_value='/usr/bin/iptables'
   st.network.dualstack.return_value.outbounds.return_value={'ipv6':'eth0'}
   m.rules(self.payload(),remove=True)
  deletes=[c for c in calls if c[0]=='iptables' and 'FORWARD' in c and '-D' in c and 'xio-managed-v1-awg' in c]
  self.assertEqual(len(deletes),4)  # the four FORWARD rules of the isolation policy

 def test_rule_presence_comes_from_one_dump_per_table(self):
  # Steady state reads one `-S` per table instead of one `-C` per rule. A rule found
  # in the dump is neither probed nor inserted, the implicit `-m udp` that iptables
  # prints must not defeat the match, and a rule missing from the dump still gets the
  # `-C` probe before it is inserted.
  calls=[];inserts=[]
  view=('-P FORWARD ACCEPT\n'
        '-A FORWARD -i xioawg0 -m comment --comment xio-managed-v1-awg -j ACCEPT\n'
        '-A FORWARD -i xioawg0 -m comment --comment xio-managed-v1-awg -j DROP\n'
        '-A INPUT -i eth0 -p udp -m udp --dport 51821 -m comment --comment xio-managed-v1-awg -j ACCEPT\n')
  def fake(argv,**kwargs):
   calls.append(list(argv))
   if '-S' in argv:return type('R',(),{'returncode':0,'stdout':view if argv[0]=='iptables' else ''})()
   return type('R',(),{'returncode':1,'stdout':''})()
  with patch.object(m,'run',side_effect=lambda *a,**k: inserts.append(a)), \
       patch.object(m,'shutil') as sh, patch.object(m,'stack') as st, \
       patch.object(m.subprocess,'run',side_effect=fake):
   sh.which.return_value='/usr/bin/iptables'
   st.network.dualstack.return_value.outbounds.return_value={'ipv6':'eth0'}
   m.rules(self.payload())
  dumps=[c for c in calls if '-S' in c]
  probes=[c for c in calls if '-C' in c]
  deletes=[c for c in calls if '-D' in c]
  self.assertEqual(len(dumps),3)  # iptables filter, iptables nat, ip6tables filter
  self.assertEqual(len([c for c in dumps if c[0]=='iptables' and c[1:]==['-w','5','-S']]),1)  # filter table once
  self.assertEqual(len(probes),6)  # eight rules minus the two found in the dump
  self.assertEqual(len(inserts),6)
  self.assertEqual(len([c for c in inserts if c[0]=='iptables' and 'FORWARD' in c]),3)
  self.assertFalse(any(c[0]=='iptables' and 'DROP' in c for c in inserts))  # found in the dump
  self.assertEqual(len(deletes),1)  # the legacy wide rule, deleted without a probe
  legacy_probe=['iptables','-w','5','-C','FORWARD','-i','xioawg0','-m','comment',
                '--comment','xio-managed-v1-awg','-j','ACCEPT']
  self.assertNotIn(legacy_probe,calls)




class DispatchScopeTests(unittest.TestCase):
 def setUp(self):
  patcher=patch.object(m,'cascade_status',return_value={'alive':False,'reason':'no-ipv6-default-route','probe':'route'})
  self.addCleanup(patcher.stop);patcher.start()
 def test_inspect_is_not_shadowed_by_a_local_named_public(self):
  # dispatch() used `public` as the decoded add-awg key, which made `public` a local
  # for the whole function: `inspect` (and a successful `add`) raised UnboundLocalError
  # instead of returning the server block.
  d={'owner':m.OWNER,'id':'srv','host':'vpn.example','publicKeys':{'awg':'server'},'awg':{},
     'protocols':['awg'],'phase':'ready'}
  capabilities={'outboundByFamily':{'ipv4':'eth0'},'ipv4DefaultRoute':True,'ipv6DefaultRoute':False}
  with patch.object(m,'load',return_value=d),patch.object(m,'stack') as st:
   st.network.dualstack.return_value.capabilities.return_value=capabilities
   answer=m.dispatch({'action':'inspect','serverId':'srv'})
  self.assertEqual(answer['phase'],'ready')
  self.assertEqual(answer['server']['id'],'srv')
  self.assertEqual(answer['server']['networkCapabilities'],capabilities)


if __name__=='__main__':unittest.main()

class SandboxPolicyTests(unittest.TestCase):
 def test_compat_containers_keep_a_read_only_system(self):
  d={}
  written={}
  with patch.object(m,'sandbox_supported',return_value=False), \
       patch.object(m,'write',side_effect=lambda path,text,mode=0o600: written.update({'path':path,'text':text,'mode':mode})), \
       patch.object(m,'save',return_value=None):
   mode=m.sandbox_prepare(d)
  self.assertEqual(mode,'compat')
  self.assertIn('ProtectSystem=full',written['text'])
  self.assertIn('ReadWritePaths=/etc/xio-managed /etc/xio-stack',written['text'])
  self.assertNotIn('ProtectSystem=no',written['text'])
  self.assertEqual(written['mode'],0o644,'unit drop-ins must stay readable by systemd')

 def test_strict_hosts_drop_the_override(self):
  with patch.object(m,'sandbox_supported',return_value=True), patch.object(m,'save',return_value=None):
   self.assertEqual(m.sandbox_prepare({}),'strict')


if __name__=='__main__':unittest.main()

class ShadowsocksConfigTests(unittest.TestCase):
 def fake(self,protocols):
  return {'restrictedNetwork':False,'outbound':'eth0','protocols':['awg','xray'],
          'stack':{'protocols':protocols,'publicKey':'k','shortId':'s','serverName':'n'},
          'users':{}}
 def test_profiles_never_advertise_a_protocol_the_fork_cannot_load(self):
  d=self.fake(['xray','shadowsocks','openvpn','cloak','ikev2'])
  d['users']={'u1':{'stack':{'uuid':'00000000-0000-0000-0000-000000000000','ssKey':'c3M='},'revoked':False}}
  d['host']='203.0.113.9'
  with patch.object(m.stack,'receipt',return_value={'serverName':'n','publicKey':'k','shortId':'s','ssKey':'x'}):
   emitted=set(m.stack.profiles(d,'u1'))
  self.assertEqual(emitted,{'xray'})
 def test_restricted_or_undeclared_profiles_never_emit_shadowsocks(self):
  import json
  for protocols in (['xray','cloak'], ['xray','openvpn'], []):
   written={}
   with patch.object(m.stack,'receipt',return_value={'target':'t','serverName':'n','privateKey':'k','shortId':'s','ssKey':'x','inactiveKey':'y'}), \
        patch.object(m.stack,'write',side_effect=lambda path,text,mode=0o600: written.update({'json':text})), \
        patch.object(m.stack.network,'dualstack',return_value=type('D',(),{'listener':lambda self:'127.0.0.1'})()):
    m.stack.config(self.fake(protocols))
   inbound=[i['protocol'] for i in json.loads(written['json'])['inbounds']]
   self.assertNotIn('shadowsocks',inbound,protocols)


class CascadeProbeTests(unittest.TestCase):
 """The shared helper behind `ipv6=true` and the IPv6 resolver in a static profile.

 A default IPv6 route is not connectivity: the cascade's route survives its dead ssh
 for the ServerAlive window, and a client handed a v6 resolver in that window hangs.
 """
 def setUp(self):
  self.dualstack=m.stack.network.dualstack()
  patcher=patch.object(self.dualstack,'routes',return_value=[{'dev':'tun0'}])
  self.addCleanup(patcher.stop);patcher.start()
 def status(self,ping,tcp):
  with tempfile.TemporaryDirectory() as directory,patch.object(self.dualstack,'CASCADE_CACHE',Path(directory)/'probe.json'),\
       patch.object(self.dualstack,'_probe_ping',**ping),patch.object(self.dualstack,'_probe_tcp',**tcp):
   return self.dualstack.cascade_status(),self.dualstack.cascade_status()
 def test_successful_probe_marks_ipv6_alive_and_is_cached(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(self.dualstack,'CASCADE_CACHE',Path(directory)/'probe.json'),\
       patch.object(self.dualstack,'_probe_ping',return_value=True) as ping,patch.object(self.dualstack,'_probe_tcp',return_value=False):
   first=self.dualstack.cascade_status();second=self.dualstack.cascade_status()
  self.assertEqual((first['alive'],first['reason'],first['probe']),(True,'ok','ping'))
  self.assertEqual(second,first)
  ping.assert_called_once()  # the second answer came from the cache, not the network
 def test_route_without_traffic_is_cascade_down(self):
  (first,second)=self.status(ping={'return_value':False},tcp={'return_value':False})
  self.assertEqual((first['alive'],first['reason']),(False,'cascade-down'))
  self.assertEqual(second,first)
 def test_tcp_probe_is_the_fallback_when_ping_fails(self):
  (first,_)=self.status(ping={'return_value':False},tcp={'return_value':True})
  self.assertEqual((first['alive'],first['probe']),(True,'tcp'))
 def test_tcp_probe_tries_the_next_port_when_one_is_closed(self):
  # 443 is closed on the exit while 8443 is the RIVET entry; a refused port must not
  # discard a working cascade.
  attempts=[]
  class Connected:
   def __enter__(self):return self
   def __exit__(self,*args):return False
  def connect(address,timeout=None):
   attempts.append(address)
   if len(attempts)==1:raise ConnectionRefusedError(111,'Connection refused')
   return Connected()
  with patch.object(self.dualstack.socket,'create_connection',side_effect=connect):
   self.assertTrue(self.dualstack._probe_tcp())
  self.assertEqual([port for _,port in attempts],[443,8443])
 def test_no_default_route_never_probes(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(self.dualstack,'CASCADE_CACHE',Path(directory)/'probe.json'),\
       patch.object(self.dualstack,'routes',return_value=[]),\
       patch.object(self.dualstack,'_probe_ping',side_effect=AssertionError('probe must not run')),\
       patch.object(self.dualstack,'_probe_tcp',side_effect=AssertionError('probe must not run')):
   status=self.dualstack.cascade_status()
  self.assertEqual((status['alive'],status['reason']),(False,'no-ipv6-default-route'))
 def test_probe_that_raises_is_reported_not_raised(self):
  (first,_)=self.status(ping={'side_effect':RuntimeError('ping exploded')},tcp={'side_effect':OSError('socket exploded')})
  self.assertEqual((first['alive'],first['reason']),(False,'probe-error'))


class StaticAwgDnsTests(unittest.TestCase):
 """The profile and the reason field that the UI shows for a static AWG device."""
 KEY='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
 def deployment(self):
  return {'owner':m.OWNER,'id':'srv','host':'203.0.113.9','phase':'ready','protocols':['wireguard','awg'],
          'users':{},'publicKeys':{'awg':'SERVERPUBKEY'},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40}}
 def request(self):
  return {'action':'add-awg','serverId':'srv','name':'router','id':'a'*32,'publicKey':self.KEY}
 def answer(self,cascade):
  d=self.deployment();writes=[]
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x:writes.append(x)),\
       patch.object(m,'apply',return_value=None),patch.object(m,'cascade_status',return_value=cascade):
   answer=m.dispatch(self.request())
  return answer,writes,d
 def test_live_cascade_puts_both_resolvers_in_the_profile(self):
  answer,writes,d=self.answer({'alive':True,'reason':'ok','probe':'ping'})
  self.assertIn('DNS = 9.9.9.9, 2620:fe::fe\n',answer['config'])
  self.assertTrue(answer['ipv6']);self.assertEqual(answer['ipv6Reason'],'ok')
  self.assertEqual(d['users']['a'*32]['transports'],['awg'])
  self.assertTrue(writes)
 def test_dead_cascade_puts_only_the_ipv4_resolver(self):
  answer,_,_=self.answer({'alive':False,'reason':'cascade-down','probe':'ping+tcp'})
  self.assertIn('DNS = 9.9.9.9\n',answer['config'])
  self.assertNotIn('2620:fe::fe',answer['config'])
  self.assertFalse(answer['ipv6']);self.assertEqual(answer['ipv6Reason'],'cascade-down')
 def test_probe_exception_degrades_to_ipv4_only_instead_of_failing(self):
  d=self.deployment()
  with patch.object(m,'load',return_value=d),patch.object(m,'save'),patch.object(m,'apply',return_value=None),\
       patch.object(m.stack.network,'dualstack',side_effect=RuntimeError('probe exploded')):
   answer=m.dispatch(self.request())
  self.assertIn('DNS = 9.9.9.9\n',answer['config'])
  self.assertFalse(answer['ipv6']);self.assertEqual(answer['ipv6Reason'],'probe-error')


class PublicIpv6ReasonTests(unittest.TestCase):
 """`rivet.ipv6` (the flag clients read) follows the probe, not the route table."""
 def deployment(self):
  return {'id':'srv','host':'vpn.example','publicKeys':{'awg':'SERVERPUBKEY'},'awg':{},'protocols':['wireguard','awg'],
          'restrictedNetwork':True,'rivet':{'serverName':'vpn.example','pin':'p'}}
 def capabilities(self):
  return {'outboundByFamily':{'ipv4':'eth0','ipv6':'tun0'},'ipv4DefaultRoute':True,'ipv6DefaultRoute':True,
          'dns64':'notProbed','nat64':'notProbed','endToEnd':'notProbed','ipv4LiteralEgress':'notProbed','note':'routes are observations'}
 def public(self,cascade):
  with patch.object(m.stack.network,'dualstack',return_value=SimpleNamespace(capabilities=self.capabilities)),\
       patch.object(m,'cascade_status',return_value=cascade):
   return m.public(self.deployment())
 def test_dead_cascade_turns_the_client_flag_off_and_names_the_reason(self):
  server=self.public({'alive':False,'reason':'cascade-down','probe':'ping+tcp'})
  self.assertFalse(server['rivet']['ipv6'])
  self.assertEqual(server['rivet']['ipv6Reason'],'cascade-down')
  self.assertFalse(server['ipv6Working'])
  self.assertEqual(server['ipv6Reason'],'cascade-down')
  # The route itself is still reported honestly; it is just not used as the flag.
  self.assertTrue(server['networkCapabilities']['ipv6DefaultRoute'])
 def test_live_cascade_turns_the_client_flag_on(self):
  server=self.public({'alive':True,'reason':'ok','probe':'ping'})
  self.assertTrue(server['rivet']['ipv6']);self.assertTrue(server['ipv6Working'])
  self.assertEqual(server['rivet']['ipv6Reason'],'ok')


class ProvisioningOrderTests(unittest.TestCase):
 """Validation runs before deployment.json is written; a failure leaves no user."""
 KEY='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
 WG='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
 def deployment(self,rivet=False):
  d={'owner':m.OWNER,'id':'srv','host':'203.0.113.9','phase':'ready','protocols':['wireguard','awg'],
     'users':{},'publicKeys':{'wireguard':'WGSERVER','awg':'SERVERPUBKEY'},'awg':{'Jc':4,'Jmin':40,'Jmax':70,'S1':32,'S2':40}}
  if rivet:d['rivet']={'serverName':'vpn.example'}
  return d
 def request(self,**extra):
  request={'action':'add','serverId':'srv','name':'phone','id':'b'*32,
           'publicKeys':{'wireguard':self.WG,'awg':self.KEY},'rivet':{'secret':'s','entryToken':'t'}}
  request.update(extra)
  return request
 def test_malformed_rivet_credentials_are_rejected_before_any_write(self):
  d=self.deployment(rivet=True);writes=[]
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x:writes.append(x)),patch.object(m,'apply') as applied:
   with self.assertRaises(AssertionError):
    m.dispatch(self.request(rivet={'secret':'only-half'}))
  self.assertEqual(d['users'],{})
  self.assertEqual(writes,[])
  applied.assert_not_called()
 def test_failed_server_block_rolls_the_user_back(self):
  d=self.deployment();writes=[]
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x:writes.append(x)),\
       patch.object(m,'apply',return_value=None),patch.object(m,'public',side_effect=RuntimeError('cannot render')):
   with self.assertRaises(RuntimeError):
    m.dispatch(self.request())
  self.assertNotIn('b'*32,d['users'])
  self.assertTrue(writes)
  self.assertNotIn('b'*32,writes[-1]['users'])
 def test_profile_failure_never_writes_a_static_peer(self):
  d=self.deployment();writes=[]
  with patch.object(m,'load',return_value=d),patch.object(m,'save',side_effect=lambda x:writes.append(x)),\
       patch.object(m,'apply') as applied,\
       patch.object(m,'cascade_status',return_value={'alive':False,'reason':'no-ipv6-default-route','probe':'route'}),\
       patch.object(m,'awg_client_config',side_effect=RuntimeError('bad profile')):
   with self.assertRaises(RuntimeError):
    m.dispatch({'action':'add-awg','serverId':'srv','name':'router','id':'a'*32,'publicKey':self.KEY})
  self.assertEqual(d['users'],{});self.assertEqual(writes,[])
  applied.assert_not_called()


if __name__=='__main__':unittest.main()
