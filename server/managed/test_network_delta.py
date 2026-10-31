"""Pure mocked-kernel IPv6 update transaction tests, never host networking."""
from contextlib import contextmanager, ExitStack
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import dualstack as net
import update
from test_update import archive
from test_update_ipv6 import deployment


@contextmanager
def kernel(root, receipt=None):
    with ExitStack() as patches:
        system = root/'proc6'; system.mkdir()
        (system/'eth6').mkdir(); ra=system/'eth6/accept_ra'; ra.write_text('1\n')
        forward=system/'forwarding'; forward.write_text('0\n')
        links=root/'interfaces';links.mkdir()
        for interface in ['xio0','xioawg0']:(links/interface).mkdir()
        receipt=receipt or root/'receipt.json'
        state=root/'network-state.json';state.write_text('{"owner":"xio-managed-v1","rivet":true}')
        old_rule=['INPUT','-i','eth6','-p','udp','--dport','51821','-m','comment','--comment','xio-dualstack-v1-xioawg0','-j','ACCEPT']
        foreign=['INPUT','-p','tcp','--dport','22','-m','comment','--comment','FOREIGN','-j','ACCEPT']
        rules={tuple(old_rule),tuple(foreign)}
        addresses={'xio0':set(),'xioawg0':{'fd78:1::1/64','fd99::1/64'}}
        calls=[]
        def call(*args,**kwargs):
            calls.append(args)
            if args[0]=='ip6tables':
                index=next(i for i,a in enumerate(args) if a in ['-C','-I','-D'])
                key=tuple(args[3:index])+tuple(args[index+1:])
                if args[index]=='-C':return SimpleNamespace(returncode=0 if key in rules else 1,stdout='')
                if args[index]=='-I':rules.add(key)
                else:rules.discard(key)
            elif args[:5]==('ip','-j','-6','address','show'):
                return SimpleNamespace(returncode=0,stdout=json.dumps([{'addr_info':[{'local':a.split('/')[0],'prefixlen':int(a.split('/')[1])} for a in addresses[args[-1]]]}]))
            elif args[:4]==('ip','-6','address','add'):addresses[args[-1]].add(args[4])
            elif args[:4]==('ip','-6','address','del'):addresses[args[-1]].discard(args[4])
            elif args[0]=='sysctl':forward.write_text(args[-1].split('=')[-1]+'\n')
            return SimpleNamespace(returncode=0,stdout='[]')
        for name,value in {'RECEIPT':receipt,'STATE':state,'SYS_NET':links,'IPV6_SYS':system,'FORWARDING':forward}.items():patches.enter_context(patch.object(net,name,value))
        patches.enter_context(patch.object(net,'routes',return_value=[{'dev':'eth6','protocol':'ra'}]))
        patches.enter_context(patch.object(net.os,'geteuid',return_value=0,create=True))
        patches.enter_context(patch.object(net,'call',side_effect=call))
        yield SimpleNamespace(rules=rules,addresses=addresses,calls=calls,ra=ra,forward=forward,receipt=receipt,old_rule=old_rule)


class DeltaTests(unittest.TestCase):
    def test_new_and_existing_receipt_rollback_preserve_preexisting_kernel_state(self):
        for existing in [False,True]:
            with self.subTest(existing=existing),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                with kernel(root) as k:
                    if existing:k.receipt.write_text(json.dumps({'owner':'xio-dualstack-v1','oldForward':'0','rules':[[[],k.old_rule]],'addresses':[['xioawg0','fd78:1::1/64']],'keep':'original'}))
                    original=k.receipt.read_bytes() if existing else None
                    rules=set(k.rules);addresses=copy.deepcopy(k.addresses)
                    plan=net.delta_begin(root)
                    net.apply();self.assertNotEqual(k.rules,rules)
                    self.assertEqual(k.forward.read_text().strip(),'1');self.assertEqual(k.ra.read_text().strip(),'2')
                    net.delta_rollback(plan)
                    self.assertEqual(k.rules,rules);self.assertEqual(k.addresses,addresses)
                    self.assertEqual(k.forward.read_text().strip(),'0');self.assertEqual(k.ra.read_text().strip(),'1')
                    self.assertEqual(k.receipt.read_bytes() if k.receipt.exists() else None,original)
                    self.assertFalse(net._fence_path().exists())
                    self.assertFalse(any('-F' in c or '-P' in c for c in k.calls))

    def test_missing_kernel_rule_already_in_old_receipt_is_still_a_new_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with kernel(root) as k:
                k.rules.discard(tuple(k.old_rule))
                k.receipt.write_text(json.dumps({'owner':'xio-dualstack-v1','oldForward':'0','rules':[[[],k.old_rule]],'addresses':[]}))
                plan=net.delta_begin(root);net.apply();self.assertIn(tuple(k.old_rule),k.rules)
                net.delta_rollback(plan);self.assertNotIn(tuple(k.old_rule),k.rules)

    def test_foreign_receipt_race_or_bad_snapshot_refuses_before_kernel_deletion(self):
        for problem in ['foreign-before','race','bad-backup','foreign-fence','ra-race','journal-hash','forged-rule']:
            with self.subTest(problem=problem),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                with kernel(root) as k:
                    if problem=='foreign-before':
                        k.receipt.write_text('{"owner":"FOREIGN"}')
                        with self.assertRaisesRegex(RuntimeError,'Foreign'):net.delta_begin(root)
                        self.assertFalse(net._fence_path().exists());continue
                    plan=net.delta_begin(root);net.apply()
                    if problem=='race':k.receipt.write_text('{"owner":"xio-dualstack-v1","changed":true}')
                    elif problem=='bad-backup':Path(plan['path']).write_text('{}')
                    elif problem=='foreign-fence':net._fence_path().write_text('{"owner":"FOREIGN"}')
                    elif problem=='ra-race':k.ra.write_text('0\n')
                    elif problem=='journal-hash':
                        fence=json.loads(net._fence_path().read_bytes());fence['effects']=[];net._fence_path().write_text(json.dumps(fence))
                    elif problem=='forged-rule':
                        fence=json.loads(net._fence_path().read_bytes());fence['effects'].append({'kind':'rule','value':[[],['FORWARD','-s','fd99::/64','-m','comment','--comment','xio-dualstack-v1-xio0','-j','ACCEPT']]});net._json_put(net._fence_path(),fence)
                    before=set(k.rules);addresses=copy.deepcopy(k.addresses);count=len(k.calls)
                    with self.assertRaises(RuntimeError):net.delta_rollback(plan)
                    self.assertEqual(k.rules,before);self.assertEqual(k.addresses,addresses);self.assertEqual(len(k.calls),count)
                    self.assertTrue(net._fence_path().exists())

    def test_success_commit_retains_new_owned_effects_and_removes_only_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with kernel(root) as k:
                plan=net.delta_begin(root);net.apply();rules=set(k.rules)
                net.delta_commit(plan)
                self.assertEqual(k.rules,rules);self.assertTrue(k.receipt.exists());self.assertFalse(net._fence_path().exists())

    def test_updater_start_failure_restores_network_before_old_service_restart_and_keys(self):
        for existing in [False,True]:
            with self.subTest(existing=existing),deployment() as (root,data,events),kernel(root,update.DUAL_RECEIPT) as k:
                if not existing:k.receipt.unlink()
                original_receipt=k.receipt.read_bytes() if existing else None
                state=update.STATE.read_bytes();public=(update.RIVET_ROOT/'public.json').read_bytes()
                unit=root/'xio-openvpn-tcp.service'
                unit_before='[Unit]\nDescription=XIO managed xio-openvpn-tcp\n[Service]\nExecStart=/usr/sbin/openvpn --config '+str(root/'tcp.ovpn')+'\n[Install]\nWantedBy=multi-user.target\n'
                unit.write_text(unit_before);(root/'receipt.json').write_text('{"owner":"xio-stack-v1"}')
                keys={p:p.read_bytes() for p in update.RIVET_ROOT.iterdir() if p.name not in ['public.json']}
                old_rules=set(k.rules);old_addresses=copy.deepcopy(k.addresses);failed=False;restarted=0
                def command(*args,**kwargs):
                    nonlocal failed,restarted
                    if args[-1:]==('reconcile-ipv6-hooks',):unit.write_text(unit_before.replace('[Install]','ExecStartPost=+new-ipv6-hook\n[Install]'))
                    if args[:2]==('systemctl','start'):
                        if not failed:
                            net.apply();failed=True;raise RuntimeError('new service failed after network hook')
                        self.assertTrue(net._fence_path().exists())
                        net.apply() # Old service startup is still transaction-fenced.
                        self.assertEqual((update.LIB/'admin.py').read_bytes(),b'# old admin\n')
                        self.assertEqual(unit.read_text(),unit_before)
                        restarted+=1
                    return SimpleNamespace(returncode=0)
                raw,digest=archive()
                with patch.object(update,'NETWORK_UNITS',(unit,)),patch.object(update,'ipv6_transaction_module',return_value=net),patch.object(update,'command',side_effect=command):
                    with self.assertRaisesRegex(RuntimeError,'new service failed'):update.update(raw,digest,'server')
                self.assertGreater(restarted,0);self.assertEqual(update.STATE.read_bytes(),state);self.assertEqual((update.RIVET_ROOT/'public.json').read_bytes(),public)
                self.assertEqual(k.rules,old_rules);self.assertEqual(k.addresses,old_addresses)
                self.assertEqual(k.receipt.read_bytes() if k.receipt.exists() else None,original_receipt)
                self.assertFalse(net._fence_path().exists());self.assertFalse((update.LIB/'dualstack.py').exists())
                self.assertEqual(k.forward.read_text().strip(),'0');self.assertEqual(k.ra.read_text().strip(),'1')
                for p,value in keys.items():self.assertEqual(p.read_bytes(),value)

    def test_updater_bad_network_snapshot_or_receipt_race_retains_recovery(self):
        for problem in ['snapshot','receipt','old-restart']:
            with self.subTest(problem=problem),deployment() as (root,data,events),kernel(root,update.DUAL_RECEIPT) as k:
                failed=False
                def command(*args,**kwargs):
                    nonlocal failed
                    if args[:2]==('systemctl','start'):
                        if not failed:
                            net.apply();failed=True
                            if problem=='snapshot':next(root.glob('.update-*/ipv6-before.json')).write_text('{}')
                            if problem=='receipt':k.receipt.write_text('{"owner":"FOREIGN"}')
                            raise RuntimeError('new service failed')
                        if problem=='old-restart':raise RuntimeError('old service also failed')
                    return SimpleNamespace(returncode=0)
                raw,digest=archive()
                with patch.object(update,'ipv6_transaction_module',return_value=net),patch.object(update,'command',side_effect=command):
                    with self.assertRaisesRegex(RuntimeError,'backup retained'):update.update(raw,digest,'server')
                recovery=list(root.glob('.update-recovery-*'));self.assertEqual(len(recovery),1)
                self.assertTrue((recovery[0]/'backup/ipv6-before.json').exists())


if __name__=='__main__':unittest.main()
