"""Native lifecycle/metadata contracts; all kernel and connector operations mocked."""
from contextlib import nullcontext,ExitStack
from datetime import datetime,timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dualstack as net
from test_admin import m as admin
from test_rivet_public import setup as rivet


def stamp(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')

def desired(ipv4=True,ipv6=True):return {protocol:dict(ipv4=ipv4,ipv6=ipv6) for protocol in ('awg','rivet')}

def capabilities(now=1000, ipv4=True, ipv6=True):
    return dict(schema=1, enabled=True, connectorId='fixture', revision=2,
                observedAt=stamp(now-1), expiresAt=stamp(now+30),
                awg=dict(ipv4=ipv4, ipv6=ipv6, reason4='fixture', reason6='fixture'),
                rivet=dict(ipv4=ipv4, ipv6=ipv6, reason4='fixture', reason6='fixture'))


class OptionalConnectorTests(unittest.TestCase):
    def test_no_module_no_config_preserves_legacy_without_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(net,'NATIVE_MODULE',root/'absent.py'), patch.object(net,'NATIVE_CONFIG_ROOT',root/'absent-config'), patch.object(net,'call') as command:
                self.assertIsNone(net.native_capabilities())
                self.assertIsNone(net.reconcile_native())
                command.assert_not_called()

    def test_configured_but_missing_module_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(net,'NATIVE_MODULE',root/'absent.py'), patch.object(net,'NATIVE_CONFIG_ROOT',root):
                for function in (net.native_capabilities,net.desired_native_families,net.reconcile_native):
                    with self.assertRaisesRegex(RuntimeError,'module is missing'):
                        function()

    def test_module_no_opt_in_preserves_legacy(self):
        with patch.object(net,'_native_module',return_value=SimpleNamespace(native_capabilities=lambda **kw:None)):
            self.assertIsNone(net.native_capabilities())

    def test_expired_future_and_invalid_timestamps_never_advertise_ready(self):
        for changes in [dict(expiresAt=stamp(999)),dict(observedAt=stamp(1010)),dict(observedAt=True),dict(expiresAt=float('nan'))]:
            value=dict(capabilities(),**changes)
            with self.subTest(changes=changes), patch.object(net.time,'time',return_value=1000), patch.object(net,'_native_module',return_value=SimpleNamespace(native_capabilities=lambda **kw:value)):
                result=net.native_capabilities()
                self.assertFalse(result['awg']['ipv4'])
                self.assertFalse(result['rivet']['ipv6'])
                self.assertEqual(result['rivet']['reason6'],'stale-readiness')
                self.assertTrue(value['awg']['ipv4']) # Do not mutate connector evidence.

    def test_exact_boolean_contract_rejects_optimistic_strings(self):
        value=capabilities();value['awg']['ipv6']='true'
        with patch.object(net,'_native_module',return_value=SimpleNamespace(native_capabilities=lambda **kw:value)):
            with self.assertRaisesRegex(RuntimeError,'family readiness'):net.native_capabilities()

    def test_malformed_schema_and_missing_readiness_identity_fail_closed(self):
        for changes in (dict(schema=True),dict(connectorId=None),dict(revision=True)):
            value=dict(capabilities(),**changes)
            with self.subTest(changes=changes),patch.object(net,'_native_module',return_value=SimpleNamespace(native_capabilities=lambda **kw:value)):
                with self.assertRaisesRegex(RuntimeError,'Invalid native cascade readiness'):net.native_capabilities()

    def test_fresh_route_observation_is_returned_without_mutation_or_reconcile(self):
        value=capabilities(ipv6=False)
        module=SimpleNamespace(native_capabilities=lambda **kw:value, reconcile_native=unittest.mock.Mock())
        with patch.object(net.time,'time',return_value=1000), patch.object(net,'_native_module',return_value=module):
            self.assertEqual(net.native_capabilities(),value)
            module.reconcile_native.assert_not_called()


class LifecycleOrderingTests(unittest.TestCase):
    def test_awg_guard_covers_firewalld_early_return(self):
        events=[]
        network=SimpleNamespace(reconcile_native=lambda **kw:events.append(kw['reason']))
        with patch.object(admin.stack.network,'dualstack',return_value=network), patch.object(admin,'firewall_managed',side_effect=lambda *a:events.append('base-firewalld') or True):
            admin.rules({})
        self.assertEqual(events,['awg-firewall-before','base-firewalld','awg-firewall-after'])

    def test_awg_partial_failure_still_reconciles_after(self):
        events=[]
        network=SimpleNamespace(reconcile_native=lambda **kw:events.append(kw['reason']))
        def base(*a):events.append('partial-base');raise RuntimeError('fixture failure')
        with patch.object(admin.stack.network,'dualstack',return_value=network),patch.object(admin,'_rules',side_effect=base):
            with self.assertRaisesRegex(RuntimeError,'fixture failure'):admin.rules({})
        self.assertEqual(events,['awg-firewall-before','partial-base','awg-firewall-after'])

    def test_awg_missing_connector_stops_before_base_mutation(self):
        network=SimpleNamespace(reconcile_native=unittest.mock.Mock(side_effect=RuntimeError('missing connector')))
        with patch.object(admin.stack.network,'dualstack',return_value=network),patch.object(admin,'_rules') as base:
            with self.assertRaisesRegex(RuntimeError,'missing connector'):admin.rules({})
            base.assert_not_called()

    def test_removal_does_not_reinstall_connector_rules(self):
        with patch.object(admin,'_rules') as base,patch.object(admin.stack.network,'dualstack') as network:
            admin.rules({},True)
            base.assert_called_once_with({},True);network.assert_not_called()
        with patch.object(rivet,'_main') as base,patch.object(rivet,'reconcile_native') as reconcile,patch.object(rivet.sys,'argv',['setup.py','remove']):
            rivet.main();base.assert_called_once();reconcile.assert_not_called()

    def test_dualstack_early_return_and_failure_reconcile_outside_lock(self):
        for failure in (False,True):
            events=[]
            def base():
                events.append('base-no-main-v6')
                if failure:raise RuntimeError('fixture failure')
                return {'ipv6Forwarding':False}
            with self.subTest(failure=failure),patch.object(net,'_lock',return_value=nullcontext()),patch.object(net,'_apply',side_effect=base),patch.object(net,'reconcile_native',side_effect=lambda **kw:events.append(kw['reason'])):
                if failure:
                    with self.assertRaises(RuntimeError):net.apply()
                else:self.assertFalse(net.apply()['ipv6Forwarding'])
            self.assertEqual(events,['dualstack-before','base-no-main-v6','dualstack-after'])

    def test_rivet_network_reapply_and_install_failure_restore_hook_priority(self):
        for action in ('network','install'):
            events=[]
            def base(*a):events.append('base-'+action);raise RuntimeError('fixture failure')
            with self.subTest(action=action),patch.object(rivet.sys,'argv',['setup.py',action]),patch.object(rivet,'_main',side_effect=base),patch.object(rivet,'reconcile_native',side_effect=lambda reason:events.append(reason)):
                with self.assertRaisesRegex(RuntimeError,'fixture failure'):rivet.main()
            self.assertEqual(events,['rivet-'+action+'-before','base-'+action,'rivet-'+action+'-after'])


class PublicMetadataTests(unittest.TestCase):
    def public(self,native,main6):
        network=SimpleNamespace(capabilities=lambda:dict(ipv6DefaultRoute=main6),native_capabilities=lambda **kw:native,desired_native_families=lambda:desired())
        deployment=dict(id='server',host='fixture.example',publicKeys={},awg={},protocols=['awg'],rivet={'serverName':'fixture.example'})
        with patch.object(admin.stack.network,'dualstack',return_value=network):return admin.public(deployment)

    def test_no_opt_in_keeps_legacy_metadata(self):
        for ipv6 in (False,True):
            result=self.public(None,ipv6)
            self.assertNotIn('nativeProfileReadiness',result)
            self.assertEqual(result['rivet']['ipv6'],ipv6)

    def test_native_ipv6_ready_without_host_main_ipv6_default(self):
        value=capabilities()
        result=self.public(value,False)
        self.assertFalse(result['networkCapabilities']['ipv6DefaultRoute'])
        self.assertTrue(result['rivet']['ipv6'])
        self.assertEqual(result['nativeProfileReadiness'],dict(value,requiredFamilies=desired()))

    def test_revision_change_between_readiness_and_intent_fails_closed(self):
        first=capabilities();second=dict(first,revision=3)
        network=SimpleNamespace(capabilities=lambda:dict(ipv6DefaultRoute=False),native_capabilities=unittest.mock.Mock(side_effect=[first,second]),desired_native_families=lambda:desired())
        deployment=dict(id='server',host='fixture.example',publicKeys={},awg={},protocols=['awg'])
        with patch.object(admin.stack.network,'dualstack',return_value=network):
            with self.assertRaisesRegex(RuntimeError,'changed during readiness'):admin.public(deployment)

    def test_native_down_overrides_host_ipv6_default(self):
        result=self.public(capabilities(ipv4=False,ipv6=False),True)
        self.assertFalse(result['rivet']['ipv6'])
        self.assertFalse(result['nativeProfileReadiness']['awg']['ipv4'])


class NativeProvisioningTests(unittest.TestCase):
    def test_policy_only_ipv6_adds_only_desired_owned_existing_interfaces(self):
        for opt_in in (None,desired(ipv4=False,ipv6=True),desired(ipv6=False)):
            with self.subTest(opt_in=opt_in),tempfile.TemporaryDirectory() as directory,ExitStack() as patches:
                root=Path(directory);links=root/'links';links.mkdir()
                for interface in ('xioawg0','xiorivet','foreign0'):(links/interface).mkdir()
                state=root/'state';state.write_text(json.dumps(dict(owner='xio-managed-v1',protocols=['awg'],rivet=True)))
                forwarding=root/'forwarding';forwarding.write_text('0\n')
                receipt=root/'receipt';calls=[]
                def command(*args,**kw):
                    calls.append(args)
                    if args[0]=='sysctl':forwarding.write_text('1\n')
                    return SimpleNamespace(returncode=0,stdout='[]')
                for name,value in dict(STATE=state,SYS_NET=links,FORWARDING=forwarding,RECEIPT=receipt).items():patches.enter_context(patch.object(net,name,value))
                patches.enter_context(patch.object(net.os,'geteuid',return_value=0))
                patches.enter_context(patch.object(net,'routes',return_value=[]))
                patches.enter_context(patch.object(net,'desired_native_families',return_value=opt_in))
                patches.enter_context(patch.object(net,'call',side_effect=command))
                result=net._apply()
                self.assertFalse(any('route' in call or 'rule' in call or 'iptables' in call or 'foreign0' in call for call in calls))
                if opt_in is not None and opt_in['awg']['ipv6']:
                    self.assertTrue(result['ipv6Forwarding'])
                    self.assertEqual(json.loads(receipt.read_text())['addresses'],[['xioawg0','fd78:1::1/64'],['xiorivet','fd79:1::1/64']])
                else:
                    self.assertFalse(result['ipv6Forwarding']);self.assertFalse(receipt.exists());self.assertEqual(calls,[])

    def test_ra_guard_precedes_native_effects_and_no_main6_still_provisions(self):
        for has_default in (True,False):
            with self.subTest(main6=has_default),tempfile.TemporaryDirectory() as directory,ExitStack() as patches:
                root=Path(directory);links=root/'links';links.mkdir()
                for interface in ('xioawg0','xiorivet'):(links/interface).mkdir()
                ipv6=root/'ipv6';(ipv6/'eth0').mkdir(parents=True)
                accept=ipv6/'eth0'/'accept_ra';accept.write_text('1\n')
                forwarding=root/'forwarding';forwarding.write_text('0\n')
                state=root/'state';state.write_text(json.dumps(dict(owner='xio-managed-v1',protocols=['awg'],rivet=True)))
                receipt=root/'receipt';alive=[has_default];events=[];addresses={interface:[] for interface in ('xioawg0','xiorivet')}
                def route_snapshot(family):
                    self.assertEqual(family,'-6');events.append('main6-snapshot')
                    return [dict(dev='eth0',protocol='ra')] if alive[0] else []
                def command(*args,**kw):
                    if args[:5]==('ip','-j','-6','address','show'):
                        return SimpleNamespace(returncode=0,stdout=json.dumps([dict(addr_info=addresses[args[-1]])]))
                    if args[:4]==('ip','-6','address','add'):
                        address=args[4];addresses[args[-1]].append(dict(local=address.split('/')[0],prefixlen=64))
                    if args[0]=='sysctl':
                        # Kernel model: forwarding suppresses RA unless the physical
                        # uplink was protected BEFORE this effect, not afterwards.
                        if accept.read_text().strip()!='2':alive[0]=False
                        forwarding.write_text('1\n')
                    return SimpleNamespace(returncode=1 if args[0]=='ip6tables' and '-C' in args else 0,stdout='[]')
                original_effect=net._effect
                def effect(kind,value,action):
                    events.append(kind)
                    return original_effect(kind,value,action)
                for name,value in dict(STATE=state,SYS_NET=links,IPV6_SYS=ipv6,FORWARDING=forwarding,RECEIPT=receipt).items():patches.enter_context(patch.object(net,name,value))
                patches.enter_context(patch.object(net.os,'geteuid',return_value=0))
                sampled=patches.enter_context(patch.object(net,'routes',side_effect=route_snapshot))
                patches.enter_context(patch.object(net,'desired_native_families',return_value=desired(ipv4=False,ipv6=True)))
                patches.enter_context(patch.object(net,'call',side_effect=command))
                patches.enter_context(patch.object(net,'_effect',side_effect=effect))
                result=net._apply();saved=json.loads(receipt.read_text())
                self.assertTrue(result['ipv6Forwarding']);self.assertEqual(forwarding.read_text().strip(),'1')
                self.assertEqual(alive[0],has_default);sampled.assert_called_once_with('-6')
                self.assertEqual(events[0],'main6-snapshot')
                self.assertEqual(saved['addresses'],[['xioawg0','fd78:1::1/64'],['xiorivet','fd79:1::1/64']])
                self.assertEqual(saved['oldForward'],'0')
                if has_default:
                    self.assertLess(events.index('ra'),events.index('address'));self.assertLess(events.index('ra'),events.index('forward'))
                    self.assertEqual(saved['acceptRa'],{'eth0':'1'})
                else:
                    self.assertNotIn('ra',events);self.assertNotIn('acceptRa',saved);self.assertEqual(accept.read_text().strip(),'1')

    def test_missing_owned_native_interface_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(net,'SYS_NET',Path(directory)),patch.object(net,'call') as command:
            self.assertFalse(net._ensure_native_ipv6(dict(protocols=['awg'],rivet=True),desired()))
            command.assert_not_called()

    def test_invalid_desired_family_types_fail_closed(self):
        value=desired();value['rivet']['ipv6']='true'
        with patch.object(net,'_native_module',return_value=SimpleNamespace(desired_native_families=lambda **kw:value)):
            with self.assertRaisesRegex(RuntimeError,'family intent'):net.desired_native_families()

    def test_connector_config_read_or_ownership_failure_is_not_legacy(self):
        for function in (net.native_capabilities,net.desired_native_families,net.reconcile_native):
            with self.subTest(function=function.__name__),patch.object(net,'_native_module',side_effect=RuntimeError('unowned or unreadable state')):
                with self.assertRaisesRegex(RuntimeError,'unowned or unreadable'):function()


if __name__=='__main__':unittest.main()
