"""Pure mocked owner RPC boundary tests. No real connector/kernel/network calls."""
import ast
import base64
import copy
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cascade_native_rpc as rpc
from test_admin import m as admin

PRIVATE = base64.b64encode(b'p' * 32).decode()
PSK = base64.b64encode(b's' * 32).decode()
PUBLIC = base64.b64encode(b'b' * 32).decode()
DEPLOYMENT = {'id': 'base-server', 'owner': 'xio-managed-v1', 'users': {}}


def configuration():
    return dict(schema=1, enabled=True, ownerOptIn=True, role='bridge', backend='userspace',
                interface='xiocascade0', innerFamilies=['ipv4', 'ipv6'], sourceMode='preserve',
                localAddresses={'ipv4': '10.209.0.1', 'ipv6': 'fd09::1'},
                peerAddresses={'ipv4': '10.209.0.2', 'ipv6': 'fd09::2'},
                peer={'publicKey': PUBLIC, 'host': '2001:db8::2', 'port': 9443},
                privateKey=PRIVATE, presharedKey=PSK)


def request(operation='inspect', **fields):
    result = dict(action='cascade-native', serverId=DEPLOYMENT['id'], operation=operation)
    result.update(fields)
    return result


def capabilities(expired=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    return dict(schema=1, enabled=True, connectorId='connector-fixture', revision=1,
                observedAt=(now-datetime.timedelta(seconds=10)).isoformat(),
                expiresAt=(now+datetime.timedelta(seconds=-1 if expired else 30)).isoformat(),
                awg=dict(ipv4=True, ipv6=True, reason4='source_bound_inner_probe_verified', reason6='source_bound_inner_probe_verified'),
                rivet=dict(ipv4=True, ipv6=True, reason4='source_bound_inner_probe_verified', reason6='source_bound_inner_probe_verified'))


def status(expired=False):
    config = configuration();config.pop('privateKey');config.pop('presharedKey')
    return dict(schema=1, enabled=True, connectorId='connector-fixture', revision=1,
                phase='applied', infrastructureReady=True, reasons=[], config=config,
                capabilities=capabilities(expired))


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.connector = SimpleNamespace(configure=Mock(), reconcile_native=Mock(),
                                         inspect=Mock(side_effect=lambda: status()),
                                         verify=Mock(side_effect=lambda: capabilities()),
                                         remove=Mock(return_value={'schema': 1, 'enabled': False}))
        self.network = SimpleNamespace(apply=Mock())
        self.public = Mock(return_value={'id': DEPLOYMENT['id'], 'host': 'fixture.example'})
        self.loader = patch.object(rpc, '_load', side_effect=lambda name: self.connector if name == 'cascade_native' else self.network).start()
        self.process = patch.object(rpc.subprocess, 'run').start()
        self.environment = patch.dict(os.environ, {}, clear=True);self.environment.start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.environment.stop)

    def call(self, req, **kwargs):
        return rpc.dispatch(req, DEPLOYMENT, public=self.public, **kwargs)

    def assert_no_effect(self):
        self.loader.assert_not_called();self.process.assert_not_called();self.public.assert_not_called()
        for value in vars(self.connector).values():value.assert_not_called()
        self.network.apply.assert_not_called()

    def test_all_delegated_and_forced_contexts_fail_before_import_or_process(self):
        for actor in ('a'*32, '', False, 0):
            with self.subTest(actor=actor):
                with self.assertRaises(rpc.NativeCascadeRPCError) as result:self.call(request(), actor=actor)
                self.assertEqual(result.exception.errorCode, 'OWNER_REQUIRED');self.assertFalse(result.exception.outcomeUnknown)
                self.assert_no_effect()
        with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': ''}):
            with self.assertRaises(rpc.NativeCascadeRPCError):self.call(request())
        self.assert_no_effect()

    def test_exact_envelope_id_types_operations_and_confirm_are_rejected_first(self):
        values = [request(serverId='other'),request(serverId=None),request(serverId=True),
                  request(operation='shell'),request(operation=['inspect']),request(root='/tmp'),
                  request(backend='fake'),request(targets={'ipv4':'127.0.0.1'}),
                  request(configuration={}),request(confirmDirect=True),
                  request('configure'),request('configure', configuration=[]),
                  request('remove'),request('remove', confirmDirect=False),
                  request('remove', confirmDirect=1),request('remove', confirmDirect='true')]
        missing=request();missing.pop('serverId');values.append(missing)
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(rpc.NativeCascadeRPCError) as result:self.call(value)
                self.assertFalse(result.exception.outcomeUnknown);self.assert_no_effect()

    def test_nested_configuration_shape_unknowns_and_key_types_rejected_before_A(self):
        for change in (lambda c:c.update(root='/tmp'), lambda c:c.update(privateKey=True),
                       lambda c:c.update(privateKey='invalid'),lambda c:c.update(schema=True),
                       lambda c:c.update(enabled=1),lambda c:c.update(innerFamilies=['ipv4',False]),
                       lambda c:c['peer'].update(argv=['unsafe']),lambda c:c['peer'].update(port=True),
                       lambda c:c.update(localAddresses={'ipv4':'x'})):
            config=configuration();change(config)
            with self.subTest(config=config):
                with self.assertRaises(rpc.NativeCascadeRPCError) as result:self.call(request('configure',configuration=config))
                self.assertEqual(result.exception.errorCode,'INVALID_REQUEST');self.assertFalse(result.exception.outcomeUnknown);self.assert_no_effect()

    def test_preflight_fixed_local_commands_report_route_observation_not_readiness(self):
        self.process.side_effect=[SimpleNamespace(returncode=0,stdout=json.dumps([{'dev':'eth0','prefsrc':'192.0.2.7'}]),stderr=PRIVATE),
                                  SimpleNamespace(returncode=2,stdout='',stderr=PSK)]
        result=self.call(request('preflight'))
        native=result['nativeCascade'];self.assertTrue(result['ok'])
        self.assertEqual(native['egress'],{'ipv4':{'routePresent':True,'interface':'eth0','source':'192.0.2.7'},
                                           'ipv6':{'routePresent':False,'interface':None}})
        self.assertNotIn('capabilities',native);self.assertNotIn('ready',native)
        self.loader.assert_not_called()
        expected=[['ip','-j','-4','route','get','1.1.1.1'],['ip','-j','-6','route','get','2606:4700:4700::1111']]
        self.assertEqual([call.args[0] for call in self.process.call_args_list],expected)
        for call in self.process.call_args_list:
            self.assertEqual(call.kwargs['timeout'],3);self.assertEqual(call.kwargs['stdin'],subprocess.DEVNULL)
            self.assertNotIn('input',call.kwargs)
        self.assertNotIn(PRIVATE,json.dumps(result));self.assertNotIn(PSK,json.dumps(result))

    def test_preflight_malformed_interface_json_and_timeout_never_claim_route_success(self):
        for value in ('invalid',json.dumps([{'dev':'eth0;unsafe'}]),json.dumps([{'dev':'eth0','prefsrc':'not-an-address'}])):
            self.process.return_value=SimpleNamespace(returncode=0,stdout=value,stderr=PRIVATE)
            with self.subTest(value=value),self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('preflight'))
            self.assertFalse(error.exception.outcomeUnknown);self.assertNotIn(PRIVATE,str(error.exception))
        self.process.side_effect=subprocess.TimeoutExpired(['ip',PRIVATE],3,output=PSK)
        with self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('preflight'))
        self.assertEqual(error.exception.errorCode,'TIMEOUT');self.assertFalse(error.exception.outcomeUnknown)

    def test_configure_completion_precedes_dualstack_and_fresh_inspect_without_probe(self):
        entered=threading.Event();complete=threading.Event();events=[];results=[]
        def configure(config):
            entered.set()
            if not complete.wait(2):raise TimeoutError('fixture')
            events.append('configure-complete')
        self.connector.configure.side_effect=configure
        self.network.apply.side_effect=lambda:events.append('native-address-apply')
        self.connector.inspect.side_effect=lambda:events.append('fresh-inspect') or status()
        worker=threading.Thread(target=lambda:results.append(self.call(request('configure',configuration=configuration()))))
        worker.start()
        try:
            self.assertTrue(entered.wait(1));self.network.apply.assert_not_called();self.connector.inspect.assert_not_called()
        finally:complete.set();worker.join(3)
        self.assertFalse(worker.is_alive());self.assertTrue(results[0]['ok'])
        self.assertEqual(events,['configure-complete','native-address-apply','fresh-inspect'])
        self.connector.verify.assert_not_called();self.connector.remove.assert_not_called();self.process.assert_not_called()
        self.connector.configure.assert_called_once_with(configuration())

    def test_inspect_is_passive_and_reconcile_orders_idempotent_hooks(self):
        self.call(request());self.connector.inspect.assert_called_once();self.network.apply.assert_not_called()
        self.connector.verify.assert_not_called();self.connector.configure.assert_not_called();self.process.assert_not_called()
        events=[]
        self.connector.reconcile_native.side_effect=lambda **kw:events.append(('A',kw))
        self.network.apply.side_effect=lambda:events.append(('native-apply',{}))
        self.connector.inspect.side_effect=lambda:events.append(('inspect',{})) or status()
        for _ in range(2):self.call(request('reconcile'))
        self.assertEqual([event[0] for event in events],['A','native-apply','inspect']*2)
        self.assertEqual(events[0][1],{'reason':'owner-rpc'})

    def test_verify_is_only_explicit_A_probe_and_stale_positive_is_not_exported(self):
        self.connector.verify.return_value=capabilities(expired=True);self.connector.verify.side_effect=None
        result=self.call(request('verify'))['nativeCascade']
        self.connector.verify.assert_called_once_with();self.network.apply.assert_not_called();self.connector.inspect.assert_not_called()
        self.assertFalse(result['awg']['ipv4']);self.assertFalse(result['rivet']['ipv6'])
        self.assertEqual(result['awg']['reason4'],'stale_readiness')

    def test_remove_requires_explicit_direct_confirmation_and_never_runs_on_error(self):
        result=self.call(request('remove',confirmDirect=True))
        self.assertFalse(result['nativeCascade']['enabled']);self.connector.remove.assert_called_once_with(confirm_direct=True)
        self.network.apply.assert_not_called()

    def test_timeout_after_partial_mutation_is_safe_unknown_and_never_auto_removes(self):
        for operation in ('configure','reconcile','verify','remove'):
            self.connector.configure.reset_mock(side_effect=True)
            self.connector.reconcile_native.reset_mock(side_effect=True)
            self.connector.verify.reset_mock(side_effect=True)
            self.connector.remove.reset_mock(side_effect=True)
            method={'configure':'configure','reconcile':'reconcile_native','verify':'verify','remove':'remove'}[operation]
            getattr(self.connector,method).side_effect=subprocess.TimeoutExpired(['unsafe',PRIVATE],3,output=PSK,stderr=PRIVATE)
            fields={'configuration':configuration()} if operation=='configure' else {'confirmDirect':True} if operation=='remove' else {}
            with self.subTest(operation=operation),self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request(operation,**fields))
            self.assertEqual(error.exception.errorCode,'TIMEOUT');self.assertTrue(error.exception.outcomeUnknown)
            self.assertNotIn(PRIVATE,str(error.exception));self.assertNotIn(PSK,str(error.exception));self.assertTrue(error.exception.__suppress_context__)
            if operation!='remove':self.connector.remove.assert_not_called()

    def test_import_failure_is_known_but_post_apply_public_failure_is_unknown(self):
        self.loader.side_effect=ImportError(PRIVATE)
        with self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('configure',configuration=configuration()))
        self.assertFalse(error.exception.outcomeUnknown);self.connector.configure.assert_not_called()
        self.loader.side_effect=lambda name:self.connector if name=='cascade_native' else self.network
        self.public.side_effect=RuntimeError(PRIVATE+' '+PSK)
        with self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('configure',configuration=configuration()))
        self.assertTrue(error.exception.outcomeUnknown);self.connector.remove.assert_not_called();self.assertNotIn(PRIVATE,str(error.exception))

    def test_incompatible_module_or_missing_apply_fails_before_admission(self):
        self.loader.side_effect=lambda name:SimpleNamespace() if name=='cascade_native' else self.network
        with self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('configure',configuration=configuration()))
        self.assertEqual(error.exception.errorCode,'MODULE_UNAVAILABLE');self.assertFalse(error.exception.outcomeUnknown)
        self.loader.side_effect=lambda name:self.connector if name=='cascade_native' else SimpleNamespace()
        with self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request('configure',configuration=configuration()))
        self.assertFalse(error.exception.outcomeUnknown);self.connector.configure.assert_not_called()

    def test_readonly_public_diagnostic_strings_are_not_exported(self):
        value=capabilities();value['awg']['reason4']=PRIVATE
        self.public.return_value={'id':'base-server','nativeProfileReadiness':value,'privateKey':PRIVATE}
        result=self.call(request())
        self.assertNotIn(PRIVATE,json.dumps(result));self.assertNotIn('privateKey',json.dumps(result))

    def test_sanitized_whitelist_and_output_suppression_never_export_secrets(self):
        raw=status();raw.update(privateKey=PRIVATE,stdout=PSK,dump=PRIVATE)
        raw['config'].update(privateKey=PRIVATE,presharedKey=PSK)
        raw['config']['peer'].update(privateKey=PRIVATE)
        raw['reasons']=[PRIVATE,'live_inspection_failed:'+PSK]
        self.connector.inspect.side_effect=lambda:raw
        self.public.return_value={'id':'base-server','privateKey':PRIVATE,'nested':{'presharedKey':PSK,'note':PRIVATE}}
        def configure(value):print(PRIVATE);print(PSK,file=sys.stderr)
        self.connector.configure.side_effect=configure
        stdout=io.StringIO();stderr=io.StringIO()
        with patch('sys.stdout',stdout),patch('sys.stderr',stderr):result=self.call(request('configure',configuration=configuration()))
        self.assertEqual(stdout.getvalue(),'');self.assertEqual(stderr.getvalue(),'')
        encoded=json.dumps(result);self.assertNotIn(PRIVATE,encoded);self.assertNotIn(PSK,encoded)
        self.assertNotIn('privateKey',encoded);self.assertNotIn('presharedKey',encoded);self.assertNotIn('stdout',encoded)

    def test_missing_or_malformed_status_is_failure_not_success(self):
        for value in (None,{},dict(status(),enabled='true'),dict(status(),phase='arbitrary-private-data')):
            self.connector.inspect.side_effect=None;self.connector.inspect.return_value=value
            with self.subTest(value=value),self.assertRaises(rpc.NativeCascadeRPCError) as error:self.call(request())
            self.assertEqual(error.exception.errorCode,'INVALID_RESULT');self.assertFalse(error.exception.outcomeUnknown)


class AdminIntegrationTests(unittest.TestCase):
    def test_admin_rejects_owner_identity_and_envelope_before_RPC_import(self):
        imported=[];original=__import__
        def importing(name,*args,**kwargs):
            if name=='cascade_native_rpc':imported.append(name)
            return original(name,*args,**kwargs)
        with patch.object(admin,'load',return_value=DEPLOYMENT),patch('builtins.__import__',side_effect=importing),patch.dict(os.environ,{},clear=True):
            for req,actor in [(request(),'a'*32),(request(serverId='wrong'),None),(request(root='/tmp'),None),(request('remove',confirmDirect=1),None)]:
                with self.subTest(req=req,actor=actor),self.assertRaises(admin._NativeCascadeRequestError):admin.dispatch(req,actor)
            self.assertEqual(imported,[])
            with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':''}):
                with self.assertRaises(admin._NativeCascadeRequestError):admin.dispatch(request())
            self.assertEqual(imported,[])

    def cli(self, req, args=None):
        # Execute the real __main__ AST using mocked load/public/process/flock.
        # No root paths are opened and no real service/network command executes.
        tree=ast.parse(Path(admin.__file__).read_text())
        block=next(node for node in tree.body if isinstance(node,ast.If) and isinstance(node.test,ast.Compare) and isinstance(node.test.left,ast.Name) and node.test.left.id=='__name__')
        code=compile(ast.Module(body=[block],type_ignores=[]),admin.__file__,'exec')
        namespace=dict(admin.__dict__,__name__='__main__')
        stdout=io.StringIO();stdin=SimpleNamespace(buffer=io.BytesIO(json.dumps(req).encode()))
        with patch.object(admin,'load',return_value=DEPLOYMENT),patch.object(admin,'public',return_value={'id':'base-server'}),patch.object(os,'geteuid',return_value=0),patch.object(admin.fcntl,'flock'),patch('builtins.open',return_value=io.StringIO()),patch.object(sys,'argv',['admin.py',*(args or [])]),patch.object(sys,'stdin',stdin),patch.object(sys,'stdout',stdout),patch.dict(os.environ,{},clear=True):
            try:exec(code,namespace)
            except SystemExit as error:self.assertEqual(error.code,1)
        return json.loads(stdout.getvalue())

    def test_CLI_wrong_owner_id_and_unknown_fields_are_typed_known_failures(self):
        for req,args,code in [(request(),['--delegate','a'*32],'OWNER_REQUIRED'),(request(serverId='wrong'),[],'SERVER_IDENTITY'),(request(root='/tmp'),[],'INVALID_REQUEST')]:
            with self.subTest(code=code),patch.object(rpc,'_load') as loader,patch.object(rpc.subprocess,'run') as process:
                result=self.cli(req,args);self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],code);self.assertFalse(result['outcomeUnknown'])
                loader.assert_not_called();process.assert_not_called()

    def test_CLI_error_redaction_and_mutation_unknown_survive_dispatch(self):
        connector=SimpleNamespace(configure=Mock(side_effect=subprocess.TimeoutExpired(['unsafe',PRIVATE],3,output=PSK,stderr=PRIVATE)),inspect=Mock(),remove=Mock())
        network=SimpleNamespace(apply=Mock())
        with patch.object(rpc,'_load',side_effect=lambda name:connector if name=='cascade_native' else network):
            result=self.cli(request('configure',configuration=configuration()))
        self.assertFalse(result['ok']);self.assertEqual(result['errorCode'],'TIMEOUT');self.assertTrue(result['outcomeUnknown'])
        self.assertNotIn(PRIVATE,json.dumps(result));self.assertNotIn(PSK,json.dumps(result));connector.remove.assert_not_called()


if __name__=='__main__':unittest.main()
