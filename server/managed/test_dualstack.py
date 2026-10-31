import unittest
from unittest.mock import patch
import dualstack

class DualstackTests(unittest.TestCase):
    def test_ipv6_only_server_selects_the_ipv6_uplink(self):
        with patch.object(dualstack,'routes',side_effect=lambda family: [] if family=='-4' else [{'dev':'eth6','metric':2}]):
            self.assertEqual(dualstack.outbound(),'eth6')
            self.assertTrue(dualstack.ipv6_ready())
    def test_dual_stack_prefers_the_existing_ipv4_uplink(self):
        with patch.object(dualstack,'routes',return_value=[{'dev':'eth0'}]):
            self.assertEqual(dualstack.outbound(),'eth0')
    def test_no_route_and_invalid_interface_fail_before_mutation(self):
        with patch.object(dualstack,'routes',return_value=[]):
            self.assertFalse(dualstack.ipv6_ready())
            with self.assertRaises(RuntimeError):dualstack.outbound()
        with patch.object(dualstack,'routes',return_value=[{'dev':'eth0;false'}]):
            with self.assertRaises(AssertionError):dualstack.outbound()

    def test_ipv6_config_preserves_keys_and_rollback_restores_only_owned_rules(self):
        import json,tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary);state=folder/'state.json';receipt=folder/'receipt.json';up=folder/'network-up';forward=folder/'forward';forward.write_text('0')
            owned={'args':['--zone=trusted'],'option':'rich-rule','value':'rule family="ipv6" source address="fd78:1::/64" drop'}
            foreign=dict(owned,value='rule family="ipv6" source address="fd99::/64" drop')
            state.write_text(json.dumps({'owner':'xio-managed-v1','firewall':{'kind':'firewalld','added':[owned,foreign]}}))
            (folder/'config.json').write_text(json.dumps({'inbounds':[{'listen':'0.0.0.0','privateKey':'unchanged-test-key'}]}))
            (folder/'cloak.json').write_text(json.dumps({'BindAddr':['0.0.0.0:9443'],'PrivateKey':'unchanged-test-key'}))
            (folder/'tcp.ovpn').write_text('server 10.81.0.0 255.255.255.0\n');up.write_text('#!/bin/sh\n');up.chmod(0o755)
            calls=[];rollback=False
            def call(*args,**kwargs):
                calls.append(args)
                return type('Result',(),{'returncode':1 if rollback and any(str(a).startswith('--query-rich-rule=') for a in args) else 0})()
            with patch.object(dualstack,'FORWARDING',forward),patch.object(dualstack,'SYS_NET',folder),patch.object(dualstack,'STATE',state),patch.object(dualstack,'RECEIPT',receipt),patch.object(dualstack,'CONFIG_DIR',folder),patch.object(dualstack,'NETWORK_UP',up),patch.object(dualstack.os,'geteuid',return_value=0),patch.object(dualstack,'ipv6_ready',return_value=True),patch.object(dualstack,'listener',return_value='::'),patch.object(dualstack,'call',side_effect=call):
                dualstack.configure()
                config=json.loads((folder/'config.json').read_text())
                self.assertEqual(config['inbounds'][0],{'listen':'::','privateKey':'unchanged-test-key'})
                self.assertEqual(json.loads((folder/'cloak.json').read_text())['PrivateKey'],'unchanged-test-key')
                self.assertIn('server-ipv6 fd80:1::/64',(folder/'tcp.ovpn').read_text())
                self.assertEqual(json.loads(receipt.read_text())['removedLegacyRules'],[owned])
                self.assertFalse(any(foreign['value'] in str(args) for args in calls))
                rollback=True;dualstack.remove(True)
                self.assertTrue(any('--add-rich-rule='+owned['value'] in args for args in calls))
                self.assertFalse(receipt.exists())
