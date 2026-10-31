import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('network_under_test', Path(__file__).with_name('network_stack.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class AccountingTests(unittest.TestCase):
    def test_ike_rekey_reset_and_month_rollover(self):
        sa = {'remote-eap-id': b'u@xio', 'state': b'ESTABLISHED', 'uniqueid': b'1', 'child-sas': {'child': {'uniqueid': b'1', 'bytes-in': b'10', 'bytes-out': b'20'}}}
        d = {'users': {'u': {'revoked': False}}}
        state = {}
        with patch.object(m, 'ike_sas', return_value=[sa]), patch.object(m, 'run', return_value=b'generation'):
            m.ike_sample(d, state, '2026-10', 100)
            m.ike_sample(d, state, '2026-10', 101)
            self.assertEqual(state['u']['monthBytes'], 30)
            sa['child-sas']['child'].update(uniqueid=b'2', **{'bytes-in': b'4', 'bytes-out': b'5'})
            m.ike_sample(d, state, '2026-10', 102)
            self.assertEqual(state['u']['monthBytes'], 39)
            sa['child-sas']['child']['bytes-in'] = b'8'
            m.ike_sample(d, state, '2026-11', 103)
            self.assertEqual(state['u']['monthBytes'], 4)
            d['users']['u']['revoked'] = True
            sa['child-sas']['child']['bytes-in'] = b'50'
            m.ike_sample(d, state, '2026-11', 104)
            self.assertEqual(state['u']['monthBytes'], 4)

    def test_openvpn_reconnect_counts_new_session_without_double_counting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root/'openvpn-udp.status'
            def snapshot(epoch, rx, tx):
                status.write_text('HEADER\tCLIENT_LIST\tCommon Name\tConnected Since (time_t)\tBytes Received\tBytes Sent\nCLIENT_LIST\tu\t'+str(epoch)+'\t'+str(rx)+'\t'+str(tx)+'\n')
            d = {'users': {'u': {'revoked': False}}}
            with patch.object(m, 'ROOT', root), patch.object(m, 'STATE', root), patch.object(m, 'ike_sample'), patch.object(m, 'run', return_value=b'generation'):
                snapshot(10, 10, 20)
                first = m.stats(d)['u']['monthBytes']
                self.assertEqual(m.stats(d)['u']['monthBytes'], first)
                snapshot(20, 15, 25)
                self.assertEqual(m.stats(d)['u']['monthBytes'], first+40)
                snapshot(20, 17, 28)
                self.assertEqual(m.stats(d)['u']['monthBytes'], first+45)

class FirewallScopeTests(unittest.TestCase):
    def test_masquerade_rule_has_no_input_interface(self):
        # POSTROUTING rejects `-i` and the inbound policy match, so a scoped
        # MASQUERADE rule makes the whole install fail at firewall time.
        for subnet, iface, ipsec in [('10.80.0.0/24', 'xioovpn0', False),
                                     ('10.82.0.0/24', None, True)]:
            nat = m.firewall_rules(subnet, iface, 'eth0', ipsec)[0]
            self.assertEqual(nat[:3], ['-t', 'nat', 'POSTROUTING'])
            self.assertNotIn('-i', nat)
            self.assertNotIn('policy', nat)
            self.assertEqual(nat[nat.index('-o') + 1], 'eth0')

    def test_forward_rules_keep_arrival_scope(self):
        _, forward, reverse = m.firewall_rules('10.80.0.0/24', 'xioovpn0', 'eth0')
        self.assertEqual(forward[forward.index('-i') + 1], 'xioovpn0')
        self.assertEqual(reverse[reverse.index('-i') + 1], 'eth0')
        ipsec = m.firewall_rules('10.82.0.0/24', None, 'eth0', True)
        self.assertIn('ipsec', ipsec[1])
        self.assertIn('ipsec', ipsec[2])

if __name__ == '__main__':
    unittest.main()
