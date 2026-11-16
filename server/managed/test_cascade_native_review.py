#!/usr/bin/env python3
"""Reviewer regressions: no host kernel/systemd mutation; private fixture files only."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch
from test_cascade_native import config, n, KEY


def row_for(rule, *, detached=False):
    row = {'priority': int(rule[1]), 'src': 'all'}
    if 'from' in rule:
        address, prefix = rule[rule.index('from') + 1].split('/')
        row.update(src=address, srclen=int(prefix))
    if 'iif' in rule:
        row['iif'] = rule[rule.index('iif') + 1]
        if detached: row['iif_detached'] = None
    if 'fwmark' in rule: row['fwmark'] = rule[rule.index('fwmark') + 1].split('/')[0]
    if rule[-1] == 'prohibit': row['action'] = 'prohibit'
    else: row['table'] = str(n.TABLE)
    return row


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-review-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'owner'; self.root.mkdir(mode=0o700)
        c = n.validate_config(config())
        self.state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='review', revision=1,
                          config=c, configHash=n.digest(c), phase='applied', proofs={})
        n.save(self.root, self.state)
        self.spec = n.plan(c)
        self.rows = {family: [row_for(rule) for rule in rules] for family, rules in self.spec['policy'].items()}

    def tearDown(self): self.temp.cleanup()

    def test_fwmark_effective_full_mask_only_and_no_unexpected_selectors(self):
        rule = self.spec['policy']['ipv4'][0]
        row = row_for(rule)
        for mask in (None, '0xffffffff', 0xffffffff, '4294967295'):
            actual = dict(row)
            if mask is not None: actual['fwmask'] = mask
            self.assertTrue(n.policy_matches(actual, rule), actual)
        for mask in ('0', 0, '0xffffff00', '0xff', None):
            actual = dict(row, fwmask=mask)
            self.assertFalse(n.policy_matches(actual, rule), actual)
        self.assertTrue(n.policy_matches(dict(row, fwmark=n.MARK), rule))
        self.assertFalse(n.policy_matches(dict(row, fwmark=n.MARK, fwmask='0'), rule))
        for key, value in [('src', '192.0.2.0/24'), ('dst', '1.1.1.1/32'), ('uidrange', '0-0'), ('oif', 'eth0'),
                           ('not', True), ('ipproto', 'tcp'), ('sport', '443'), ('dport', '443'),
                           ('suppress_prefixlength', 0), ('goto', 123), ('flags', ['not']), ('unknown_selector', True)]:
            self.assertFalse(n.policy_matches(dict(row, **{key: value}), rule), (key, value))

    def test_native_lookup_and_terminal_rule_reject_narrowing_but_keep_kernel_metadata(self):
        for family, rules in self.spec['policy'].items():
            for rule in rules[1:]:
                actual = row_for(rule, detached=True)
                actual.update(protocol='boot', flags=['iif-detached'], dst='all', dstlen=0)
                self.assertTrue(n.policy_matches(actual, rule), actual)
                destination = '1.1.1.1/32' if family == 'ipv4' else '2606:4700::/32'
                self.assertFalse(n.policy_matches(dict(actual, dst=destination, dstlen=int(destination.split('/')[1])), rule))
                for key, value in [('uidrange', '0-0'), ('oif', 'eth0'), ('fwmark', '0'), ('fwmask', '0'), ('suppress_ifgroup', 0), ('ipproto', 'icmp')]:
                    self.assertFalse(n.policy_matches(dict(actual, **{key: value}), rule), (key, value))
                wrong = dict(actual, iifname='eth0')
                self.assertFalse(n.policy_matches(wrong, rule))

    def test_foreign_policy_conflicts_validated_both_families_before_any_route_or_rule_write(self):
        conflicts = []
        for family in self.rows:
            bad = copy.deepcopy(self.rows); bad[family][0]['fwmask'] = '0'; conflicts.append(bad)
            for index in (1, 2):
                bad = copy.deepcopy(self.rows)
                bad[family][index]['dst'] = '1.1.1.1/32' if family == 'ipv4' else '2606:4700::/32'
                conflicts.append(bad)
        for rows in conflicts:
            def observe(flag, *args): return rows['ipv4' if flag == '-4' else 'ipv6']
            with patch.object(n, 'owned_table_routes', return_value=[]), patch.object(n, 'ipjson', side_effect=observe), patch.object(n, 'command', side_effect=AssertionError('MUST NOT add even rejecting route')):
                with self.assertRaisesRegex(RuntimeError, 'foreign/modified'): n.policy_sync(self.spec)

    def test_live_capabilities_never_green_for_zero_mask_foreign_rule(self):
        addresses = ['10.78.0.1', '10.79.0.1', 'fd78:1::1', 'fd79:1::1', '10.203.0.2', 'fd42:203::2']
        for proto, item in n.NATIVE_MAP.items():
            for family in ('ipv4', 'ipv6'):
                source = item[family].split('/')[0].rstrip('0') + '1' if family == 'ipv4' else item[family].split('/')[0] + '1'
                self.state['proofs'][proto + '.' + family] = dict(success=True, source=source, observedAt=int(time.time()), configHash=self.state['configHash'])
        n.save(self.root, self.state)
        def observe(*args):
            if args[0] in ('-4', '-6'): return self.rows['ipv4' if args[0] == '-4' else 'ipv6']
            return [{'addr_info': [{'local': x} for x in addresses]}]
        def chains(tool, table, chain):
            family = 'ipv4' if tool == 'iptables' else 'ipv6'
            if chain in self.spec['firewall'][family]['chains']: return self.spec['firewall'][family]['chains'][chain]
            return [n.jump(owned) for tab, parent, owned in n.CHAINS if tab == table and parent == chain]
        def routes(spec, family):
            return [{'type': 'unreachable', 'dst': 'default'}, {'dev': self.state['config']['interface'], 'dst': 'default'}]
        peer = dict(handshake=time.time(), allowedIPs=['0.0.0.0/0', '::/0'])
        with patch.object(n, 'exists_link', return_value=True), patch.object(n, 'require_owned_link'), patch.object(n, 'ipjson', side_effect=observe), patch.object(n, 'peer_snapshot', return_value=peer), patch.object(n, 'chain_rules', side_effect=chains), patch.object(n, 'owned_table_routes', side_effect=routes), patch.object(n, 'command', return_value=types.SimpleNamespace(returncode=0, stdout='1')):
            reasons = n.infrastructure(self.state)
            self.assertEqual(reasons, [])
            self.assertTrue(n.native_capabilities(root=self.root, _observed=reasons)['awg']['ipv4'])
            self.rows['ipv6'][0]['fwmask'] = '0'
            reasons = n.infrastructure(self.state)
            self.assertTrue(any('foreign/modified' in x for x in reasons), reasons)
            caps = n.native_capabilities(root=self.root, _observed=reasons)
            self.assertFalse(caps['awg']['ipv4']); self.assertFalse(caps['rivet']['ipv6'])

    def test_actual_private_kernel_zero_mask_conflict_never_installs_reject_route(self):
        if any(os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind) for kind in ('net', 'mnt')):
            self.skipTest('requires fresh private network AND mount namespaces; never mutates host')
        if any(x['ifname'] != 'lo' for x in n.ipjson('link', 'show')):
            self.skipTest('requires empty private outer network namespace')
        real = n.command
        if any(x.get('priority') == n.PRIORITY for x in n.ipjson('-4', 'rule', 'show')):
            self.skipTest('reserved private fixture priority already occupied')
        mark = n.MARK.split('/')[0] + '/0x0'
        real('ip', '-4', 'rule', 'add', 'priority', str(n.PRIORITY), 'fwmark', mark, 'table', str(n.TABLE))
        try:
            actual = next(x for x in n.ipjson('-4', 'rule', 'show') if x['priority'] == n.PRIORITY)
            self.assertFalse(n.policy_matches(actual, self.spec['policy']['ipv4'][0]))
            def read_only(*args, **kwargs):
                if args[0] != 'ip' or '-j' not in args or 'show' not in args:
                    raise AssertionError('foreign rule must be rejected before any kernel write')
                return real(*args, **kwargs)
            with patch.object(n, 'command', side_effect=read_only):
                with self.assertRaisesRegex(RuntimeError, 'foreign/modified'): n.policy_sync(self.spec)
            self.assertEqual(n.table_routes('-4'), [])
        finally:
            real('ip', '-4', 'rule', 'del', 'priority', str(n.PRIORITY), 'fwmark', mark, 'table', str(n.TABLE))

    def test_foreign_policy_at_other_priority_or_duplicate_refused_not_adopted(self):
        rows = copy.deepcopy(self.rows['ipv4'])
        for extra in (dict(rows[0], priority=20000), dict(rows[0])):
            with self.assertRaises(RuntimeError): n.assert_policy_rows(self.spec, 'ipv4', rows + [extra])

    def test_foreign_policy_blocks_remove_before_lifecycle_or_network_effects(self):
        self.rows['ipv6'][0]['fwmask'] = '0'
        def observe(flag, *args): return self.rows['ipv4' if flag == '-4' else 'ipv6']
        with patch.object(n, 'assert_owned_chains'), patch.object(n, 'owned_table_routes', return_value=[]), patch.object(n, 'ipjson', side_effect=observe), patch.object(n, 'lifecycle_for', side_effect=AssertionError('must not stop lifecycle')), patch.object(n, 'command', side_effect=AssertionError('must not delete foreign rule or guards')):
            with self.assertRaisesRegex(RuntimeError, 'foreign/modified'): n.remove(root=self.root, confirm_direct=True)
        self.assertEqual(n.load(self.root)['phase'], 'applied')
        self.assertTrue(n.load(self.root)['enabled'])

    def test_private_key_reader_valid_optional_and_no_secret_error_text(self):
        path = self.root / 'private.key'
        n.atomic(path, KEY + '\n')
        self.assertEqual(n.read_key_file(path), KEY)
        self.assertIsNone(n.read_key_file(self.root / 'missing-psk', optional=True))
        path.write_text(KEY + '\n' + 'private-material-not-for-errors')
        with self.assertRaises(RuntimeError) as caught: n.read_key_file(path)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertNotIn('private-material', str(caught.exception))
        self.assertNotIn(str(path), str(caught.exception))

    def test_key_symlink_public_mode_nonregular_and_oversize_are_refused(self):
        target = self.base / 'target.key'; n.atomic(target, KEY)
        symlink = self.root / 'symlink.key'; symlink.symlink_to(target)
        dangling = self.root / 'dangling.key'; dangling.symlink_to(self.base / 'missing')
        public = self.root / 'public.key'; n.atomic(public, KEY); public.chmod(0o644)
        oversized = self.root / 'oversize.key'; n.atomic(oversized, 'x' * 129)
        fifo = self.root / 'fifo.key'; os.mkfifo(fifo, 0o600)
        for path in (symlink, dangling, public, oversized, fifo, self.root):
            with self.subTest(path=str(path)), self.assertRaises(RuntimeError): n.read_key_file(path, optional=True)
        with patch.object(n.os, 'read', side_effect=AssertionError('oversize must fail before read')):
            with self.assertRaises(RuntimeError): n.read_key_file(oversized)
        fake = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid() + 1, st_size=44)
        with patch.object(n.os, 'fstat', return_value=fake), patch.object(n.os, 'read', side_effect=AssertionError('foreign owner must fail before read')):
            with self.assertRaises(RuntimeError): n.read_key_file(target)

    def test_private_and_psk_unsafe_reads_fail_before_backend_or_configure_effects(self):
        for name in ('private.key', 'preshared.key'):
            n.atomic(self.root / 'private.key', KEY)
            n.atomic(self.root / 'preshared.key', KEY)
            (self.root / name).chmod(0o644)
            with patch.object(n, 'peer_snapshot', side_effect=AssertionError('must not touch backend')), patch.object(n, 'command', side_effect=AssertionError('must not touch routes')):
                with self.assertRaises(RuntimeError): n.set_peer(self.root, self.state['config'])
            with patch.object(n, 'lifecycle_for', side_effect=AssertionError('must not install units')), patch.object(n, 'owned_preflight', side_effect=AssertionError('must not preflight/apply')), patch.object(n, 'command', side_effect=AssertionError('must not mutate')):
                with self.assertRaises(RuntimeError): n.configure(config(), root=self.root)

    def test_after_guard_backend_failure_keeps_installed_guard_state_no_direct_rollback(self):
        fresh = self.base / 'new-owner'
        effects = []
        life = Mock()
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, 'owned_preflight'), patch.object(n, 'policy_sync', side_effect=lambda spec: effects.append('policy-installed')), patch.object(n, 'firewall_sync', side_effect=lambda spec: effects.append('firewall-installed')), patch.object(n, 'start_backend', side_effect=RuntimeError('injected backend failure')), patch.object(n, 'command', side_effect=AssertionError('must not roll back guards to direct')):
            with self.assertRaises(RuntimeError): n.configure(config(), root=fresh)
        state = n.load(fresh)
        self.assertEqual(effects, ['policy-installed', 'firewall-installed'])
        self.assertEqual(state['phase'], 'fail_closed')
        self.assertEqual(state['guardState'], 'last_installed')
        self.assertTrue(state['enabled']); self.assertEqual(state['proofs'], {})
        life.remove.assert_not_called()


if __name__ == '__main__': unittest.main(verbosity=2)
