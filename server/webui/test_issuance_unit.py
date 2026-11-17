"""Unit tests for the WebUI issuance path (issue_user).

The loopback transport tests in test_webui.py never reach a real add: they
exercise TLS, framing and the token/state surface. issue_user is the only place
where a *remote user identity* is minted, so its contract with the managed
admin CLI is pinned here with the side effects faked out.

Nothing in this module spawns the admin CLI, touches systemd or reads the live
token file; every external call is monkeypatched on a temp-dir copy of the
source, matching the harness in test_webui.py.
"""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

SERVER_ID = 'srv-1a2b3c'


def _load_module():
    workspace = tempfile.TemporaryDirectory(prefix='xio-webui-issuance-')
    source = Path(__file__).with_name('xio-webui.py')
    copied = Path(workspace.name) / source.name
    shutil.copyfile(source, copied)
    spec = importlib.util.spec_from_file_location('xio_webui_issuance_test', copied)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return workspace, module


MATERIAL = {
    'id': 'a' * 32,
    'public': {'wireguard': 'pub-wg', 'awg': 'pub-awg'},
    'private': {'wireguard': 'prv-wg', 'awg': 'prv-awg'},
    'rivet': {'secret': 'c2VjcmV0', 'entryToken': 'dG9rZW4='},
}


class IssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace, cls.module = _load_module()

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self._reset()

    def _reset(self):
        """Re-arm fresh key material and fakes (also used between sub-cases)."""
        self.calls = []
        self.material = {key: (dict(value) if isinstance(value, dict) else value)
                         for key, value in MATERIAL.items()}

        def fake_material():
            return self.material

        def fake_admin(action, payload, timeout=None):
            self.calls.append((action, payload))
            return self.admin_result

        self.module.generate_issuance_material = fake_material
        self.module.admin_call = fake_admin
        self.module.build_xio_profile = lambda projected, material: 'xio://profile'
        self.admin_result = {'schema': 1, 'ok': True, 'code': 200,
                             'data': {'server': {'id': SERVER_ID},
                                      'user': {'id': MATERIAL['id'], 'name': 'anna', 'slot': 7}}}

    # --- payload validation -------------------------------------------------

    def test_rejects_malformed_payloads_without_side_effects(self):
        bad_payloads = [
            None,
            [],
            'name',
            {},                                                        # missing keys
            {'name': 'anna'},                                          # missing server
            {'expectedServerId': SERVER_ID},                           # missing name
            {'expectedServerId': SERVER_ID, 'name': 'anna', 'x': 1},   # extra key
            {'expectedServerId': '', 'name': 'anna'},                  # empty server
            {'expectedServerId': 'srv 1', 'name': 'anna'},             # space in id
            {'expectedServerId': 's' * 81, 'name': 'anna'},            # id too long
            {'expectedServerId': 42, 'name': 'anna'},                  # wrong id type
            {'expectedServerId': SERVER_ID, 'name': '   '},            # blank name
            {'expectedServerId': SERVER_ID, 'name': 'n' * 81},         # name too long
            {'expectedServerId': SERVER_ID, 'name': None},             # wrong name type
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                result = self.module.issue_user(payload)
                self.assertFalse(result['ok'])
                self.assertEqual(result['code'], 400)
                self.assertEqual(result['errorCode'], 'INVALID_REQUEST')
        self.assertEqual(self.calls, [], 'validation failures must not reach the admin CLI')

    # --- key material ------------------------------------------------------

    def test_key_failure_is_reported_before_any_remote_change(self):
        def unavailable():
            raise self.module.KeyUtilityUnavailable

        self.module.generate_issuance_material = unavailable
        result = self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 503)
        self.assertEqual(result['errorCode'], 'KEY_UNAVAILABLE')
        self.assertEqual(self.calls, [])

    # --- managed add -------------------------------------------------------

    def test_add_request_matches_managed_protocol(self):
        result = self.module.issue_user({'expectedServerId': SERVER_ID, 'name': '  anna  '})

        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.calls), 1)
        action, payload = self.calls[0]
        self.assertEqual(action, 'add')
        self.assertEqual(set(payload), {'serverId', 'id', 'name', 'publicKeys', 'rivet',
                                        'admin', 'userLimit'})
        self.assertEqual(payload['serverId'], SERVER_ID)
        self.assertEqual(payload['id'], MATERIAL['id'])
        self.assertEqual(payload['name'], 'anna', 'name must be stripped before add')
        self.assertEqual(payload['publicKeys'], MATERIAL['public'])
        self.assertEqual(payload['rivet'], MATERIAL['rivet'])
        self.assertIs(payload['admin'], False)
        self.assertEqual(payload['userLimit'], 0)

    def test_add_failure_is_passed_through_and_not_retried(self):
        self.admin_result = {'schema': 1, 'ok': False, 'code': 409,
                             'errorCode': 'DUPLICATE', 'error': 'duplicate',
                             'outcomeUnknown': False}
        result = self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 409)
        self.assertEqual(len(self.calls), 1, 'a refused add must not be retried')

    def test_success_returns_profile_and_uid(self):
        result = self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})
        self.assertTrue(result['ok'])
        self.assertEqual(result['data']['uid'], MATERIAL['id'])
        self.assertEqual(result['data']['profile'], 'xio://profile')
        self.assertIs(result['outcomeUnknown'], False)

    def test_success_clears_private_material(self):
        self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})
        self.assertEqual(self.material, {}, 'private key material must be released')

    # --- profile build failure after a successful add ----------------------

    def test_profile_build_failure_is_unknown_outcome(self):
        """The user exists remotely; the client must not be told it failed cleanly."""
        for error in (KeyError('server'), TypeError('shape'), ValueError('identity'),
                      AttributeError('attr'), OverflowError('slot')):
            with self.subTest(error=type(error).__name__):
                self.calls.clear()
                self._reset()

                def raiser(projected, material, _error=error):
                    raise _error

                self.module.build_xio_profile = raiser
                result = self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})
                self.assertFalse(result['ok'])
                self.assertEqual(result['code'], 502)
                self.assertEqual(result['errorCode'], 'INVALID_RESULT')
                self.assertIs(result['outcomeUnknown'], True,
                              'an add that already succeeded must never look like a clean failure')
                self.assertEqual(len(self.calls), 1, 'must not compensate by issuing again')
                self.assertNotIn('data', result)

    def test_unexpected_exception_propagates_instead_of_lying(self):
        def boom(projected, material):
            raise RuntimeError('unexpected')

        self.module.build_xio_profile = boom
        with self.assertRaises(RuntimeError):
            self.module.issue_user({'expectedServerId': SERVER_ID, 'name': 'anna'})


if __name__ == '__main__':
    unittest.main()
