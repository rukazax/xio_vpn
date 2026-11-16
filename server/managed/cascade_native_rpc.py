#!/usr/bin/env python3
"""Owner RPC adapter; connector policy and proof implementation live in cascade_native.

No operation receipt is added here. The caller must persist its encrypted setup
journal before sending a mutation and reconcile an unknown result explicitly.
"""
import base64
import contextlib
import datetime
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

OPERATIONS = ('preflight', 'inspect', 'configure', 'reconcile', 'verify', 'remove')
BASE_FIELDS = {'action', 'serverId', 'operation'}
CONFIG_FIELDS = {'schema', 'enabled', 'ownerOptIn', 'role', 'backend', 'interface',
                 'ingresses', 'innerFamilies', 'sourceMode', 'localAddresses',
                 'peerAddresses', 'peer', 'listenPort', 'exitInterfaces',
                 'privateKey', 'presharedKey'}
CODES = {
    'OWNER_REQUIRED': 'Native cascade requires the owner session',
    'SERVER_IDENTITY': 'Server identity changed; reopen setup',
    'INVALID_REQUEST': 'Invalid native cascade request',
    'MODULE_UNAVAILABLE': 'Native cascade module unavailable; update the server',
    'PREFLIGHT_FAILED': 'Native cascade local route observation failed',
    'INVALID_RESULT': 'Native cascade returned invalid status',
    'TIMEOUT': 'Native cascade operation timed out',
    'IO_FAILURE': 'Native cascade I/O failed',
    'OPERATION_FAILED': 'Native cascade operation failed',
}


class NativeCascadeRPCError(RuntimeError):
    def __init__(self, code, outcome_unknown=False):
        if code not in CODES: code = 'OPERATION_FAILED'
        self.errorCode = code
        self.outcomeUnknown = bool(outcome_unknown)
        suffix = '; outcome unknown; inspect/reconcile before retry' if self.outcomeUnknown else ''
        super().__init__(CODES[code] + suffix)


def _require(condition):
    if not condition: raise NativeCascadeRPCError('INVALID_REQUEST')


def validate(request, deployment, actor=None):
    """Pure request validation, before loading connector/dualstack or processes."""
    if actor is not None or 'SSH_ORIGINAL_COMMAND' in os.environ:
        raise NativeCascadeRPCError('OWNER_REQUIRED')
    _require(type(request) is dict)
    identity = request.get('serverId')
    if type(identity) is not str or not identity or identity != deployment.get('id'):
        raise NativeCascadeRPCError('SERVER_IDENTITY')
    operation = request.get('operation')
    _require(type(operation) is str and operation in OPERATIONS and request.get('action') == 'cascade-native')
    expected = BASE_FIELDS | ({'configuration'} if operation == 'configure' else {'confirmDirect'} if operation == 'remove' else set())
    _require(set(request) == expected)
    if operation == 'remove': _require(request['confirmDirect'] is True)
    if operation == 'configure': _configuration_shape(request['configuration'])
    try: encoded = json.dumps(request, allow_nan=False)
    except (TypeError, ValueError): raise NativeCascadeRPCError('INVALID_REQUEST') from None
    _require(len(encoded.encode('utf-8')) <= 32768)
    return operation


def _configuration_shape(value):
    # Shape checks do not duplicate A's route/ownership validation. A validates
    # semantics purely before configure; arbitrary RPC paths/backends never exist.
    _require(type(value) is dict and not set(value) - CONFIG_FIELDS)
    _require(value.get('enabled') is True and value.get('ownerOptIn') is True)
    _require(value.get('role') in ('bridge', 'exit'))
    _require(type(value.get('schema', 1)) is int and value.get('schema', 1) == 1)
    for name in ('backend', 'interface', 'sourceMode'):
        if name in value: _require(type(value[name]) is str)
    if 'backend' in value: _require(value['backend'] in ('userspace', 'kernel'))
    if 'sourceMode' in value: _require(value['sourceMode'] in ('preserve', 'hop-snat'))
    if 'listenPort' in value: _require(type(value['listenPort']) is int and 0 <= value['listenPort'] <= 65535)
    if 'innerFamilies' in value:
        families = value['innerFamilies']
        _require(type(families) is list and bool(families) and all(type(f) is str and f in ('ipv4', 'ipv6') for f in families))
        _require(len(families) == len(set(families)))
    for name in ('localAddresses', 'peerAddresses'):
        entry = value.get(name)
        _require(type(entry) is dict and set(entry) == {'ipv4', 'ipv6'} and all(type(x) is str for x in entry.values()))
    peer = value.get('peer')
    _require(type(peer) is dict and not set(peer) - {'publicKey', 'host', 'port'} and type(peer.get('publicKey')) is str)
    if 'host' in peer: _require(type(peer['host']) is str)
    if 'port' in peer: _require(type(peer['port']) is int and 1 <= peer['port'] <= 65535)
    if 'ingresses' in value:
        entries = value['ingresses']
        _require(type(entries) is dict and set(entries) == {'awg', 'rivet'})
        for entry in entries.values():
            _require(type(entry) is dict and set(entry) == {'interface', 'ipv4', 'ipv6'} and all(type(x) is str for x in entry.values()))
    if 'exitInterfaces' in value:
        entries = value['exitInterfaces']
        _require(type(entries) is dict and not set(entries) - {'ipv4', 'ipv6'} and all(type(x) is str for x in entries.values()))
    for name in ('privateKey', 'presharedKey'):
        if name in value:
            raw = value[name]
            _require(type(raw) is str and len(raw) == 44)
            try: valid = len(base64.b64decode(raw, validate=True)) == 32
            except (ValueError, TypeError): valid = False
            _require(valid)


def _load(name):
    # Names are fixed at call sites, never supplied by the request.
    if name not in ('cascade_native', 'dualstack'): raise NativeCascadeRPCError('MODULE_UNAVAILABLE')
    path = Path(__file__).with_name(name + '.py')
    if not path.is_file(): raise NativeCascadeRPCError('MODULE_UNAVAILABLE')
    spec = importlib.util.spec_from_file_location('xio_rpc_' + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _interface(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', value):
        raise NativeCascadeRPCError('INVALID_RESULT')
    return value


def _ip(value, version=None):
    if type(value) is not str or not re.fullmatch(r'[0-9a-fA-F:.]+', value): raise NativeCascadeRPCError('INVALID_RESULT')
    try: address = ipaddress.ip_address(value)
    except ValueError: raise NativeCascadeRPCError('INVALID_RESULT') from None
    if version is not None and address.version != version: raise NativeCascadeRPCError('INVALID_RESULT')
    return str(address)


def _preflight():
    egress = {}
    for family, flag, target, version in [('ipv4', '-4', '1.1.1.1', 4), ('ipv6', '-6', '2606:4700:4700::1111', 6)]:
        result = subprocess.run(['ip', '-j', flag, 'route', 'get', target],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=3, check=False)
        entry = {'routePresent': False, 'interface': None}
        if result.returncode == 0:
            if not isinstance(result.stdout, str) or len(result.stdout) > 32768: raise NativeCascadeRPCError('PREFLIGHT_FAILED')
            try: rows = json.loads(result.stdout)
            except (TypeError, ValueError): raise NativeCascadeRPCError('PREFLIGHT_FAILED') from None
            if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict: raise NativeCascadeRPCError('PREFLIGHT_FAILED')
            row = rows[0]
            if row.get('type', 'unicast') == 'unicast':
                interface = _interface(row.get('dev'))
                if interface != 'lo':
                    entry.update(routePresent=True, interface=interface)
                    source = row.get('prefsrc', row.get('src'))
                    if source is not None: entry['source'] = _ip(source, version)
        egress[family] = entry
    return {'schema': 1, 'moduleAvailable': Path(__file__).with_name('cascade_native.py').is_file(),
            'egress': egress}


_REASON_CODES = {'uplink_missing', 'native_interface_missing', 'native_address_missing',
                 'fresh_peer_handshake_required', 'peer_allowed_ips_mismatch', 'uplink_address_missing',
                 'owned_firewall_missing', 'owned_firewall_mismatch', 'owned_jump_not_first',
                 'routing_fence_missing', 'routing_fence_mismatch', 'reject_route_missing',
                 'uplink_route_missing', 'reverse_route_missing', 'forwarding_disabled',
                 'connector_not_applied', 'fresh_native_probe_required', 'exit_role_not_a_native_bridge',
                 'family_not_selected_no_direct_fallback', 'source_bound_inner_probe_verified',
                 'stale-readiness', 'stale_readiness', 'infrastructure_not_ready'}


def _reason(value):
    if type(value) is not str: return 'connector_not_ready'
    return ','.join(part if part in _REASON_CODES else 'connector_not_ready' for part in value.split(',')[:32])


def _timestamp(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)', value): raise NativeCascadeRPCError('INVALID_RESULT')
    try: return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError: raise NativeCascadeRPCError('INVALID_RESULT') from None


def _identity(value):
    identity, revision = value.get('connectorId'), value.get('revision')
    if type(identity) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identity): raise NativeCascadeRPCError('INVALID_RESULT')
    if type(revision) not in (int, str) or (type(revision) is int and revision < 0) or (type(revision) is str and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', revision)): raise NativeCascadeRPCError('INVALID_RESULT')


def _capabilities(value):
    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or value.get('enabled') is not True: raise NativeCascadeRPCError('INVALID_RESULT')
    _identity(value)
    observed, expires = _timestamp(value.get('observedAt')), _timestamp(value.get('expiresAt'))
    now = time.time()
    fresh = (observed <= now + 5 and now < expires and observed < expires
             and expires - observed <= 60 and now - observed <= 60)
    result = {key: value[key] for key in ('schema', 'enabled', 'connectorId', 'revision', 'observedAt', 'expiresAt')}
    for protocol in ('awg', 'rivet'):
        entry = value.get(protocol)
        if type(entry) is not dict or any(type(entry.get(f)) is not bool for f in ('ipv4', 'ipv6')): raise NativeCascadeRPCError('INVALID_RESULT')
        result[protocol] = {f: entry[f] and fresh for f in ('ipv4', 'ipv6')}
        result[protocol].update({key: _reason(entry.get(key)) if fresh else 'stale_readiness' for key in ('reason4', 'reason6')})
    return result


def _public_config(value):
    if type(value) is not dict: raise NativeCascadeRPCError('INVALID_RESULT')
    # The connector's config is already normalized. Whitelist data rather than
    # ever copying its private state, UAPI, command output or unknown extensions.
    result = {key: value[key] for key in CONFIG_FIELDS - {'privateKey', 'presharedKey'} if key in value}
    if type(result.get('peer')) is dict:
        result['peer'] = {key: result['peer'][key] for key in ('publicKey', 'host', 'port') if key in result['peer']}
    try: _configuration_shape(result)
    except NativeCascadeRPCError: raise NativeCascadeRPCError('INVALID_RESULT') from None
    public_key = result['peer']['publicKey']
    try: valid_key = len(public_key) == 44 and len(base64.b64decode(public_key, validate=True)) == 32
    except (TypeError, ValueError): valid_key = False
    if not valid_key: raise NativeCascadeRPCError('INVALID_RESULT')
    for key in ('interface',):
        if key in result: result[key] = _interface(result[key])
    for name in ('localAddresses', 'peerAddresses'):
        result[name] = {f: _ip(address, 4 if f == 'ipv4' else 6) for f, address in result[name].items()}
    if 'host' in result['peer']: result['peer']['host'] = _ip(result['peer']['host'])
    if 'ingresses' in result:
        entries = {}
        for protocol, item in result['ingresses'].items():
            entry = {'interface': _interface(item['interface'])}
            for family, version in (('ipv4', 4), ('ipv6', 6)):
                try: network = ipaddress.ip_network(item[family], strict=True)
                except ValueError: raise NativeCascadeRPCError('INVALID_RESULT') from None
                if network.version != version: raise NativeCascadeRPCError('INVALID_RESULT')
                entry[family] = str(network)
            entries[protocol] = entry
        result['ingresses'] = entries
    if 'exitInterfaces' in result: result['exitInterfaces'] = {f: _interface(interface) for f, interface in result['exitInterfaces'].items()}
    return result


def sanitize(value):
    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or type(value.get('enabled')) is not bool: raise NativeCascadeRPCError('INVALID_RESULT')
    if not value['enabled']: return {'schema': 1, 'enabled': False}
    if 'observedAt' in value: return _capabilities(value) # A.verify returns flat capabilities.
    _identity(value)
    if type(value.get('reasons', [])) is not list: raise NativeCascadeRPCError('INVALID_RESULT')
    result = {key: value[key] for key in ('schema', 'enabled', 'connectorId', 'revision') if key in value}
    phase = value.get('phase')
    if type(phase) is not str or phase not in ('prepared', 'applying', 'guarded', 'applied', 'preparation_failed', 'apply_failed', 'fail_closed', 'removing', 'removed'): raise NativeCascadeRPCError('INVALID_RESULT')
    # Legacy responses may omit provenance. Never infer current guards from phase.
    if 'guardState' in value:
        guard = value['guardState']
        if type(guard) is not str or guard not in ('unknown', 'last_installed'): raise NativeCascadeRPCError('INVALID_RESULT')
        result['guardState'] = guard
    if type(value.get('infrastructureReady')) is not bool: raise NativeCascadeRPCError('INVALID_RESULT')
    result.update(phase=phase, infrastructureReady=value['infrastructureReady'],
                  reasons=[_reason(reason) for reason in value.get('reasons', [])][:64],
                  config=_public_config(value.get('config')))
    capabilities = value.get('capabilities')
    if capabilities is not None:
        result['capabilities'] = _capabilities(capabilities)
        if not result['infrastructureReady'] or phase != 'applied':
            for protocol in ('awg', 'rivet'):
                result['capabilities'][protocol].update(ipv4=False, ipv6=False,
                                                       reason4='infrastructure_not_ready', reason6='infrastructure_not_ready')
    else: result['capabilities'] = None
    return result


def _redact(value, secrets):
    forbidden = {'privatekey', 'presharedkey', 'private', 'psk', 'secret', 'stdout', 'stderr', 'uapi', 'dump', 'traceback', 'argv'}
    if isinstance(value, dict):
        result = {}
        for key, entry in value.items():
            if not isinstance(key, str) or key.replace('_', '').replace('-', '').lower() in forbidden or any(secret in key for secret in secrets): continue
            if key in ('reason4', 'reason6'): result[key] = _reason(entry)
            elif key == 'reasons' and isinstance(entry, list): result[key] = [_reason(item) for item in entry][:64]
            else: result[key] = _redact(entry, secrets)
        return result
    if isinstance(value, list): return [_redact(entry, secrets) for entry in value]
    if isinstance(value, str):
        for secret in secrets: value = value.replace(secret, '[redacted]')
    return value


def _dispatch_validated(request, deployment, public, operation):
    mutation_admitted = False
    secrets = [request.get('configuration', {}).get(name) for name in ('privateKey', 'presharedKey')]
    secrets = [value for value in secrets if isinstance(value, str) and value]
    try:
        if operation == 'preflight':
            result = _preflight()
        else:
            connector = _load('cascade_native')
            required = {'configure': ('configure', 'inspect'), 'reconcile': ('reconcile_native', 'inspect'),
                        'verify': ('verify',), 'remove': ('remove',), 'inspect': ('inspect',)}[operation]
            if any(not callable(getattr(connector, name, None)) for name in required): raise NativeCascadeRPCError('MODULE_UNAVAILABLE')
            if operation in ('configure', 'reconcile'):
                network = _load('dualstack') # Missing dependency fails before mutation.
                if not callable(getattr(network, 'apply', None)): raise NativeCascadeRPCError('MODULE_UNAVAILABLE')
            mutation_admitted = operation in ('configure', 'reconcile', 'verify', 'remove')
            if operation == 'configure':
                connector.configure(request['configuration'])
                network.apply()
                result = connector.inspect()
            elif operation == 'reconcile':
                connector.reconcile_native(reason='owner-rpc')
                network.apply()
                result = connector.inspect()
            elif operation == 'verify': result = connector.verify()
            elif operation == 'remove': result = connector.remove(confirm_direct=True)
            else: result = connector.inspect()
            result = sanitize(result)
        # This callback must be admin.public, which only samples local state; it
        # never verifies, modifies connector state or invokes public probes.
        server = public(deployment)
        if type(server) is not dict: raise NativeCascadeRPCError('INVALID_RESULT')
        response = {'ok': True, 'nativeCascade': _redact(result, secrets), 'server': _redact(server, secrets)}
        if len(json.dumps(response, allow_nan=False).encode('utf-8')) > 262144: raise NativeCascadeRPCError('INVALID_RESULT')
        return response
    except NativeCascadeRPCError as error:
        raise NativeCascadeRPCError(error.errorCode, mutation_admitted) from None
    except (TimeoutError, subprocess.TimeoutExpired):
        raise NativeCascadeRPCError('TIMEOUT', mutation_admitted) from None
    except (OSError, subprocess.SubprocessError):
        raise NativeCascadeRPCError('IO_FAILURE', mutation_admitted) from None
    except (ImportError, SyntaxError):
        raise NativeCascadeRPCError('MODULE_UNAVAILABLE', mutation_admitted) from None
    except Exception:
        raise NativeCascadeRPCError('OPERATION_FAILED', mutation_admitted) from None


class _Discard:
    # Do not retain connector debug output, even transiently in StringIO/logs.
    def write(self, value): return len(value)
    def flush(self): pass


def dispatch(request, deployment, *, public, actor=None):
    operation = validate(request, deployment, actor)
    with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
        return _dispatch_validated(request, deployment, public, operation)
