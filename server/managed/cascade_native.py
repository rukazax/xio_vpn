#!/usr/bin/env python3
"""Opt-in native L3 cascade. No main default/OUTPUT/UID policy or package installs.

Hooks: desired_native_families(), reconcile_native(), native_capabilities().
CLI: validate|plan|configure|reconcile|inspect|verify|remove, JSON stdin/stdout.
The owner must provision both peer public keys. Native client transports are unchanged.
"""
import argparse
import base64
import contextlib
import contextvars
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

OWNER = 'xio-cascade-native-v1'
DEFAULT_ROOT = Path('/etc/xio-managed/cascade-native')
AWG_SHA256 = 'fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a'
AWG_PATHS = ('/usr/local/lib/xio-managed/amneziawg-go', '/usr/local/bin/xio-amneziawg-go')
NATIVE_MAP = {'awg': {'interface': 'xioawg0', 'ipv4': '10.78.0.0/24', 'ipv6': 'fd78:1::/64'},
              'rivet': {'interface': 'xiorivet', 'ipv4': '10.79.0.0/24', 'ipv6': 'fd79:1::/64'}}
TABLE = 20792
PRIORITY = 12042
MARK = '0x58494f00/0xffffffff'
PROOF_TTL = 60
_DEADLINE = contextvars.ContextVar('cascade_inspect_deadline', default=None)
CHAINS = [('mangle', 'PREROUTING', 'XIO_CNP'), ('mangle', 'FORWARD', 'XIO_CNK'),
          ('filter', 'FORWARD', 'XIO_CNF'), ('nat', 'POSTROUTING', 'XIO_CNN'),
          ('filter', 'INPUT', 'XIO_CNI')]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError('32-byte base64 key required')
    try:
        if len(base64.b64decode(value, validate=True)) != 32: raise ValueError()
    except Exception:
        raise ValueError('32-byte base64 key required') from None
    return value


def literal(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F:.]+', value):
        raise ValueError('bare IP literal required (no URL/CIDR/zone/brackets)')
    addr = ipaddress.ip_address(value)
    if addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_multicast or getattr(addr, 'ipv4_mapped', None):
        raise ValueError('unusable IP literal')
    return str(addr)


def interface(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', value):
        raise ValueError('invalid interface')
    return value


def networks(native_map=None):
    native_map = NATIVE_MAP if native_map is None else native_map
    if not isinstance(native_map, dict) or set(native_map) != {'awg', 'rivet'}:
        raise ValueError('native map must describe exactly awg and rivet')
    result = {}
    for proto in ('awg', 'rivet'):
        item = native_map[proto]
        if not isinstance(item, dict) or set(item) != {'interface', 'ipv4', 'ipv6'}:
            raise ValueError('native entry requires exactly interface, ipv4 and ipv6')
        result[proto] = {'interface': interface(item['interface'])}
        for family, version in [('ipv4', 4), ('ipv6', 6)]:
            if not isinstance(item[family], str): raise ValueError('native subnet must be a CIDR string')
            value = str(ipaddress.ip_network(item[family], strict=True))
            if ipaddress.ip_network(value).version != version: raise ValueError('native subnet family mismatch')
            result[proto][family] = value
    if result['awg']['interface'] == result['rivet']['interface']: raise ValueError('distinct native interfaces required')
    for family in ('ipv4', 'ipv6'):
        if ipaddress.ip_network(result['awg'][family]).overlaps(ipaddress.ip_network(result['rivet'][family])):
            raise ValueError('overlapping native subnets')
    return result


def validate_config(request):
    """Pure, no filesystem/process/network access; strips private fields from result."""
    if not isinstance(request, dict) or request.get('enabled') is not True or request.get('ownerOptIn') is not True:
        raise ValueError('explicit enabled:true and ownerOptIn:true required')
    allowed = {'schema', 'enabled', 'ownerOptIn', 'role', 'backend', 'interface', 'ingresses', 'innerFamilies',
               'sourceMode', 'localAddresses', 'peerAddresses', 'peer', 'listenPort', 'exitInterfaces', 'privateKey', 'presharedKey'}
    if set(request) - allowed or request.get('schema', 1) != 1: raise ValueError('unknown configuration fields/schema')
    if request.get('role') not in ('bridge', 'exit'): raise ValueError('role bridge|exit required')
    backend = request.get('backend', 'userspace')
    if backend not in ('userspace', 'kernel'): raise ValueError('backend userspace|kernel required')
    iface = interface(request.get('interface', 'xiocascade0'))
    if not iface.startswith('xioc') or iface in ('xioawg0', 'xiorivet', 'xio0'):
        raise ValueError('dedicated xioc* uplink required; existing native devices are forbidden')
    if 'ingresses' in request and not isinstance(request['ingresses'], dict):
        raise ValueError('ingresses must be the authoritative native map')
    native = networks(request.get('ingresses'))
    if native != networks():
        raise ValueError('ingresses must match the authoritative AWG/RIVET interfaces and subnets')
    if iface in [i['interface'] for i in native.values()]: raise ValueError('uplink/ingress conflict')
    families = request.get('innerFamilies', ['ipv4', 'ipv6'])
    if not isinstance(families, list) or not families or len(set(families)) != len(families) or not set(families) <= {'ipv4', 'ipv6'}:
        raise ValueError('explicit nonempty innerFamilies ipv4/ipv6 list required')
    source_mode = request.get('sourceMode', 'preserve')
    if source_mode not in ('preserve', 'hop-snat'): raise ValueError('sourceMode preserve|hop-snat required')
    local, remote = {}, {}
    for family, version in [('ipv4', 4), ('ipv6', 6)]:
        l = literal(request['localAddresses'][family])
        r = literal(request['peerAddresses'][family])
        if ipaddress.ip_address(l).version != version or ipaddress.ip_address(r).version != version or l == r:
            raise ValueError('invalid local/peer hop family/address')
        if any(ipaddress.ip_address(x) in ipaddress.ip_network(item[family]) for x in (l, r) for item in native.values()):
            raise ValueError('hop/native subnet overlap')
        local[family], remote[family] = l, r
    peer = {'publicKey': key(request['peer']['publicKey'])}
    if request['peer'].get('host'):
        peer['host'] = literal(request['peer']['host'])
        port = request['peer'].get('port', 9443)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535: raise ValueError('invalid endpoint port')
        peer['port'] = port
    elif request['role'] == 'bridge': raise ValueError('bridge peer host/port required')
    listen = request.get('listenPort', 0 if request['role'] == 'bridge' else 9443)
    if not isinstance(listen, int) or isinstance(listen, bool) or not 0 <= listen <= 65535: raise ValueError('invalid listenPort')
    if request['role'] == 'exit' and not listen: raise ValueError('exit listenPort required')
    egress = {}
    if request['role'] == 'exit':
        for family in families:
            egress[family] = interface(request.get('exitInterfaces', {}).get(family))
            if egress[family] == iface: raise ValueError('exit egress cannot be uplink')
    result = dict(schema=1, enabled=True, ownerOptIn=True, role=request['role'], backend=backend,
                  interface=iface, ingresses=native, innerFamilies=sorted(families), sourceMode=source_mode,
                  localAddresses=local, peerAddresses=remote, peer=peer, listenPort=listen, exitInterfaces=egress)
    if request.get('presharedKey'): key(request['presharedKey'])
    if request.get('privateKey'): key(request['privateKey'])
    return result


def source_networks(config, family):
    hop = config['peerAddresses'][family] + ('/32' if family == 'ipv4' else '/128')
    return [hop] + ([v[family] for v in config['ingresses'].values()] if config['sourceMode'] == 'preserve' else [])


def plan(config):
    """Pure owned firewall/routing plan, no secret key values."""
    c = validate_config(config)
    result = {'config': c, 'table': TABLE, 'mark': MARK, 'firewall': {}, 'policy': {}}
    for family, tool, flag in [('ipv4', 'iptables', '-4'), ('ipv6', 'ip6tables', '-6')]:
        selected = family in c['innerFamilies']
        chains = {chain: [] for _, _, chain in CHAINS}
        if c['role'] == 'bridge':
            for item in c['ingresses'].values():
                match = ['-i', item['interface'], '-s', item[family]]
                if selected:
                    chains['XIO_CNP'].append(match + ['-j', 'MARK', '--set-xmark', MARK])
                    chains['XIO_CNK'].append(match + ['-o', c['interface'], '-j', 'RETURN'])
                    chains['XIO_CNF'].append(match + ['-o', c['interface'], '-j', 'ACCEPT'])
                    chains['XIO_CNF'].append(['-i', c['interface'], '-o', item['interface'], '-d', item[family], '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
                    nat = ['-s', item[family], '-o', c['interface'], '-m', 'mark', '--mark', MARK]
                    chains['XIO_CNN'].append(nat + (['-j', 'ACCEPT'] if c['sourceMode'] == 'preserve' else ['-j', 'SNAT', '--to-source', c['localAddresses'][family]]))
                # Unselected native families are deliberately blocked, never downgraded direct.
                chains['XIO_CNK'].append(match + ['-j', 'DROP'])
            policy = []
            # Marked source-bound diagnostic sockets only; no UID/OUTPUT marking.
            policy.append(['priority', str(PRIORITY), 'fwmark', MARK, 'lookup', str(TABLE)])
            for i, item in enumerate(c['ingresses'].values()):
                match = ['iif', item['interface'], 'from', item[family]]
                if selected:
                    policy.append(['priority', str(PRIORITY + 1 + 2 * i), *match, 'lookup', str(TABLE)])
                policy.append(['priority', str(PRIORITY + 2 + 2 * i), *match, 'prohibit'])
            result['policy'][family] = policy
        else:
            if selected:
                for subnet in source_networks(c, family):
                    chains['XIO_CNK'].append(['-i', c['interface'], '-s', subnet, '-o', c['exitInterfaces'][family], '-j', 'RETURN'])
                    chains['XIO_CNF'].append(['-i', c['interface'], '-s', subnet, '-o', c['exitInterfaces'][family], '-j', 'ACCEPT'])
                    chains['XIO_CNF'].append(['-o', c['interface'], '-d', subnet, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
                    chains['XIO_CNN'].append(['-s', subnet, '-o', c['exitInterfaces'][family], '-j', 'MASQUERADE'])
                chains['XIO_CNI'].append(['-p', 'udp', '--dport', str(c['listenPort']), '-j', 'ACCEPT'])
            chains['XIO_CNK'].append(['-i', c['interface'], '-j', 'DROP'])
            result['policy'][family] = []
        result['firewall'][family] = {'tool': tool, 'flag': flag, 'chains': chains}
    return result


def command(*args, input=None, check=True):
    deadline = _DEADLINE.get()
    timeout = 10 if deadline is None else min(2, deadline - time.monotonic())
    if timeout <= 0: raise RuntimeError('local inspection deadline exhausted')
    p = subprocess.run(list(map(str, args)), input=input, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode: raise RuntimeError('command failed: ' + ' '.join(map(str, args)) + ' (stderr suppressed; rc=' + str(p.returncode) + ')')
    return p


def atomic(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.owned-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(value); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def load(root=DEFAULT_ROOT):
    path = Path(root) / 'state.json'
    if not path.exists(): return None
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise RuntimeError('unsafe connector receipt ownership/mode')
    state = json.loads(path.read_text())
    if state.get('owner') != OWNER or state.get('schema') != 1: raise RuntimeError('foreign connector receipt')
    if state.get('configHash') != digest(validate_config(state['config'])): raise RuntimeError('connector config hash mismatch')
    return state


def save(root, state):
    atomic(Path(root) / 'state.json', canonical(state) + '\n')


@contextlib.contextmanager
def locked(root):
    root = Path(root)
    if root.resolve() == Path('/') or root.is_symlink(): raise ValueError('unsafe connector root')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077: raise ValueError('connector root must be private/owned')
    path = root / 'lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def ipjson(*args):
    p = command('ip', '-j', *args)
    return json.loads(p.stdout or '[]')


def exists_link(iface):
    return command('ip', 'link', 'show', 'dev', iface, check=False).returncode == 0


def table_routes(flag):
    p = command('ip', '-j', flag, 'route', 'show', 'table', str(TABLE), check=False)
    if p.returncode:
        if 'FIB table does not exist' in p.stderr: return []
        raise RuntimeError('cannot inspect reserved table')
    return json.loads(p.stdout or '[]')


def require_owned_link(state):
    c = state['config']
    rows = ipjson('link', 'show', 'dev', c['interface'])
    if len(rows) != 1 or rows[0].get('ifalias') != OWNER + ':' + state['connectorId']:
        raise RuntimeError('uplink alias/ownership mismatch; refusing adoption/deletion')


def jump(chain):
    return ['-m', 'comment', '--comment', OWNER, '-j', chain]


def chain_rules(tool, table, chain):
    p = command(tool, '-w', '5', '-t', table, '-S', chain, check=False)
    if p.returncode: return None
    return [shlex.split(line)[2:] for line in p.stdout.splitlines() if line.startswith('-A ')]


def normalized_rule(rule):
    result = []
    i = 0
    while i < len(rule):
        if rule[i:i+2] in (['-m', 'udp'], ['-m', 'tcp']): i += 2; continue
        token = rule[i].replace('/0xffffffff', '')
        if i and rule[i-1] == '--ctstate': token = ','.join(sorted(token.split(',')))
        result.append(token)
        i += 1
    if len(result) % 2 or any(not result[i].startswith('-') for i in range(0, len(result), 2)):
        return tuple(result)
    # iptables -S canonicalizes match order (-s/-d before -i/-o).
    return tuple(sorted(zip(result[::2], result[1::2])))


def assert_owned_chains(spec):
    for entry in spec['firewall'].values():
        for table, _, chain in CHAINS:
            actual = chain_rules(entry['tool'], table, chain)
            expected = {normalized_rule(r) for r in entry['chains'][chain]}
            if actual is not None and any(normalized_rule(r) not in expected for r in actual):
                raise RuntimeError('foreign rule inside reserved chain; refusing to flush/delete it')


def firewall_sync(spec):
    assert_owned_chains(spec)
    for family, entry in spec['firewall'].items():
        tool = entry['tool']
        for table, parent, chain in CHAINS:
            if chain_rules(tool, table, chain) is None: command(tool, '-w', '5', '-t', table, '-N', chain)
            # Flush ONLY a reserved, receipt-owned chain, never a native/base chain.
            command(tool, '-w', '5', '-t', table, '-F', chain)
            for rule in entry['chains'][chain]: command(tool, '-w', '5', '-t', table, '-A', chain, *rule)
            target = jump(chain)
            while not command(tool, '-w', '5', '-t', table, '-C', parent, *target, check=False).returncode:
                command(tool, '-w', '5', '-t', table, '-D', parent, *target)
            command(tool, '-w', '5', '-t', table, '-I', parent, '1', *target)


def rule_args(family, rule):
    return ['ip', '-4' if family == 'ipv4' else '-6', 'rule', *rule]


def rule_prefix(row, name):
    value, length = row.get(name, 'all'), row.get(name + 'len')
    if value in (None, 'all', 'default'):
        if length not in (None, 0, '0'): raise ValueError('wildcard prefix length mismatch')
        return None
    value = str(value)
    if length is not None:
        if '/' in value:
            if ipaddress.ip_network(value, strict=True).prefixlen != int(length): raise ValueError('prefix length mismatch')
        else: value += '/' + str(length)
    net = ipaddress.ip_network(value, strict=True)
    return net if net.prefixlen else None


def policy_matches(row, rule):
    """Exact effective selectors/action; unknown selectors never imply ownership."""
    allowed = {'priority', 'src', 'srclen', 'dst', 'dstlen', 'table', 'action', 'fwmark', 'fwmask',
               'iif', 'iifname', 'protocol', 'flags', 'iif_detached'}
    try:
        if not isinstance(row, dict) or set(row) - allowed or row.get('priority') != int(rule[1]): return False
        expected_iif = rule[rule.index('iif') + 1] if 'iif' in rule else None
        interfaces = [row[k] for k in ('iif', 'iifname') if row.get(k) not in (None, '')]
        if expected_iif:
            if not interfaces or any(x != expected_iif for x in interfaces): return False
        elif interfaces: return False
        if 'iif_detached' in row and (not expected_iif or row['iif_detached'] not in (None, True, False)): return False
        flags = row.get('flags', [])
        if not isinstance(flags, list) or any(x != 'iif-detached' or not expected_iif for x in flags): return False
        expected_source = ipaddress.ip_network(rule[rule.index('from') + 1]) if 'from' in rule else None
        if rule_prefix(row, 'src') != expected_source or rule_prefix(row, 'dst') is not None: return False
        if rule[-1] == 'prohibit':
            if row.get('action') != 'prohibit' or row.get('table') not in (None, 0, '0'): return False
        elif str(row.get('table')) != str(TABLE) or row.get('action') not in (None, 'lookup', 'to_tbl'): return False
        if 'fwmark' in rule:
            parts = str(row.get('fwmark', '')).split('/')
            if len(parts) not in (1, 2): return False
            mark = int(parts[0], 0)
            embedded = int(parts[1], 0) if len(parts) == 2 else None
            mask = int(str(row['fwmask']), 0) if 'fwmask' in row else (embedded if embedded is not None else 0xffffffff)
            expected_mark, expected_mask = [int(x, 0) for x in rule[rule.index('fwmark') + 1].split('/')]
            if embedded is not None and embedded != mask: return False
            if mark != expected_mark or mask != expected_mask or mask != 0xffffffff: return False
        elif 'fwmark' in row or 'fwmask' in row: return False
        return True
    except (ValueError, TypeError, KeyError):
        return False


def assert_policy_rows(spec, family, rows):
    expected = {int(rule[1]): rule for rule in spec['policy'][family]}
    occupied = set()
    for row in rows:
        priority = row.get('priority', -1)
        reserved = isinstance(priority, int) and PRIORITY <= priority <= PRIORITY + 4
        if not reserved and str(row.get('table')) != str(TABLE): continue
        if priority not in expected or priority in occupied or not policy_matches(row, expected[priority]):
            raise RuntimeError('foreign/modified reserved policy rule; refusing adoption/deletion')
        occupied.add(priority)
    return occupied


def policy_snapshot(spec):
    """Validate BOTH families before adding a reject route (which a broad foreign mark could capture)."""
    if spec['config']['role'] != 'bridge': return {}
    result = {}
    for family, rules in spec['policy'].items():
        flag = spec['firewall'][family]['flag']
        routes = owned_table_routes(spec, family)
        occupied = assert_policy_rows(spec, family, ipjson(flag, 'rule', 'show'))
        result[family] = (routes, occupied)
    return result


def owned_table_routes(spec, family):
    entry = spec['firewall'][family]
    c = spec['config']
    routes = table_routes(entry['flag'])
    for row in routes:
        reject = row.get('type') == 'unreachable' and row.get('dst') == 'default' and row.get('metric') == 32760
        uplink = row.get('dev') == c['interface'] and row.get('dst') == 'default' and row.get('metric') == 10 and family in c['innerFamilies']
        if not (reject or uplink) or str(row.get('protocol')) != '242':
            raise RuntimeError('foreign route in reserved table; refusing takeover')
    return routes


def policy_sync(spec):
    c = spec['config']
    if c['role'] != 'bridge': return
    observed = policy_snapshot(spec)
    for family, rules in spec['policy'].items():
        flag = '-4' if family == 'ipv4' else '-6'
        existing, occupied = observed[family]
        # Rejecting route survives interface deletion and avoids lookup fall-through.
        if not any(r.get('type') == 'unreachable' and r.get('dst') == 'default' for r in existing):
            command('ip', flag, 'route', 'add', 'unreachable', 'default', 'metric', '32760', 'table', str(TABLE), 'proto', '242')
        # Terminal iif+source prohibit installed before a lookup is ever enabled.
        for rule in sorted(rules, key=lambda r: r[-1] != 'prohibit'):
            if int(rule[1]) not in occupied: command(*rule_args(family, ['add', *rule]))


def owned_preflight(spec):
    c = spec['config']
    if exists_link(c['interface']): raise RuntimeError('uplink interface already exists; refusing adoption')
    existing_addresses = {a['local'] for row in ipjson('addr', 'show') for a in row.get('addr_info', [])}
    for family, entry in spec['firewall'].items():
        hops = [ipaddress.ip_address(c[k][family]) for k in ('localAddresses', 'peerAddresses')]
        if any(str(a) in existing_addresses for a in hops): raise RuntimeError('dedicated hop collides with existing local address')
        for route in ipjson(entry['flag'], 'route', 'show', 'table', 'main'):
            dst = route.get('dst', 'default')
            if dst != 'default' and any(a in ipaddress.ip_network(dst, strict=False) for a in hops):
                raise RuntimeError('dedicated hop overlaps an existing host/management route')
        for table, _, chain in CHAINS:
            if chain_rules(entry['tool'], table, chain) is not None: raise RuntimeError('reserved firewall chain exists without receipt')
        if c['role'] == 'bridge':
            if table_routes(entry['flag']): raise RuntimeError('reserved route table occupied')
            for rule in ipjson(entry['flag'], 'rule', 'show'):
                if PRIORITY <= rule.get('priority', -1) <= PRIORITY + 4 or str(rule.get('table')) == str(TABLE):
                    raise RuntimeError('reserved policy priority/table occupied')
        else:
            if family not in c['innerFamilies']: continue
            target = '1.1.1.1' if family == 'ipv4' else '2606:4700:4700::1111'
            route = ipjson(entry['flag'], 'route', 'get', target)
            if not route or route[0].get('dev') != c['exitInterfaces'][family]:
                raise RuntimeError('requested exit family has no matching actual egress route')
            rows = ipjson('addr', 'show', 'dev', c['exitInterfaces'][family])
            version = 4 if family == 'ipv4' else 6
            sources = [a.get('local') for r in rows for a in r.get('addr_info', []) if a.get('family') == ('inet' if version == 4 else 'inet6')]
            if not any(not ipaddress.ip_address(a).is_link_local for a in sources):
                raise RuntimeError('requested exit family has no egress source address')
            current = ipjson(entry['flag'], 'route', 'show', 'table', 'main')
            for subnet in source_networks(c, family):
                net = ipaddress.ip_network(subnet)
                for route in current:
                    dst = route.get('dst', 'default')
                    if dst == 'default': continue
                    if net.overlaps(ipaddress.ip_network(dst, strict=False)):
                        raise RuntimeError('exit reverse-prefix route collision; use explicit matching hop-snat on both peers or distinct prefixes')


def runtime_binary():
    for value in AWG_PATHS:
        path = Path(value)
        if path.is_file() and not path.is_symlink() and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022:
            if hashlib.sha256(path.read_bytes()).hexdigest() == AWG_SHA256: return str(path)
    raise RuntimeError('pinned existing signed-server AWG runtime missing/mismatched; no download/install/fallback attempted')


def uapi(iface, text):
    path = '/run/amneziawg/' + iface + '.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(path)
        s.sendall((text.rstrip('\n') + '\n\n').encode())
        data = b''
        while b'\n\n' not in data:
            part = s.recv(65536)
            if not part or len(data) > 1048576: raise RuntimeError('invalid UAPI response')
            data += part
    if not data.endswith(b'errno=0\n\n'): raise RuntimeError('AWG UAPI rejected request')
    return data.decode()


def process_identity(pid):
    try:
        path = Path('/proc') / str(pid)
        return {'pid': pid, 'start': (path / 'stat').read_text().split(') ', 1)[1].split()[19],
                'exe': os.readlink(path / 'exe'), 'argv': (path / 'cmdline').read_bytes().split(b'\0')[:-1]}
    except (OSError, IndexError): return None


def start_backend(root, state):
    c = state['config']
    if exists_link(c['interface']):
        require_owned_link(state)
        if c['backend'] == 'userspace':
            observed = process_identity(state.get('process', {}).get('pid', -1))
            if not observed or observed['start'] != state['process']['start'] or observed['exe'] != state['process']['exe']:
                raise RuntimeError('existing uplink process identity mismatch')
        return
    if c['backend'] == 'kernel':
        command('ip', 'link', 'add', 'dev', c['interface'], 'type', 'wireguard')
        command('ip', 'link', 'set', 'dev', c['interface'], 'alias', OWNER + ':' + state['connectorId'])
        return
    binary = runtime_binary()
    socket_path = Path('/run/amneziawg') / (c['interface'] + '.sock')
    if socket_path.exists(): raise RuntimeError('foreign/stale userspace socket; refusing unlink/adoption')
    with (Path(root) / 'runtime.log').open('ab') as log:
        process = subprocess.Popen([binary, '-f', c['interface']], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   start_new_session=True, env=dict(os.environ, WG_PROCESS_FOREGROUND='1', LOG_LEVEL='error'))
    for _ in range(50):
        observed = process_identity(process.pid)
        if observed:
            state['process'] = {k: v for k, v in observed.items() if k != 'argv'}
            save(root, state)
        if socket_path.exists() and exists_link(c['interface']):
            command('ip', 'link', 'set', 'dev', c['interface'], 'alias', OWNER + ':' + state['connectorId'])
            return
        if process.poll() is not None: break
        time.sleep(.05)
    raise RuntimeError('pinned userspace uplink did not become available')


def read_key_file(path, *, optional=False):
    """Read <=128 bytes from one no-follow, regular, private, current-euid inode."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 128:
            raise ValueError('unsafe key inode')
        data = b''
        while len(data) <= 128:
            chunk = os.read(fd, 129 - len(data))
            if not chunk: break
            data += chunk
        if len(data) > 128: raise ValueError('oversized key inode')
        return key(data.decode('ascii').strip())
    except FileNotFoundError:
        if optional: return None
        raise RuntimeError('private key file unavailable or unsafe') from None
    except (OSError, ValueError, UnicodeError):
        raise RuntimeError('private key file unavailable or unsafe') from None
    finally:
        if fd is not None: os.close(fd)


def set_peer(root, c):
    private = read_key_file(Path(root) / 'private.key')
    psk = read_key_file(Path(root) / 'preshared.key', optional=True)
    allowed = ['0.0.0.0/0', '::/0'] if c['role'] == 'bridge' else [n for f in c['innerFamilies'] for n in source_networks(c, f)]
    peer = c['peer']
    endpoint = None
    if peer.get('host'): endpoint = ('[' + peer['host'] + ']' if ':' in peer['host'] else peer['host']) + ':' + str(peer['port'])
    try:
        observed = peer_snapshot(c)
        configured = bool(observed and set(observed['allowedIPs']) == set(allowed) and
                          (not endpoint or observed.get('endpoint') == endpoint))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        configured = False
    if c['backend'] == 'userspace' and not configured:
        lines = ['set=1', 'private_key=' + base64.b64decode(private).hex(), 'listen_port=' + str(c['listenPort']),
                 'replace_peers=true', 'public_key=' + base64.b64decode(peer['publicKey']).hex(), 'replace_allowed_ips=true']
        lines += ['allowed_ip=' + n for n in allowed]
        if endpoint: lines.append('endpoint=' + endpoint)
        lines.append('persistent_keepalive_interval=15')
        if psk: lines.append('preshared_key=' + base64.b64decode(psk).hex())
        uapi(c['interface'], '\n'.join(lines))
    elif c['backend'] == 'kernel' and not configured:
        lines = ['[Interface]', 'PrivateKey = ' + private, 'ListenPort = ' + str(c['listenPort']),
                 '[Peer]', 'PublicKey = ' + peer['publicKey'], 'AllowedIPs = ' + ', '.join(allowed), 'PersistentKeepalive = 15']
        if endpoint: lines.append('Endpoint = ' + endpoint)
        if psk: lines.append('PresharedKey = ' + psk)
        command('wg', 'setconf', c['interface'], '/dev/stdin', input='\n'.join(lines) + '\n')
    command('ip', 'link', 'set', 'dev', c['interface'], 'mtu', '1280', 'up')
    for family in c['innerFamilies']:
        flag = '-4' if family == 'ipv4' else '-6'
        address = c['localAddresses'][family] + ('/32' if family == 'ipv4' else '/128')
        command('ip', flag, 'addr', 'replace', address, 'dev', c['interface'])
        if c['role'] == 'bridge':
            command('ip', flag, 'route', 'replace', 'default', 'dev', c['interface'], 'metric', '10', 'table', str(TABLE), 'proto', '242')
        else:
            for subnet in source_networks(c, family):
                command('ip', flag, 'route', 'replace', subnet, 'dev', c['interface'], 'proto', '242')
    # Reverse packets arrive on the owned uplink, not the normal main-default device.
    command('sysctl', '-qw', 'net.ipv4.conf.' + c['interface'] + '.rp_filter=2')
    return not configured


def _apply(root, state):
    spec = plan(state['config'])
    state['phase'] = 'applying'; state['guardState'] = 'unknown'; save(root, state)
    # Routing fence first: guard survives firewall resets, no host main fallback.
    policy_sync(spec)
    firewall_sync(spec)
    state['phase'] = 'guarded'; state['guardState'] = 'last_installed'
    save(root, state)
    start_backend(root, state)
    if set_peer(root, state['config']): state['proofs'] = {}
    state['phase'] = 'applied'
    state.pop('error', None)
    save(root, state)


def lifecycle_for(root):
    # Ad-hoc roots are private test instances, NOT supported production lifecycles.
    # The managed production path always requires the signed sibling helper.
    path = Path(root)
    if path.absolute() != DEFAULT_ROOT and path.resolve() != DEFAULT_ROOT:
        try:
            isolated = all(os.readlink('/proc/self/ns/' + kind) != os.readlink('/proc/1/ns/' + kind) for kind in ('net', 'mnt'))
        except OSError:
            isolated = False
        if not isolated: raise RuntimeError('custom connector roots require private network AND mount namespaces; production must use managed lifecycle')
        return None
    import cascade_native_lifecycle
    return cascade_native_lifecycle


def record_failure(root, state, *, preparation):
    state['proofs'] = {}
    if preparation:
        state['phase'] = 'preparation_failed'; state['guardState'] = 'unknown'
        state['error'] = 'preparation_failed; no network apply attempted; existing guard completeness unknown'
    elif state.get('guardState') == 'last_installed' and state.get('phase') in ('guarded', 'applied'):
        state['phase'] = 'fail_closed'
        state['error'] = 'apply_failed after guard installation; no automatic direct rollback; inspect current guards'
    else:
        state['phase'] = 'apply_failed'; state['guardState'] = 'unknown'
        state['error'] = 'apply_failed; guard completeness unknown; owned effects not rolled back to direct'
    save(root, state)


def configure(request, root=DEFAULT_ROOT):
    c = validate_config(request)
    private = request.get('privateKey')
    if private: key(private)
    elif not os.path.lexists(Path(root) / 'private.key'): raise ValueError('owner privateKey required on first configure (JSON stdin, never argv)')
    if os.geteuid() != 0: raise PermissionError('root required')
    with locked(root):
        state = load(root)
        if state and not state.get('enabled'): state = None
        if state and state['configHash'] != digest(c): raise RuntimeError('configuration change requires explicit remove/confirmation, not silent takeover')
        stored_private = read_key_file(Path(root) / 'private.key', optional=True)
        stored_psk = read_key_file(Path(root) / 'preshared.key', optional=True)
        if state and private and stored_private != private:
            raise RuntimeError('private key change requires explicit remove/reconfigure')
        if state and request.get('presharedKey') and stored_psk != request['presharedKey']:
            raise RuntimeError('PSK change requires explicit remove/reconfigure')
        if state is None:
            owned_preflight(plan(c))
            state = dict(owner=OWNER, schema=1, enabled=True, connectorId=str(uuid.uuid4()), revision=1,
                         config=c, configHash=digest(c), phase='prepared', proofs={})
            if private: atomic(Path(root) / 'private.key', private + '\n')
            if request.get('presharedKey'): atomic(Path(root) / 'preshared.key', key(request['presharedKey']) + '\n')
            save(root, state)
        apply_started = False
        try:
            life = lifecycle_for(root)
            if life: life.install(state, root=root)
            apply_started = True
            state['guardState'] = 'unknown'
            _apply(root, state)
            if life: life.activate(state, root=root)
        except Exception:
            record_failure(root, state, preparation=not apply_started)
            raise
    return inspect(root=root)


def desired_native_families(native_map=None, *, root=DEFAULT_ROOT):
    state = load(root)
    if not state or not state.get('enabled') or state['config']['role'] != 'bridge': return None
    current = networks(native_map)
    if current != state['config']['ingresses']: raise RuntimeError('native ingress map changed; refusing silent adoption')
    return {p: {f: state['config']['role'] == 'bridge' and f in state['config']['innerFamilies'] for f in ('ipv4', 'ipv6')} for p in current}


def reconcile_native(native_map=None, reason='native-network-reapply', *, root=DEFAULT_ROOT):
    state = load(root)
    if not state or not state.get('enabled'): return None
    desired_native_families(native_map, root=root)
    with locked(root):
        state = load(root)
        apply_started = False
        try:
            life = lifecycle_for(root)
            if life: life.assert_installed(state, root=root)
            apply_started = True
            state['guardState'] = 'unknown'
            _apply(root, state)
        except Exception:
            record_failure(root, state, preparation=not apply_started)
            raise
    return None


def peer_snapshot(c):
    """Never return raw UAPI/dump; both contain private key material."""
    if c['backend'] == 'userspace':
        text = uapi(c['interface'], 'get=1')
        peer = None
        result = None
        for line in text.splitlines():
            name, _, value = line.partition('=')
            if name == 'public_key':
                peer = base64.b64encode(bytes.fromhex(value)).decode()
                if peer == c['peer']['publicKey']: result = {'publicKey': peer, 'handshake': 0, 'allowedIPs': []}
            elif peer == c['peer']['publicKey'] and result is not None:
                if name == 'last_handshake_time_sec': result['handshake'] = int(value)
                elif name == 'allowed_ip': result['allowedIPs'].append(value)
                elif name == 'endpoint': result['endpoint'] = value
        return result
    text = command('wg', 'show', c['interface'], 'dump').stdout
    for line in text.splitlines()[1:]:
        fields = line.split('\t')
        if len(fields) >= 8 and fields[0] == c['peer']['publicKey']:
            return {'publicKey': fields[0], 'handshake': int(fields[4]), 'allowedIPs': fields[3].split(','), 'endpoint': fields[2]}
    return None


def bounded_local(function):
    def call(*args, **kwargs):
        token = _DEADLINE.set(time.monotonic() + 2)
        try: return function(*args, **kwargs)
        finally: _DEADLINE.reset(token)
    return call


@bounded_local
def infrastructure(state, *, root=None):
    c, reasons = state['config'], []
    if not exists_link(c['interface']): return ['uplink_missing']
    try:
        require_owned_link(state)
        life = lifecycle_for(root) if root is not None else None
        if life: life.assert_installed(state, root=root)
        if c['role'] == 'bridge':
            for item in c['ingresses'].values():
                if not exists_link(item['interface']):
                    reasons.append('native_interface_missing'); continue
                rows = ipjson('addr', 'show', 'dev', item['interface'])
                native_addresses = [a['local'] for row in rows for a in row.get('addr_info', [])]
                proto = next(p for p, value in c['ingresses'].items() if value == item)
                for family in c['innerFamilies']:
                    proof_source = state.get('proofs', {}).get(proto + '.' + family, {}).get('source')
                    if proof_source and proof_source not in native_addresses: reasons.append('native_proof_source_missing')
                    net = ipaddress.ip_network(item[family])
                    if not any(ipaddress.ip_address(a).version == net.version and ipaddress.ip_address(a) in net for a in native_addresses):
                        reasons.append('native_address_missing')
        peer = peer_snapshot(c)
        if not peer or not 0 <= time.time() - peer['handshake'] <= 180: reasons.append('fresh_peer_handshake_required')
        expected = {'0.0.0.0/0', '::/0'} if c['role'] == 'bridge' else {n for f in c['innerFamilies'] for n in source_networks(c, f)}
        if not peer or set(peer['allowedIPs']) != expected: reasons.append('peer_allowed_ips_mismatch')
        addresses = {a['local'] for row in ipjson('addr', 'show', 'dev', c['interface']) for a in row.get('addr_info', [])}
        if not all(c['localAddresses'][f] in addresses for f in c['innerFamilies']): reasons.append('uplink_address_missing')
        spec = plan(c)
        for family, entry in spec['firewall'].items():
            for table, parent, chain in CHAINS:
                actual = chain_rules(entry['tool'], table, chain)
                # iptables may canonicalize numbers/case; exact -C probes avoid loose textual adoption.
                if actual is None or len(actual) != len(entry['chains'][chain]): reasons.append('owned_firewall_missing'); continue
                for rule in entry['chains'][chain]:
                    if command(entry['tool'], '-w', '5', '-t', table, '-C', chain, *rule, check=False).returncode: reasons.append('owned_firewall_mismatch')
                parents = chain_rules(entry['tool'], table, parent)
                if not parents or parents[0] != jump(chain): reasons.append('owned_jump_not_first')
            if c['role'] == 'bridge':
                rule_rows = ipjson(entry['flag'], 'rule', 'show')
                assert_policy_rows(spec, family, rule_rows)
                for rule in spec['policy'][family]:
                    priority = int(rule[1])
                    matches = [r for r in rule_rows if r.get('priority') == priority]
                    if len(matches) != 1: reasons.append('routing_fence_missing'); continue
                    if not policy_matches(matches[0], rule): reasons.append('routing_fence_mismatch')
                routes = owned_table_routes(spec, family)
                if not any(r.get('type') == 'unreachable' for r in routes): reasons.append('reject_route_missing')
                if family in c['innerFamilies'] and not any(r.get('dev') == c['interface'] and r.get('dst') == 'default' for r in routes): reasons.append('uplink_route_missing')
            elif family in c['innerFamilies']:
                routes = ipjson(entry['flag'], 'route', 'show', 'dev', c['interface'])
                destinations = {r.get('dst') for r in routes}
                for subnet in source_networks(c, family):
                    if subnet not in destinations and str(ipaddress.ip_network(subnet).network_address) not in destinations: reasons.append('reverse_route_missing')
        for family in c['innerFamilies']:
            name = 'net.ipv4.ip_forward' if family == 'ipv4' else 'net.ipv6.conf.all.forwarding'
            if command('sysctl', '-n', name).stdout.strip() != '1': reasons.append('forwarding_disabled')
    except (ImportError, OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        reasons.append('live_inspection_failed:' + str(error))
    return sorted(set(reasons))


def inspect(*, root=DEFAULT_ROOT):
    state = load(root)
    if state is None or not state.get('enabled'): return {'schema': 1, 'enabled': False}
    reasons = infrastructure(state, root=root)
    # Historical installation provenance, never evidence of current guard health.
    guard = state.get('guardState')
    if type(guard) is not str or guard not in ('unknown', 'last_installed'): guard = 'unknown'
    return dict(schema=1, enabled=True, connectorId=state['connectorId'], revision=state['revision'],
                phase=state['phase'], guardState=guard, config=state['config'], infrastructureReady=not reasons,
                reasons=reasons, capabilities=native_capabilities(root=root, _observed=reasons))


def native_capabilities(native_map=None, *, root=DEFAULT_ROOT, _observed=None):
    state = load(root)
    if not state or not state.get('enabled') or state['config']['role'] != 'bridge': return None
    desired_native_families(native_map, root=root)
    now = int(time.time())
    reasons = infrastructure(state, root=root) if _observed is None else list(_observed)
    if state['phase'] != 'applied': reasons = list(reasons) + ['connector_not_applied']
    stamp = lambda value: datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    result = dict(schema=1, enabled=True, connectorId=state['connectorId'], revision=state['revision'], observedAt=stamp(now), expiresAt=stamp(now))
    expiries = []
    for proto, item in state['config']['ingresses'].items():
        values = {}
        for family, suffix in [('ipv4', '4'), ('ipv6', '6')]:
            proof = state.get('proofs', {}).get(proto + '.' + family, {})
            reason = ','.join(reasons) if reasons else 'fresh_native_probe_required'
            ready = False
            if state['config']['role'] != 'bridge': reason = 'exit_role_not_a_native_bridge'
            elif family not in state['config']['innerFamilies']: reason = 'family_not_selected_no_direct_fallback'
            elif not reasons and proof.get('configHash') == state['configHash'] and 0 <= now - proof.get('observedAt', 0) < PROOF_TTL and proof.get('success') is True:
                ready = True; reason = 'source_bound_inner_probe_verified'
                expiries.append(proof['observedAt'] + PROOF_TTL)
            values[family], values['reason' + suffix] = ready, reason
        result[proto] = values
    if expiries: result['expiresAt'] = stamp(min(expiries))
    return result


def verify(*, root=DEFAULT_ROOT, targets=None):
    """Explicit active source-bound probes; inspect/hooks NEVER perform Internet I/O."""
    targets = targets or {'ipv4': '1.1.1.1', 'ipv6': '2606:4700:4700::1111'}
    for family, value in targets.items():
        value = literal(value)
        addr = ipaddress.ip_address(value)
        if not addr.is_global or addr.version != (4 if family == 'ipv4' else 6): raise ValueError('public family-correct proof target required')
    with locked(root):
        state = load(root)
        if not state: raise RuntimeError('no owner opt-in')
        c = state['config']
        if c['role'] != 'bridge': raise ValueError('native probe belongs on bridge')
        reasons = infrastructure(state, root=root)
        if reasons: raise RuntimeError('infrastructure not ready: ' + ','.join(reasons))
        observed = int(time.time())
        for proto, item in c['ingresses'].items():
            rows = ipjson('addr', 'show', 'dev', item['interface'])
            addresses = [a['local'] for r in rows for a in r.get('addr_info', [])]
            for family in c['innerFamilies']:
                subnet = ipaddress.ip_network(item[family])
                source = next((x for x in addresses if ipaddress.ip_address(x).version == subnet.version and ipaddress.ip_address(x) in subnet), None)
                good = False
                if source:
                    p = command('ping', '-4' if family == 'ipv4' else '-6', '-n', '-c', '1', '-W', '2', '-m', str(int(MARK.split('/')[0], 16)), '-I', source, targets[family], check=False)
                    good = p.returncode == 0
                state.setdefault('proofs', {})[proto + '.' + family] = dict(success=good, source=source, target=targets[family], observedAt=observed, configHash=state['configHash'], scope='source-bound native-prefix active probe; not device anti-DPI acceptance')
        save(root, state)
    return native_capabilities(root=root)


def remove(*, root=DEFAULT_ROOT, confirm_direct=False):
    if not confirm_direct: raise ValueError('explicit confirmDirect:true required; removal restores native direct policy')
    with locked(root):
        state = load(root)
        if state is None: return {'schema': 1, 'enabled': False}
        c = state['config']; spec = plan(c)
        assert_owned_chains(spec)
        policy_snapshot(spec)
        life = lifecycle_for(root)
        if life: life.remove(state, root=root)
        state['phase'] = 'removing'; state['proofs'] = {}; save(root, state)
        # Stop only the owned runtime/interface; routing fences remain until final removal.
        if exists_link(c['interface']): require_owned_link(state)
        if c['backend'] == 'userspace' and state.get('process'):
            identity = process_identity(state['process']['pid'])
            if identity and identity['start'] == state['process']['start'] and identity['exe'] == state['process']['exe']:
                os.kill(identity['pid'], signal.SIGTERM)
            elif identity: raise RuntimeError('runtime ownership changed; refusing signal')
        if exists_link(c['interface']):
            command('ip', 'link', 'delete', 'dev', c['interface'], check=False)
            if exists_link(c['interface']): raise RuntimeError('owned uplink did not stop; fences retained')
        for family, entry in spec['firewall'].items():
            flag, tool = entry['flag'], entry['tool']
            if c['role'] == 'bridge':
                # Delete exact scoped rules, never arbitrary priorities or foreign table contents.
                for rule in spec['policy'][family]: command(*rule_args(family, ['del', *rule]), check=False)
                command('ip', flag, 'route', 'del', 'unreachable', 'default', 'metric', '32760', 'table', str(TABLE), 'proto', '242', check=False)
            for table, parent, chain in reversed(CHAINS):
                while not command(tool, '-w', '5', '-t', table, '-C', parent, *jump(chain), check=False).returncode:
                    command(tool, '-w', '5', '-t', table, '-D', parent, *jump(chain))
                if chain_rules(tool, table, chain) is not None:
                    command(tool, '-w', '5', '-t', table, '-F', chain)
                    command(tool, '-w', '5', '-t', table, '-X', chain)
        state['enabled'] = False; state['phase'] = 'removed'; save(root, state)
    return {'schema': 1, 'enabled': False}


def guard_auto(*, root=DEFAULT_ROOT):
    """Mandatory boot dependency: missing/disabled/foreign receipt is FAILURE, not skip."""
    state = load(root)
    if not state or not state.get('enabled'): raise RuntimeError('active owned native receipt required by boot guard')
    with locked(root):
        state = load(root)
        if not state or not state.get('enabled'): raise RuntimeError('native opt-in removed during boot guard')
        apply_started = False
        try:
            life = lifecycle_for(root)
            if life: life.assert_installed(state, root=root)
            apply_started = True
            state['guardState'] = 'unknown'
            _apply(root, state)
        except Exception:
            record_failure(root, state, preparation=not apply_started)
            raise
    return {'schema': 1, 'enabled': True, 'guarded': True, 'connectorId': state['connectorId']}


def verify_auto(*, root=DEFAULT_ROOT):
    """Timer-safe, stdin-independent, owner-scoped recovery and active verification."""
    state = load(root)
    if not state or not state.get('enabled') or state['config']['role'] != 'bridge':
        return {'schema': 1, 'enabled': False, 'verified': False}
    reconcile_native(root=root, reason='owned-periodic-verifier')
    return verify(root=root)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['validate', 'plan', 'configure', 'reconcile', 'inspect', 'verify', 'remove', 'guard-auto', 'verify-auto'])
    p.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    a = p.parse_args()
    request = {} if a.action in ('inspect', 'reconcile', 'guard-auto', 'verify-auto') else json.load(sys.stdin)
    if a.action == 'validate': value = validate_config(request)
    elif a.action == 'plan': value = plan(request)
    elif a.action == 'configure': value = configure(request, a.root)
    elif a.action == 'inspect': value = inspect(root=a.root)
    elif a.action == 'reconcile': reconcile_native(root=a.root); value = inspect(root=a.root)
    elif a.action == 'verify': value = verify(root=a.root, targets=request.get('targets'))
    elif a.action == 'guard-auto': value = guard_auto(root=a.root)
    elif a.action == 'verify-auto': value = verify_auto(root=a.root)
    else: value = remove(root=a.root, confirm_direct=request.get('confirmDirect') is True)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__ + ': ' + str(error)}))
        sys.exit(1)
