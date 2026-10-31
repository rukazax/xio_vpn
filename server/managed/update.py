#!/usr/bin/env python3
"""Transactional update of an existing owned deployment from the app bundle.

The SSH peer and archive SHA256 are authenticated by the installed app. This
script never downloads code, runs package managers, regenerates keys or changes
ports. New schema migrations must explicitly extend and test this transaction.
"""
import fcntl
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

LIB = Path('/usr/local/lib/xio-managed')
STATE = Path('/etc/xio-managed/deployment.json')
RECIPE = 25
OWNER = 'xio-managed-v1'
UNITS = ('xio-managed-stats.timer', 'xio-managed-awg.service',
         'xio-rivet-entry.service', 'xio-rivet-gateway.service', 'xio-stack.service', 'xio-cloak.service', 'xio-openvpn-tcp.service')
STACK_CONFIG = Path('/etc/xio-stack/config.json')
WG_CONFIG = Path('/etc/wireguard/xio0.conf')
NETWORK_CONFIGS=(Path('/etc/xio-stack/cloak.json'),Path('/etc/xio-stack/tcp.ovpn'),Path('/usr/local/lib/xio-rivet/network-up'))
DUAL_RECEIPT=Path('/etc/xio-managed/dualstack-receipt.json')
RIVET_ROOT = Path('/etc/xio-rivet')
RIVET_SETUP = Path('/usr/local/lib/xio-rivet/setup.py')
RIVET_PRIVATE_FILES = ('gateway.json', 'users.json', 'seal.key', 'inner.crt',
                       'inner.key', 'entry.json', 'tokens.json', 'outer.crt', 'outer.key')
NETWORK_UNITS = tuple(Path('/etc/systemd/system/xio-openvpn-' + t + '.service') for t in ('udp', 'tcp'))
LEGACY_UNITS = ('xio-openvpn-udp.service', 'xio-ikev2.service', 'xio-headscale.service', 'xio-tailscaled.service')
RUNTIMES = {'amneziawg-go': '/usr/local/bin/xio-amneziawg-go',
            'rivet': '/usr/local/bin/xio-rivet',
            'xraygateway': '/usr/local/bin/xio-stack',
            'cloak': '/usr/local/bin/xio-cloak'}


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, check=check, timeout=60)


def atomic(source, target, mode):
    target = Path(target)
    regular(target, missing=True)
    descriptor, name = tempfile.mkstemp(prefix='.' + target.name + '.update-', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as out, Path(source).open('rb') as data:
            shutil.copyfileobj(data, out)
            out.flush()
            os.fsync(out.fileno())
        temporary.chmod(mode)
        os.replace(temporary, target)
        if shutil.which('restorecon'):
            command('restorecon', str(target))
    finally:
        temporary.unlink(missing_ok=True)


def regular(path, missing=False):
    """Reject links, including linked parents, before touching owned files."""
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('Symlink in managed deployment: ' + path.name)
    try:
        info = path.stat()
    except FileNotFoundError:
        if missing:
            return
        raise RuntimeError('Missing owned file: ' + path.name)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError('Non-regular owned file: ' + path.name)


def snapshot(path):
    regular(path)
    raw = Path(path).read_bytes()
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'raw': raw,
            'mode': Path(path).stat().st_mode & 0o777}


def verify(snapshots):
    for path, previous in snapshots.items():
        if snapshot(path)['sha256'] != previous['sha256']:
            raise RuntimeError('Owned file changed during update: ' + path.name)


def rivet_metadata(data):
    """Bind legacy public metadata to BOTH owned receipts; never re-key.

    The old recipe has no public-file hash. Exact agreement of its two public
    copies, its ready owner receipt and its original fixed endpoint is required
    before taking a hash snapshot. A divergent copy is owner review, not repair.
    """
    if not data.get('rivet'):
        if RIVET_ROOT.exists() or RIVET_ROOT.is_symlink() or RIVET_SETUP.parent.exists() or RIVET_SETUP.parent.is_symlink():
            raise RuntimeError('RIVET ownership does not match deployment')
        return None, {}
    paths = [RIVET_ROOT / 'install-receipt.json', RIVET_ROOT / 'public.json',
             RIVET_SETUP, *[RIVET_ROOT / name for name in RIVET_PRIVATE_FILES]]
    snapshots = {p: snapshot(p) for p in paths}
    receipt = json.loads(snapshots[paths[0]]['raw'])
    public = json.loads(snapshots[paths[1]]['raw'])
    if receipt.get('owner') != 'xio-rivet-v1' or receipt.get('phase') != 'ready':
        raise RuntimeError('Unowned or incomplete RIVET receipt')
    if not isinstance(public, dict) or public != data['rivet']:
        raise RuntimeError('RIVET public metadata differs from owned deployment')
    if data.get('rivetPublicSha256') and data['rivetPublicSha256'] != snapshots[paths[1]]['sha256']:
        raise RuntimeError('RIVET public metadata digest differs from owned deployment')
    name = public.get('serverName')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', name):
        raise RuntimeError('Invalid raw RIVET server name')
    if ':' in name:
        try:
            ipaddress.IPv6Address(name)
        except ValueError:
            raise RuntimeError('Invalid raw RIVET IPv6 address') from None
    if receipt.get('serverName') != name:
        raise RuntimeError('RIVET server name differs from owner receipt')
    endpoint = ('[' + name + ']' if ':' in name else name) + ':8443'
    if public.get('endpoint') not in (name + ':8443', endpoint):
        raise RuntimeError('Unrecognized RIVET endpoint; owner review required')
    return dict(public, endpoint=endpoint), snapshots


def unpack(raw, destination, expected):
    if len(raw) > 256 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError('Update archive integrity check failed')
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        names = set()
        for member in archive:
            name = member.name
            path = Path(name)
            if (not member.isfile() or path.is_absolute() or '..' in path.parts
                    or name in names or len(path.parts) > 2
                    or len(path.parts) == 2 and path.parts[0] != 'xio_vici'):
                raise RuntimeError('Invalid update archive entry')
            names.add(name)
            total += member.size
            if member.size > 128 * 1024 * 1024 or total > 320 * 1024 * 1024:
                raise RuntimeError('Update archive too large')
            target = destination / path
            target.parent.mkdir(exist_ok=True)
            with archive.extractfile(member) as source, target.open('wb') as out:
                shutil.copyfileobj(source, out)
        required = {'admin.py', 'stack.py', 'network_stack.py', 'mesh_stack.py',
                    'mesh-pins.json', 'rivet-setup.py', 'dualstack.py', 'client_api.py', *RUNTIMES}
        if not required.issubset(names):
            raise RuntimeError('Incomplete update archive')
    for source in destination.rglob('*.py'):
        compile(source.read_bytes(), source.name, 'exec')


def ipv6_transaction_module(stage):
    import importlib.util
    spec = importlib.util.spec_from_file_location('xio_update_ipv6', stage / 'dualstack.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def update(raw, expected, server_id):
    if os.geteuid() != 0:
        raise RuntimeError('Owner root access required')
    regular(LIB / '.owner')
    regular(STATE)
    if (LIB / '.owner').read_text().strip() != OWNER:
        raise RuntimeError('Unowned deployment')
    guards = {p: snapshot(p) for p in (LIB / '.owner', STATE)}
    data = json.loads(guards[STATE]['raw'])
    if data.get('owner') != OWNER or data.get('id') != server_id:
        raise RuntimeError('Server identity mismatch')
    if data.get('phase') != 'ready':
        raise RuntimeError('Deployment is not ready')
    current = data.get('recipeVersion', 13)
    if type(current) is not int:
        raise RuntimeError('Invalid server recipe')
    if current > RECIPE:
        raise RuntimeError('Server is newer than this application')
    if current == RECIPE and data.get('bundleSha256') == expected:
        return {'updated': False, 'recipeVersion': RECIPE}
    if current == RECIPE and data.get('bundleSha256'):
        raise RuntimeError('Conflicting bundle at the same recipe revision')
    # Never permit a different archive to replace the same recipe revision.
    if current not in (13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24):
        raise RuntimeError('Unsupported server recipe')
    public, rivet_guards = rivet_metadata(data)
    guards.update(rivet_guards)
    network_units = []
    for unit in NETWORK_UNITS:
        regular(unit, missing=True)
        if not unit.exists():
            continue
        receipt = STACK_CONFIG.parent / 'receipt.json'
        guards[receipt] = snapshot(receipt)
        if not data.get('stack') or json.loads(guards[receipt]['raw']).get('owner') != 'xio-stack-v1':
            raise RuntimeError('Unowned OpenVPN stack')
        text = unit.read_text()
        transport = 'udp' if unit.name == 'xio-openvpn-udp.service' else 'tcp'
        if ('Description=XIO managed xio-openvpn-' + transport + '\n' not in text
                or ' --config ' + str(STACK_CONFIG.parent / (transport + '.ovpn')) + '\n' not in text):
            raise RuntimeError('Unowned OpenVPN service')
        network_units.append(unit)
    legacy_network = current < 24
    if DUAL_RECEIPT.exists() or DUAL_RECEIPT.is_symlink():
        dual = snapshot(DUAL_RECEIPT)
        if legacy_network or json.loads(dual['raw']).get('owner') != 'xio-dualstack-v1':
            raise RuntimeError('Existing IPv6 migration receipt requires owner review')
        guards[DUAL_RECEIPT] = dual
    with tempfile.TemporaryDirectory(prefix='.update-', dir=LIB.parent) as folder:
        work = Path(folder)
        stage = work / 'stage'
        stage.mkdir(mode=0o700)
        unpack(raw, stage, expected)
        targets = [(p, LIB / p.relative_to(stage), 0o755 if p.name in RUNTIMES else 0o600)
                   for p in sorted(stage.rglob('*')) if p.is_file()]
        targets += [(stage / name, Path(dest), 0o755)
                    for name, dest in RUNTIMES.items() if Path(dest).exists()]
        if public is not None:
            auxiliary = RIVET_SETUP.with_name('rivet')
            if auxiliary.exists() or auxiliary.is_symlink():
                targets.append((stage / 'rivet', auxiliary, 0o755))
            # The installed network-up script calls this copy, not LIB/rivet-setup.py.
            targets.append((stage / 'rivet-setup.py', RIVET_SETUP, 0o700))
        migration_targets = [STATE, *network_units]
        if public is not None:
            migration_targets.append(RIVET_ROOT / 'public.json')
        if legacy_network:
            migration_targets += [STACK_CONFIG, WG_CONFIG, *NETWORK_CONFIGS]
        # All destination ownership/link checks precede service stops and writes.
        for target in [*migration_targets, *[t for _, t, _ in targets]]:
            regular(target, missing=True)
            if target.exists() and target not in guards:
                guards[target] = snapshot(target)
        active = [u for u in UNITS if command('systemctl', 'is-active', '--quiet', u, check=False).returncode == 0]
        legacy = []
        if legacy_network:
            for unit in LEGACY_UNITS:
                path = Path('/etc/systemd/system') / unit
                if path.is_file() and ('XIO' in path.read_text() or 'xio' in path.read_text()):
                    legacy.append((unit, command('systemctl', 'is-active', '--quiet', unit, check=False).returncode == 0,
                                   command('systemctl', 'is-enabled', '--quiet', unit, check=False).returncode == 0))
        verify(guards)
        (work / 'hashes-before.json').write_text(json.dumps({str(p): v['sha256'] for p, v in guards.items()}))
        backups = []
        network = ipv6_transaction_module(stage)
        network_plan = None
        committed = False

        def backup(target):
            previous = work / ('backup-' + str(len(backups)))
            existed = target.exists()
            if existed:
                shutil.copy2(target, previous)
                if snapshot(previous)['sha256'] != guards[target]['sha256']:
                    raise RuntimeError('Owned backup integrity check failed: ' + target.name)
            backups.append((target, previous, existed))

        try:
            network_plan = network.delta_begin(work)
            (work / 'ipv6-plan.json').write_text(json.dumps(network_plan))
            for unit in active:
                command('systemctl', 'stop', unit)
            for unit, _, _ in legacy:
                command('systemctl', 'disable', '--now', unit)
            verify(guards)
            # Public metadata and deployment are a single rollback transaction.
            # Per-file replacements are atomic; STATE (the commit record) is last.
            for target in migration_targets:
                if target.exists():
                    backup(target)
            if legacy_network:
                data['restrictedNetwork'] = True
                if isinstance(data.get('stack'), dict):
                    data['stack']['protocols'] = ['xray', 'cloak']
                staged_state = work / 'migration-state.json'
                staged_state.write_text(json.dumps(data))
                atomic(staged_state, STATE, 0o600)
                if WG_CONFIG.exists():
                    staged_wg = work / 'migration-wg.conf'
                    staged_wg.write_text(WG_CONFIG.read_text().split('[Peer]', 1)[0])
                    atomic(staged_wg, WG_CONFIG, 0o600)
                if STACK_CONFIG.exists():
                    config = json.loads(STACK_CONFIG.read_text())
                    config['inbounds'] = [i for i in config.get('inbounds', []) if i.get('protocol') != 'shadowsocks']
                    staged_config = work / 'migration-xray.json'
                    staged_config.write_text(json.dumps(config))
                    atomic(staged_config, STACK_CONFIG, 0o600)
            # Runtime backups share the same transaction. Never touch private keys,
            # certificates, delegated SSH keys or provider addresses/routes.
            for source, target, mode in targets:
                target.parent.mkdir(exist_ok=True)
                backup(target)
                atomic(source, target, mode)
            if network_units:
                command('python3', str(LIB / 'network_stack.py'), 'reconcile-ipv6-hooks')
                command('systemctl', 'daemon-reload')
            public_path = RIVET_ROOT / 'public.json'
            if public is not None:
                if public != data['rivet']:
                    staged_public = work / 'public.json'
                    staged_public.write_text(json.dumps(public))
                    atomic(staged_public, public_path, rivet_guards[public_path]['mode'])
                data['rivet'] = public
                data['rivetPublicSha256'] = snapshot(public_path)['sha256']
            if legacy_network:
                command('python3', str(LIB / 'dualstack.py'), 'configure')
            for unit in reversed(active):
                command('systemctl', 'start', unit)
            for unit in active:
                command('systemctl', 'is-active', '--quiet', unit)
            if legacy_network:
                command('python3', str(LIB / 'dualstack.py'), 'apply')
            # Services may read keys but may not silently replace them during an
            # endpoint-only migration. Verify the untouched receipt/keys again.
            verify({p: v for p, v in rivet_guards.items() if p not in (public_path, RIVET_SETUP)})
            if public is not None and snapshot(public_path)['sha256'] != data['rivetPublicSha256']:
                raise RuntimeError('RIVET public metadata changed before commit')
            data['recipeVersion'] = RECIPE
            data['bundleSha256'] = expected
            temporary = work / 'deployment.json'
            temporary.write_text(json.dumps(data))
            atomic(temporary, STATE, 0o600)
            if snapshot(STATE)['sha256'] != snapshot(temporary)['sha256']:
                raise RuntimeError('Deployment commit integrity check failed')
            network.delta_commit(network_plan)
            committed = True
        finally:
            if not committed:
                try:
                    for unit in active:
                        if command('systemctl', 'stop', unit, check=False).returncode:
                            raise RuntimeError('Cannot stop new service before IPv6 rollback')
                    deferred_network_runtime = []
                    for target, previous, existed in reversed(backups):
                        if network_plan is not None and target == LIB / 'dualstack.py':
                            deferred_network_runtime.append((target, previous, existed))
                            continue
                        if existed:
                            if snapshot(previous)['sha256'] != guards[target]['sha256']:
                                raise RuntimeError('Rollback backup integrity check failed')
                            atomic(previous, target, previous.stat().st_mode & 0o777)
                        else:
                            target.unlink(missing_ok=True)
                    if network_units:
                        command('systemctl', 'daemon-reload')
                    try:
                        # Keep the fenced helper during old-service restart too:
                        # restored startup scripts can otherwise re-add effects
                        # after an early network rollback. Restore helper last.
                        for unit in reversed(active):
                            command('systemctl', 'start', unit)
                        for unit, was_active, was_enabled in legacy:
                            if was_enabled:
                                command('systemctl', 'enable', unit)
                            if was_active:
                                command('systemctl', 'start', unit)
                    finally:
                        if network_plan is not None:
                            network.delta_rollback(network_plan)
                        for target, previous, existed in deferred_network_runtime:
                            if existed:
                                if snapshot(previous)['sha256'] != guards[target]['sha256']:
                                    raise RuntimeError('Rollback network runtime backup hash mismatch')
                                atomic(previous, target, previous.stat().st_mode & 0o777)
                            else:
                                target.unlink(missing_ok=True)
                except Exception:
                    recovery = Path(tempfile.mkdtemp(prefix='.update-recovery-', dir=LIB.parent))
                    shutil.copytree(work, recovery / 'backup')
                    fence = DUAL_RECEIPT.with_name('.dualstack-update.json')
                    if fence.is_file() and not any(p.is_symlink() for p in (fence, *fence.parents)):
                        shutil.copy2(fence, recovery / 'backup/ipv6-intent-recovery.json')
                    raise RuntimeError('Rollback requires owner recovery; backup retained')
    return {'updated': True, 'recipeVersion': RECIPE}


def main():
    os.umask(0o077)
    try:
        expected, server_id = sys.argv[1:]
        if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
            raise RuntimeError('Invalid archive digest')
        def interrupted(*_):
            raise RuntimeError('Update interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        # Serialize with administration and the statistics sampler.
        with open('/run/lock/xio-managed.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            raw = sys.stdin.buffer.read(256 * 1024 * 1024 + 1)
            result = update(raw, expected, server_id)
        print(json.dumps({'ok': True, **result}))
    except Exception:
        print(json.dumps({'ok': False, 'error': 'Server update failed; previous runtime restored when possible'}))
        sys.exit(1)


if __name__ == '__main__':
    main()
