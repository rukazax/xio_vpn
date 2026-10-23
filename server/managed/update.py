#!/usr/bin/env python3
"""Transactional update of an existing owned deployment from the app bundle.

The SSH peer and archive SHA256 are authenticated by the installed app. This
script never downloads code, runs package managers, regenerates keys or changes
ports. New schema migrations must explicitly extend and test this transaction.
"""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile

LIB = Path('/usr/local/lib/x1o-managed')
STATE = Path('/etc/x1o-managed/deployment.json')
RECIPE = 23
OWNER = 'x1o-managed-v1'
UNITS = ('x1o-managed-stats.timer', 'x1o-managed-awg.service',
         'xio-rivet-entry.service', 'xio-rivet-gateway.service', 'xio-stack.service', 'xio-cloak.service', 'xio-openvpn-tcp.service')
STACK_CONFIG = Path('/etc/xio-stack/config.json')
WG_CONFIG = Path('/etc/wireguard/x1o0.conf')
NETWORK_CONFIGS=(Path('/etc/xio-stack/cloak.json'),Path('/etc/xio-stack/tcp.ovpn'),Path('/usr/local/lib/xio-rivet/network-up'))
DUAL_RECEIPT=Path('/etc/x1o-managed/dualstack-receipt.json')
LEGACY_UNITS = ('xio-openvpn-udp.service', 'xio-ikev2.service', 'xio-headscale.service', 'xio-tailscaled.service')
RUNTIMES = {'amneziawg-go': '/usr/local/bin/xio-amneziawg-go',
            'rivet': '/usr/local/bin/xio-rivet',
            'xraygateway': '/usr/local/bin/xio-stack',
            'cloak': '/usr/local/bin/xio-cloak'}


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, check=check, timeout=60)


def atomic(source, target, mode):
    target = Path(target)
    temporary = target.with_name(target.name + '.update-new')
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(mode)
        os.replace(temporary, target)
        if shutil.which('restorecon'):
            command('restorecon', str(target))
    finally:
        temporary.unlink(missing_ok=True)


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


def update(raw, expected, server_id):
    if os.geteuid() != 0:
        raise RuntimeError('Owner root access required')
    if (LIB / '.owner').read_text().strip() != OWNER:
        raise RuntimeError('Unowned deployment')
    data = json.loads(STATE.read_bytes())
    if data.get('owner') != OWNER or data.get('id') != server_id:
        raise RuntimeError('Server identity mismatch')
    if data.get('phase') != 'ready':
        raise RuntimeError('Deployment is not ready')
    current = data.get('recipeVersion', 13)
    if current > RECIPE:
        raise RuntimeError('Server is newer than this application')
    if current == RECIPE and data.get('bundleSha256') == expected:
        return {'updated': False, 'recipeVersion': RECIPE}
    if current == RECIPE and data.get('bundleSha256'):
        raise RuntimeError('Conflicting bundle at the same recipe revision')
    # This release supports only the known schema. Never guess a migration.
    if current not in (13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23):
        raise RuntimeError('Unsupported server recipe')
    with tempfile.TemporaryDirectory(prefix='.update-', dir=LIB.parent) as folder:
        work = Path(folder)
        stage = work / 'stage'
        stage.mkdir(mode=0o700)
        unpack(raw, stage, expected)
        active = [u for u in UNITS if command('systemctl', 'is-active', '--quiet', u, check=False).returncode == 0]
        legacy = []
        for unit in LEGACY_UNITS:
            path = Path('/etc/systemd/system') / unit
            if path.is_file() and ('XIO' in path.read_text() or 'xio' in path.read_text()):
                legacy.append((unit, command('systemctl', 'is-active', '--quiet', unit, check=False).returncode == 0,
                               command('systemctl', 'is-enabled', '--quiet', unit, check=False).returncode == 0))
        backups = []
        network_changes_started=False
        if DUAL_RECEIPT.exists():raise RuntimeError('Existing IPv6 migration receipt requires owner review')
        committed = False
        try:
            for unit in active:
                command('systemctl', 'stop', unit)
            for unit, _, _ in legacy:
                command('systemctl', 'disable', '--now', unit)
            # Migrate only the owned deployment and its own Xray listener.
            for target in [STATE, STACK_CONFIG, WG_CONFIG, *NETWORK_CONFIGS]:
                if target.exists():
                    previous = work / ('migration-' + target.name)
                    shutil.copy2(target, previous)
                    backups.append((target, previous, True))
            data['restrictedNetwork'] = True
            if isinstance(data.get('stack'), dict):
                data['stack']['protocols'] = ['xray', 'cloak']
            staged_state = work / 'migration-state.json'
            staged_state.write_text(json.dumps(data))
            atomic(staged_state, STATE, 0o600)
            if WG_CONFIG.exists():
                staged_wg = work / 'migration-wg.conf'
                staged_wg.write_text(WG_CONFIG.read_text().split('[Peer]',1)[0])
                atomic(staged_wg, WG_CONFIG, 0o600)
            if STACK_CONFIG.exists():
                config = json.loads(STACK_CONFIG.read_text())
                config['inbounds'] = [i for i in config.get('inbounds', []) if i.get('protocol') != 'shadowsocks']
                staged_config = work / 'migration-xray.json'
                staged_config.write_text(json.dumps(config))
                atomic(staged_config, STACK_CONFIG, 0o600)
            # Runtime/config replacements retain rollback copies. IPv6 network additions
            # below have a separate owned receipt. Preserve private users,
            # certificates, delegated SSH keys, firewall and package receipts.
            targets = [(p, LIB / p.relative_to(stage), 0o755 if p.name in RUNTIMES else 0o600)
                       for p in sorted(stage.rglob('*')) if p.is_file()]
            targets += [(stage / name, Path(dest), 0o755)
                        for name, dest in RUNTIMES.items() if Path(dest).exists()]
            auxiliary = LIB.parent / 'xio-rivet' / 'rivet'
            if auxiliary.exists():
                targets.append((stage / 'rivet', auxiliary, 0o755))
            for number, (source, target, mode) in enumerate(targets):
                if target.is_symlink():
                    raise RuntimeError('Symlink in managed runtime')
                target.parent.mkdir(exist_ok=True)
                previous = work / ('backup-' + str(number))
                existed = target.exists()
                if existed:
                    shutil.copy2(target, previous)
                backups.append((target, previous, existed))
                atomic(source, target, mode)
            network_changes_started=True
            command('python3',str(LIB/'dualstack.py'),'configure')
            for unit in reversed(active):
                command('systemctl', 'start', unit)
            for unit in active:
                command('systemctl', 'is-active', '--quiet', unit)
            command('python3',str(LIB/'dualstack.py'),'apply')
            data['recipeVersion'] = RECIPE
            data['bundleSha256'] = expected
            temporary = work / 'deployment.json'
            temporary.write_text(json.dumps(data))
            atomic(temporary, STATE, 0o600)
            committed = True
        finally:
            if not committed:
                if network_changes_started:command('python3',str(LIB/'dualstack.py'),'rollback',check=False)
                for unit in active:
                    command('systemctl', 'stop', unit, check=False)
                try:
                    for target, previous, existed in reversed(backups):
                        if existed:
                            atomic(previous, target, previous.stat().st_mode & 0o777)
                        else:
                            target.unlink(missing_ok=True)
                    for unit in reversed(active):
                        command('systemctl', 'start', unit)
                    for unit, was_active, was_enabled in legacy:
                        if was_enabled:
                            command('systemctl', 'enable', unit)
                        if was_active:
                            command('systemctl', 'start', unit)
                except Exception:
                    # Preserve recovery files even if the old service cannot start.
                    recovery = Path(tempfile.mkdtemp(prefix='.update-recovery-', dir=LIB.parent))
                    shutil.copytree(work, recovery / 'backup')
                    raise RuntimeError('Rollback requires owner recovery; backup retained')
                # The receipt remains unchanged. A later run retries the update.
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
        with open('/run/lock/x1o-managed.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            raw = sys.stdin.buffer.read(256 * 1024 * 1024 + 1)
            result = update(raw, expected, server_id)
        print(json.dumps({'ok': True, **result}))
    except Exception:
        print(json.dumps({'ok': False, 'error': 'Server update failed; previous runtime restored when possible'}))
        sys.exit(1)


if __name__ == '__main__':
    main()
