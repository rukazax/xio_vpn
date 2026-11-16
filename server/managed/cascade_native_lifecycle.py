#!/usr/bin/env python3
"""Owned native-cascade boot dependency and periodic probe lifecycle.

No native generator edits. File/symlink effects are journaled; foreign content is
never overwritten or removed. Production is the fixed managed root/unit path.
Tests inject a private unit directory and a mocked systemctl runner.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

OWNER = 'xio-cascade-native-lifecycle-v1'
ROOT = Path('/etc/xio-managed/cascade-native')
UNIT_DIR = Path('/etc/systemd/system')
PROGRAM = '/usr/local/lib/xio-managed/cascade_native.py'
GUARD = 'xio-cascade-native-guard.service'
VERIFY = 'xio-cascade-native-verify.service'
TIMER = 'xio-cascade-native-verify.timer'
NATIVE_UNITS = ('xio-managed-awg.service', 'xio-rivet-gateway.service', 'xio-rivet-entry.service')
DROPIN = '20-xio-cascade-native-guard.conf'


def digest(data): return hashlib.sha256(data).hexdigest()


def systemctl(*args):
    p = subprocess.run(['systemctl', *args], text=True, capture_output=True, timeout=20)
    if p.returncode: raise RuntimeError('owned lifecycle systemctl failed: ' + ' '.join(args))


def atomic(path, data):
    path = Path(path)
    fd, temp = tempfile.mkstemp(prefix='.lifecycle-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def receipt_path(root): return Path(root) / 'lifecycle.json'


def read_receipt(root):
    path = receipt_path(root)
    if not path.exists(): return None
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise RuntimeError('unsafe lifecycle receipt')
    value = json.loads(path.read_text())
    if value.get('owner') != OWNER or value.get('schema') != 1: raise RuntimeError('foreign lifecycle receipt')
    return value


def save(root, value): atomic(receipt_path(root), (json.dumps(value, sort_keys=True) + '\n').encode())


def templates(state):
    """Pure file and enable-link plan. No Condition*= successful-skip bypasses."""
    bridge = state['config']['role'] == 'bridge'
    tag = '# ' + OWNER + ' connector=' + state['connectorId'] + '\n'
    before = 'Before=' + ' '.join(NATIVE_UNITS) + '\n' if bridge else ''
    files = {GUARD: tag + '[Unit]\nDescription=XIO native cascade guard and uplink\nAfter=network-pre.target\n' + before +
             '[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=45s\nStandardInput=null\n' +
             'ExecStart=/usr/bin/python3 ' + PROGRAM + ' guard-auto\n' +
             '[Install]\nWantedBy=multi-user.target\n'}
    links = {'multi-user.target.wants/' + GUARD: '../' + GUARD}
    if bridge:
        for unit in NATIVE_UNITS:
            files[unit + '.d/' + DROPIN] = tag + '[Unit]\nRequires=' + GUARD + '\nAfter=' + GUARD + '\n'
        files[VERIFY] = (tag + '[Unit]\nDescription=XIO source-bound native family verifier\nRequires=' + GUARD + '\nAfter=' + GUARD + '\n' +
            '[Service]\nType=oneshot\nTimeoutStartSec=25s\nStandardInput=null\nExecStart=/usr/bin/python3 ' + PROGRAM + ' verify-auto\n')
        files[TIMER] = tag + '[Unit]\nDescription=Refresh XIO native family evidence\n[Timer]\nOnActiveSec=15s\nOnUnitActiveSec=30s\nAccuracySec=1s\nRandomizedDelaySec=0\nUnit=' + VERIFY + '\n[Install]\nWantedBy=timers.target\n'
        links['timers.target.wants/' + TIMER] = '../' + TIMER
    return {'files': {k: v.encode() for k, v in files.items()}, 'links': links}


def _path(directory, name):
    path = Path(directory) / name
    if path.is_symlink() and name.endswith('.d'): raise RuntimeError('foreign unit directory symlink')
    # Parent directories may already contain foreign drop-ins, which remain untouched.
    parent = path.parent
    while parent != Path(directory):
        if parent.is_symlink(): raise RuntimeError('foreign symlink in owned unit path')
        if parent.exists() and (parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o022):
            raise RuntimeError('unsafe owned unit parent permissions')
        if parent == parent.parent: raise RuntimeError('unit path escapes owner directory')
        parent = parent.parent
    return path


def expected_receipt(state, plan, directory):
    return {'owner': OWNER, 'schema': 1, 'connectorId': state['connectorId'], 'revision': state['revision'],
            'unitDir': str(Path(directory)), 'role': state['config']['role'], 'phase': 'prepared',
            'files': {k: digest(v) for k, v in plan['files'].items()}, 'links': plan['links'], 'created': []}


def matches_file(path, expected):
    return path.is_file() and not path.is_symlink() and path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o022 and digest(path.read_bytes()) == expected


def preflight_paths(directory, plan, receipt):
    for name, data in plan['files'].items():
        path = _path(directory, name)
        exists = os.path.lexists(path)
        if exists and (not receipt or not matches_file(path, digest(data))):
            raise RuntimeError('foreign/modified owned unit file: ' + name)
    for name, target in plan['links'].items():
        path = _path(directory, name)
        if os.path.lexists(path) and (not receipt or not path.is_symlink() or os.readlink(path) != target):
            raise RuntimeError('foreign/modified enable link: ' + name)


def validate_receipt(state, plan, receipt, directory):
    expected = expected_receipt(state, plan, directory)
    if any(receipt.get(k) != expected[k] for k in ('owner', 'schema', 'connectorId', 'revision', 'unitDir', 'role', 'files', 'links')):
        raise RuntimeError('lifecycle receipt/config mismatch; no adoption')


def install(state, *, root=ROOT, unit_dir=UNIT_DIR, ctl=systemctl):
    """Install only reserved absent/unchanged paths. Caller holds core owner lock."""
    root, directory = Path(root), Path(unit_dir)
    plan = templates(state)
    old = read_receipt(root)
    if old and old['phase'] == 'removed': old = None
    if old: validate_receipt(state, plan, old, directory)
    preflight_paths(directory, plan, old)
    receipt = old or expected_receipt(state, plan, directory)
    receipt['phase'] = 'installing'
    save(root, receipt)  # durable intent before unit/drop-in/link effects
    created_now = []
    try:
        for name, data in plan['files'].items():
            path = _path(directory, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(path): continue
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as out:
                out.write(data); out.flush(); os.fsync(out.fileno())
            created_now.append(name)
            if name not in receipt['created']: receipt['created'].append(name)
            save(root, receipt)
        for name, target in plan['links'].items():
            path = _path(directory, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(path): continue
            os.symlink(target, path)
            created_now.append(name)
            if name not in receipt['created']: receipt['created'].append(name)
            save(root, receipt)
        for parent in {directory, *[(_path(directory, n)).parent for n in [*plan['files'], *plan['links']]]}:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        ctl('daemon-reload')
        receipt['phase'] = 'installed'; save(root, receipt)
    except Exception:
        # Only newly created and still exactly matching artifacts are rolled back.
        # A concurrent foreign edit is preserved and remains recorded for review.
        for name in reversed(created_now):
            path = _path(directory, name)
            if name in plan['links']:
                if path.is_symlink() and os.readlink(path) == plan['links'][name]: path.unlink()
            elif matches_file(path, digest(plan['files'][name])): path.unlink()
        receipt['phase'] = 'install_failed'; save(root, receipt)
        try: ctl('daemon-reload')
        except Exception: pass
        raise
    return receipt


def assert_installed(state, *, root=ROOT, unit_dir=UNIT_DIR):
    plan = templates(state)
    receipt = read_receipt(root)
    if not receipt or receipt.get('phase') not in ('installed', 'active'): raise RuntimeError('owned boot lifecycle not installed/active')
    validate_receipt(state, plan, receipt, unit_dir)
    preflight_paths(unit_dir, plan, receipt)
    for name, data in plan['files'].items():
        if not matches_file(_path(unit_dir, name), digest(data)): raise RuntimeError('required owned unit/drop-in missing')
    for name, target in plan['links'].items():
        path = _path(unit_dir, name)
        if not path.is_symlink() or os.readlink(path) != target: raise RuntimeError('required owned boot enable link missing')
    return receipt


def activate(state, *, root=ROOT, unit_dir=UNIT_DIR, ctl=systemctl):
    receipt = assert_installed(state, root=root, unit_dir=unit_dir)
    # Do not synchronously start the guard while configure holds the same owner lock.
    # Native startup Requires/After and timer Requires start it before any scoped use.
    if state['config']['role'] == 'bridge': ctl('start', TIMER)
    receipt['phase'] = 'active'; save(root, receipt)


def remove(state, *, root=ROOT, unit_dir=UNIT_DIR, ctl=systemctl):
    """Refuse ANY foreign file before stopping/removing anything. Caller confirms direct."""
    receipt = read_receipt(root)
    if receipt is None: return
    plan = templates(state)
    validate_receipt(state, plan, receipt, unit_dir)
    preflight_paths(unit_dir, plan, receipt)
    # Missing owned files are safe to finish removing; changed files are not.
    receipt['phase'] = 'removing'; save(root, receipt)
    if state['config']['role'] == 'bridge':
        for name in (TIMER, VERIFY):
            if matches_file(_path(unit_dir, name), digest(plan['files'][name])): ctl('stop', name)
    # Drop-ins/enable links are removed before stopping guard: stopping an active
    # Requires dependency first could stop live native transports unnecessarily.
    for name, target in plan['links'].items():
        path = _path(unit_dir, name)
        if path.is_symlink() and os.readlink(path) == target: path.unlink()
    for unit in NATIVE_UNITS:
        name = unit + '.d/' + DROPIN
        if name in plan['files']:
            path = _path(unit_dir, name)
            if matches_file(path, digest(plan['files'][name])): path.unlink()
    ctl('daemon-reload')
    if matches_file(_path(unit_dir, GUARD), digest(plan['files'][GUARD])): ctl('stop', GUARD)
    for name, data in plan['files'].items():
        path = _path(unit_dir, name)
        if matches_file(path, digest(data)): path.unlink()
    ctl('daemon-reload')
    receipt['phase'] = 'removed'; save(root, receipt)
