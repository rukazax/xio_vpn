#!/usr/bin/env bash
# Infrastructure diagnostics only, NOT native app/client egress acceptance.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
import argparse, importlib.util, ipaddress, json, pathlib, shutil, subprocess, sys, time, urllib.parse
spec = importlib.util.spec_from_file_location('config', pathlib.Path(sys.argv[1]) / 'cascade-config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
p = argparse.ArgumentParser(description='Container infrastructure diagnostics, not full client egress proof')
p.add_argument('--role', choices=['exit', 'bridge', 'both'], default='both')
p.add_argument('--data-dir', default='/var/lib/xio-cascade')
p.add_argument('--runtime', choices=['docker', 'podman'])
p.add_argument('--exit-host', default='')
p.add_argument('--exit-family', choices=['ipv4', 'ipv6'])
p.add_argument('--routing', choices=['all', 'split'])
p.add_argument('--max-handshake', type=int, default=180)
p.add_argument('--timeout', type=int, default=8)
p.add_argument('--egress-url', default='https://ifconfig.co/ip')
p.add_argument('--no-whitelist-check', action='store_true')
p.add_argument('--json-strict', action='store_true')
a = p.parse_args(sys.argv[2:])
if a.max_handshake < 1 or not 1 <= a.timeout <= 60: p.error('invalid timeout/handshake interval')
u = urllib.parse.urlsplit(a.egress_url)
if u.scheme != 'https' or not u.hostname or u.username or u.password: p.error('HTTPS egress URL required')
try: host = config.literal(a.exit_host) if a.exit_host else ''
except ValueError as e: p.error(str(e))
checks = []
def check(name, ok, detail): checks.append(dict(name=name, ok=bool(ok), detail=detail))
def run(*args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=a.timeout + 2)
        return r.returncode == 0, r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired): return False, ''
def state(role):
    try: return json.loads((pathlib.Path(a.data_dir) / role / 'state.json').read_text())
    except (OSError, ValueError): return {}
runtime = a.runtime or next((r for r in ('docker', 'podman') if shutil.which(r) and run(r, 'info')[0]), None)
if not runtime: check('runtime', False, 'working Docker/Podman required')
else:
    for role in ('exit', 'bridge') if a.role == 'both' else (a.role,):
        container = 'xio-cascade-' + role
        ok, text = run(runtime, 'inspect', '-f', '{{.State.Running}}', container)
        check(role + '.container', ok and text == 'true', 'running container required')
        if not ok or text != 'true': continue
        def execute(*args): return run(runtime, 'exec', container, *args)
        ok, text = execute('wg', 'show', 'interfaces')
        needed = {'wg0', 'wg1'} if role == 'bridge' else {'wg0'}
        check(role + '.interfaces', ok and needed <= set(text.split()), 'expected ' + ','.join(sorted(needed)))
        for iface in sorted(needed):
            ok, peers = execute('wg', 'show', iface, 'peers')
            check(role + '.' + iface + '.peers', ok and bool(peers), 'public-key registration required on BOTH ends')
        ok, text = execute('wg', 'show', 'wg0', 'latest-handshakes')
        timestamps = [int(x.split()[1]) for x in text.splitlines() if len(x.split()) == 2 and x.split()[1].isdigit()]
        fresh = [t for t in timestamps if 0 <= time.time() - t <= a.max_handshake]
        check(role + '.handshake', ok and bool(fresh), 'fresh wg0 handshake required')
        metadata = state(role)
        if role == 'bridge':
            remote = host or metadata.get('host', '')
            try:
                remote = config.literal(remote)
                family = '-6' if ':' in remote else '-4'
                ok, text = execute('ip', family, 'route', 'get', remote)
                check('bridge.exit_route', ok, 'transport route only, not handshake/egress proof')
            except ValueError: check('bridge.exit_route', False, 'valid exit host required')
            routing = a.routing or metadata.get('routing', 'split')
            if routing == 'split' and not a.no_whitelist_check:
                ok, text = execute('nft', 'list', 'set', 'inet', 'xio_cascade', 'xio_whitelist4')
                check('bridge.whitelist', ok and 'elements' in text, 'split mode needs populated whitelist for selected IPv4 traffic')
        else:
            families = [a.exit_family or metadata.get('exit_family', 'ipv6')]
            if metadata.get('ipv4_egress') and 'ipv4' not in families: families.append('ipv4')
            for family in families:
                ok, text = execute('curl', '-4' if family == 'ipv4' else '-6', '--fail', '--silent', '--show-error',
                                   '--proto', '=https', '--proto-redir', '=https', '--max-time', str(a.timeout), a.egress_url)
                try: observed = ipaddress.ip_address(text); valid = observed.version == (4 if family == 'ipv4' else 6) and observed.is_global
                except ValueError: valid = False
                check('exit.egress.' + family, ok and valid, text if ok and valid else 'no validated global response')
passed = bool(checks) and all(c['ok'] for c in checks)
print(json.dumps(dict(ok=passed, scope='container infrastructure ONLY; native XIO/client egress NOT proven', checks=checks), indent=2))
sys.exit(0 if passed else 1)
PY
