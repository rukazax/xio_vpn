#!/usr/bin/env bash
# Trusted bootstrap: this file itself must be shipped/pinned by the caller.
# No mutable-main default, no unpinned bypass, no curl|bash dependency chain.
set -euo pipefail
umask 077
export LC_ALL=C
URL= EXPECTED_SHA= DATA_DIR= LOG_FILE= UNATTENDED=0
INSTALL_ARGS=()
fail() { printf 'terminal-install: %s\n' "$*" >&2; exit 2; }
need() { [ "$#" -ge 2 ] || fail "$1 needs a value"; }
usage() {
    cat <<'EOF'
terminal-install.sh --bundle-url https://.../xio-cascade.tar.gz --sha256 HEX \
  --data-dir /var/lib/xio-cascade --unattended -- --role bridge \
  --exit-host 203.0.113.7 --exit-pubkey BASE64 --routing all

--bundle-url (alias --url) and --sha256 are REQUIRED explicit trust inputs.
The archive SHA and every manifest dependency SHA are verified before execution.
--data-dir is REQUIRED persistent state, never the private payload temp directory.
--log PATH optionally saves installer output (not arguments). --unattended skips prompt.
All options following -- are forwarded as an argv array, preserving spaces.
No --allow-unpinned, package install, native XIO tunnel or host network configuration.
EOF
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bundle-url|--url) need "$@"; URL=$2; shift 2;;
        --sha256) need "$@"; EXPECTED_SHA=$2; shift 2;;
        --data-dir) need "$@"; DATA_DIR=$2; shift 2;;
        --log) need "$@"; LOG_FILE=$2; shift 2;;
        --unattended) UNATTENDED=1; shift;;
        --help|-h) usage; exit 0;;
        --) shift; INSTALL_ARGS+=("$@"); break;;
        --allow-unpinned) fail 'unpinned execution is forbidden';;
        *) INSTALL_ARGS+=("$1"); shift;;
    esac
done
[ "$(id -u)" -eq 0 ] || fail 'root required'
command -v curl >/dev/null || fail 'curl required'
command -v python3 >/dev/null || fail 'python3 required'
command -v sha256sum >/dev/null || fail 'sha256sum required'
[[ "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{64}$ ]] || fail 'explicit 64-digit archive SHA256 required'
EXPECTED_SHA=${EXPECTED_SHA,,}
[ "$EXPECTED_SHA" != "0000000000000000000000000000000000000000000000000000000000000000" ] || fail 'zero hash is not a trust pin'
python3 - "$URL" "$DATA_DIR" "${INSTALL_ARGS[@]}" <<'PY'
import os, sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
if u.scheme != 'https' or not u.hostname or u.username or u.password or any(c.isspace() for c in sys.argv[1]):
    raise SystemExit('HTTPS URL without credentials required')
p = sys.argv[2]
if not os.path.isabs(p) or os.path.realpath(p) == '/' or any(c in p for c in '\r\n:,'):
    raise SystemExit('explicit absolute persistent data-dir required')
# Prevent a forwarded override from moving state under the disposable payload.
if any(x == '--data-dir' or x.startswith('--data-dir=') for x in sys.argv[3:]):
    raise SystemExit('data-dir must be specified to bootstrap, not forwarded')
PY
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/xio-cascade-bootstrap.XXXXXXXX")
chmod 700 "$TMP_DIR"
TMP_ID=$(stat -c '%d:%i:%u' -- "$TMP_DIR")
cleanup() {
    # Never follow a symlink or remove a replacement/unowned directory.
    if [ -n "$TMP_DIR" ] && [ ! -L "$TMP_DIR" ] && [ -d "$TMP_DIR" ] &&
       [ "$(stat -c '%d:%i:%u' -- "$TMP_DIR")" = "$TMP_ID" ]; then
        rm -rf --one-file-system -- "$TMP_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$TMP_DIR" "$DATA_DIR" <<'PY'
import os,sys
root, data = map(os.path.realpath, sys.argv[1:])
if os.path.commonpath([root, data]) == root: raise SystemExit('persistent data cannot live inside bootstrap temp')
PY
# curl protocol restrictions apply to initial request AND every redirect.
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --max-time 120 --max-filesize 2097152 --retry 2 --output "$TMP_DIR/payload.tar.gz" "$URL"
printf '%s  %s\n' "$EXPECTED_SHA" "$TMP_DIR/payload.tar.gz" | sha256sum --check --status || fail 'archive SHA256 mismatch; nothing executed'
# This verifier is part of the trusted bootstrap, not loaded from the archive.
python3 - "$TMP_DIR/payload.tar.gz" "$TMP_DIR/payload" <<'PY'
import gzip, hashlib, io, json, os, pathlib, sys, tarfile
required = {
    'Dockerfile', 'entrypoint.sh', 'cascade-install.sh', 'cascade-config.py',
    'cascade-bridge-setup.sh', 'cascade-exit-setup.sh', 'cascade-healthcheck.sh',
    'terminal-install.sh', 'whitelist-update.sh', 'whitelists.conf', 'README.md',
    '99-xio-cascade.conf', 'xio-awg-uapi.conf', 'xio-cascade-awg-firewall.sh',
    'xio-cascade-exit.service', 'xio-cascade-exit.sh', 'xio-cascade-tunnel.sh', 'xio-cascade.service',
}
with gzip.open(sys.argv[1], 'rb') as gz:
    raw = gz.read(2097153)
if len(raw) > 2097152:
    raise SystemExit('decompressed payload exceeds limit; nothing executed')
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
    members = tar.getmembers()
    names = [m.name for m in members]
    if len(set(names)) != len(names) or set(names) != required | {'manifest.json'}:
        raise SystemExit('missing/extra/duplicate payload dependencies; nothing executed')
    if any(not m.isfile() or m.size > 1048576 for m in members) or sum(m.size for m in members) > 2097152:
        raise SystemExit('unsafe payload member; nothing executed')
    blobs = {m.name: tar.extractfile(m).read() for m in members}
manifest = json.loads(blobs.pop('manifest.json'))
if manifest.get('schema') != 1 or set(manifest.get('files', {})) != required:
    raise SystemExit('invalid dependency manifest; nothing executed')
for name, content in blobs.items():
    if manifest['files'][name] != hashlib.sha256(content).hexdigest():
        raise SystemExit('dependency SHA256 mismatch; nothing executed')
# All hashes passed before ANY file is made executable or executed. No tar path extraction.
root = pathlib.Path(sys.argv[2])
root.mkdir(mode=0o700)
for name, content in blobs.items():
    target = root / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out: out.write(content)
PY
if [ "$UNATTENDED" -eq 0 ]; then
    [ -t 0 ] || fail 'noninteractive execution requires --unattended'
    printf 'Execute verified standalone cascade installer? [y/N] ' >&2
    read -r answer
    case "$answer" in y|Y|yes) ;; *) fail 'cancelled';; esac
fi
if [ -n "$LOG_FILE" ]; then
    [ ! -L "$LOG_FILE" ] || fail 'log must not be a symlink'
    touch -- "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    bash "$TMP_DIR/payload/cascade-install.sh" --data-dir "$DATA_DIR" "${INSTALL_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"
else
    bash "$TMP_DIR/payload/cascade-install.sh" --data-dir "$DATA_DIR" "${INSTALL_ARGS[@]}"
fi
