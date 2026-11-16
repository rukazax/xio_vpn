#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fail-closed Linux payload gate. Reads tar/DEB bytes; never extracts or installs.

Capture from the exact prepared Flutter app before building, then verify both
finished package containers against that immutable snapshot, not filenames.
"""
import argparse
import _compression
import bz2
from contextlib import contextmanager, ExitStack
import gzip
import hashlib
import lzma
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

SERVER_FILES = {
    'xio-server.tar.gz', 'xio-server-release.json', 'xio-bootstrap.sh',
    'xio-server-update.py', 'xio-admin.py', 'xio-stack.py',
    'xio-network-stack.py', 'xio-mesh-stack.py', 'mesh-pins.json',
    'install-wireguard.sh', 'vpn-sharing.sh', 'xio_vici',
}
CLIENT_ASSET_DIRS = {'help', 'licenses', 'l10n', 'security', 'fonts'}
MIRRORS = {'xio-admin.py': 'admin.py', 'xio-stack.py': 'stack.py',
           'xio-network-stack.py': 'network_stack.py',
           'xio-mesh-stack.py': 'mesh_stack.py', 'mesh-pins.json': 'mesh-pins.json'}
# Inspection policy, not extraction limits: all payloads (including irrelevant
# entries) are bounded. 1 GiB expanded / 512 MiB compressed allows release
# bundles with many libraries while bounding work; a single file stays <=128 MiB.
MAX_MEMBER = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_COMPRESSED = 512 * 1024 * 1024
MAX_MEMBERS = 32768
MAX_METADATA = 1024 * 1024
MAX_CODEC_MEMORY = 128 * 1024 * 1024  # XZ dictionary is attacker-controlled too.


class ArchiveTree:
    """Canonical names and implicit parents, independent of archive order."""
    def __init__(self):
        self.entries = {}
        self.parents = set()

    def add(self, member):
        name = safe_name(member.name)
        if name in self.entries:
            raise ProvenanceError(f'Duplicate archive member: {name}')
        parents = ['/'.join(name.split('/')[:i]) for i in range(1, len(name.split('/')))]
        if any(parent in self.entries and not self.entries[parent] for parent in parents):
            raise ProvenanceError(f'Non-directory archive ancestor: {name}')
        if not member.isdir() and (name in self.parents or not name):
            raise ProvenanceError(f'Non-directory archive ancestor: {name}')
        self.entries[name] = member.isdir()
        self.parents.update(parents)
        return name


class ExpandedReader:
    """Bound actual decompressed reads, including pre-yield PAX/GNU metadata."""
    def __init__(self, stream):
        self.stream = stream
        self.total = 0

    def read(self, size):
        # tarfile streaming requests small blocks; never let a codec allocate an
        # attacker-selected unbounded read before the budget has been checked.
        if size < 0 or size > MAX_TOTAL - self.total:
            raise ProvenanceError('Archive expanded-byte inspection limit exceeded')
        # read1 avoids the codecs' buffered read() prefetching expanded payload
        # beyond this request (the gzip/bz2/xz raw decoders honor max_length).
        data = (self.stream.read1(size) if hasattr(self.stream, 'read1') else self.stream.read(size))
        self.total += len(data)
        return data


@contextmanager
def bounded_tar(stream):
    """Streaming tar with policy checked at each *physical* header, before skip.

    TarInfo._proc_member runs before tarfile reads extension bodies. Checking
    only yielded members would miss GNU/PAX allocations and their header count.
    bufsize=512 prevents read-ahead into an irrelevant payload before its header
    is checked. Sparse formats are not produced by these packagers; reject them.
    """
    state = {'count': 0, 'declared': 0, 'metadata': 0, 'depth': 0}

    class CheckedInfo(tarfile.TarInfo):
        def _reject_sparse(self, *args):
            raise ProvenanceError('Sparse archive metadata is unsupported')

        # PAX sparse maps are processed before yield too, not just old type S.
        _proc_gnusparse_00 = _reject_sparse
        _proc_gnusparse_01 = _reject_sparse
        _proc_gnusparse_10 = _reject_sparse

        def _proc_member(self, tar):
            state['count'] += 1
            if state['count'] > MAX_MEMBERS:
                raise ProvenanceError('Archive member-count inspection limit exceeded')
            if self.size < 0 or self.size > MAX_MEMBER:
                raise ProvenanceError(f'Archive member exceeds inspection limit: {self.size}')
            self._inspection_size = self.size
            state['declared'] += 512 + ((self.size + 511) // 512) * 512
            if state['declared'] > MAX_TOTAL:
                raise ProvenanceError('Archive aggregate inspection limit exceeded')
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                state['metadata'] += self.size
                if self.size > MAX_METADATA or state['metadata'] > 4 * MAX_METADATA:
                    raise ProvenanceError('Archive extension metadata inspection limit exceeded')
            elif self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
                raise ProvenanceError('Unsupported archive member type (including sparse)')
            state['depth'] += 1
            try:
                if state['depth'] > 16:
                    raise ProvenanceError('Archive extension chain inspection limit exceeded')
                return super()._proc_member(tar)
            finally:
                state['depth'] -= 1

    with ExitStack() as stack:
        # Peek without asking tarfile to instantiate an unbounded codec stream.
        magic = stream.read(6)
        class Prefixed:
            def __init__(self):
                self.prefix = magic
            def read(self, size=-1):
                if size < 0:
                    raise ProvenanceError('Unbounded compressed archive read')
                head, self.prefix = self.prefix[:size], self.prefix[size:]
                return head + stream.read(size - len(head))
        raw = Prefixed()
        if magic.startswith(b'\x1f\x8b'):
            decoded = stack.enter_context(gzip.GzipFile(fileobj=raw))
        elif magic.startswith(b'\xfd7zXZ\x00'):
            # LZMAFile has no memlimit parameter. Its stdlib raw reader accepts
            # the same decoder with a limit, including concatenated XZ streams.
            decoded = stack.enter_context(_compression.DecompressReader(
                raw, lzma.LZMADecompressor, format=lzma.FORMAT_XZ,
                memlimit=MAX_CODEC_MEMORY, trailing_error=lzma.LZMAError))
        elif magic.startswith(b'BZh'):
            decoded = stack.enter_context(bz2.BZ2File(raw))
        else:
            decoded = raw  # unsupported compression fails tar header parsing
        tar = stack.enter_context(tarfile.open(fileobj=ExpandedReader(decoded), mode='r|',
                                              bufsize=512, tarinfo=CheckedInfo))
        tar._inspection_state = state
        yield tar


def checked_members(tar):
    tree = ArchiveTree()
    for member in tar:
        # PAX can override the next header's size after _proc_member ran.
        if member.size < 0 or member.size > MAX_MEMBER:
            raise ProvenanceError(f'Archive member exceeds inspection limit: {member.size}')
        state = tar._inspection_state
        state['declared'] += (((member.size + 511) // 512) -
                              ((member._inspection_size + 511) // 512)) * 512
        if state['declared'] > MAX_TOTAL:
            raise ProvenanceError('Archive aggregate inspection limit exceeded after PAX size')
        if any(key.startswith('GNU.sparse') for key in member.pax_headers):
            raise ProvenanceError('Sparse archive metadata is unsupported')
        yield tree.add(member), member


class ProvenanceError(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    # Bound parent tracking too: a PAX name with hundreds of thousands of path
    # components must not turn a bounded metadata block into quadratic work.
    if len(name) > 4096 or name.count('/') > 64:
        raise ProvenanceError('Archive/source path inspection limit exceeded')
    parts = name.split('/')
    if '\\' in name or ':' in name or '\0' in name or name.startswith('/') or '..' in parts:
        raise ProvenanceError(f'Unsafe archive/source path: {name!r}')
    return '/'.join(part for part in parts if part not in ('', '.'))


def client_path(name):
    parts = PurePosixPath(name).parts
    if any(part in SERVER_FILES for part in parts):
        raise ProvenanceError(f'Client contains server-only payload: {name}')


def validate_server(payload):
    """Validate source/embedded manifest bindings, not merely a recipe label."""
    try:
        manifest = json.loads(payload['xio-server-release.json'])
        if manifest.get('schema') != 1 or type(manifest.get('recipeVersion')) is not int:
            raise ProvenanceError('Invalid server manifest schema/recipeVersion')
        if manifest['sha256'] != digest(payload['xio-server.tar.gz']):
            raise ProvenanceError('Server archive SHA256 differs from manifest')
        artifacts = manifest['artifacts']
        required = set(MIRRORS) | {'xio-bootstrap.sh', 'xio-server-update.py'}
        if not isinstance(artifacts, dict) or not required <= artifacts.keys():
            raise ProvenanceError('Server manifest is missing required artifact digests')
        for name, expected in artifacts.items():
            if safe_name(name) != name or not re.fullmatch('[0-9a-f]{64}', expected):
                raise ProvenanceError('Invalid manifest artifact digest/path')
            if digest(payload[name]) != expected:
                raise ProvenanceError(f'Server mirror SHA256 mismatch: {name}')
        if manifest['bootstrapSha256'] != artifacts['xio-bootstrap.sh']:
            raise ProvenanceError('bootstrapSha256 does not bind bootstrap artifact')
        if manifest['updateSha256'] != artifacts['xio-server-update.py']:
            raise ProvenanceError('updateSha256 does not bind updater artifact')
        inner = {}
        with bounded_tar(io.BytesIO(payload['xio-server.tar.gz'])) as tar:
            for name, member in checked_members(tar):
                if not member.isfile():
                    if member.isdir():
                        continue
                    raise ProvenanceError(f'Non-file server archive member: {name}')
                inner[name] = None
                if name in MIRRORS.values():
                    inner[name] = bounded_read(tar.extractfile(member), member.size)
        for mirror, name in MIRRORS.items():
            if inner.get(name) != payload[mirror].replace(b'\r\n', b'\n'):
                raise ProvenanceError(f'Server archive/mirror mismatch: {name}')
        for name, data in [('archive admin.py', inner['admin.py']),
                           ('xio-server-update.py', payload['xio-server-update.py'])]:
            recipes = re.findall(rb'^RECIPE\s*=\s*(\d+)\s*$', data, re.M)
            if recipes != [str(manifest['recipeVersion']).encode()]:
                raise ProvenanceError(f'Server recipe mismatch: {name}')
        return manifest['recipeVersion']
    except (KeyError, TypeError, ValueError, tarfile.TarError, OSError, EOFError, lzma.LZMAError) as error:
        raise ProvenanceError(f'Invalid server payload: {error}') from error


def bounded_read(stream, size):
    if size > MAX_MEMBER:
        raise ProvenanceError(f'Asset exceeds inspection limit: {size}')
    data = stream.read(size + 1)
    if len(data) != size:
        raise ProvenanceError('Truncated/oversized asset data')
    return data


def source_files(app, flavor):
    assets = app / 'assets'
    if not assets.is_dir() or assets.is_symlink():
        raise ProvenanceError('Prepared source assets missing or symlinked')
    files = {}
    for path in sorted(assets.rglob('*')):
        relative = path.relative_to(assets).as_posix()
        if path.is_symlink():
            raise ProvenanceError(f'Symlink in source assets: {relative}')
        if flavor == 'client':
            client_path(relative)
            if relative.split('/')[0] not in CLIENT_ASSET_DIRS:
                raise ProvenanceError(f'Client source has unapproved asset: {relative}')
        if path.is_file() and relative.startswith('l10n/'):
            files[relative] = path.read_bytes()
    if not files:
        raise ProvenanceError('Prepared source has no localization payload')
    if flavor == 'full':
        manifest_path = assets / 'xio-server-release.json'
        try:
            manifest = json.loads(manifest_path.read_bytes())
            names = {'xio-server.tar.gz', 'xio-server-release.json'} | set(manifest['artifacts'])
        except (KeyError, TypeError, ValueError) as error:
            raise ProvenanceError(f'Invalid source server manifest: {error}') from error
        for name in names:
            if safe_name(name) != name:
                raise ProvenanceError('Unsafe source manifest path')
            files[name] = (assets / name).read_bytes()
    return files


def capture(app, flavor):
    app = Path(app)
    if flavor not in ('full', 'client'):
        raise ProvenanceError('Expected full or client flavor')
    version = re.findall(r'^version:\s*([^\s#]+)\s*$',
                         (app / 'pubspec.yaml').read_text(encoding='utf-8'), re.M)
    if len(version) != 1:
        raise ProvenanceError('Prepared source needs exactly one version')
    payload = source_files(app, flavor)
    recipe = validate_server(payload) if flavor == 'full' else None
    files = {name: digest(data) for name, data in sorted(payload.items())}
    if {name: digest(data) for name, data in source_files(app, flavor).items()} != files:
        raise ProvenanceError('Source changed while capturing provenance')
    return {'schema': 1, 'flavor': flavor, 'appVersion': version[0],
            'recipeVersion': recipe, 'files': files}


def verify_source(app, expected):
    if capture(app, expected['flavor']) != expected:
        raise ProvenanceError('Prepared source changed since provenance capture')


def check_payload(payload, expected):
    if expected.get('schema') != 1 or expected.get('flavor') not in ('full', 'client'):
        raise ProvenanceError('Unsupported provenance snapshot')
    files = expected['files']
    l10n = {name for name in payload if name.startswith('l10n/')}
    if l10n != {name for name in files if name.startswith('l10n/')}:
        raise ProvenanceError('Localization member set differs from staged source')
    for name, sha256 in files.items():
        if name not in payload:
            raise ProvenanceError(f'Package missing staged asset: {name}')
        if digest(payload[name]) != sha256:
            raise ProvenanceError(f'Package asset differs from staged source: {name}')
    if expected['flavor'] == 'full':
        if validate_server(payload) != expected['recipeVersion']:
            raise ProvenanceError('Package recipe differs from staged source')
    return {'flavor': expected['flavor'], 'appVersion': expected['appVersion'],
            'recipeVersion': expected['recipeVersion'], 'checkedAssets': len(files)}


def verify_bundle(bundle, expected):
    assets = Path(bundle) / 'data/flutter_assets/assets'
    if not assets.is_dir():
        raise ProvenanceError('Bundle has no Flutter assets')
    if any(path.is_symlink() for path in [assets, assets.parent, assets.parent.parent]):
        raise ProvenanceError('Bundle asset directory is symlinked')
    payload = {}
    for path in assets.rglob('*'):
        name = path.relative_to(assets).as_posix()
        if path.is_symlink():
            raise ProvenanceError(f'Symlink in bundle assets: {name}')
        if expected['flavor'] == 'client':
            client_path(name)
            if name.split('/')[0] not in CLIENT_ASSET_DIRS:
                raise ProvenanceError(f'Client bundle has unapproved asset: {name}')
        if path.is_file() and (name in expected['files'] or name.startswith('l10n/')):
            payload[name] = path.read_bytes()
    return check_payload(payload, expected)


class ArSlice:
    """Read a compressed member in place, without allocating its entire body."""
    def __init__(self, stream, offset, size):
        stream.seek(offset)
        self.stream, self.remaining = stream, size

    def read(self, size):
        if size < 0:
            raise ProvenanceError('Unbounded ar member read')
        data = self.stream.read(min(size, self.remaining))
        self.remaining -= len(data)
        return data


def validate_control(stream):
    control = None
    with bounded_tar(stream) as tar:
        for name, member in checked_members(tar):
            if not (member.isdir() or member.isfile()):
                raise ProvenanceError('Non-file DEB control member')
            if name == 'control':
                if not member.isfile():
                    raise ProvenanceError('DEB control metadata must be a regular file')
                control = bounded_read(tar.extractfile(member), member.size)
    if control is None:
        raise ProvenanceError('DEB missing regular control metadata')
    text = control.decode('utf-8').replace('\r\n', '\n')
    fields, previous = {}, None
    for line in text.rstrip('\n').split('\n'):
        if line.startswith((' ', '\t')) and previous:
            fields[previous] += '\n' + line
            continue
        match = re.fullmatch(r'([A-Za-z0-9][-A-Za-z0-9]*):[ \t]*(.*)', line)
        if not match or '\0' in line:
            raise ProvenanceError('Malformed DEB control metadata')
        previous = match[1].lower()
        if previous in fields:
            raise ProvenanceError('Duplicate DEB control field')
        fields[previous] = match[2]
    if any(not fields.get(name, '').strip() for name in ('package', 'version', 'architecture', 'maintainer', 'description')):
        raise ProvenanceError('DEB control missing required package fields')
    if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', fields['package']):
        raise ProvenanceError('Invalid DEB Package field')
    if not re.fullmatch(r'(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*', fields['version']):
        raise ProvenanceError('Invalid DEB Version field')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', fields['architecture']):
        raise ProvenanceError('Invalid DEB Architecture field')


@contextmanager
def deb_data(path):
    """Required leading DEB members in order; permit trailing '_' extensions.

    Supported compression is deliberately limited to the standard-library
    codecs available on all gate hosts; unsupported codecs fail closed.
    """
    with Path(path).open('rb') as stream:
        length = Path(path).stat().st_size
        if length > MAX_COMPRESSED:
            raise ProvenanceError('DEB compressed inspection limit exceeded')
        if stream.read(8) != b'!<arch>\n':
            raise ProvenanceError('Invalid DEB/ar magic')
        members, seen = [], set()
        while True:
            header = stream.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:] != b'`\n':
                raise ProvenanceError('Truncated/invalid DEB ar header')
            name = header[:16].decode('ascii').strip().rstrip('/')
            size = int(header[48:58])
            if size < 0 or size > MAX_COMPRESSED or name in seen or len(members) >= MAX_MEMBERS:
                raise ProvenanceError('Invalid/duplicate/oversized DEB ar member')
            seen.add(name)
            offset = stream.tell()
            if offset + size > length:
                raise ProvenanceError('Truncated DEB ar member')
            members.append((name, offset, size))
            stream.seek(size, 1)
            if size % 2 and stream.read(1) != b'\n':
                raise ProvenanceError('Invalid DEB ar padding')
        suffixes = ('', '.gz', '.xz', '.bz2')
        if (len(members) < 3 or members[0][0] != 'debian-binary' or
                members[1][0] not in tuple('control.tar' + s for s in suffixes) or
                members[2][0] not in tuple('data.tar' + s for s in suffixes) or
                any(not name.startswith('_') for name, _, _ in members[3:])):
            raise ProvenanceError('Invalid DEB required member order/format or trailing extension')
        _, offset, size = members[0]
        if size != 4 or ArSlice(stream, offset, size).read(4) != b'2.0\n':
            raise ProvenanceError('Invalid DEB format version')
        for name, offset, size in members[1:3]:
            head = ArSlice(stream, offset, size).read(6)
            suffix = ('.gz' if head.startswith(b'\x1f\x8b') else
                      '.xz' if head.startswith(b'\xfd7zXZ\x00') else
                      '.bz2' if head.startswith(b'BZh') else '')
            if name != name.split('.tar')[0] + '.tar' + suffix:
                raise ProvenanceError('DEB archive compression does not match member name')
        _, offset, size = members[1]
        validate_control(ArSlice(stream, offset, size))
        _, offset, size = members[2]
        yield ArSlice(stream, offset, size)


def verify_package(path, expected):
    path = Path(path)
    with path.open('rb') as stream:
        is_deb = stream.read(8) == b'!<arch>\n'
    if path.name.endswith(('.deb', '.deb.part')) and not is_deb:
        raise ProvenanceError('DEB output is not an ar container')
    if path.name.endswith(('.tar', '.tar.gz', '.tar.gz.part')) and is_deb:
        raise ProvenanceError('Portable tar output is an ar container')
    flavor = expected['flavor']
    root = ('opt/xio' if flavor == 'full' else 'opt/xio-client') if is_deb else (
        'XIO' if flavor == 'full' else 'XIOClient')
    prefix = root + '/data/flutter_assets/assets/'
    payload = {}
    try:
        if path.stat().st_size > MAX_COMPRESSED:
            raise ProvenanceError('Package compressed inspection limit exceeded')
        with ExitStack() as stack:
            stream = stack.enter_context(deb_data(path) if is_deb else path.open('rb'))
            tar = stack.enter_context(bounded_tar(stream))
            for name, member in checked_members(tar):
                if flavor == 'client':
                    client_path(name)
                if name and prefix.startswith(name.rstrip('/') + '/') and not member.isdir():
                    raise ProvenanceError(f'Non-directory Flutter asset ancestor: {name}')
                if not name.startswith(prefix):
                    continue
                relative = name[len(prefix):]
                if not relative:
                    continue
                if not member.isfile():
                    if member.isdir():
                        continue
                    raise ProvenanceError(f'Non-file package asset: {name}')
                if flavor == 'client' and relative.split('/')[0] not in CLIENT_ASSET_DIRS:
                    raise ProvenanceError(f'Client package has unapproved asset: {relative}')
                if relative in expected['files'] or relative.startswith('l10n/'):
                    payload[relative] = bounded_read(tar.extractfile(member), member.size)
    except (tarfile.TarError, ValueError, UnicodeError, OSError, EOFError, lzma.LZMAError) as error:
        raise ProvenanceError(f'Unreadable Linux payload (compression must be supported): {error}') from error
    result = check_payload(payload, expected)
    result.update({'artifact': str(path), 'container': 'deb' if is_deb else 'tar'})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    snap = sub.add_parser('capture')
    snap.add_argument('--app-source', type=Path, required=True)
    snap.add_argument('--flavor', choices=['full', 'client'], required=True)
    snap.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('--expected', type=Path, required=True)
    check.add_argument('--app-source', type=Path, help='also reject changed build input')
    check.add_argument('packages', type=Path, nargs='+')
    args = parser.parse_args(argv)
    try:
        if args.command == 'capture':
            result = capture(args.app_source, args.flavor)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        else:
            expected = json.loads(args.expected.read_text(encoding='utf-8'))
            if args.app_source:
                verify_source(args.app_source, expected)
            result = [verify_package(path, expected) for path in args.packages]
    except (OSError, KeyError, TypeError, ValueError, ProvenanceError) as error:
        parser.exit(1, f'Linux provenance FAILED: {error}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
