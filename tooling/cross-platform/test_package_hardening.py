"""Focused reviewer regressions; never execute any packaged executable."""
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

import test_linux_provenance as fixtures
from test_linux_provenance import tar_bytes, full_payload
import linux_provenance as gate

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTROL = (b'Package: fixture\nVersion: 1.0\nArchitecture: all\n'
           b'Maintainer: Fixture <fixture@example.invalid>\nDescription: tiny valid fixture\n')


def ar_bytes(members):
    out = bytearray(b'!<arch>\n')
    for name, data in members:
        out += f'{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n'.encode() + data
        if len(data) % 2:
            out += b'\n'
    return bytes(out)


class LinuxHardeningTests(unittest.TestCase):
    # Reuse fixture construction without rerunning/inheriting the baseline suite.
    setUp = fixtures.LinuxProvenanceTests.setUp
    put = fixtures.LinuxProvenanceTests.put
    write_source = fixtures.LinuxProvenanceTests.write_source
    package = fixtures.LinuxProvenanceTests.package

    def deb_members(self):
        files = {'opt/xio/data/flutter_assets/assets/' + n: d for n, d in self.payload.items()}
        return [('debian-binary', b'2.0\n'), ('control.tar.gz', tar_bytes({'control': CONTROL})),
                ('data.tar.xz', tar_bytes(files, 'w:xz'))]

    def test_control_invalid_suffix_bytes_order_and_metadata(self):
        good = self.deb_members()
        cases = [good[:1] + [('control.tar.evil', b'x')] + good[2:],
                 good[:1] + [('control.tar.gz', b'not a tar')] + good[2:],
                 [good[2], good[1], good[0]],
                 good[:1] + [('control.tar.gz', tar_bytes({'control': b'Package: fixture\n'}))] + good[2:],
                 good[:1] + [('control.tar.gz', tar_bytes({'control': CONTROL + b'Package: duplicate\n'}))] + good[2:]]
        duplicate = tarfile.TarInfo('./control'); duplicate.size = len(CONTROL)
        cases.append(good[:1] + [('control.tar.gz', tar_bytes({'control': CONTROL}, extra=(duplicate, CONTROL)))] + good[2:])
        for members in cases:
            with self.subTest(names=[n for n, _ in members]), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(self.put(self.root / 'bad.deb', ar_bytes(members)), self.expected)
        gate.verify_package(self.put(self.root / 'good.deb', ar_bytes(good + [('_extra', b'extension')])), self.expected)

    def test_supported_control_compressions_and_regular_metadata(self):
        good = self.deb_members()
        for suffix, mode in [('', 'w'), ('.gz', 'w:gz'), ('.xz', 'w:xz'), ('.bz2', 'w:bz2')]:
            members = [good[0], ('control.tar' + suffix, tar_bytes({'./control': CONTROL}, mode)), good[2]]
            with self.subTest(suffix=suffix):
                gate.verify_package(self.put(self.root / 'codec.deb', ar_bytes(members)), self.expected)
        link = tarfile.TarInfo('control'); link.type = tarfile.SYMTYPE; link.linkname = 'other'
        for content in (tar_bytes({}, extra=(link, None)), gzip.compress(b'not tar'), b'\x1f\x8b\x08'):
            with self.subTest(control=len(content)), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(self.put(self.root / 'bad-control.deb', ar_bytes(
                    [good[0], ('control.tar.gz', content), good[2]])), self.expected)

    def test_regular_watched_ancestor_and_legitimate_launcher(self):
        for kind in ('deb', 'tar'):
            root = 'opt/xio' if kind == 'deb' else 'XIO'
            parent = tarfile.TarInfo(root + '/data/flutter_assets/assets/l10n'); parent.size = 1
            with self.subTest(kind=kind), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(self.package(self.payload, kind, extra=(parent, b'x')), self.expected)
            link = tarfile.TarInfo('usr/bin/xio'); link.type = tarfile.SYMTYPE; link.linkname = '/opt/xio/XIO'
            gate.verify_package(self.package(self.payload, kind, extra=(link, None)), self.expected)

    def rebound_inner(self, archive):
        payload = dict(self.payload, **{'xio-server.tar.gz': archive})
        manifest = json.loads(payload['xio-server-release.json']); manifest['sha256'] = gate.digest(archive)
        payload['xio-server-release.json'] = json.dumps(manifest).encode()
        return payload

    def test_inner_directory_first_duplicate(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz') as tar:
            directory = tarfile.TarInfo('admin.py'); directory.type = tarfile.DIRTYPE; tar.addfile(directory)
            for mirror, name in gate.MIRRORS.items():
                info = tarfile.TarInfo(name); info.size = len(self.payload[mirror])
                tar.addfile(info, io.BytesIO(self.payload[mirror]))
        with self.assertRaises(gate.ProvenanceError):
            gate.validate_server(self.rebound_inner(raw.getvalue()))

    def test_unwatched_sizes_bounded_before_skipping_both_containers(self):
        limit = max(map(len, self.payload.values()))
        info = tarfile.TarInfo('unwatched.bin'); info.size = limit * 10
        for kind in ('deb', 'tar'):
            package = self.package(self.payload, kind, extra=(info, b'0' * info.size))
            with self.subTest(kind=kind), patch.object(gate, 'MAX_MEMBER', limit), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(package, self.expected)

    def test_inner_unwatched_size_bounded(self):
        files = {member: self.payload[name] for name, member in gate.MIRRORS.items()}
        info = tarfile.TarInfo('unwatched'); info.size = 10000
        payload = self.rebound_inner(tar_bytes(files, extra=(info, b'0' * info.size)))
        with patch.object(gate, 'MAX_MEMBER', 1000), self.assertRaises(gate.ProvenanceError):
            gate.validate_server(payload)

    def test_archive_count_aggregate_and_pre_yield_metadata_bounded(self):
        # Small, highly compressed inputs exercise limits without creating a bomb.
        for kind in ('deb', 'tar'):
            package = self.package(self.payload, kind)
            for setting, value in [('MAX_MEMBERS', 3), ('MAX_TOTAL', 2048)]:
                with self.subTest(kind=kind, setting=setting), patch.object(gate, setting, value, create=True), self.assertRaises(gate.ProvenanceError):
                    gate.verify_package(package, self.expected)
            info = tarfile.TarInfo('unwatched'); info.pax_headers = {'comment': 'x' * 10000}
            package = self.package(self.payload, kind, extra=(info, b''))
            with self.subTest(kind=kind, metadata='pax'), patch.object(gate, 'MAX_METADATA', 1024, create=True), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(package, self.expected)
        # GNU long-name metadata also gets parsed before tarfile yields a member.
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz', format=tarfile.GNU_FORMAT) as tar:
            tar.addfile(tarfile.TarInfo('x' * 10000))
        package = self.put(self.root / 'gnu.tar.gz', raw.getvalue())
        with patch.object(gate, 'MAX_METADATA', 1024, create=True), self.assertRaises(gate.ProvenanceError):
            gate.verify_package(package, self.expected)

    def test_limits_reject_header_before_reading_irrelevant_body(self):
        class HeaderOnly(io.BytesIO):
            def read(self, size=-1):
                if self.tell() + size > 512:
                    raise AssertionError('reader consumed irrelevant body before rejecting its header')
                return super().read(size)
        info = tarfile.TarInfo('unwatched'); info.size = 10000
        for info in (info, tarfile.TarInfo('metadata')):
            if info.name == 'metadata':
                info.type = tarfile.XHDTYPE; info.size = 10000
            with self.subTest(type=info.type), patch.object(gate, 'MAX_MEMBER', 1000), \
                 patch.object(gate, 'MAX_METADATA', 1000), self.assertRaises(gate.ProvenanceError):
                with gate.bounded_tar(HeaderOnly(info.tobuf())) as tar:
                    list(gate.checked_members(tar))

    def test_inner_and_control_have_count_aggregate_and_metadata_budgets(self):
        for setting, value in [('MAX_MEMBERS', 2), ('MAX_TOTAL', 1024), ('MAX_METADATA', 1024)]:
            files = {name: b'x' * 10 for name in ('a', 'b', 'c')}
            info = tarfile.TarInfo('extra'); info.pax_headers = {'comment': 'x' * 10000}
            archive = tar_bytes(files, extra=(info, b''))
            for target in ('inner', 'control'):
                with self.subTest(setting=setting, target=target), patch.object(gate, setting, value), self.assertRaises(gate.ProvenanceError):
                    if target == 'inner':
                        gate.validate_server(self.rebound_inner(archive))
                    else:
                        good = self.deb_members()
                        good[1] = ('control.tar.gz', archive)
                        gate.verify_package(self.put(self.root / 'control.deb', ar_bytes(good)), self.expected)

    def test_xz_decoder_memory_is_bounded_before_payload_inspection(self):
        package = self.package(self.payload, 'deb')
        with patch.object(gate, 'MAX_CODEC_MEMORY', 1024 * 1024), \
             self.assertRaisesRegex(gate.ProvenanceError, 'Memory usage limit'):
            gate.verify_package(package, self.expected)

    def test_pax_effective_size_sparse_and_extension_chains_fail_bounded(self):
        for headers in ({'size': '10000'}, {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'},
                        {'GNU.sparse.map': '0,10000'}):
            info = tarfile.TarInfo('unwatched'); info.pax_headers = headers
            package = self.package(self.payload, 'tar', extra=(info, b''))
            with self.subTest(headers=headers), patch.object(gate, 'MAX_MEMBER', 1000), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(package, self.expected)
        # Each tiny extension is valid and below its byte limit, but recursive
        # chains must not reach Python's recursion limit before rejection.
        info = tarfile.TarInfo('pax'); info.type = tarfile.XHDTYPE; info.size = 0
        data = info.tobuf() * 20 + tarfile.TarInfo('ordinary').tobuf() + b'\0' * 1024
        with self.assertRaisesRegex(gate.ProvenanceError, 'extension chain'):
            with gate.bounded_tar(io.BytesIO(data)) as tar: list(gate.checked_members(tar))

    def test_canonical_tree_conflicts_in_either_order(self):
        for first_dir in (False, True):
            for path in ('watched/l10n', 'admin.py'):
                parent = tarfile.TarInfo(path); parent.type = tarfile.DIRTYPE if first_dir else tarfile.REGTYPE
                child = tarfile.TarInfo(path + '/child' if not first_dir else './' + path)
                tree = gate.ArchiveTree(); tree.add(parent)
                with self.subTest(first_dir=first_dir, path=path), self.assertRaises(gate.ProvenanceError):
                    tree.add(child)
        # A non-directory parent arriving after an already declared child.
        tree = gate.ArchiveTree(); tree.add(tarfile.TarInfo('l10n/en.json'))
        with self.assertRaises(gate.ProvenanceError): tree.add(tarfile.TarInfo('l10n'))
        for name in ('x' * 4097, 'x/' * 65 + 'leaf'):
            with self.assertRaisesRegex(gate.ProvenanceError, 'path inspection limit'):
                gate.ArchiveTree().add(tarfile.TarInfo(name))

    @unittest.skipUnless(shutil.which('pwsh'), 'requires PowerShell')
    def test_actual_linux_step_both_copy_paths_preserve_finals_on_failure(self):
        shutil.copy2(HERE / 'linux_provenance.py', self.put(self.root / 'tooling/cross-platform/linux_provenance.py', b''))
        self.put(self.root / 'tools/build-linux.sh', b'# fixture: build is mocked, never run\n')
        ps = r'''$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$RepoRoot=$env:T_ROOT; $OutDir=Join-Path $RepoRoot 'out'; $Stage=Join-Path $OutDir '.stage'
$Version='9.9.9'; $DryRun=$false; $LinuxArtifacts=if($env:T_MODE -eq 'import'){Join-Path $RepoRoot 'incoming'}else{''}
$script:Tools=@{Python=$env:T_PYTHON}
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:T_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'syntax error'}
foreach($name in @('Invoke-Native','Read-FileHead','Resolve-LinuxArtifact','Assert-DebAndTar','Invoke-LinuxStep')){
 $node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $node){throw "missing $name"}; Invoke-Expression $node.Extent.Text
}
# Platform-only shim in this disposable test process enables the exact local-copy branch.
Set-Variable IsWindows -Value $false -Force
$script:RealNative=${function:Invoke-Native}
function Invoke-Native {param($Exe,$Arguments,$WorkDir)
 if($Exe -eq 'sh'){return 0}
 if($env:T_FAIL -eq 'capture' -and $Arguments -contains 'capture'){return 9}
 & $script:RealNative -Exe $Exe -Arguments $Arguments -WorkDir $WorkDir
}
$script:Copies=0
function Copy-Item {param($LiteralPath,$Destination)
 $script:Copies++
 if($env:T_FAIL -eq 'copy' -and $script:Copies -eq 2){throw 'injected second-copy failure'}
 Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination
}
function Write-Step {param($Text)}
function New-StepRecord {param($Name,$Status,$Outputs,$Note); return $Status}
function Add-Artifact {param($Path,$Step)
 Add-Content -LiteralPath (Join-Path $RepoRoot 'accepted') -Value $Path
 return [pscustomobject]@{Name=[IO.Path]::GetFileName($Path)}
}
try {Invoke-LinuxStep; exit 0} catch {Write-Host $_.Exception.Message; exit 7}
'''
        random = os.urandom(1100000)
        for mode in ('import', 'local'):
            for bad in ('deb', 'tar', 'missing-tar', 'capture', 'copy', None):
                with self.subTest(mode=mode, bad=bad):
                    incoming = self.root / ('incoming' if mode == 'import' else 'releases')
                    out = self.root / 'out'; out.mkdir(exist_ok=True)
                    foreign = self.put(out / 'unrelated.part', b'NOT OWNED BY THIS INVOCATION')
                    accepted = self.root / 'accepted'
                    if accepted.exists(): accepted.unlink()
                    originals = {}
                    finals = []
                    for kind, tail in [('deb', 'ubuntu-amd64.deb'), ('tar', 'ubuntu-x64.tar.gz')]:
                        info = tarfile.TarInfo('unwatched'); info.size = len(random)
                        p = self.package(full_payload(27) if bad == kind else self.payload, kind, extra=(info, random))
                        name = 'XIO-9.9.9-' + tail
                        source = incoming / name
                        if bad == 'missing-tar' and kind == 'tar':
                            if source.exists(): source.unlink()
                        else:
                            self.put(source, p.read_bytes()); originals[source] = source.read_bytes()
                        finals.append(self.put(out / name, b'PREVIOUS ACCEPTED ' + kind.encode()))
                    before = [p.read_bytes() for p in finals]
                    env = dict(os.environ, T_ROOT=str(self.root), T_MODE=mode, T_FAIL=bad or '', T_PYTHON=sys.executable,
                               T_SCRIPT=str(ROOT / 'tools/release/build-all.ps1'))
                    result = subprocess.run(['pwsh', '-NoProfile', '-Command', ps], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if bad is None else 7, result.stdout + result.stderr)
                    if bad is not None:
                        self.assertEqual([p.read_bytes() for p in finals], before, result.stdout)
                        self.assertFalse(accepted.exists())
                    else:
                        self.assertTrue(accepted.exists()); self.assertEqual(len(accepted.read_text().splitlines()), 2)
                        self.assertEqual([p.read_bytes() for p in finals], list(originals.values()))
                    for p, data in originals.items(): self.assertEqual(p.read_bytes(), data)
                    self.assertEqual(list(out.glob('*.part')), [foreign])
                    self.assertEqual(foreign.read_bytes(), b'NOT OWNED BY THIS INVOCATION')


if __name__ == '__main__':
    unittest.main()
