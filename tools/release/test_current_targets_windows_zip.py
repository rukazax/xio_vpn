"""Actual Windows PowerShell ZIP producer -> unchanged shared LAYOUT clauses.

Inert dummy payloads are NOT PE/native/provenance/runtime acceptance. No build,
network, signing or app execution. Retain every tiny fixture in owned evidence;
this regression never removes/moves anything or runs build-all's main entrypoint.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import current_targets as gate

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCRIPT = HERE / 'build-all.ps1'
REQUIRED = ['XIO.exe', 'flutter_windows.dll', 'data/app.so', 'data/icudtl.dat',
            'libexec/xio-tunnel.exe', 'libexec/wintun.dll', 'libexec/WINTUN-LICENSE.txt',
            'data/flutter_assets/AssetManifest.bin']
PAYLOAD = {name: ('INERT layout fixture, NOT executable: ' + name).encode() for name in REQUIRED}
PAYLOAD.update({'plugin.dll': bytes(range(256)), 'hidden-plugin.dll': b'hidden inert plugin',
                'data/flutter_assets/.hidden-fixture': b'hidden inert data',
                'data/flutter_assets/assets/l10n/en.json': b'{"fixture":true}',
                'data/flutter_assets/fonts/fixture font.ttf': b'inert font',
                'LICENSE': b'inert license fixture', 'COPYRIGHT': b'inert copyright fixture'})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def shared_layout(path):
    """Execute exact brand/root/required-entry AST nodes, NOT the whole artifact gate."""
    tree = ast.parse((HERE / 'current_targets.py').read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'windows')
    assignments = {node.targets[0].id: node for node in function.body
                   if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    messages = ['Unexpected Windows archive root', 'Incomplete Windows native/runtime bundle']
    calls = {}
    for node in function.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            for message in messages:
                if any(isinstance(arg, ast.Constant) and arg.value == message for arg in node.value.args):
                    calls[message] = node
    if set(calls) != set(messages) or not {'brand', 'required'} <= assignments.keys():
        raise AssertionError('Shared Windows layout clauses changed; review required')
    selected = [assignments['brand'], calls[messages[0]], assignments['required'], calls[messages[1]]]
    with zipfile.ZipFile(path) as archive:
        files = {info.filename: info for info in archive.infolist() if not info.is_dir()}
    context = {'flavor': 'full', 'files': files, 'require': gate.require}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(HERE/'current_targets.py'), 'exec'), context)
    return files


DRIVER = r'''$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:XIO_ZIP_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'PowerShell syntax errors in actual release source' }
foreach($name in @('New-WindowsFullArchive','Get-Sha256','Add-Artifact')) {
 $nodes=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
 if($nodes.Count -ne 1) { throw "Expected exactly one actual function: $name" }
 Invoke-Expression $nodes[0].Extent.Text
}
# Only suppress cosmetic output; actual Add-Artifact computes size/hash and registers it.
function Show-Artifact { param($Record) }
$script:Assets=New-Object 'System.Collections.Generic.List[object]'
$step=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-WindowsStep'},$true)
$calls=@($step.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-WindowsFullArchive'},$true))
$registration=@($step.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Artifact'},$true))
$zipAssignments=@($step.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$zipPath'},$true))
if($calls.Count -ne 1 -or $registration.Count -ne 1 -or $zipAssignments.Count -ne 1) { throw 'Actual packaging callsite/filename/registration contract changed' }
if($step.Body.Extent.Text -match 'Compress-Archive|CreateFromDirectory|Remove-Item') { throw 'Inline archive override/deletion returned to Windows step' }
$bundle=$env:XIO_ZIP_BUNDLE; $Stage=$env:XIO_ZIP_STAGE; $OutDir=$env:XIO_ZIP_OUTPUT; $Version=$env:XIO_ZIP_VERSION
foreach($name in @('hidden-plugin.dll','data/flutter_assets/.hidden-fixture')) {
 $path=Join-Path $bundle $name
 if(Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path -Force).Attributes = [IO.FileAttributes]::Hidden }
}
# Execute ONLY the exact archive filename assignment, producer call and registration,
# never Invoke-WindowsStep, tool resolution, main, native builds or Wintun download.
Invoke-Expression $zipAssignments[0].Extent.Text
$names=@(Invoke-Expression $calls[0].Extent.Text)
$asset=Invoke-Expression $registration[0].Extent.Text
if($script:Assets.Count -ne 1) { throw 'Actual artifact registration did not run exactly once' }
@{Archive=$asset; Entries=$names; ProducerCall=$calls[0].Extent.Text; Filename=$zipAssignments[0].Extent.Text; LayoutOnly=$true; AppExecuted=$false} |
 ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $env:XIO_ZIP_RECEIPT -Encoding utf8NoBOM
'''


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = ROOT / '.build-support/windows-full-zip-fixtures'
        cls.evidence.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='case-', dir=self.evidence)).resolve()

    def zip(self, rows, name='layout.zip'):
        path = self.root / name
        with zipfile.ZipFile(path, 'w') as archive:
            for member, data in rows.items():
                archive.writestr(member, data)
        return path


class LayoutTests(FixtureCase):
    def test_exact_shared_gate_rejects_flat_mixed_wrong_brand(self):
        rooted = {'XIO/' + name: data for name, data in PAYLOAD.items()}
        self.assertTrue(shared_layout(self.zip(rooted, 'rooted.zip')))
        for name, rows in [('flat', PAYLOAD), ('mixed', dict(rooted, **{'stray.dll': b'inert'})),
                           ('client-root', {'XIOClient/' + key: value for key, value in PAYLOAD.items()})]:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'Unexpected Windows archive root'):
                shared_layout(self.zip(rows, name+'.zip'))

    def test_exact_shared_gate_rejects_each_missing_native_runtime_entry(self):
        # AssetManifest is producer-required too; the shared layout gate itself requires seven other entries.
        for missing in REQUIRED[:-1]:
            rows = {'XIO/' + name: data for name, data in PAYLOAD.items() if name != missing}
            with self.subTest(missing=missing), self.assertRaisesRegex(RuntimeError, 'Incomplete Windows native/runtime bundle'):
                shared_layout(self.zip(rows, missing.replace('/', '-')+'.zip'))


@unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'Actual Windows built-in archive producer requires Windows PowerShell7')
class ProducerTests(FixtureCase):
    def fixture(self, payload=None):
        case = Path(tempfile.mkdtemp(prefix='producer-', dir=self.root))
        bundle, stage, output = case/'Release', case/'stage', case/'out'
        for folder in [bundle, stage, output]:
            folder.mkdir()
        for name, data in (PAYLOAD if payload is None else payload).items():
            path = bundle/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        driver = case/'producer.ps1'
        driver.write_text(DRIVER, encoding='utf-8')
        return case, bundle, stage, output, driver

    def run_producer(self, fixture, version='9.9.9', stage=None, output=None):
        case, bundle, default_stage, default_output, driver = fixture
        env = dict(os.environ, XIO_ZIP_SCRIPT=str(SCRIPT), XIO_ZIP_BUNDLE=str(bundle),
                   XIO_ZIP_STAGE=str(stage or default_stage), XIO_ZIP_OUTPUT=str(output or default_output),
                   XIO_ZIP_VERSION=version, XIO_ZIP_RECEIPT=str(case/'receipt.json'))
        result = subprocess.run(['pwsh','-NoProfile','-File',str(driver)], env=env, capture_output=True, text=True)
        (case/'stdout.log').write_text(result.stdout, encoding='utf-8')
        (case/'stderr.log').write_text(result.stderr, encoding='utf-8')
        return result

    def source_bytes(self, bundle):
        return {path.relative_to(bundle).as_posix(): path.read_bytes() for path in bundle.rglob('*') if path.is_file()}

    def test_actual_producer_callsite_preserves_every_byte_and_records_actual_hash(self):
        for version in ['9.9.9', '1.2.3-rc.1']:
            with self.subTest(version=version):
                fixture = self.fixture()
                case, bundle, stage, output, _ = fixture
                before = self.source_bytes(bundle)
                result = self.run_producer(fixture, version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                path = output/f'XIO-Full-{version}-windows-x64.zip'
                files = shared_layout(path)
                self.assertEqual(set(files), {'XIO/'+name for name in before})
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual({name.removeprefix('XIO/'): archive.read(name) for name in files}, before)
                self.assertEqual(self.source_bytes(bundle), before)
                receipt = json.loads((case/'receipt.json').read_text(encoding='utf-8-sig'))
                self.assertEqual(receipt['Archive']['Name'], path.name)
                self.assertEqual(receipt['Archive']['Step'], 'windows')
                self.assertEqual(receipt['Archive']['Bytes'], path.stat().st_size)
                self.assertEqual(receipt['Archive']['Sha256'], digest(path.read_bytes()))
                self.assertEqual(receipt['Archive']['SignerSha256'], '')
                self.assertTrue(receipt['LayoutOnly'])
                self.assertFalse(receipt['AppExecuted'])
                self.assertEqual(len(list(stage.glob('windows-full-*/XIO'))), 1)

    def test_actual_producer_rejects_each_missing_entry_without_creating_zip(self):
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                fixture = self.fixture({key: value for key, value in PAYLOAD.items() if key != missing})
                before = self.source_bytes(fixture[1])
                result = self.run_producer(fixture)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Missing Windows bundle entry', result.stderr)
                self.assertFalse(list(fixture[3].glob('*.zip')))
                self.assertEqual(self.source_bytes(fixture[1]), before)

    def test_actual_postarchive_entry_check_is_case_exact_and_never_registers_bad_zip(self):
        payload = {('xio.exe' if key == 'XIO.exe' else key): value for key, value in PAYLOAD.items()}
        fixture = self.fixture(payload)
        result = self.run_producer(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing Windows archive entry: XIO/XIO.exe', result.stderr)
        self.assertFalse((fixture[0]/'receipt.json').exists())
        path = fixture[3]/'XIO-Full-9.9.9-windows-x64.zip'
        with self.assertRaisesRegex(RuntimeError, 'Incomplete Windows native/runtime bundle'):
            shared_layout(path)
        self.assertEqual(self.source_bytes(fixture[1]), payload)

    def test_actual_producer_never_overwrites_existing_archive(self):
        fixture = self.fixture()
        previous = fixture[3]/'XIO-Full-9.9.9-windows-x64.zip'
        previous.write_bytes(b'preserve pre-existing owned sentinel')
        result = self.run_producer(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Refusing to replace an existing archive', result.stderr)
        self.assertEqual(previous.read_bytes(), b'preserve pre-existing owned sentinel')
        self.assertFalse(list(fixture[2].iterdir()))

    def test_actual_producer_rejects_source_stage_or_output_overlap(self):
        for kind in ['stage', 'output']:
            with self.subTest(kind=kind):
                fixture = self.fixture()
                before = self.source_bytes(fixture[1])
                result = self.run_producer(fixture, **{kind: fixture[1]})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('must not overlap', result.stderr)
                self.assertEqual(self.source_bytes(fixture[1]), before)
                self.assertFalse(list(fixture[2].iterdir()))


if __name__ == '__main__':
    unittest.main()
