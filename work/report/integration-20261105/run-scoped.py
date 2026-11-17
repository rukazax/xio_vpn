from pathlib import Path
import os, sys, unittest, json, hashlib, subprocess
root=Path(sys.argv[1]).resolve()
os.environ['XIO_CLIENT_PE_FIXTURE']=str(root.parent / 'win-release' / 'XIOClient.exe')
loader=unittest.TestLoader(); suite=unittest.TestSuite()
for folder, patterns in [
 ('tooling/cross-platform',['test_linux_provenance.py','test_package_hardening.py','test_pe_version_hardening.py']),
 ('client',['test_windows_version.py']),
 ('tools/release',['test_current_targets.py','test_current_targets_yaml.py']),
 ('tools/acceptance',['test_android_acceptance.py']),
]:
    start=str(root/folder)
    for pattern in patterns:
        suite.addTests(loader.discover(start, pattern=pattern, top_level_dir=start))
result=unittest.TextTestRunner(verbosity=2).run(suite)
print('SUMMARY', 'run',result.testsRun,'failures',len(result.failures),'errors',len(result.errors),'skips',len(result.skipped))
if len(sys.argv)>2:
    checked=[]
    for entry in json.loads((root/'evidence/source-hashes.json').read_text(encoding='utf-8')):
        relative=entry['path']
        if relative not in ('server/managed/cascade_native.py','server/managed/cascade_native_rpc.py','server/managed/dualstack.py','server/managed/test_cascade_native.py','server/managed/test_cascade_native_review.py','server/managed/test_native_integration_boundary.py','app/lib/native_profile_readiness.dart','app/test/native_profile_readiness_test.dart'):
            raise RuntimeError('unexpected source receipt path')
        raw=(root/relative).read_bytes()
        if len(raw)!=entry['bytes'] or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            raise RuntimeError('native reviewed source differs: '+relative)
        checked.append(entry)
    head=subprocess.run(['git','rev-parse','HEAD'],cwd=root,check=True,capture_output=True,text=True).stdout.strip()
    receipt={'testedIntegrationHead':head,'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':[{'test':str(t),'reason':r} for t,r in result.skipped],'nativeReviewedHead':'280625da9377d076879c06523988482ed2dd1750','nativeSourcesMatch':checked,'acceptanceScope':'Python package/CI/Android harness mocks and native source-byte comparison; no build/install/device/native activation.'}
    with Path(sys.argv[2]).open('x',encoding='utf-8',newline='\n') as out:
        out.write(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(0 if result.wasSuccessful() else 1)
