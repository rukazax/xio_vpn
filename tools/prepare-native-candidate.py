#!/usr/bin/env python3
"""Create isolated test-candidate inputs; never qualify or replace release inputs."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,shutil,struct
from native_fingerprint import fingerprint
ROOT=Path(__file__).resolve().parent.parent

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--candidate-root',type=Path,required=True);a=p.parse_args()
 work=a.work.resolve();target=a.candidate_root.resolve()
 if target==ROOT or target.is_relative_to(ROOT) or ROOT.is_relative_to(target):raise RuntimeError('Candidate root must be outside canonical source tree')
 owner=target/'.xio-test-candidate.json'
 if target.exists() and any(target.iterdir()):
  if not owner.is_file():raise RuntimeError('Unowned candidate directory preserved')
  saved=json.loads(owner.read_text())
  if saved.get('owner')!='xio-test-candidate-v1' or saved.get('sourceRoot')!=str(ROOT):raise RuntimeError('Foreign candidate directory preserved')
 cross=json.loads((work/'linux-cross-build-receipt.json').read_text())
 aar=json.loads((work/'android-native-ea067-build-receipt.json').read_text(encoding='utf-8-sig'))
 checked=json.loads((work/'aar-ea067-verification.json').read_text())
 linux=json.loads((work/'linux-vps-smoke-result.json').read_text())
 proof=next(json.loads(line) for line in linux['stdout'].splitlines() if line.startswith('{') and '"managed"' in line)
 if linux['remoteExitCode']!=0 or not linux['hostKeyMatched'] or proof['managed']['passed']!=67 or proof['managed']['skipped'] or proof['packaging']['passed']!=5 or not proof['routesAndForwardingUnchanged'] or 'XIO_TEMP_CLEANUP_OK' not in linux['stdout']:raise RuntimeError('Linux unit/entry evidence not complete')
 source=fingerprint(ROOT)
 if not cross['sourceStableDuringBuild'] or cross['sourceFingerprint']!=source or aar['exitCode']!=0 or not aar['sourceStable'] or aar['sourceBeforeSha256']!=source or aar['sourceAfterSha256']!=source:raise RuntimeError('Native source snapshot differs')
 aarfile=work/'rivet-dualstack-ea067-candidate.aar'
 if digest(aarfile)!=aar['aarSha256'] or checked['aarSha256']!=aar['aarSha256'] or not checked['publicMobileApiEqual']:raise RuntimeError('AAR identity/API guard failed')
 names=['amneziawg-go-linux-amd64','xio-rivet-linux-amd64','xio-xray-linux-amd64','xio-cloak-linux-amd64']
 for name in names:
  file=work/'native-linux'/name;raw=file.read_bytes()
  if digest(file)!=cross['serverBinaryHashes'][name] or raw[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',raw,18)[0]!=62:raise RuntimeError('Native Linux digest/ABI mismatch: '+name)
 if cross['serverBinaryHashes'][names[0]]!='fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a':raise RuntimeError('Pinned AWG differs')
 canonical={p:digest(ROOT/p) for p in ['vendor-metadata/rivet-build.json','app/android/app/libs/rivet.aar','app/assets/xio-server-release.json','app/assets/xio-server.tar.gz']}
 target.mkdir(parents=True,exist_ok=True);owner.write_text(json.dumps({'owner':'xio-test-candidate-v1','sourceRoot':str(ROOT),'notProductionQualified':True})+'\n')
 managed=ROOT/'server/managed';dest=target/'server/managed'
 for file in sorted(managed.rglob('*')):
  if file.is_file() and (file.suffix in {'.py','.json','.sh'} or file.name=='LICENSE'):
   if file.is_symlink():raise RuntimeError('Linked managed source refused')
   out=dest/file.relative_to(managed);out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,out)
   if digest(file)!=digest(out):raise RuntimeError('Managed source copy differs')
 (target/'vendor-server').mkdir(exist_ok=True)
 for name in names:shutil.copyfile(work/'native-linux'/name,target/'vendor-server'/name)
 output=target/'app/android/app/libs/rivet.aar';output.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(aarfile,output)
 metadata=json.loads((ROOT/'vendor-metadata/rivet-build.json').read_text())
 metadata.update({'go':'go version go'+cross['goVersion']+' windows/amd64','sourceSha256':source,'serverSha256':cross['serverBinaryHashes'][names[1]],'xrayServerSha256':cross['serverBinaryHashes'][names[2]],'cloakServerSha256':cross['serverBinaryHashes'][names[3]],'androidAarSha256':aar['aarSha256'],'candidateOnly':True,'buildHost':'Windows/amd64','serverTarget':'Linux/amd64 CGO_ENABLED=0','linuxUnitsPassed':67,'linuxPackagingFixturesPassed':5,'linuxBinaryEntryChecksOnly':True,'linuxGoRaceTested':False,'realVpnTested':False})
 (target/'vendor-metadata').mkdir(exist_ok=True);(target/'vendor-metadata/rivet-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
 spec=importlib.util.spec_from_file_location('xio_candidate_packager',ROOT/'tools/package-server.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 checked_inputs=module.package(target,ROOT,target/'assets',check=True)
 manifest=module.package(target,ROOT,target/'assets')
 if any(digest(ROOT/p)!=before for p,before in canonical.items()):raise RuntimeError('Canonical release inputs changed unexpectedly')
 if fingerprint(ROOT)!=source:raise RuntimeError('Native source changed while packaging')
 report={'candidateRoot':str(target),'assets':str(target/'assets'),'nativeSourceSha256':source,'checkedInputs':checked_inputs,'manifest':manifest,'canonicalReleaseInputsUnchanged':True,'candidateOnly':True,'productionQualified':False,'goRaceTested':False,'vpnTested':False,'nativeBuildHost':'Windows/amd64','linuxEntryAndUnitsVerified':True}
 (work/'candidate-package-receipt.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
if __name__=='__main__':main()
