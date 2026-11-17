from pathlib import Path
import hashlib,json,os,subprocess,zipfile
b=Path('/srv/archives/agent-review-rivet-aar-20261106'); old=Path('/srv/archives/agent-android-compile-preflight-20261106')
env=dict(os.environ,HOME=str(b/'home'),TMPDIR=str(b/'tmp'),GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOMAXPROCS='2',GOTELEMETRY='off',JAVA_TOOL_OPTIONS=f'-Duser.home={b}/home -Djava.io.tmpdir={b}/tmp -XX:-UsePerfData')
for abi in ['arm64-v8a','armeabi-v7a','x86_64']:
 p=subprocess.run(['/opt/go1.27.3/bin/go','version','-m',str(b/'payload'/f'{abi}-libgojni.so')],capture_output=True,text=True,env=env)
 (b/'logs'/f'{abi}-go-buildinfo.txt').write_text(p.stdout+p.stderr);assert p.returncode==0
 sym=subprocess.run(['readelf','--dyn-syms','--wide',str(b/'payload'/f'{abi}-libgojni.so')],capture_output=True,text=True,env=env);assert sym.returncode==0
 (b/'logs'/f'{abi}-dynamic-symbols.txt').write_text(sym.stdout+sym.stderr)
 matches={method:[line.strip() for line in sym.stdout.splitlines() if 'Java_app_xio_mobile_Mobile_'+method in line] for method in ['cancelConnect','stopWithTimeout','connectPolicyTimeout','connectionPolicyMode']}
 assert all(matches.values()),(abi,matches)
 assert all(' UND ' not in line for lines in matches.values() for line in lines)
 (b/'logs'/f'{abi}-jni-api-exports.json').write_text(json.dumps(matches,indent=2))
stale=old/'src/app/android/app/libs/rivet.aar';assert hashlib.sha256(stale.read_bytes()).hexdigest()=='cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7'
(b/'payload/stale-classes.jar').write_bytes(zipfile.ZipFile(stale).read('classes.jar'))
p=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/javap','-classpath',str(b/'payload/stale-classes.jar'),'app.xio.mobile.Mobile'],capture_output=True,text=True,env=env);assert p.returncode==0
for absent in ['cancelConnect','stopWithTimeout','connectPolicyTimeout']:assert absent not in p.stdout
(b/'logs/stale-Mobile-api.txt').write_text(p.stdout+p.stderr)
private=Path('/srv/archives/agent-rivet-aar-20261106/go-private')
assert (private/'.xio-patched').read_text().strip()=='CLOCK_BOOTTIME on arm/arm64/amd64'
patches={}
for arch in ['arm','arm64','amd64']:
 rel=f'src/runtime/sys_linux_{arch}.s'; expected=hashlib.sha256((old/'go-private'/rel).read_bytes()).hexdigest(); actual=hashlib.sha256((private/rel).read_bytes()).hexdigest(); assert expected==actual
 patches[rel]=actual
(b/'logs/private-go-patch-check.json').write_text(json.dumps(patches,indent=2))
# Verify tools against previously sampled identities without writing any SDK/cache.
checks={}
for line in (old/'toolchain-baseline.sha256').read_text().splitlines():
 expected,path=line.split(maxsplit=1);actual=hashlib.sha256(Path(path.strip()).read_bytes()).hexdigest();checks[path.strip()]={'expected':expected,'actual':actual,'equal':expected==actual}
assert all(v['equal'] for v in checks.values())
(b/'logs/toolchain-hash-check.json').write_text(json.dumps(checks,indent=2))
