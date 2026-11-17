"""Offline real Kotlin gate execution + explicit source wiring checks (not APK)."""
from pathlib import Path
import hashlib, json, subprocess
base = Path('/srv/archives/agent-split-routing-fixes-20261106')
src = base / 'final/app/android/app/src'
cache = Path('/root/.gradle/caches/modules-2/files-2.1')
relative = [
'org.jetbrains.kotlin/kotlin-compiler-embeddable/2.4.0/f1a24af8bd111a83950236b1aec7a6d72a97e92c/kotlin-compiler-embeddable-2.4.0.jar',
'org.jetbrains.kotlin/kotlin-stdlib/2.4.0/4e9f4b531dce5c7dee58ed2de9a8b9a763c8dc6c/kotlin-stdlib-2.4.0.jar',
'org.jetbrains.kotlin/kotlin-script-runtime/2.4.0/1de03f0ef3e208ab5f97ee6a587e9b8480447df6/kotlin-script-runtime-2.4.0.jar',
'org.jetbrains.kotlin/kotlin-build-tools-api/2.4.0/46429d5887df2d02f33fe11a0c8444c5be5fd8da/kotlin-build-tools-api-2.4.0.jar',
'org.jetbrains.kotlin/kotlin-daemon-embeddable/2.4.0/1ecabef3a8ba6a8e25654573d54edb7e4136e903/kotlin-daemon-embeddable-2.4.0.jar',
'org.jetbrains.kotlin/kotlin-reflect/1.6.10/1cbe9c92c12a94eea200d23c2bbaedaf3daf5132/kotlin-reflect-1.6.10.jar',
'org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.0/ac1dc37a30a93150b704022f8d895ee1bd3a36b3/kotlinx-coroutines-core-jvm-1.8.0.jar',
'org.jetbrains/annotations/13.0/919f0dfe192fb4e063e7dacadee7f8bb9a2672a9/annotations-13.0.jar',
]
jars = [cache / p for p in relative]
for p in jars: assert p.is_file(), str(p)
java='/usr/lib/jvm/java-21-openjdk-amd64/bin/java'
classes = base / 'kotlin-classes'
classes.mkdir(exist_ok=True)
gate=src/'main/kotlin/app/xio/xio/RoutingResolutionGate.kt'
test=src/'test/java/app/xio/xio/RoutingResolutionGateTest.kt'
cmd=[java, '-Djava.io.tmpdir='+str(base/'tmp'), '-cp', ':'.join(map(str,jars)), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target','17','-classpath',str(jars[1])+':'+str(jars[-1]),'-d',str(classes),str(gate),str(test)]
result=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
(base/'kotlin-compile.log').write_text(result.stdout+result.stderr)
assert result.returncode==0, 'Kotlin compilation failed'
run=[java,'-cp',str(classes)+':'+str(jars[1]),'app.xio.xio.RoutingResolutionGateTest']
result=subprocess.run(run,text=True,capture_output=True,timeout=20)
(base/'kotlin-tests.log').write_text(result.stdout+result.stderr)
assert result.returncode==0, 'Kotlin tests failed'
routing=(src/'main/kotlin/app/xio/xio/SplitRouting.kt').read_text()
activity=(src/'main/kotlin/app/xio/xio/MainActivity.kt').read_text()
assert 'addresses.take(' not in routing
assert 'fun saveResolved(addresses: List<String>, revision: String, lease: String, validForMillis: Long): Policy = synchronized(gate)' in routing
assert 'gate.commit(revision, lease, validForMillis) { write(policy) }' in routing
assert 'current.revision != revision' in routing
assert 'resolved.size + current.networks.size > MAX_NETWORKS' in routing
assert '(current.domains.isNotEmpty() && resolved.isEmpty())' in routing
assert 'UUID.randomUUID().toString()' in routing
assert '.put("revision", policy.revision)' in routing
assert 'requireResolved(policy)' in routing[routing.index('fun apply(config:'):]
assert 'requireResolved(policy)' in routing[routing.index('fun applyNative('):]
assert '"routingBegin" ->' in activity and '"routingCancel" ->' in activity
assert 'call.argument<String>("revision") ?: ""' in activity
assert 'call.argument<String>("lease") ?: ""' in activity
(base/'native-wiring.log').write_text('PASS source wiring: versioned atomic save; no truncation; capacity/empty checks; UUID persisted; both native apply paths require receipt; channel begin/cancel/revision+lease arguments\n')
inputs=[gate,test,src/'main/kotlin/app/xio/xio/SplitRouting.kt',src/'main/kotlin/app/xio/xio/MainActivity.kt',*jars]
(base/'native-receipt.json').write_text(json.dumps({'compileCommand':cmd,'testCommand':run,'inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}},indent=2))
print('Kotlin gate and source wiring PASS; no Android runtime or APK claim')
