from pathlib import Path
import hashlib
base = Path('/srv/archives/agent-split-routing-ttl-followup-20261106')
files = ['app/analysis_options.yaml', 'app/test/routing_native_clock_test.dart',
'app/android/app/src/test/java/app/xio/xio/RoutingProvenanceTest.kt',
'app/lib/core.dart', 'app/lib/routing_domains.dart',
'app/test/routing_contract_invariants_test.dart', 'app/test/routing_resolution_completeness_test.dart',
'app/test/split_domains_store_test.dart', 'app/test/connection_users_test.dart',
'app/android/app/src/main/kotlin/app/xio/xio/MainActivity.kt',
'app/android/app/src/main/kotlin/app/xio/xio/SplitRouting.kt',
'app/android/app/src/main/kotlin/app/xio/xio/RoutingResolutionGate.kt',
'app/android/app/src/test/java/app/xio/xio/RoutingResolutionGateTest.kt',
]
lines = [hashlib.sha256((base/'final'/p).read_bytes()).hexdigest()+'  '+p for p in files]
(base/'source-sha256.txt').write_text('\n'.join(lines)+'\n')
archives = ['base.tar', 'overlay.tar', 'cross-clock-allowance.txt', 'cross-clock-contract.log', 'cross-clock-contract-exit.txt', 'ReviewGate.kt', 'review_clock_observation_test.dart']
(base/'archive-sha256.txt').write_text('\n'.join(hashlib.sha256((base/p).read_bytes()).hexdigest()+'  '+p for p in archives)+'\n')
print('Source manifest recorded for actual tested final files')
