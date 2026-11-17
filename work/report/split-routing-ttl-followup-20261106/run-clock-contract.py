from pathlib import Path
import json,subprocess
b=Path('/srv/archives/agent-split-routing-review-20261106')
r=json.loads((b/'independent-native-receipt.json').read_text())
cmd=r['testCommand']+['clock',str(b/'cross-clock-allowance.txt')]
p=subprocess.run(cmd,text=True,capture_output=True,timeout=20)
(b/'cross-clock-contract.log').write_text(p.stdout+p.stderr)
(b/'cross-clock-contract-exit.txt').write_text(str(p.returncode)+'\n')
print('Actual command:',cmd)
print(p.stdout+p.stderr)
print('ACTUAL_CROSS_CLOCK_CONTRACT_EXIT',p.returncode)
# This wrapper confirms reproduction, NOT contract acceptance.
assert p.returncode==1 and 'CONTRACT FAILURE: cached DNS older than original10m' in p.stderr
print('Reproduction confirmed: actual contract assertion FAIL1 (not compiler/setup error).')
