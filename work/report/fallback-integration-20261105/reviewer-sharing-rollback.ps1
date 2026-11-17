param([Parameter(Mandatory=$true)][string]$SourcePath)
$ErrorActionPreference='Stop'
# Source-extracted rollback core only; NOT the COM/ICS prefix or a native command.
$source=[IO.File]::ReadAllText((Resolve-Path $SourcePath))
$loop=[regex]::Match($source,'(?s)rollback := script \+ `(?<code>.*?)` \+')
$tail=[regex]::Match($source,'(?s)return rollback \+ `(?<code>.*?)`')
if(!$loop.Success -or !$tail.Success){throw 'Frozen rollback source changed; inspect fixture'}
$script:receiptExists=$true
$script:ruleExists=$true
$receipt='FAKE-RECEIPT-NOT-A-FILE'
$rule='FAKE-RULE-NOT-A-FIREWALL-RULE'
function Remove-Item { param($LiteralPath,$ErrorAction); if($LiteralPath -ne $receipt){throw 'Not fake receipt'}; $script:receiptExists=$false }
function Remove-NetFirewallRule { param($Name,$ErrorAction); if($Name -ne $rule){throw 'Not fake firewall rule'}; $script:ruleExists=$false }
function FakeConfig {
  $cfg=[pscustomobject]@{SharingEnabled=$true}
  $cfg|Add-Member -MemberType ScriptMethod -Name DisableSharing -Value { throw 'INJECTED COM disable failure' }
  return $cfg
}
$public=@([pscustomobject]@{Config=(FakeConfig)})
$private=@([pscustomobject]@{Config=(FakeConfig)})
$thrown=$null
try { Invoke-Expression ($loop.Groups['code'].Value + "`n" + $tail.Groups['code'].Value) } catch { $thrown=$_ }
Write-Output ('Mock actual rollback: threw={0} publicEnabled={1} privateEnabled={2} receiptExists={3}' -f ($null -ne $thrown),$public[0].Config.SharingEnabled,$private[0].Config.SharingEnabled,$script:receiptExists)
if($null -eq $thrown -and !$script:receiptExists -and $public[0].Config.SharingEnabled){
  throw 'DESIRED INVARIANT FAILED: actual rollback swallowed disable failure and deleted ownership receipt while owned sharing stayed enabled'
}
if($null -ne $thrown -and $script:receiptExists){Write-Output 'PASS desired rollback-failure truthfulness invariant';exit 0}
throw 'Unexpected mocked rollback result; inspect source semantics'
