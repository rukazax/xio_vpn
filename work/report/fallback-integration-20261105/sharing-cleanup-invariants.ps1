param([Parameter(Mandatory=$true)][string]$SourcePath)
$ErrorActionPreference='Stop'
# Executes ONLY source-extracted cleanup bodies with fake COM configurations,
# fake receipt/rule functions, no COM prefix and no native network/file mutation.
$source=[IO.File]::ReadAllText((Resolve-Path $SourcePath))
$loop=[regex]::Match($source,'(?s)rollback := script \+ `(?<code>.*?)` \+')
$rulePart=[regex]::Match($source,'(?s)rollback \+= `(?<code>.*?)` \+')
$tail=[regex]::Match($source,'(?s)return rollback \+ `(?<code>.*?)`')
$disable=[regex]::Match($source,'(?s)script \+= `(?<code>if\(Test-Path -LiteralPath \$receipt\).*?)`')
if(!$loop.Success -or !$rulePart.Success -or !$tail.Success -or !$disable.Success){throw 'Actual source cleanup extraction failed'}
$receipt='FAKE-RECEIPT-NOT-A-FILE';$rule='FAKE-RULE-NOT-A-FIREWALL-RULE'
function Test-Path {param($LiteralPath);if($LiteralPath -ne $receipt){throw 'Unexpected host file access'};return $script:receiptExists}
function Get-Content {param([switch]$Raw,$LiteralPath);if($LiteralPath -ne $receipt){throw 'Unexpected host file read'};return $script:receiptJson}
function Remove-Item {param($LiteralPath,$ErrorAction);if($LiteralPath -ne $receipt){throw 'Unexpected host file mutation'};$script:receiptExists=$false}
function Get-NetFirewallRule {param($Name,$ErrorAction);if($Name -ne $rule){throw 'Unexpected native rule query'};if($script:ruleExists){[pscustomobject]@{Name=$Name}}}
function Remove-NetFirewallRule {param($Name,$ErrorAction);if($Name -ne $rule){throw 'Unexpected native firewall mutation'};if($script:ruleFails){throw 'Injected rule removal failure'};$script:ruleExists=$false}
function FakeConfig([string]$Mode,[int]$Type) {
 $cfg=[pscustomobject]@{SharingEnabled=$true;SharingConnectionType=$Type;Mode=$Mode}
 $cfg|Add-Member -MemberType ScriptMethod -Name DisableSharing -Value {
  if($this.Mode -eq 'throw'){throw 'Injected COM disable failure'}
  if($this.Mode -ne 'sticky'){$this.SharingEnabled=$false}
 }
 return $cfg
}
$failures=0
foreach($body in @('rollback','disable')) {
 foreach($case in @('both-throw','private-throw','public-throw','sticky-success','success','rule-failure','already-disabled')) {
  $script:receiptExists=$true;$script:ruleExists=$true;$script:ruleFails=$case -eq 'rule-failure'
  $script:receiptJson=@{public='public-id';private='private-id';owner='xio-sharing-v1';rule=$rule}|ConvertTo-Json -Compress
  $publicMode=if($case -in @('both-throw','public-throw')){'throw'}elseif($case -eq 'sticky-success'){'sticky'}else{'ok'}
  $privateMode=if($case -in @('both-throw','private-throw')){'throw'}else{'ok'}
  $public=@([pscustomobject]@{Props=[pscustomobject]@{Guid='public-id'};Config=(FakeConfig $publicMode 0)})
  $private=@([pscustomobject]@{Props=[pscustomobject]@{Guid='private-id'};Config=(FakeConfig $privateMode 1)})
  $all=@($public[0],$private[0])
  if($case -eq 'already-disabled'){$public[0].Config.SharingEnabled=$false;$private[0].Config.SharingEnabled=$false}
  $code=if($body -eq 'rollback'){$loop.Groups['code'].Value+"`n"+$rulePart.Groups['code'].Value+"`n"+$tail.Groups['code'].Value}else{$disable.Groups['code'].Value}
  $threw=$false
  try { $null=Invoke-Expression $code } catch {$threw=$true}
  $expectedFailure=$case -notin @('success','already-disabled')
  $ok=if($expectedFailure){$threw -and $script:receiptExists}else{!$threw -and !$script:receiptExists -and !$script:ruleExists -and !$public[0].Config.SharingEnabled -and !$private[0].Config.SharingEnabled}
  Write-Output ('{0}/{1}: ok={2} threw={3} public={4} private={5} receipt={6} rule={7}' -f $body,$case,$ok,$threw,$public[0].Config.SharingEnabled,$private[0].Config.SharingEnabled,$script:receiptExists,$script:ruleExists)
  if(!$ok){$failures++}
 }
}
# Same source rollback must not delete a pre-existing rule that it did not create.
$script:receiptExists=$true;$script:ruleExists=$true;$script:ruleFails=$false
$public=@([pscustomobject]@{Config=(FakeConfig 'ok' 0)});$private=@([pscustomobject]@{Config=(FakeConfig 'ok' 1)})
$null=Invoke-Expression ($loop.Groups['code'].Value+"`n"+$tail.Groups['code'].Value)
if(!$script:ruleExists -or $script:receiptExists){$failures++;Write-Output 'pre-existing rule ownership invariant FAILED'}
if($failures){throw "Desired actual-source cleanup invariants FAILED: $failures cases"}
Write-Output 'PASS: 14 actual cleanup-body failure/success/partial/no-op cases + pre-existing rule retention; no COM/network/host mutation'
