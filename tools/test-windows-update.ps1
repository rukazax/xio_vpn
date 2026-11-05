# SPDX-License-Identifier: GPL-3.0-only
# Export windowsUpdateScript via app/test/update_windows_test.dart first.
# Root must equal XIO_WINDOWS_TEST_ROOT used for that export and is test-only.
param(
  [Parameter(Mandatory)][string]$TemplatePath,
  [Parameter(Mandatory)][string]$Root,
  [string]$ResultsPath
)
$ErrorActionPreference = 'Stop'
$template = [IO.File]::ReadAllText($TemplatePath)
$expectedRoot = [IO.Path]::GetFullPath($Root)
$portableRoot = $expectedRoot.Replace('\', '/')
$literalRoot = "'" + ($portableRoot + '/target').Replace("'", "''") + "'"
if (!$template.Contains('$target = ' + $literalRoot)) { throw 'Exported script does not target the supplied fixture root' }
$marker = Join-Path $Root '.xio-update-test-fixture'
$results = [Collections.Generic.List[object]]::new()

function Assert-That([bool]$Condition, [string]$Message) {
  if (!$Condition) { throw $Message }
}
function Reset-Fixture {
  if (Test-Path -LiteralPath $root) {
    $item = Get-Item -LiteralPath $root -Force
    Assert-That (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Refuse fixture reparse point'
    Assert-That ((Convert-Path -LiteralPath $root) -eq $expectedRoot) 'Refuse unexpected fixture path'
    Assert-That ((Test-Path -LiteralPath $marker -PathType Leaf) -and [IO.File]::ReadAllText($marker) -eq 'XIO test fixture') 'Refuse non-fixture directory'
    Remove-Item -LiteralPath $root -Recurse -Force
  }
  [IO.Directory]::CreateDirectory("$root/target/data") | Out-Null
  [IO.File]::WriteAllText($marker, 'XIO test fixture')
  [IO.Directory]::CreateDirectory("$root/stage/XIO/data") | Out-Null
  [IO.File]::WriteAllText("$root/target/XIO.exe", 'OLD')
  [IO.File]::WriteAllText("$root/target/data/app.so", 'OLD AOT')
  [IO.File]::WriteAllText("$root/stage/XIO/XIO.exe", 'NEW')
  [IO.File]::WriteAllText("$root/stage/XIO/flutter_windows.dll", 'ENGINE')
  [IO.File]::WriteAllText("$root/stage/XIO/data/app.so", 'NEW AOT')
  [IO.File]::WriteAllText("$root/release.zip", 'ARCHIVE')
  [IO.File]::WriteAllText("$root/install.ps1", $template, [Text.UTF8Encoding]::new($true))
}

# No applications are started and no real process IDs are stopped/waited for.
# All rename/copy/delete operations of the generated production script remain real.
function Wait-Process { [CmdletBinding()] param([int]$Id) }
function Start-Process {
  [CmdletBinding()]
  param([string]$FilePath, [string]$WorkingDirectory, [switch]$PassThru)
  $content = [IO.File]::ReadAllText($FilePath)
  $script:launches.Add($content)
  if ($content -eq 'NEW') {
    if ($script:scenario -eq 'launch-failure') { throw 'Simulated startup refusal (4551)' }
    if ($script:scenario -eq 'success') { [IO.File]::WriteAllText("$root/installed-5020", '0.24.3') }
    if ($script:scenario -eq 'ack-mismatch') { [IO.File]::WriteAllText("$root/installed-5020", '0.24.2') }
    $script:fakeProcess = [pscustomobject]@{
      Id = 424242
      HasExited = ($script:scenario -notin @('success', 'startup-timeout', 'stop-failure'))
    }
    $script:fakeProcess | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
    $script:fakeProcess | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Milliseconds) return $true }
    if ($PassThru) { return $script:fakeProcess }
  }
}
function Stop-Process {
  [CmdletBinding()] param([int]$Id, [switch]$Force)
  $script:stopCalls++
  Assert-That ($Id -eq 424242) 'Unexpected stop target'
  if ($script:scenario -eq 'stop-failure') { throw 'Simulated replacement process stop failure' }
  $script:fakeProcess.HasExited = $true
}
function Copy-Item {
  [CmdletBinding()]
  param([string]$LiteralPath, [string]$Destination, [switch]$Recurse, [switch]$Force)
  if ($script:scenario -eq 'copy-failure') { throw 'Simulated copy failure' }
  Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
}

function Remove-Item {
  [CmdletBinding()]
  param([string]$LiteralPath, [switch]$Recurse, [switch]$Force)
  if ($script:scenario -eq 'ack-remove-failure' -and
      [IO.Path]::GetFullPath($LiteralPath) -eq [IO.Path]::GetFullPath("$root/installed-5020")) {
    $denied = [UnauthorizedAccessException]::new('Simulated stale acknowledgement removal failure')
    $record = [Management.Automation.ErrorRecord]::new($denied, 'StaleAckDenied', [Management.Automation.ErrorCategory]::PermissionDenied, $LiteralPath)
    $PSCmdlet.WriteError($record)
    return
  }
  Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
}

foreach ($case in @('launch-failure', 'unconfirmed-exit', 'startup-timeout', 'ack-mismatch', 'stale-ack', 'ack-remove-failure', 'copy-failure', 'backup-conflict', 'stop-failure', 'success')) {
  Reset-Fixture
  $script:scenario = $case
  $script:launches = [Collections.Generic.List[string]]::new()
  $script:stopCalls = 0
  if ($case -in @('stale-ack', 'ack-remove-failure')) { [IO.File]::WriteAllText("$root/installed-5020", '0.24.3') }
  if ($case -eq 'backup-conflict') {
    [IO.Directory]::CreateDirectory("$root/target.xio-backup-5020") | Out-Null
    [IO.File]::WriteAllText("$root/target.xio-backup-5020/unrelated", 'KEEP')
  }
  . "$root/install.ps1"
  if ($case -eq 'success') {
    Assert-That ([IO.File]::ReadAllText("$root/target/XIO.exe") -eq 'NEW') 'Success did not keep new app'
    Assert-That (!(Test-Path -LiteralPath "$root/target.xio-backup-5020")) 'Success backup not cleaned'
    Assert-That (!(Test-Path -LiteralPath "$root/release.zip")) 'Success archive not cleaned'
    Assert-That (!(Test-Path -LiteralPath "$root/stage")) 'Success stage not cleaned'
    Assert-That (!(Test-Path -LiteralPath "$root/install-error.txt")) 'Success reported an error'
    Assert-That (($script:launches -join ',') -eq 'NEW') 'Success unexpectedly relaunched old app'
  } elseif ($case -eq 'stop-failure') {
    Assert-That ([IO.File]::ReadAllText("$root/target.xio-backup-5020/XIO.exe") -eq 'OLD') 'Failed rollback lost original backup'
    Assert-That ([IO.File]::ReadAllText("$root/target/XIO.exe") -eq 'NEW') 'Failed stop deleted running replacement'
    Assert-That ([IO.File]::ReadAllText("$root/install-error.txt").Contains('Rollback failed')) 'Missing rollback failure evidence'
  } else {
    Assert-That ([IO.File]::ReadAllText("$root/target/XIO.exe") -eq 'OLD') "$case did not restore old app"
    Assert-That ([IO.File]::ReadAllText("$root/target/data/app.so") -eq 'OLD AOT') "$case did not preserve old AOT"
    Assert-That (Test-Path -LiteralPath "$root/install-error.txt") "$case did not record failure"
    Assert-That (Test-Path -LiteralPath "$root/release.zip") "$case removed retry archive"
    if ($case -eq 'backup-conflict') {
      Assert-That ([IO.File]::ReadAllText("$root/target.xio-backup-5020/unrelated") -eq 'KEEP') 'Existing backup overwritten'
      Assert-That ($script:launches.Count -eq 0) 'Existing backup allowed a replacement launch'
    } elseif ($case -eq 'ack-remove-failure') {
      Assert-That ($script:launches.Count -eq 0) 'Stale ACK removal failure allowed a replacement launch'
      Assert-That (!(Test-Path -LiteralPath "$root/target.xio-backup-5020")) 'Stale ACK removal failure moved the original app'
    } else {
      Assert-That (!(Test-Path -LiteralPath "$root/target.xio-backup-5020")) "$case did not restore backup path"
      Assert-That ($script:launches.Contains('OLD')) "$case did not relaunch original app"
    }
    if ($case -eq 'startup-timeout') { Assert-That ($script:stopCalls -eq 1) 'Timeout did not stop replacement' }
  }
  $results.Add([pscustomobject]@{Scenario=$case; Passed=$true; Launches=($script:launches -join ','); StopCalls=$script:stopCalls})
}
if ($ResultsPath) { $results | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath $ResultsPath }
$results | Format-Table -AutoSize
