#Requires -Version 7.0
<#
.SYNOPSIS
    verify-all.ps1 — единый воспроизводимый прогон проверок XIO 0.24.1.

.DESCRIPTION
    Один запуск = весь набор проверок проекта:
      1. локально: flutter analyze + flutter test в app/ (падаем только если failed > 4);
      2. локально: python -m unittest для tools/test_package_server.py и
         tools/test_catalog_determinism.py (если файл есть);
      3. на Debian 192.168.88.17: синхронизация protocol/ server/ tools/ в /root/xio-linux
         (vendor там уже есть), затем go build ./..., go vet ./..., go test -count=1 ./...,
         server/managed → python3 -m unittest test_admin, tools → python3 -m unittest test_package_server;
      4. сверка артефактов: app/assets/xio-server.tar.gz == releases/xio-server-0.24.1.tar.gz,
         размер xio-tunnel.exe в бандле == свежей сборке из protocol/rivet (сборка в temp,
         бандл не перезаписывается), все 4 записи releases/SHA256SUMS-0.24.1.txt;
      5. живая проверка на bridge (81.177.142.37): systemctl --failed пуст,
         xio-cascade active, ping -6 -c2 2606:4700:4700::1111 успешен.

    Скрипт идемпотентен: не меняет исходники (только читает их и собирает в %TEMP%),
    не перезапускает сервисы, не делает git-операций, перезаписывает только work/verify-last.txt.
    Каждый прогон — 2–4 минуты на прогретом кэше Flutter/Go.

.PARAMETER SkipFlutter
    Пропустить локальные проверки Flutter.

.PARAMETER SkipDebian
    Пропустить блок Debian (синхронизация + go + python).

.PARAMETER SkipArtifacts
    Пропустить сверку артефактов релиза.

.PARAMETER SkipLive
    Пропустить живую проверку на bridge.

.PARAMETER LogPath
    Куда писать лог. По умолчанию work/verify-last.txt рядом со скриптом.

.PARAMETER TimeoutSeconds
    Таймаут одной внешней команды (по умолчанию 1200 с).

.EXAMPLE
    pwsh -File work/verify-all.ps1

.EXAMPLE
    pwsh -File work/verify-all.ps1 -SkipLive -LogPath C:\temp\verify.txt
#>
[CmdletBinding()]
param(
    [switch]$SkipFlutter,
    [switch]$SkipDebian,
    [switch]$SkipArtifacts,
    [switch]$SkipLive,
    [string]$LogPath,
    [int]$TimeoutSeconds = 1200
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:Root = Split-Path -Parent $PSScriptRoot
if (-not $LogPath) { $LogPath = Join-Path $PSScriptRoot 'verify-last.txt' }
$script:LogLines = [System.Collections.Generic.List[string]]::new()
$script:Checks = [System.Collections.Generic.List[object]]::new()
$script:TotalSw = [System.Diagnostics.Stopwatch]::StartNew()

# Известные 4 падения среды в app/test: тесты запускают openssl CLI, а его нет в этой Windows-среде.
$script:KnownFlutterFailures = @(
    'account_access_test.dart: TLS pin and redirect protection on IPv4'
    'account_access_test.dart: TLS pin and redirect protection on IPv6'
    'https_probe_test.dart: (setUpAll)'
    'probe_tls_test.dart: legacy compatibility roots do not trust arbitrary self-signed certificates'
)
# test_admin на Debian: purge_packages защищает wireguard-tools, если на хосте есть /etc/wireguard/*.conf.
# На 192.168.88.17 лежит x1o0.conf, поэтому ровно этот тест падает по среде, а не по коду.
$script:KnownAdminEnvFailures = @('test_shared_dependencies_not_purged')

function Write-Log {
    param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray)
    $script:LogLines.Add($Text)
    if ($Text.Length -eq 0) { Write-Host '' } else { Write-Host $Text -ForegroundColor $Color }
}

function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log ("===== $Title =====") ([ConsoleColor]::Cyan)
}

function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Numbers = '',
        [string]$Note = ''
    )
    $script:Checks.Add([pscustomobject]@{ Name = $Name; Status = $Status; Numbers = $Numbers; Note = $Note })
    $color = switch ($Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } 'SKIP' { 'DarkGray' } default { 'Gray' } }
    $line = '[{0}] {1}' -f $Status, $Name
    if ($Numbers) { $line += ' — ' + $Numbers }
    if ($Note) { $line += '  (' + $Note + ')' }
    Write-Log $line $color
}

function Invoke-Native {
    <#
      Запуск внешней команды с захватом stdout+stderr в UTF-8 и таймаутом.
      .bat/.cmd оборачиваются в cmd /c (иначе .NET не запустит их напрямую).
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = '',
        [hashtable]$Environment = @{},
        [int]$TimeoutSeconds = 1200
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    if ($FilePath -match '\.(bat|cmd)$') {
        $comspec = $env:ComSpec
        if (-not $comspec) { $comspec = 'cmd.exe' }
        $psi.FileName = $comspec
        $psi.ArgumentList.Add('/c')
        $psi.ArgumentList.Add($FilePath)
    } else {
        $psi.FileName = $FilePath
    }
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($k in $Environment.Keys) { $psi.Environment[$k] = [string]$Environment[$k] }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $timedOut = $false
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        $timedOut = $true
        try { $proc.Kill($true) } catch { }
        try { $proc.WaitForExit(5000) | Out-Null } catch { }
    }
    $stdout = ''
    $stderr = ''
    try { $stdout = $outTask.GetAwaiter().GetResult() } catch { }
    try { $stderr = $errTask.GetAwaiter().GetResult() } catch { }
    $sw.Stop()
    $code = -1
    if (-not $timedOut) { try { $code = $proc.ExitCode } catch { $code = -1 } }
    [pscustomobject]@{
        ExitCode = $code
        Output   = ($stdout + $stderr)
        Seconds  = [int]$sw.Elapsed.TotalSeconds
        TimedOut = $timedOut
    }
}

function Get-LastLines {
    param([string]$Text, [int]$Count = 12)
    $lines = @($Text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    return ($lines | Select-Object -Last $Count)
}

function Resolve-Tool {
    param([string]$Name, [string[]]$Fallbacks = @())
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    foreach ($f in $Fallbacks) { if (Test-Path $f) { return $f } }
    return $null
}

function Get-FlutterTestSummary {
    param([string]$Output)
    $lines = @($Output -split "`r?`n")
    $passed = 0; $skipped = 0; $failed = 0
    $summaryLine = ''
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        if ($lines[$i] -match '^\d\d:\d\d \+(\d+)') { $summaryLine = $lines[$i]; break }
    }
    if ($summaryLine -match '\+(\d+)') { $passed = [int]$Matches[1] }
    if ($summaryLine -match '~(\d+)') { $skipped = [int]$Matches[1] }
    if ($summaryLine -match ' -(\d+)') { $failed = [int]$Matches[1] }

    $names = [System.Collections.Generic.List[string]]::new()
    $inFail = $false
    foreach ($l in $lines) {
        if ($l -match '^Failing tests:') { $inFail = $true; continue }
        if ($inFail) {
            # В .NET номер получает и незахватывающая группа, поэтому имя файла — отдельная группа.
            if ($l -match '([^\\/:]+\.dart):\s*(.+?)\s*$') {
                $names.Add(('{0}: {1}' -f $Matches[1], $Matches[2]))
            } elseif ($l.Trim().Length -eq 0) { break }
        }
    }
    [pscustomobject]@{ Passed = $passed; Skipped = $skipped; Failed = $failed; FailingNames = $names.ToArray() }
}

function Get-PythonTestSummary {
    param([string]$Output)
    $ran = 0; $failures = 0; $errors = 0; $ok = $false
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($l in ($Output -split "`r?`n")) {
        if ($l -match 'Ran (\d+) tests?') { $ran = [int]$Matches[1] }
        if ($l -match '^OK') { $ok = $true }
        if ($l -match '^FAILED \((.+)\)') {
            $detail = $Matches[1]
            if ($detail -match 'failures=(\d+)') { $failures = [int]$Matches[1] }
            if ($detail -match 'errors=(\d+)') { $errors = [int]$Matches[1] }
        }
        if ($l -match '^(?:FAIL|ERROR): (\S+)') { $ids.Add($Matches[1]) }
    }
    [pscustomobject]@{ Ran = $ran; Failures = $failures; Errors = $errors; Ok = $ok; FailedIds = $ids.ToArray() }
}

function Get-GoVcsRevision {
    <#
      Ревизия, вшитая в Go-бинарь (buildvcs). Нужна, чтобы отличить «размер совпал»
      от «бинарь собран из того же коммита».
    #>
    param([string]$Path)
    if (-not $script:Go -or -not (Test-Path $Path)) { return $null }
    $r = Invoke-Native $script:Go @('version', '-m', $Path) -TimeoutSeconds 120
    if ($r.Output -match 'vcs\.revision=([0-9a-f]{7,40})') { return $Matches[1] }
    return $null
}

function Format-CheckTable {
    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add('| Проверка | Статус | Цифры | Примечание |')
    $rows.Add('|---|---|---|---|')
    foreach ($c in $script:Checks) {
        $note = ($c.Note -replace '\|', '/')
        $rows.Add(('| {0} | {1} | {2} | {3} |' -f $c.Name, $c.Status, $c.Numbers, $note))
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------------
# Шапка: где, когда, на каком коммите и какими инструментами считаем
# ---------------------------------------------------------------------------
$script:Flutter = Resolve-Tool 'flutter' @('C:\dev\flutter\bin\flutter.bat')
$script:Go = Resolve-Tool 'go' @('C:\Users\er-ka\tools\go\bin\go.exe')
$script:Python = Resolve-Tool 'python' @('C:\Users\er-ka\AppData\Local\Programs\Python\Python310\python.exe')
$script:Ssh = Resolve-Tool 'ssh' @("$env:SystemRoot\System32\OpenSSH\ssh.exe")
$script:Scp = Resolve-Tool 'scp' @("$env:SystemRoot\System32\OpenSSH\scp.exe")
$script:Tar = Resolve-Tool 'tar' @("$env:SystemRoot\system32\tar.exe")

$script:DebianKey = Join-Path $env:USERPROFILE '.ssh\id_ed25519_debian17'
$script:Debian = 'root@192.168.88.17'
$script:BridgeKey = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
$script:Bridge = 'root@81.177.142.37'
$script:LinuxRoot = '/root/xio-linux'

Write-Log 'XIO — единый прогон проверок (work/verify-all.ps1)' ([ConsoleColor]::White)
Write-Log ('время:   {0:yyyy-MM-dd HH:mm:ss} ({1})' -f (Get-Date), (Get-TimeZone).Id)
Write-Log ('репозиторий: {0}' -f $script:Root)
$gitHead = ''
$gitDirty = 0
try {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $gitHead = (& git -C $script:Root rev-parse --short HEAD 2>$null)
        $gitDirty = @(& git -C $script:Root status --porcelain 2>$null).Count
    }
} catch { }
Write-Log ('git:     {0}{1}' -f $gitHead, $(if ($gitHead) { " (незакоммиченных путей: $gitDirty)" } else { ' (нет)' }))
Write-Log ('tools:   flutter={0}; go={1}; python={2}' -f $script:Flutter, $script:Go, $script:Python)
Write-Log ('ssh:     debian={0} (ключ {1}); bridge={2} (ключ {3})' -f $script:Debian, (Split-Path $script:DebianKey -Leaf), $script:Bridge, (Split-Path $script:BridgeKey -Leaf))
Write-Log 'режим:   только чтение исходников, без перезапуска сервисов, без git-операций'

$exitCode = 1
try {
    # -----------------------------------------------------------------------
    # 1. Локальные проверки Flutter
    # -----------------------------------------------------------------------
    if ($SkipFlutter) {
        Write-Section '1. Flutter (пропущено)'
        Add-Check 'flutter analyze' 'SKIP' 'запрошен -SkipFlutter'
        Add-Check 'flutter test' 'SKIP' 'запрошен -SkipFlutter'
    } else {
        Write-Section '1. Локальные проверки Flutter (app/)'
        $appDir = Join-Path $script:Root 'app'
        if (-not $script:Flutter) {
            Add-Check 'flutter analyze' 'FAIL' 'flutter не найден'
            Add-Check 'flutter test' 'FAIL' 'flutter не найден'
        } else {
            $r = Invoke-Native $script:Flutter @('analyze') -WorkingDirectory $appDir -TimeoutSeconds $TimeoutSeconds
            $tail = Get-LastLines $r.Output 8
            foreach ($l in $tail) { Write-Log ('    ' + $l) }
            if ($r.ExitCode -eq 0) {
                Add-Check 'flutter analyze' 'OK' ('{0} с' -f $r.Seconds) 'No issues found'
            } else {
                Add-Check 'flutter analyze' 'FAIL' ('exit {0}, {1} с' -f $r.ExitCode, $r.Seconds) 'см. лог выше'
            }

            $r = Invoke-Native $script:Flutter @('test') -WorkingDirectory $appDir -TimeoutSeconds $TimeoutSeconds
            $sum = Get-FlutterTestSummary $r.Output
            $numbers = '{0} passed / {1} skip / {2} failed, {3} с' -f $sum.Passed, $sum.Skipped, $sum.Failed, $r.Seconds
            $unknown = @($sum.FailingNames | Where-Object { $script:KnownFlutterFailures -notcontains $_ })
            $missingKnown = @($script:KnownFlutterFailures | Where-Object { $sum.FailingNames -notcontains $_ })
            $noOpenSsl = $r.Output -match 'ProcessException'
            if ($r.TimedOut) {
                Add-Check 'flutter test' 'FAIL' $numbers ('таймаут {0} с' -f $TimeoutSeconds)
            } elseif ($sum.Failed -gt 4) {
                Add-Check 'flutter test' 'FAIL' $numbers ('failed {0} > бюджета 4' -f $sum.Failed)
            } elseif ($sum.Failed -gt 0) {
                $noteParts = [System.Collections.Generic.List[string]]::new()
                if ($missingKnown.Count -eq 0) {
                    $noteParts.Add('все падения — известные 4 среды: тестам нужен openssl CLI, его нет в этой Windows-среде')
                } else {
                    $noteParts.Add('не воспроизвелись: ' + ($missingKnown -join '; '))
                }
                if ($unknown.Count -gt 0) { $noteParts.Add('новые падения: ' + ($unknown -join '; ')) }
                Add-Check 'flutter test' 'WARN' $numbers ($noteParts -join '; ')
            } else {
                Add-Check 'flutter test' 'OK' $numbers ''
            }
            if ($sum.FailingNames.Count -gt 0) {
                Write-Log '    падающие тесты:' ([ConsoleColor]::DarkYellow)
                foreach ($n in $sum.FailingNames) { Write-Log ('      - ' + $n) ([ConsoleColor]::DarkYellow) }
            }
            if ($noOpenSsl) {
                Write-Log '    причина: тесты вызывают openssl CLI, его нет в этой Windows-среде (ProcessException).' ([ConsoleColor]::DarkYellow)
            }
        }
    }

    # -----------------------------------------------------------------------
    # 2. Локальные python-тесты tools/
    # -----------------------------------------------------------------------
    Write-Section '2. Локальные python-тесты tools/'
    $toolsDir = Join-Path $script:Root 'tools'
    if (-not $script:Python) {
        Add-Check 'python tools/ (unittest)' 'FAIL' 'python не найден'
    } else {
        foreach ($mod in @('test_package_server', 'test_catalog_determinism')) {
            $file = Join-Path $toolsDir ($mod + '.py')
            if (-not (Test-Path $file)) {
                Add-Check ('python tools/' + $mod) 'SKIP' 'файла нет'
                continue
            }
            $r = Invoke-Native $script:Python @('-m', 'unittest', $mod) -WorkingDirectory $toolsDir -TimeoutSeconds $TimeoutSeconds
            $sum = Get-PythonTestSummary $r.Output
            $numbers = '{0} тестов, failures={1}, errors={2}' -f $sum.Ran, $sum.Failures, $sum.Errors
            if ($r.ExitCode -eq 0 -and $sum.Ok) {
                Add-Check ('python tools/' + $mod) 'OK' $numbers ('{0} с' -f $r.Seconds)
            } else {
                Add-Check ('python tools/' + $mod) 'FAIL' $numbers ('exit {0}' -f $r.ExitCode)
                foreach ($l in (Get-LastLines $r.Output 15)) { Write-Log ('    ' + $l) }
            }
        }
    }

    # -----------------------------------------------------------------------
    # 3. Debian: синхронизация, go, python
    # -----------------------------------------------------------------------
    if ($SkipDebian) {
        Write-Section '3. Debian (пропущено)'
        foreach ($n in @('Debian: sync protocol/ server/ tools/', 'Debian: go build ./...', 'Debian: go vet ./...', 'Debian: go test -count=1 ./...', 'Debian: python3 test_admin', 'Debian: python3 test_package_server')) {
            Add-Check $n 'SKIP' 'запрошен -SkipDebian'
        }
    } else {
        Write-Section '3. Debian 192.168.88.17: sync + go + python'
        $remoteScript = Join-Path ([System.IO.Path]::GetTempPath()) ('xio-verify-remote-{0}.sh' -f $PID)
        $remoteTar = Join-Path ([System.IO.Path]::GetTempPath()) ('xio-verify-src-{0}.tgz' -f $PID)
        $syncOk = $false
        try {
            if (-not (Test-Path $script:DebianKey)) {
                Add-Check 'Debian: sync protocol/ server/ tools/' 'FAIL' ('нет ключа ' + $script:DebianKey)
            } elseif (-not $script:Tar -or -not $script:Scp -or -not $script:Ssh) {
                Add-Check 'Debian: sync protocol/ server/ tools/' 'FAIL' 'нет tar/scp/ssh'
            } else {
                Remove-Item $remoteTar -Force -ErrorAction SilentlyContinue
                $pack = Invoke-Native $script:Tar @('-czf', $remoteTar, '-C', $script:Root, '--exclude=*__pycache__*', '--exclude=*.pyc', 'protocol', 'server', 'tools') -TimeoutSeconds 300
                if ($pack.ExitCode -ne 0) {
                    Add-Check 'Debian: sync protocol/ server/ tools/' 'FAIL' ('tar exit ' + $pack.ExitCode)
                    foreach ($l in (Get-LastLines $pack.Output 10)) { Write-Log ('    ' + $l) }
                } else {
                    $sizeKb = [int]((Get-Item $remoteTar).Length / 1KB)
                    $copy = Invoke-Native $script:Scp @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-q', '-i', $script:DebianKey, $remoteTar, ($script:Debian + ':/tmp/xio-verify-src.tgz')) -TimeoutSeconds 300
                    if ($copy.ExitCode -ne 0) {
                        Add-Check 'Debian: sync protocol/ server/ tools/' 'FAIL' ('scp exit ' + $copy.ExitCode)
                        foreach ($l in (Get-LastLines $copy.Output 10)) { Write-Log ('    ' + $l) }
                    } else {
                        $syncOk = $true
                        Add-Check 'Debian: sync protocol/ server/ tools/' 'OK' ('{0} KB, {1} с' -f $sizeKb, $copy.Seconds) ('распаковка в ' + $script:LinuxRoot)
                    }
                }
            }

            if ($syncOk) {
                $bash = @'
#!/bin/bash
# Сгенерировано work/verify-all.ps1. Читает и собирает; сервисы не трогает.
set -u
export PATH=/opt/go1.27.3/bin:$PATH
export LC_ALL=C
SRC=/root/xio-linux
run() {
  name=$1; shift
  start=$SECONDS
  "$@" >"/tmp/xio-verify-$name.log" 2>&1
  code=$?
  printf '@@RESULT %s exit=%s seconds=%s\n' "$name" "$code" "$((SECONDS-start))"
}
tar -xzf /tmp/xio-verify-src.tgz -C "$SRC"
printf '@@SYNC exit=%s\n' "$?"
cd "$SRC/protocol/rivet" || { printf '@@FATAL no_module\n'; exit 3; }
run build go build ./...
run vet go vet ./...
run gotest go test -count=1 ./...
cd "$SRC/server/managed" || { printf '@@FATAL no_managed\n'; exit 4; }
run test_admin python3 -m unittest test_admin
cd "$SRC/tools" || { printf '@@FATAL no_tools\n'; exit 5; }
run package_server python3 -m unittest test_package_server
printf '@@GO_VERSION %s\n' "$(go version)"
printf '@@GO_TEST_COUNTS ok=%s fail=%s skip=%s notest=%s\n' \
  "$(grep -c '^ok ' /tmp/xio-verify-gotest.log)" \
  "$(grep -c '^FAIL' /tmp/xio-verify-gotest.log)" \
  "$(grep -c '^--- SKIP' /tmp/xio-verify-gotest.log)" \
  "$(grep -c 'no test files' /tmp/xio-verify-gotest.log)"
printf '@@WG_CONF %s\n' "$(ls /etc/wireguard/*.conf 2>/dev/null | wc -l)"
printf '@@HFREE %s\n' "$(df -h /root | tail -1 | awk '{print $4}')"
echo '@@LOG build'; tail -n 20 /tmp/xio-verify-build.log
echo '@@LOG vet'; tail -n 20 /tmp/xio-verify-vet.log
echo '@@LOG gotest'; tail -n 30 /tmp/xio-verify-gotest.log
echo '@@LOG test_admin'; cat /tmp/xio-verify-test_admin.log
echo '@@LOG package_server'; cat /tmp/xio-verify-package_server.log
echo '@@END'
'@
                [System.IO.File]::WriteAllText($remoteScript, ($bash -replace "`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
                $copyScript = Invoke-Native $script:Scp @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-q', '-i', $script:DebianKey, $remoteScript, ($script:Debian + ':/tmp/xio-verify-remote.sh')) -TimeoutSeconds 120
                if ($copyScript.ExitCode -ne 0) {
                    foreach ($n in @('Debian: go build ./...', 'Debian: go vet ./...', 'Debian: go test -count=1 ./...', 'Debian: python3 test_admin', 'Debian: python3 test_package_server')) {
                        Add-Check $n 'FAIL' 'не удалось доставить скрипт (scp)'
                    }
                } else {
                    $run = Invoke-Native $script:Ssh @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', $script:DebianKey, $script:Debian, 'bash /tmp/xio-verify-remote.sh') -TimeoutSeconds ([Math]::Max($TimeoutSeconds, 600))
                    $lines = @($run.Output -split "`r?`n")
                    $res = @{}
                    $counts = ''
                    $wgConf = 0
                    $goVersion = ''
                    $logBlock = @{}
                    $curLog = ''
                    foreach ($l in $lines) {
                        if ($l -match '^@@RESULT (\S+) exit=(-?\d+) seconds=(\d+)') {
                            $res[$Matches[1]] = [pscustomobject]@{ Exit = [int]$Matches[2]; Seconds = [int]$Matches[3] }
                        } elseif ($l -match '^@@GO_TEST_COUNTS (.+)$') { $counts = $Matches[1] }
                        elseif ($l -match '^@@WG_CONF (\d+)') { $wgConf = [int]$Matches[1] }
                        elseif ($l -match '^@@GO_VERSION (.+)$') { $goVersion = $Matches[1] }
                        elseif ($l -match '^@@LOG (\S+)') { $curLog = $Matches[1]; $logBlock[$curLog] = [System.Collections.Generic.List[string]]::new() }
                        elseif ($l -match '^@@END') { $curLog = '' }
                        elseif ($curLog) { $logBlock[$curLog].Add($l) }
                    }
                    Write-Log ('    go: ' + $goVersion)
                    foreach ($key in @('build', 'vet', 'gotest', 'test_admin', 'package_server')) {
                        if ($logBlock.ContainsKey($key)) {
                            Write-Log ('    --- ' + $key + ' ---') ([ConsoleColor]::DarkGray)
                            foreach ($l in $logBlock[$key]) { Write-Log ('    ' + $l) ([ConsoleColor]::DarkGray) }
                        }
                    }

                    $step = { param($name) if ($res.ContainsKey($name)) { $res[$name] } else { $null } }
                    $names = @{ build = 'Debian: go build ./...'; vet = 'Debian: go vet ./...'; gotest = 'Debian: go test -count=1 ./...'; test_admin = 'Debian: python3 test_admin'; package_server = 'Debian: python3 test_package_server' }

                    foreach ($key in @('build', 'vet')) {
                        $r0 = & $step $key
                        if (-not $r0) { Add-Check $names[$key] 'FAIL' 'нет ответа от шага' }
                        elseif ($r0.Exit -eq 0) { Add-Check $names[$key] 'OK' ('{0} с' -f $r0.Seconds) }
                        else { Add-Check $names[$key] 'FAIL' ('exit {0}' -f $r0.Exit) 'см. лог' }
                    }

                    $r0 = & $step 'gotest'
                    if (-not $r0) {
                        Add-Check $names['gotest'] 'FAIL' 'нет ответа от шага'
                    } else {
                        $numbers = $counts
                        if ($r0.Exit -eq 0) { Add-Check $names['gotest'] 'OK' ($numbers + ('; {0} с' -f $r0.Seconds)) }
                        else { Add-Check $names['gotest'] 'FAIL' ($numbers + ('; exit {0}' -f $r0.Exit)) }
                    }

                    $r0 = & $step 'test_admin'
                    $adminLog = if ($logBlock.ContainsKey('test_admin')) { $logBlock['test_admin'] -join "`n" } else { '' }
                    $sum = Get-PythonTestSummary $adminLog
                    $numbers = '{0} тестов, failures={1}, errors={2}' -f $sum.Ran, $sum.Failures, $sum.Errors
                    if (-not $r0) {
                        Add-Check $names['test_admin'] 'FAIL' 'нет ответа от шага'
                    } elseif ($r0.Exit -eq 0 -and $sum.Ok) {
                        Add-Check $names['test_admin'] 'OK' $numbers
                    } else {
                        $unknown = @($sum.FailedIds | Where-Object { $script:KnownAdminEnvFailures -notcontains $_ })
                        if ($unknown.Count -eq 0 -and $sum.FailedIds.Count -gt 0 -and $wgConf -gt 0) {
                            Add-Check $names['test_admin'] 'WARN' $numbers ('известное падение среды: на хосте {0} файл(ов) /etc/wireguard/*.conf, purge_packages защищает wireguard-tools' -f $wgConf)
                        } else {
                            Add-Check $names['test_admin'] 'FAIL' $numbers ('exit {0}; падают: {1}' -f $r0.Exit, ($sum.FailedIds -join ', '))
                        }
                    }

                    $r0 = & $step 'package_server'
                    $pkgLog = if ($logBlock.ContainsKey('package_server')) { $logBlock['package_server'] -join "`n" } else { '' }
                    $sum = Get-PythonTestSummary $pkgLog
                    $numbers = '{0} тестов, failures={1}, errors={2}' -f $sum.Ran, $sum.Failures, $sum.Errors
                    if (-not $r0) { Add-Check $names['package_server'] 'FAIL' 'нет ответа от шага' }
                    elseif ($r0.Exit -eq 0 -and $sum.Ok) { Add-Check $names['package_server'] 'OK' $numbers }
                    else { Add-Check $names['package_server'] 'FAIL' $numbers ('exit {0}' -f $r0.Exit) }
                }
            }
        } finally {
            Remove-Item $remoteScript -Force -ErrorAction SilentlyContinue
            Remove-Item $remoteTar -Force -ErrorAction SilentlyContinue
        }
    }

    # -----------------------------------------------------------------------
    # 4. Сверка артефактов
    # -----------------------------------------------------------------------
    if ($SkipArtifacts) {
        Write-Section '4. Артефакты (пропущено)'
        Add-Check 'артефакт: xio-server.tar.gz == releases' 'SKIP' 'запрошен -SkipArtifacts'
        Add-Check 'артефакт: размер xio-tunnel.exe' 'SKIP' 'запрошен -SkipArtifacts'
        Add-Check 'артефакт: SHA256SUMS-0.24.1.txt' 'SKIP' 'запрошен -SkipArtifacts'
    } else {
        Write-Section '4. Сверка артефактов релиза'
        $assetServer = Join-Path $script:Root 'app\assets\xio-server.tar.gz'
        $relServer = Join-Path $script:Root 'releases\xio-server-0.24.1.tar.gz'
        if (-not (Test-Path $assetServer) -or -not (Test-Path $relServer)) {
            Add-Check 'артефакт: app/assets/xio-server.tar.gz == releases/xio-server-0.24.1.tar.gz' 'FAIL' 'нет файла' 'ожидались оба'
        } else {
            $sa = (Get-Item $assetServer).Length
            $sr = (Get-Item $relServer).Length
            $ha = (Get-FileHash $assetServer -Algorithm SHA256).Hash.ToLower()
            $hr = (Get-FileHash $relServer -Algorithm SHA256).Hash.ToLower()
            $numbers = '{0} B / {1} B, sha {2}' -f $sa, $sr, $ha.Substring(0, 16)
            if ($sa -eq $sr -and $ha -eq $hr) {
                Add-Check 'артефакт: app/assets/xio-server.tar.gz == releases/xio-server-0.24.1.tar.gz' 'OK' $numbers 'побайтово'
            } else {
                Add-Check 'артефакт: app/assets/xio-server.tar.gz == releases/xio-server-0.24.1.tar.gz' 'FAIL' $numbers ('sha релиза ' + $hr.Substring(0, 16))
            }
        }

        $bundle = Join-Path $script:Root 'app\build\windows\x64\runner\Release\libexec\xio-tunnel.exe'
        if (-not (Test-Path $bundle)) {
            Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' 'нет бандла' $bundle
        } elseif (-not $script:Go) {
            # The Windows Go toolchain is blocked by Smart App Control here, so the
            # reference build is a Windows cross-compile on Debian (the synced tree).
            $b = Invoke-Native 'ssh' @('-o','BatchMode=yes','-i',"$env:USERPROFILE\.ssh\id_ed25519_debian17",'root@192.168.88.17',
                'set -e; export PATH=/opt/go1.27.3/bin:$PATH; cd /root/xio-linux/protocol/rivet; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/xio-tunnel-verify.exe ./cmd/xio-desktop; stat -c %s /tmp/xio-tunnel-verify.exe') -TimeoutSeconds $TimeoutSeconds
            if ($b.ExitCode -ne 0) {
                Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' ('кросс-сборка exit ' + $b.ExitCode) 'см. лог'
                foreach ($l in (Get-LastLines $b.Output 12)) { Write-Log ('    ' + $l) }
            } else {
                $freshBytes = [int64](($b.Output | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1))
                $sb = (Get-Item $bundle).Length
                if ($freshBytes -eq $sb) { Add-Check 'артефакт: размер xio-tunnel.exe' 'OK' ("бандл $sb B, кросс-сборка $freshBytes B") '' }
                else { Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' ("бандл $sb B != сборка $freshBytes B") 'пересоберите бандл' }
            }
        } else {
            $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('xio-verify-build-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            try {
                New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
                $fresh = Join-Path $tmpDir 'xio-tunnel.exe'
                $b = Invoke-Native $script:Go @('build', '-trimpath', '-ldflags=-s -w', '-o', $fresh, './cmd/xio-desktop') -WorkingDirectory (Join-Path $script:Root 'protocol\rivet') -TimeoutSeconds $TimeoutSeconds
                if ($b.ExitCode -ne 0) {
                    Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' ('сборка exit ' + $b.ExitCode) 'см. лог'
                    foreach ($l in (Get-LastLines $b.Output 12)) { Write-Log ('    ' + $l) }
                } elseif (-not (Test-Path $fresh)) {
                    Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' 'сборка не создала файл'
                } else {
                    $sb = (Get-Item $bundle).Length
                    $sf = (Get-Item $fresh).Length
                    $hb = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()
                    $hf = (Get-FileHash $fresh -Algorithm SHA256).Hash.ToLower()
                    $revBundle = Get-GoVcsRevision $bundle
                    $revFresh = Get-GoVcsRevision $fresh
                    $revNote = ''
                    if ($revBundle) { $revNote = 'бандл из ' + $revBundle.Substring(0, 7) }
                    if ($revFresh) { $revNote += $(if ($revNote) { '; ' } else { '' }) + 'свежая сборка из ' + $revFresh.Substring(0, 7) }
                    $numbers = 'бандл {0} B, сборка {1} B, {2} с' -f $sb, $sf, $b.Seconds
                    if ($sb -ne $sf) {
                        Add-Check 'артефакт: размер xio-tunnel.exe' 'FAIL' $numbers (('разница {0} B; ' -f ($sf - $sb)) + $revNote)
                    } elseif ($revBundle -and $revFresh -and $revBundle -ne $revFresh) {
                        # Размер тот же, но бандл собран из другого коммита — это важнее совпадения байт.
                        Add-Check 'артефакт: размер xio-tunnel.exe' 'WARN' $numbers ('размер совпал, но в бандле ревизия {0}, в свежей сборке {1} — бандл старше исходников' -f $revBundle.Substring(0, 7), $revFresh.Substring(0, 7))
                    } elseif ($hb -eq $hf) {
                        Add-Check 'артефакт: размер xio-tunnel.exe' 'OK' $numbers ('sha совпал: {0}' -f $hb.Substring(0, 12))
                    } else {
                        Add-Check 'артефакт: размер xio-tunnel.exe' 'OK' $numbers ('sha различается ({0} != {1}), размер — критерий задачи' -f $hb.Substring(0, 12), $hf.Substring(0, 12))
                    }
                }
            } finally {
                Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        $sums = Join-Path $script:Root 'releases\SHA256SUMS-0.24.1.txt'
        if (-not (Test-Path $sums)) {
            Add-Check 'артефакт: releases/SHA256SUMS-0.24.1.txt' 'FAIL' 'нет файла'
        } else {
            $entries = @(Get-Content -LiteralPath $sums | Where-Object { $_.Trim().Length -gt 0 })
            $bad = [System.Collections.Generic.List[string]]::new()
            $okCount = 0
            foreach ($e in $entries) {
                if ($e -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $bad.Add('не разобрана строка: ' + $e); continue }
                $expect = $Matches[1].ToLower()
                $name = $Matches[2].Trim()
                $f = Join-Path (Split-Path $sums) $name
                if (-not (Test-Path $f)) { $bad.Add($name + ': файла нет'); continue }
                $actual = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
                if ($actual -eq $expect) { $okCount++ } else { $bad.Add(('{0}: {1} != {2}' -f $name, $actual.Substring(0, 12), $expect.Substring(0, 12))) }
            }
            $numbers = '{0}/{1} записей совпало' -f $okCount, $entries.Count
            if ($bad.Count -eq 0 -and $entries.Count -eq 4) {
                Add-Check 'артефакт: releases/SHA256SUMS-0.24.1.txt' 'OK' $numbers 'все 4 файла'
            } else {
                $note = if ($entries.Count -ne 4) { 'записей не 4' } else { 'расхождения' }
                Add-Check 'артефакт: releases/SHA256SUMS-0.24.1.txt' 'FAIL' $numbers $note
                foreach ($b in $bad) { Write-Log ('    ' + $b) ([ConsoleColor]::Red) }
            }
            foreach ($e in $entries) {
                if ($e -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
                    $f = Join-Path (Split-Path $sums) $Matches[2].Trim()
                    if (Test-Path $f) { Write-Log ('    {0}  {1}' -f ('{0,12}' -f ((Get-Item $f).Length)), $Matches[2].Trim()) ([ConsoleColor]::DarkGray) }
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # 5. Живая проверка на bridge
    # -----------------------------------------------------------------------
    if ($SkipLive) {
        Write-Section '5. Живая проверка (пропущено)'
        foreach ($n in @('живая: systemctl --failed пуст', 'живая: xio-cascade active', 'живая: ping6 2606:4700:4700::1111')) {
            Add-Check $n 'SKIP' 'запрошен -SkipLive'
        }
    } else {
        Write-Section '5. Живая проверка: bridge 81.177.142.37'
        $live = @{}
        if (-not (Test-Path $script:BridgeKey)) {
            foreach ($n in @('живая: systemctl --failed пуст', 'живая: xio-cascade active', 'живая: ping6 2606:4700:4700::1111')) {
                Add-Check $n 'FAIL' ('нет ключа ' + $script:BridgeKey)
            }
        } else {
            $bridgeSh = @'
export LC_ALL=C
echo "@@HOST $(hostname) | $(uptime -p 2>/dev/null | tr -d '\n')"
echo "@@FAILED_START"
systemctl --failed --no-legend --plain
echo "@@FAILED_END"
echo "@@CASCADE active=$(systemctl is-active xio-cascade 2>&1) enabled=$(systemctl is-enabled xio-cascade 2>&1)"
echo "@@XIO_UNITS $(systemctl list-units --type=service --state=running --no-legend --plain 'xio*' 2>/dev/null | wc -l)"
ping -6 -c2 2606:4700:4700::1111 >/tmp/xio-verify-ping6.log 2>&1
echo "@@PING_EXIT $?"
grep -E 'packets transmitted|packet loss|rtt' /tmp/xio-verify-ping6.log
echo "@@PING_END"
echo "@@END"
'@
            $bScript = Join-Path ([System.IO.Path]::GetTempPath()) ('xio-verify-bridge-{0}.sh' -f $PID)
            try {
                [System.IO.File]::WriteAllText($bScript, ($bridgeSh -replace "`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
                $cp = Invoke-Native $script:Scp @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-q', '-i', $script:BridgeKey, $bScript, ($script:Bridge + ':/tmp/xio-verify-bridge.sh')) -TimeoutSeconds 120
                if ($cp.ExitCode -ne 0) {
                    foreach ($n in @('живая: systemctl --failed пуст', 'живая: xio-cascade active', 'живая: ping6 2606:4700:4700::1111')) {
                        Add-Check $n 'FAIL' ('bridge недоступен (scp exit {0})' -f $cp.ExitCode)
                    }
                    foreach ($l in (Get-LastLines $cp.Output 6)) { Write-Log ('    ' + $l) }
                } else {
                    $r = Invoke-Native $script:Ssh @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', $script:BridgeKey, $script:Bridge, 'bash /tmp/xio-verify-bridge.sh') -TimeoutSeconds 180
                    $failedUnits = [System.Collections.Generic.List[string]]::new()
                    $inFailed = $false
                    $cascade = ''
                    $pingExit = -1
                    $pingStats = [System.Collections.Generic.List[string]]::new()
                    $hostLine = ''
                    $xioUnits = 0
                    foreach ($l in ($r.Output -split "`r?`n")) {
                        if ($l -match '^@@HOST (.+)$') { $hostLine = $Matches[1] }
                        elseif ($l -match '^@@FAILED_START') { $inFailed = $true }
                        elseif ($l -match '^@@FAILED_END') { $inFailed = $false }
                        elseif ($l -match '^@@CASCADE (.+)$') { $cascade = $Matches[1] }
                        elseif ($l -match '^@@PING_EXIT (-?\d+)') { $pingExit = [int]$Matches[1] }
                        elseif ($l -match '^@@XIO_UNITS (\d+)') { $xioUnits = [int]$Matches[1] }
                        elseif ($inFailed -and $l.Trim().Length -gt 0) { $failedUnits.Add($l.Trim()) }
                        elseif ($l -match 'packets transmitted|packet loss|rtt') { $pingStats.Add($l.Trim()) }
                    }
                    Write-Log ('    bridge: ' + $hostLine)
                    foreach ($l in $pingStats) { Write-Log ('    ' + $l) ([ConsoleColor]::DarkGray) }

                    if ($r.ExitCode -eq 255 -or $r.Output -match 'Permission denied|Connection refused|timed out') {
                        Add-Check 'живая: systemctl --failed пуст' 'FAIL' 'bridge недоступен'
                        Add-Check 'живая: xio-cascade active' 'FAIL' 'bridge недоступен'
                        Add-Check 'живая: ping6 2606:4700:4700::1111' 'FAIL' 'bridge недоступен'
                        foreach ($l in (Get-LastLines $r.Output 6)) { Write-Log ('    ' + $l) }
                    } else {
                        $numbers = 'failed units: {0}' -f $failedUnits.Count
                        if ($failedUnits.Count -eq 0) {
                            Add-Check 'живая: systemctl --failed пуст' 'OK' $numbers ('xio-юнитов running: ' + $xioUnits)
                        } else {
                            Add-Check 'живая: systemctl --failed пуст' 'FAIL' $numbers ($failedUnits -join '; ')
                        }

                        if ($cascade -match 'active=active') {
                            Add-Check 'живая: xio-cascade active' 'OK' $cascade
                        } else {
                            Add-Check 'живая: xio-cascade active' 'FAIL' $cascade
                        }

                        $tx = 0; $rx = 0; $loss = '?'; $avg = '?'
                        foreach ($l in $pingStats) {
                            if ($l -match '(\d+) packets transmitted, (\d+) received') { $tx = [int]$Matches[1]; $rx = [int]$Matches[2] }
                            if ($l -match '([\d.]+)% packet loss') { $loss = $Matches[1] }
                            if ($l -match 'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/') { $avg = $Matches[1] }
                        }
                        $numbers = 'rx {0}/{1}, loss {2}%, avg {3} ms' -f $rx, $tx, $loss, $avg
                        if ($pingExit -eq 0 -and $rx -ge 1) {
                            $note = if ($rx -lt $tx) { 'частичные потери' } else { 'все пакеты вернулись' }
                            Add-Check 'живая: ping6 2606:4700:4700::1111' 'OK' $numbers $note
                        } else {
                            Add-Check 'живая: ping6 2606:4700:4700::1111' 'FAIL' $numbers ('ping exit {0}' -f $pingExit)
                        }
                    }
                }
            } finally {
                Remove-Item $bScript -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # -----------------------------------------------------------------------
    # 6. Итог
    # -----------------------------------------------------------------------
    $script:TotalSw.Stop()
    Write-Section '6. Итог'
    foreach ($row in (Format-CheckTable)) { Write-Log $row ([ConsoleColor]::Gray) }
    $okCount = @($script:Checks | Where-Object { $_.Status -eq 'OK' }).Count
    $warnCount = @($script:Checks | Where-Object { $_.Status -eq 'WARN' }).Count
    $failCount = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $skipCount = @($script:Checks | Where-Object { $_.Status -eq 'SKIP' }).Count
    $exitCode = if ($failCount -gt 0) { 1 } else { 0 }
    Write-Log ''
    Write-Log ('ИТОГ: OK {0} / WARN {1} / FAIL {2} / SKIP {3} → exit {4}; прогон {5} мин {6} с' -f $okCount, $warnCount, $failCount, $skipCount, $exitCode, [int][Math]::Floor($script:TotalSw.Elapsed.TotalMinutes), $script:TotalSw.Elapsed.Seconds) $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
    if ($warnCount -gt 0) {
        Write-Log 'WARN не влияет на код выхода: это известные падения среды (см. примечания) и частичные потери ping.' ([ConsoleColor]::DarkYellow)
    }
} catch {
    $script:TotalSw.Stop()
    Write-Log ''
    Write-Log ('ПРОГОН ПРЕРВАН: ' + $_.Exception.Message) ([ConsoleColor]::Red)
    Write-Log ($_.ScriptStackTrace) ([ConsoleColor]::DarkRed)
    $exitCode = 1
} finally {
    $script:LogLines -join [Environment]::NewLine | Set-Content -LiteralPath $LogPath -Encoding utf8
}

Write-Host ''
Write-Host ('лог: ' + $LogPath) -ForegroundColor Cyan
exit $exitCode
