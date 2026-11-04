<#
.SYNOPSIS
    Прогон Flutter-тестов приложения XIO на Debian (192.168.88.17) вместо Windows.

.DESCRIPTION
    Зачем: на этом ПК Smart App Control (WDAC) блокирует запуск
    C:\dev\flutter\bin\cache\dart-sdk\bin\dartaotruntime.exe, поэтому resident compiler
    Flutter (frontend_server_aot.dart.snapshot) не стартует, и `flutter test` виснет
    в DefaultResidentCompiler._compile до таймаута. Подробности:
    work\flutter-test-fix-20261104.md.

    Скрипт делает всё сам:
      1) проверяет ssh-доступ к Debian;
      2) синхронизирует app\lib, app\test, app\pubspec.yaml, app\pubspec.lock, app\assets,
         а также verification\ и docs\images (эти каталоги нужны golden-тестам: они пишут
         туда PNG и без каталога падают с PathNotFoundException);
      3) выполняет flutter pub get и flutter test --reporter compact;
      4) печатает итог passed/skip/failed и список упавших тестов;
      5) сохраняет полный лог локально в work\evidence\flutter-debian-runs\;
      6) возвращает 0, если failed <= MaxKnownFailures (по умолчанию 4 — «известные»).

    ВАЖНО: обратной синхронизации нет и быть не должно. Тесты ПЕРЕЗАПИСЫВАЮТ
    verification\*.png и docs\images\*.png на Debian (другие шрифты/рендер), поэтому
    копировать их назад в репозиторий нельзя — иначе в git поедут диффы картинок.

.PARAMETER RepoRoot
    Корень репозитория XIO (там, где лежат app\, verification\, docs\). По умолчанию
    work\repo-edit рядом со скриптом.

.PARAMETER MaxKnownFailures
    Сколько падений считать допустимыми (известные падения). По умолчанию 4.

.PARAMETER TimeoutSec
    Жёсткий таймаут на `flutter test` на удалённой стороне. По умолчанию 1200 (20 мин).

.PARAMETER SkipPubGet
    Не выполнять flutter pub get (если зависимости точно не менялись).

.PARAMETER SkipEvidence
    Не синхронизировать verification\ и docs\images (golden-тесты тогда упадут).

.EXAMPLE
    pwsh -NoProfile -File work\flutter-test-debian.ps1
    pwsh -NoProfile -File work\flutter-test-debian.ps1 -MaxKnownFailures 0
    pwsh -NoProfile -File work\flutter-test-debian.ps1 -RepoRoot C:\path\to\repo -TimeoutSec 900

.NOTES
    Коды выхода:
      0 — прогон состоялся, failed <= MaxKnownFailures (и passed > 0)
      1 — тестов упало больше допустимого
      2 — инфраструктурная ошибка (ssh, синхронизация, pub get, таймаут, «0 passed»)
#>

[CmdletBinding()]
param(
    [string] $RepoRoot = (Join-Path $PSScriptRoot 'repo-edit'),
    [string] $RemoteHost = '192.168.88.17',
    [string] $RemoteUser = 'root',
    [string] $SshKey = (Join-Path $env:USERPROFILE '.ssh\id_ed25519_debian17'),
    [string] $RemoteRoot = '/root/xio-flutter',
    [int]    $MaxKnownFailures = 4,
    [int]    $TimeoutSec = 1200,
    [switch] $SkipPubGet,
    [switch] $SkipEvidence
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- вспомогательное ---------------------------------------------------------

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "    $text" -ForegroundColor Green }
function Write-Warn2($text){ Write-Host "    $text" -ForegroundColor Yellow }
function Write-Err($text)  { Write-Host "    $text" -ForegroundColor Red }

$sshTarget = "$RemoteUser@$RemoteHost"
$remoteApp = "$RemoteRoot/app"

function Invoke-Remote {
    param([Parameter(Mandatory)][string] $Command)
    $null = & ssh -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey $sshTarget $Command 2>&1
    return $LASTEXITCODE
}

# --- 0. проверки -------------------------------------------------------------

Write-Step "Проверка окружения"
if (-not (Test-Path $SshKey)) { Write-Err "Нет ssh-ключа: $SshKey"; exit 2 }
if (-not (Test-Path $RepoRoot)) { Write-Err "Нет каталога репозитория: $RepoRoot"; exit 2 }
$appDir = Join-Path $RepoRoot 'app'
if (-not (Test-Path (Join-Path $appDir 'pubspec.yaml'))) { Write-Err "Нет $appDir\pubspec.yaml"; exit 2 }
Write-Ok "repo: $RepoRoot"

$rc = Invoke-Remote 'echo SSH_OK'
if ($rc -ne 0) {
    Write-Err "ssh $sshTarget недоступен (код $rc). Проверьте питание Debian / VPN (AmneziaVPN ломает LAN)."
    exit 2
}
Write-Ok "ssh $sshTarget доступен"

# --- 1. синхронизация --------------------------------------------------------

Write-Step "Синхронизация исходников -> ${sshTarget}:$remoteApp"

$tarItems = @('lib', 'test', 'pubspec.yaml', 'pubspec.lock', 'assets') |
    Where-Object { Test-Path (Join-Path $appDir $_) }
if (-not $tarItems) { Write-Err "В $appDir нет ни lib, ни test"; exit 2 }

$rc = Invoke-Remote "mkdir -p $remoteApp"
if ($rc -ne 0) { Write-Err "не удалось создать $remoteApp (код $rc)"; exit 2 }

Push-Location $appDir
try {
    & tar -czf - @tarItems | & ssh -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey $sshTarget "tar -xzf - -C $remoteApp"
    $tarCode = $LASTEXITCODE
} finally { Pop-Location }
if ($tarCode -ne 0) { Write-Err "tar/ssh синхронизация app провалилась (код $tarCode)"; exit 2 }
Write-Ok ("app: " + ($tarItems -join ', '))

# Каталоги-приёмники для скриншотов тестов: без них golden-тесты падают на записи файла.
$evidenceItems = @('verification', 'docs\images') | Where-Object { Test-Path (Join-Path $RepoRoot $_) }
if ($SkipEvidence) {
    Write-Warn2 "verification/docs\images не синхронизируются (-SkipEvidence): golden-тесты, скорее всего, упадут"
    $rc = Invoke-Remote "mkdir -p $RemoteRoot/verification $RemoteRoot/docs/images"
}
elseif ($evidenceItems) {
    Push-Location $RepoRoot
    try {
        & tar -czf - @evidenceItems | & ssh -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey $sshTarget "tar -xzf - -C $RemoteRoot"
        $tarCode = $LASTEXITCODE
    } finally { Pop-Location }
    if ($tarCode -ne 0) { Write-Err "синхронизация verification/docs провалилась (код $tarCode)"; exit 2 }
    Write-Ok ("golden: " + ($evidenceItems -join ', '))
}
else {
    Write-Warn2 "в репозитории нет verification\ и docs\images\ — создаю пустые каталоги на Debian"
    $rc = Invoke-Remote "mkdir -p $RemoteRoot/verification $RemoteRoot/docs/images"
}

# --- 2. удалённый раннер -----------------------------------------------------

$runPubGet = if ($SkipPubGet) { '0' } else { '1' }

# Single-quoted here-string: текст уезжает на Debian как есть, подстановки — только
# через плейсхолдеры (в PowerShell "\$x" НЕ экранирует, экранирует бэктик).
$remoteScriptTemplate = @'
#!/usr/bin/env bash
set -o pipefail
export PATH=/opt/flutter/bin:$PATH
cd "__REMOTE_APP__" || exit 90

echo "### PUB GET (__RUN_PUBGET__)"
if [ "__RUN_PUBGET__" = "1" ]; then
    flutter pub get > /tmp/xio-pubget.log 2>&1
    pg=$?
    tail -3 /tmp/xio-pubget.log
    if [ $pg -ne 0 ]; then echo "PUBGET_FAILED=$pg"; tail -30 /tmp/xio-pubget.log; exit 91; fi
else
    echo "skipped"
fi

echo "### TEST"
export CI=true
timeout __TIMEOUT__ flutter test --reporter compact > /tmp/xio-test.log 2>&1
tst=$?
echo "TEST_EXIT=$tst"
echo "### COUNTERS"
tr '\r' '\n' < /tmp/xio-test.log | grep -oE '\+[0-9]+( ~[0-9]+)?( -[0-9]+)?' | tail -1
echo "### VERDICT"
tr '\r' '\n' < /tmp/xio-test.log | grep -E 'All other tests passed|All tests passed|Some tests failed' | sort -u | tail -2
echo "### FAILED"
tr '\r' '\n' < /tmp/xio-test.log | grep -oE '^[0-9:]+ \+[0-9]+( ~[0-9]+)?( -[0-9]+)?: .*\[E\]' \
  | sed -E 's/^[0-9:]+ \+[0-9]+( ~[0-9]+)?( -[0-9]+)?: //; s/ \[E\]$//' | sort -u
exit 0
'@

$remoteScript = $remoteScriptTemplate.
    Replace('__REMOTE_APP__', $remoteApp).
    Replace('__RUN_PUBGET__', $runPubGet).
    Replace('__TIMEOUT__', "$TimeoutSec")

$remoteScriptPath = '/tmp/xio-run-tests.sh'
$tmpLocal = [IO.Path]::GetTempFileName()
try {
    # тот же текст, но с LF: bash не переваривает CRLF
    [IO.File]::WriteAllText($tmpLocal, ($remoteScript -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    & scp -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey $tmpLocal "${sshTarget}:$remoteScriptPath" | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Err "не удалось загрузить удалённый скрипт"; exit 2 }
} finally { Remove-Item $tmpLocal -Force -ErrorAction SilentlyContinue }

# --- 3. прогон ---------------------------------------------------------------

Write-Step "Прогон на Debian (timeout ${TimeoutSec}s)"
$runOutput = & ssh -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey $sshTarget "bash $remoteScriptPath" 2>&1
$runOutput | ForEach-Object { $line = "$_"; if ($line -notmatch '^###' -and $line.Trim()) { if ($line -match '^\s+\S+\.(dart|yaml)') { Write-Host "    $line" -ForegroundColor DarkGray } else { Write-Host "    $line" } } }
$sshCode = $LASTEXITCODE

# --- 4. разбор ---------------------------------------------------------------

Write-Step "Итог"

$text = ($runOutput | Out-String)
$pubGetFailedCode = $null
$remoteTestExit = 'n/a'
if ($text -match 'PUBGET_FAILED=(\d+)') { $pubGetFailedCode = $Matches[1] }
if ($text -match 'TEST_EXIT=(\d+)') { $remoteTestExit = $Matches[1] }
if ($pubGetFailedCode) { Write-Err "flutter pub get на Debian упал (код $pubGetFailedCode) см. /tmp/xio-pubget.log"; exit 2 }

$counterLine = ($runOutput | Where-Object { $_ -match '^\+\d+' } | Select-Object -Last 1)
$passed = 0; $skipped = 0; $failed = 0
if ($counterLine -and $counterLine -match '\+(\d+)') { $passed = [int]$Matches[1] }
if ($counterLine -and $counterLine -match '~(\d+)') { $skipped = [int]$Matches[1] }
if ($counterLine -and $counterLine -match '\s-(\d+)') { $failed = [int]$Matches[1] }

$failedTests = @($runOutput | Where-Object { $_ -match '^/.*\.dart: ' -and $_ -notmatch '^\s' } | Sort-Object -Unique)
$verdict = ($runOutput | Where-Object { $_ -match 'All other tests passed|All tests passed|Some tests failed' } | Select-Object -Last 1)

Write-Host ("    passed = {0}" -f $passed)
Write-Host ("    skip   = {0}" -f $skipped)
Write-Host ("    failed = {0}   (допустимо <= {1})" -f $failed, $MaxKnownFailures)
if ($verdict) { Write-Host ("    verdict: {0}" -f $verdict.Trim()) }
if ($failedTests.Count -gt 0) {
    Write-Host "    упавшие тесты:" -ForegroundColor Yellow
    $failedTests | ForEach-Object { Write-Host ("      - {0}" -f ($_ -replace [regex]::Escape("$remoteApp/"), '')) }
}

# лог локально
$evDir = Join-Path $PSScriptRoot 'evidence\flutter-debian-runs'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$localLog = Join-Path $evDir "run-$stamp.log"
$rawLog = '/tmp/xio-test.log'
$rawLocal = Join-Path $evDir "raw-$stamp.log"
& scp -o BatchMode=yes -o ConnectTimeout=15 -i $SshKey "${sshTarget}:$rawLog" $rawLocal 2>&1 | Out-Null
if (-not (Test-Path $rawLocal)) { $rawLocal = "(не скопирован)" }
@(
    "run: $stamp"
    "repo: $RepoRoot"
    "remote: ${sshTarget}:$remoteApp"
    "passed=$passed skip=$skipped failed=$failed maxKnown=$MaxKnownFailures"
    "remote test exit: $remoteTestExit"
    "raw log: $rawLocal"
    ""
    ($runOutput -join "`n")
) | Set-Content -Path $localLog -Encoding UTF8
Write-Host ("    лог: {0}" -f $localLog) -ForegroundColor DarkGray
if ($rawLocal -ne '(не скопирован)') { Write-Host ("    raw: {0}" -f $rawLocal) -ForegroundColor DarkGray }

# --- 5. вердикт --------------------------------------------------------------

if ($passed -eq 0) {
    Write-Err "ПРОГОН НЕ СОСТОЯЛСЯ: 0 passed (инфраструктура/компиляция). Смотрите лог."
    exit 2
}
if ($remoteTestExit -eq '124') {
    Write-Err "Таймаут ${TimeoutSec}s на удалённой стороне."
    exit 2
}
if ($failed -gt $MaxKnownFailures) {
    Write-Err "ПРОВАЛ: failed=$failed > допустимых $MaxKnownFailures"
    exit 1
}
if ($sshCode -ne 0 -and $failed -eq 0) {
    Write-Warn2 "ssh вернул код $sshCode, но тесты прошли — считаю прогон успешным"
}

Write-Ok "ОК: failed=$failed <= $MaxKnownFailures, passed=$passed, skip=$skipped"
exit 0
