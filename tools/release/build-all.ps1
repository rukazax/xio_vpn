#Requires -Version 7.0
<#
.SYNOPSIS
    Единый конвейер сборки релиза XIO: Android Full/Client, Windows Full, Ubuntu и сервер.

.DESCRIPTION
    Последовательно собирает артефакты одного выпуска в один каталог и пишет
    manifest.json с составом и SHA-256 каждого файла. Любой шаг можно исключить
    параметром -Skip; повторный запуск не ломает каталоги (артефакты перезаписываются).

    Шаги выполняются в таком порядке (порядок важен: Full-сборки встраивают
    серверный архив из app/assets):

      server          python tools/package-server.py
                      -> xio-server-<ver>.tar.gz, xio-server-release-<ver>.json
                      и подкладывает архив + зеркала в app/assets; после сборки
                      исходные файлы app/assets возвращаются на место
      android-full    flutter build apk --release --split-per-abi + universal
                      -> XIO-Full-<ver>-android-<abi>.apk
      android-client  python client/build.py --stage <temp> --output-dir <temp>
                      -> XIO-Client-<ver>-android-<abi>.apk (4 ABI: arm64, armv7, x86_64, universal)
      windows         flutter build windows + go helper + wintun
                      -> XIO-Full-<ver>-windows-x64.zip (плоский ZIP, как в выпусках 0.24.x)
      linux           XIO-<ver>-ubuntu-amd64.deb + XIO-<ver>-ubuntu-x64.tar.gz
                      (собирается на Linux либо импортируется из -LinuxArtifacts)

.PARAMETER Version
    Версия выпуска без префикса v, например 0.24.1. Должна совпадать с version
    в app/pubspec.yaml (до знака '+'); иначе сборка падает до первого шага.

.PARAMETER OutDir
    Каталог артефактов. По умолчанию <repo>/releases/<Version> (каталог в .gitignore).

.PARAMETER Skip
    Шаги, которые не нужно выполнять: server, android-full, android-client,
    windows, linux. Например: -Skip linux,windows.

.PARAMETER AndroidOnly
    То же, что -Skip windows,linux.

.PARAMETER DryRun
    Ничего не собирать и не писать: проверить входные данные и напечатать план.

.PARAMETER RepoRoot
    Корень репозитория XIO. По умолчанию — каталог на два уровня выше этого скрипта.

.PARAMETER AndroidAbis
    Набор ABI для Android Full: arm64-v8a, armeabi-v7a, x86_64, universal.
    По умолчанию arm64-v8a,armeabi-v7a,universal.

.PARAMETER ClientStage
    Каталог стейджинга для client/build.py. По умолчанию <OutDir>/.stage/client.

.PARAMETER SignApks
    После сборки подписать APK через tools/release/sign-apk.ps1 (нужны -Keystore
    либо переменная окружения XIO_KEYSTORE и пароли).

.PARAMETER Keystore / KeyAlias / StorePassword / KeyPassword / BuildTools
    Передаются в sign-apk.ps1 как есть. Пароли в вывод не попадают.

.PARAMETER Analyze
    Дополнительно прогнать flutter analyze перед сборками (по умолчанию нет).

.PARAMETER LinuxArtifacts
    Каталог с уже собранными на Linux файлами XIO-<ver>-ubuntu-amd64.deb и
    XIO-<ver>-ubuntu-x64.tar.gz (например releases/ на Debian). Если задан,
    шаг linux копирует их, а не собирает.

.PARAMETER KeepAppAssets
    Не возвращать исходные app/assets после сборки (по умолчанию возвращаются).

.EXAMPLE
    pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -DryRun

.EXAMPLE
    pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -Skip linux

.EXAMPLE
    pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -AndroidOnly -SignApks

.NOTES
    Коды выхода: 0 — успех, 1 — ошибка сборки или проверки.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?$')][string]$Version,
    [string]$OutDir,
    [string[]]$Skip = @(),
    [switch]$AndroidOnly,
    [switch]$DryRun,
    [string]$RepoRoot,
    [string]$AndroidAbis = 'arm64-v8a,armeabi-v7a,universal',
    [string]$ClientStage,
    [switch]$SignApks,
    [string]$Keystore,
    [string]$KeyAlias,
    [string]$StorePassword,
    [string]$KeyPassword,
    [string]$BuildTools,
    [switch]$Analyze,
    [string]$LinuxArtifacts,
    [switch]$KeepAppAssets
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

# --- вывод -------------------------------------------------------------------

function Write-Step { param([string]$Text) Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Sub { param([string]$Text) Write-Host "    $Text" }
function Write-Ok { param([string]$Text) Write-Host "    OK  $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host "    !   $Text" -ForegroundColor Yellow }
function Write-Err { param([string]$Text) Write-Host "    X   $Text" -ForegroundColor Red }

function Format-Bytes {
    param([long]$Bytes)
    $units = 'B', 'KiB', 'MiB', 'GiB'
    $value = [double]$Bytes
    $index = 0
    while ($value -ge 1024 -and $index -lt $units.Count - 1) { $value /= 1024; $index++ }
    if ($index -eq 0) { return ('{0:N0} Б' -f $Bytes) }
    return ('{0:N1} {1} ({2:N0} Б)' -f $value, $units[$index], $Bytes)
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Format-CommandLine {
    param([string]$Exe, [string[]]$Arguments = @())
    $parts = @($Exe) + @($Arguments | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        })
    return ($parts -join ' ')
}

# --- запуск внешних программ -------------------------------------------------

function Invoke-Native {
    <# Запускает программу, транслируя вывод в консоль; возвращает код выхода. #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkDir
    )
    if ($WorkDir) { Push-Location -LiteralPath $WorkDir }
    try {
        & $Exe @Arguments 2>&1 | Out-Host
        return $LASTEXITCODE
    } finally {
        if ($WorkDir) { Pop-Location }
    }
}

function Invoke-NativeCapture {
    <# Запускает программу и возвращает код выхода + объединённый вывод. #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkDir
    )
    if ($WorkDir) { Push-Location -LiteralPath $WorkDir }
    try {
        $text = & $Exe @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $text }
    } finally {
        if ($WorkDir) { Pop-Location }
    }
}

function Find-Tool {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { return $command.Source }
    }
    return $null
}

function Find-BuildTool {
    <# Ищет apksigner/zipalign в build-tools: параметр -> env -> ANDROID_HOME/build-tools/<новее>. #>
    param([Parameter(Mandatory)][string]$Name)
    $fileNames = @($Name)
    if ($IsWindows) { $fileNames += @("$Name.bat", "$Name.exe") }
    $directories = New-Object System.Collections.Generic.List[string]
    if ($BuildTools) { $directories.Add($BuildTools) | Out-Null }
    if ($env:XIO_ANDROID_BUILD_TOOLS) { $directories.Add($env:XIO_ANDROID_BUILD_TOOLS) | Out-Null }
    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $HOME 'Android/Sdk' }
    $buildToolsRoot = Join-Path $sdk 'build-tools'
    if (Test-Path -LiteralPath $buildToolsRoot) {
        $sorted = @(Get-ChildItem -LiteralPath $buildToolsRoot -Directory -ErrorAction SilentlyContinue | Sort-Object -Property @{
                Expression = {
                    $base = ($_.Name -split '-')[0]
                    try { [version]$base } catch { [version]'0.0.0' }
                }
            })
        for ($i = $sorted.Count - 1; $i -ge 0; $i--) { $directories.Add($sorted[$i].FullName) | Out-Null }
    }
    foreach ($directory in $directories) {
        foreach ($fileName in $fileNames) {
            $candidate = Join-Path $directory $fileName
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    return $null
}

# --- входные данные ----------------------------------------------------------

function Read-PubspecVersion {
    param([Parameter(Mandatory)][string]$Path)
    $match = [regex]::Match((Get-Content -LiteralPath $Path -Raw), '(?m)^version:\s*([^\r\n#]+)')
    if (-not $match.Success) { throw "В $Path нет строки version:" }
    $raw = $match.Groups[1].Value.Trim()
    $base = ($raw -split '\+')[0]
    $build = if ($raw -match '\+(\d+)') { $Matches[1] } else { '' }
    return [pscustomobject]@{ Raw = $raw; Version = $base; Build = $build }
}

function Read-ClientPins {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $buildPy = Join-Path $RepoRoot 'client/build.py'
    $verifyPy = Join-Path $RepoRoot 'client/verify.py'
    if (-not (Test-Path -LiteralPath $buildPy) -or -not (Test-Path -LiteralPath $verifyPy)) { return $null }
    $build = Get-Content -LiteralPath $buildPy -Raw
    $verify = Get-Content -LiteralPath $verifyPy -Raw
    $release = ([regex]::Match($build, "(?m)^RELEASE\s*=\s*'([^']+)'")).Groups[1].Value
    $buildCode = ([regex]::Match($build, "(?m)^VERSION\s*=\s*RELEASE\s*\+\s*'\+(\d+)'")).Groups[1].Value
    $verifyRelease = ([regex]::Match($verify, "(?m)^RELEASE\s*=\s*'([^']+)'")).Groups[1].Value
    $verifyCode = ([regex]::Match($verify, "(?m)^VERSION_CODE\s*=\s*'(\d+)'")).Groups[1].Value
    return [pscustomobject]@{
        BuildVersion  = "$release+$buildCode"
        BuildRelease  = $release
        BuildCode     = $buildCode
        VerifyRelease = $verifyRelease
        VerifyCode    = $verifyCode
    }
}

function Get-AndroidTargetPlatforms {
    param([string[]]$Abis)
    $platforms = New-Object System.Collections.Generic.List[string]
    foreach ($abi in $Abis) {
        switch ($abi) {
            'arm64-v8a' { if (-not $platforms.Contains('android-arm64')) { $platforms.Add('android-arm64') | Out-Null } }
            'armeabi-v7a' { if (-not $platforms.Contains('android-arm')) { $platforms.Add('android-arm') | Out-Null } }
            'x86_64' { if (-not $platforms.Contains('android-x64')) { $platforms.Add('android-x64') | Out-Null } }
        }
    }
    # AppLocker/WDAC блокирует x64-снапшот Flutter: по умолчанию arm + arm64.
    if ($platforms.Count -eq 0) { return 'android-arm,android-arm64' }
    return ($platforms -join ',')
}

# --- каталоги и общая бухгалтерия --------------------------------------------

function Initialize-Directories {
    if ($DryRun) { return }
    # Каталог артефактов не удаляем: он может содержать уже собранный выпуск.
    # Чистим только стейджинг и артефакты этой же версии, чтобы повторный запуск
    # не оставлял в релизе файлы от прошлой сборки.
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null
    foreach ($pattern in "XIO-*-$Version-*.apk", "XIO-*-$Version-*.zip", "XIO-$Version-ubuntu-*",
        "xio-server-$Version.tar.gz", "xio-server-release-$Version.json",
        "SHA256SUMS-$Version.txt", 'manifest.json') {
        Get-ChildItem -LiteralPath $OutDir -Filter $pattern -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

function Add-Artifact {
    <# Регистрирует готовый файл из OutDir как ассет релиза. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Step,
        [string]$SignerSha256 = ''
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Ожидаемый артефакт не создан: $Path" }
    $item = Get-Item -LiteralPath $Path
    $record = [pscustomobject]@{
        Name         = $item.Name
        Step         = $Step
        Path         = $item.FullName
        Bytes        = $item.Length
        Sha256       = Get-Sha256 -Path $item.FullName
        SignerSha256 = $SignerSha256
    }
    Show-Artifact -Record $record
    $script:Assets.Add($record) | Out-Null
    return $record
}

function Show-Artifact {
    param([Parameter(Mandatory)]$Record)
    Write-Ok $Record.Name
    Write-Sub "путь:   $($Record.Path)"
    Write-Sub "размер: $(Format-Bytes -Bytes $Record.Bytes)"
    Write-Sub "sha256: $($Record.Sha256)"
    if ($Record.SignerSha256) { Write-Sub "подпись: apksigner v2, сертификат sha256 $($Record.SignerSha256)" }
}

function New-StepRecord {
    param([string]$Name, [string]$Status, $Outputs = @(), [string]$Note = '')
    return [pscustomobject]@{
        name    = $Name
        status  = $Status
        note    = $Note
        outputs = @($Outputs)
        seconds = 0
    }
}

# --- app/assets: серверный архив внутри Full-сборок -------------------------

$script:AssetsRestore = New-Object System.Collections.Generic.List[object]

function Install-ServerAssets {
    <# Кладёт упакованный серверный архив и зеркала в app/assets, запоминая оригиналы. #>
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [Parameter(Mandatory)][string]$AppAssets,
        [Parameter(Mandatory)][string]$BackupDir
    )
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    $count = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $SourceDir -Force)) {
        $target = Join-Path $AppAssets $item.Name
        $existing = Test-Path -LiteralPath $target
        $backup = $null
        if ($existing) {
            $backup = Join-Path $BackupDir $item.Name
            Copy-Item -LiteralPath $target -Destination $backup -Recurse -Force
        }
        $script:AssetsRestore.Add([pscustomobject]@{ Target = $target; Backup = $backup }) | Out-Null
        Copy-Item -LiteralPath $item.FullName -Destination $target -Recurse -Force
        $count++
    }
    Write-Sub "подложено в app/assets: $count элемент(ов)"
}

function Restore-ServerAssets {
    if ($script:AssetsRestore.Count -eq 0) { return }
    if ($KeepAppAssets) {
        Write-Warn 'app/assets оставлен с серверным архивом (-KeepAppAssets)'
        return
    }
    $entries = @($script:AssetsRestore.ToArray())
    for ($i = $entries.Count - 1; $i -ge 0; $i--) {
        $entry = $entries[$i]
        if (Test-Path -LiteralPath $entry.Target) { Remove-Item -LiteralPath $entry.Target -Recurse -Force }
        if ($entry.Backup -and (Test-Path -LiteralPath $entry.Backup)) {
            Copy-Item -LiteralPath $entry.Backup -Destination $entry.Target -Recurse -Force
        }
    }
    Write-Sub 'app/assets возвращён к исходному состоянию'
    $script:AssetsRestore.Clear()
}

# --- предполётные проверки ---------------------------------------------------

function Assert-ReleaseInputs {
    Write-Step 'Предполётные проверки'

    $appPubspec = Join-Path $RepoRoot 'app/pubspec.yaml'
    if (-not (Test-Path -LiteralPath $appPubspec)) { throw "Не найден репозиторий XIO: $RepoRoot (нет app/pubspec.yaml)" }
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'client/build.py'))) { throw "Не найден $RepoRoot/client/build.py — это не корень репозитория XIO" }
    Write-Ok "репозиторий: $RepoRoot"

    $pubspec = Read-PubspecVersion -Path $appPubspec
    if ($pubspec.Version -ne $Version) {
        throw (("app/pubspec.yaml содержит version: {0}, а запрошен -Version {1}. " +
                "Сначала поднимите версию в app/pubspec.yaml (и в CHANGELOG.md), затем повторите сборку.") -f $pubspec.Raw, $Version)
    }
    Write-Ok "версия совпадает с app/pubspec.yaml: $($pubspec.Raw)"

    $abis = @($AndroidAbis.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($abis.Count -eq 0) { throw 'Параметр -AndroidAbis пуст' }
    $allowed = 'arm64-v8a', 'armeabi-v7a', 'x86_64', 'universal'
    $unknown = @($abis | Where-Object { $allowed -notcontains $_ })
    if ($unknown.Count -gt 0) { throw "Неизвестные ABI в -AndroidAbis: $($unknown -join ', '). Допустимо: $($allowed -join ', ')" }
    if (@($abis | Select-Object -Unique).Count -ne $abis.Count) { throw 'В -AndroidAbis есть повторы' }

    $script:Tools.Flutter = Find-Tool 'flutter.bat', 'flutter'
    $script:Tools.Python = Find-Tool 'python', 'python3'
    $script:Tools.Go = Find-Tool 'go'
    $script:Tools.Curl = Find-Tool 'curl.exe', 'curl'
    $script:Tools.ApkSigner = Find-BuildTool -Name 'apksigner'
    $script:Tools.Zipalign = Find-BuildTool -Name 'zipalign'

    $needsFlutter = @('android-full', 'android-client', 'windows', 'linux') | Where-Object { -not $Skipped.Contains($_) }
    $needsGo = @('windows', 'linux') | Where-Object { -not $Skipped.Contains($_) }

    if (-not $script:Tools.Flutter -and $needsFlutter) { throw 'Не найден flutter (PATH). Установите Flutter 3.x и повторите запуск.' }
    if (-not $script:Tools.Python) { throw 'Не найден python (PATH): он нужен для tools/package-server.py и client/build.py.' }
    if (-not $script:Tools.Go -and $needsGo) { throw 'Не найден go (PATH): он нужен для xio-tunnel (Windows/Linux).' }
    if ($script:Tools.Flutter) { Write-Ok "flutter: $($script:Tools.Flutter)" }
    Write-Ok "python: $($script:Tools.Python)"
    if ($script:Tools.Go) { Write-Ok "go: $($script:Tools.Go)" }
    if ($script:Tools.ApkSigner) { Write-Ok "apksigner: $($script:Tools.ApkSigner)" } else { Write-Warn 'apksigner не найден: подпись APK не будет проверена (задайте -BuildTools)' }
    if ($script:Tools.Zipalign) { Write-Ok "zipalign: $($script:Tools.Zipalign)" }

    # Версии инструментов — в манифест, чтобы выпуск был воспроизводим.
    if ($script:Tools.Flutter) {
        $res = Invoke-NativeCapture -Exe $script:Tools.Flutter -Arguments @('--version', '--machine')
        if ($res.Code -eq 0) {
            try {
                $info = ($res.Output.Trim() | ConvertFrom-Json)
                $script:Versions.Flutter = [string]$info.frameworkVersion
                $script:Versions.Dart = [string]$info.dartSdkVersion
            } catch { Write-Warn 'не удалось разобрать flutter --version --machine' }
        }
    }
    if ($script:Tools.Go) {
        $res = Invoke-NativeCapture -Exe $script:Tools.Go -Arguments @('version')
        if ($res.Code -eq 0) { $script:Versions.Go = ($res.Output.Trim() -replace '^go version\s+', '') }
    }
    $pyVersion = Invoke-NativeCapture -Exe $script:Tools.Python -Arguments @('--version')
    if ($pyVersion.Code -eq 0) { $script:Versions.Python = $pyVersion.Output.Trim() }

    if (-not $Skipped.Contains('server')) {
        Write-Sub 'python tools/package-server.py --check (закреплённые входные данные)'
        $check = Invoke-NativeCapture -Exe $script:Tools.Python -Arguments @('tools/package-server.py', '--check') -WorkDir $RepoRoot
        if ($check.Code -ne 0) {
            $checkMessage = ("tools/package-server.py --check не прошёл:`n" + $check.Output.Trim() + "`n" +
                'Соберите/восстановите закреплённые vendor-бинарники (docs/ru/build.md), затем повторите.')
            if ($DryRun) {
                Write-Warn 'серверный пакет сейчас не соберётся (DryRun продолжает показывать план):'
                Write-Sub $check.Output.Trim()
            } else {
                throw $checkMessage
            }
        } else {
            Write-Ok 'серверный пакет: входные данные на месте'
        }
    }

    if (-not $Skipped.Contains('android-client')) {
        $pins = Read-ClientPins -RepoRoot $RepoRoot
        if (-not $pins) { throw 'Нет client/build.py или client/verify.py — нечего собирать в шаге android-client' }
        $expected = "$Version+$($pubspec.Build)"
        if ($pins.BuildVersion -ne $expected -or $pins.VerifyRelease -ne $Version -or $pins.VerifyCode -ne $pubspec.Build) {
            $pinFix = ("Клиент нельзя собрать: пины не совпадают с приложением.`n" +
                "  app/pubspec.yaml : $($pubspec.Raw)`n" +
                "  client/build.py  : $($pins.BuildVersion)`n" +
                "  client/verify.py : $($pins.VerifyRelease)+$($pins.VerifyCode)`n" +
                "Поднимите RELEASE/VERSION в client/build.py и RELEASE/VERSION_CODE в client/verify.py`n" +
                "до $Version/+$($pubspec.Build) — это отдельные файлы, tools/release их не меняет.`n" +
                "Либо исключите шаг: -Skip android-client.")
            if ($DryRun) {
                Write-Warn 'шаг android-client сейчас не соберётся (DryRun продолжает показывать план):'
                Write-Sub $pinFix
            } else {
                throw $pinFix
            }
        } else {
            Write-Ok "пины клиента совпадают: $($pins.BuildVersion)"
        }
    }

    if ($Skipped.Contains('server') -and -not $Skipped.Contains('android-full')) {
        if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'app/assets/xio-server.tar.gz'))) {
            throw 'Шаг server пропущен, а app/assets/xio-server.tar.gz отсутствует: Full-сборка не сможет встроить серверный архив'
        }
        Write-Warn 'шаг server пропущен: Full-сборки встроят уже лежащий в app/assets архив (проверьте его версию)'
    }

    if (-not $Skipped.Contains('linux')) {
        $hasLocalLinux = (-not $IsWindows) -and [bool](Find-Tool 'dpkg-deb')
        if (-not $LinuxArtifacts -and -not $hasLocalLinux) {
            throw ("Ubuntu .deb/.tar.gz собираются только на Linux. Варианты:`n" +
                "  1) собрать на Debian: sh tools/build-linux.sh, затем передать -LinuxArtifacts <каталог releases>;`n" +
                "  2) запустить этот скрипт на Linux;`n" +
                "  3) исключить шаг: -Skip linux.")
        }
    }

    if ($SignApks -and -not $script:Tools.ApkSigner) { throw 'Задан -SignApks, но apksigner не найден (задайте -BuildTools)' }
    if ($SignApks -and -not ($Keystore -or $env:XIO_KEYSTORE)) { throw 'Задан -SignApks, но не задан keystore: -Keystore <путь> или $env:XIO_KEYSTORE' }

    $script:Pubspec = $pubspec
    Write-Ok "каталог артефактов: $OutDir"
}

# --- шаги --------------------------------------------------------------------

function Invoke-ServerStep {
    Write-Step 'server — серверный архив (tools/package-server.py)'
    $stageDir = Join-Path $Stage 'server'
    $archiveOut = Join-Path $OutDir "xio-server-$Version.tar.gz"
    $manifestOut = Join-Path $OutDir "xio-server-release-$Version.json"

    if ($DryRun) {
        Write-Sub (Format-CommandLine $script:Tools.Python @('tools/package-server.py', '--output-dir', $stageDir))
        Write-Sub "  -> $archiveOut"
        Write-Sub "  -> $manifestOut"
        Write-Sub '  -> app/assets (архив + зеркала, после сборки вернутся на место)'
        return New-StepRecord -Name 'server' -Status 'dry-run' -Note 'план'
    }

    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    $code = Invoke-Native -Exe $script:Tools.Python -Arguments @('tools/package-server.py', '--output-dir', $stageDir) -WorkDir $RepoRoot
    if ($code -ne 0) { throw "tools/package-server.py завершился с кодом $code (см. вывод выше)" }

    $archive = Join-Path $stageDir 'xio-server.tar.gz'
    if (-not (Test-Path -LiteralPath $archive)) { throw "package-server.py не создал $archive" }
    Copy-Item -LiteralPath $archive -Destination $archiveOut -Force
    Copy-Item -LiteralPath (Join-Path $stageDir 'xio-server-release.json') -Destination $manifestOut -Force

    $recipe = ''
    try { $recipe = [string]((Get-Content -LiteralPath $manifestOut -Raw | ConvertFrom-Json).recipeVersion) } catch { }
    $archiveAsset = Add-Artifact -Path $archiveOut -Step 'server'
    Add-Artifact -Path $manifestOut -Step 'server' | Out-Null

    Install-ServerAssets -SourceDir $stageDir -AppAssets (Join-Path $RepoRoot 'app/assets') -BackupDir (Join-Path $Stage 'assets-backup')

    return New-StepRecord -Name 'server' -Status 'built' -Outputs @($archiveAsset.Name, (Split-Path $manifestOut -Leaf)) -Note "recipeVersion=$recipe"
}

function Invoke-AndroidFullStep {
    Write-Step 'android-full — Android Full (flutter build apk --release)'
    $appDir = Join-Path $RepoRoot 'app'
    $abis = @($AndroidAbis.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $splitAbis = @($abis | Where-Object { $_ -ne 'universal' })
    $splitPlatforms = Get-AndroidTargetPlatforms -Abis $splitAbis
    $allPlatforms = Get-AndroidTargetPlatforms -Abis $abis
    $apkDir = Join-Path $appDir 'build/app/outputs/flutter-apk'

    if ($DryRun) {
        Write-Sub ((Format-CommandLine $script:Tools.Flutter @('pub', 'get')) + '   [в app/]')
        if ($Analyze) { Write-Sub ((Format-CommandLine $script:Tools.Flutter @('analyze')) + '   [в app/]') }
        if ($splitAbis.Count -gt 0) {
            Write-Sub ((Format-CommandLine $script:Tools.Flutter @('build', 'apk', '--release', '--split-per-abi', '--target-platform', $splitPlatforms)) + '   [в app/]')
        }
        Write-Sub ((Format-CommandLine $script:Tools.Flutter @('build', 'apk', '--release', '--target-platform', $allPlatforms)) + '   [в app/]')
        foreach ($abi in $abis) { Write-Sub "  -> $(Join-Path $OutDir "XIO-Full-$Version-android-$abi.apk")" }
        return New-StepRecord -Name 'android-full' -Status 'dry-run' -Note 'план'
    }

    $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('pub', 'get') -WorkDir $appDir
    if ($code -ne 0) { throw "flutter pub get завершился с кодом $code" }
    if ($Analyze) {
        $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('analyze') -WorkDir $appDir
        if ($code -ne 0) { throw "flutter analyze завершился с кодом $code" }
    }

    if ($splitAbis.Count -gt 0) {
        $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('build', 'apk', '--release', '--split-per-abi', '--target-platform', $splitPlatforms) -WorkDir $appDir
        if ($code -ne 0) { throw "flutter build apk --split-per-abi завершился с кодом $code" }
    }
    $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('build', 'apk', '--release', '--target-platform', $allPlatforms) -WorkDir $appDir
    if ($code -ne 0) { throw "flutter build apk (universal) завершился с кодом $code" }

    $sourceNames = @{
        'arm64-v8a'   = 'app-arm64-v8a-release.apk'
        'armeabi-v7a' = 'app-armeabi-v7a-release.apk'
        'x86_64'      = 'app-x86_64-release.apk'
        'universal'   = 'app-release.apk'
    }
    if (-not (Test-Path -LiteralPath $apkDir)) { throw "Flutter не создал каталог с APK: $apkDir" }

    $outputs = New-Object System.Collections.Generic.List[string]
    foreach ($abi in $abis) {
        $source = Join-Path $apkDir $sourceNames[$abi]
        if (-not (Test-Path -LiteralPath $source)) {
            $present = @(Get-ChildItem -LiteralPath $apkDir -Filter '*.apk' -ErrorAction SilentlyContinue | ForEach-Object Name) -join ', '
            throw "Нет $($sourceNames[$abi]) в $apkDir (есть: $present). Проверьте -AndroidAbis и --target-platform."
        }
        $target = Join-Path $OutDir "XIO-Full-$Version-android-$abi.apk"
        Copy-Item -LiteralPath $source -Destination $target -Force
        $signer = Assert-Apk -Path $target
        Add-Artifact -Path $target -Step 'android-full' -SignerSha256 $signer | Out-Null
        $outputs.Add((Split-Path $target -Leaf)) | Out-Null
    }
    return New-StepRecord -Name 'android-full' -Status 'built' -Outputs $outputs.ToArray()
}

function Assert-Apk {
    <# Проверяет zipalign и подпись APK; возвращает sha256 сертификата (или пусто). #>
    param([Parameter(Mandatory)][string]$Path)
    if ($script:Tools.Zipalign) {
        $align = Invoke-NativeCapture -Exe $script:Tools.Zipalign -Arguments @('-c', '-P', '16', '4', $Path)
        if ($align.Code -ne 0) { throw "zipalign -c не прошёл для $(Split-Path $Path -Leaf): $($align.Output.Trim())" }
    }
    if (-not $script:Tools.ApkSigner) { return '' }
    $res = Invoke-NativeCapture -Exe $script:Tools.ApkSigner -Arguments @('verify', '--verbose', '--print-certs', $Path)
    if ($res.Code -ne 0) { throw "apksigner verify не прошёл для $(Split-Path $Path -Leaf):`n$($res.Output.Trim())" }
    if ($res.Output -notmatch 'Verified using v2 scheme \(APK Signature Scheme v2\): true') {
        throw "APK $(Split-Path $Path -Leaf) подписан без схемы v2 (см. apksigner verify --verbose)"
    }
    $cert = ''
    if ($res.Output -match 'Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]+)') { $cert = $Matches[1] }
    return $cert
}

function Invoke-AndroidClientStep {
    Write-Step 'android-client — Android Client (client/build.py)'
    $clientStage = if ($ClientStage) { $ClientStage } else { Join-Path $Stage 'client' }
    $clientOut = Join-Path $Stage 'client-out'
    $argList = @('client/build.py', '--stage', $clientStage, '--output-dir', $clientOut)

    if ($DryRun) {
        Write-Sub (Format-CommandLine $script:Tools.Python $argList)
        Write-Sub "  -> XIO-Client-$Version-android-{arm64-v8a,armeabi-v7a,x86_64,universal}.apk в $OutDir"
        Write-Sub '  (client/build.py сам запускает flutter build apk и client/verify.py)'
        return New-StepRecord -Name 'android-client' -Status 'dry-run' -Note 'план'
    }

    $code = Invoke-Native -Exe $script:Tools.Python -Arguments $argList -WorkDir $RepoRoot
    if ($code -ne 0) { throw "client/build.py завершился с кодом $code (см. вывод выше; частые причины — пины версии и staging)" }

    $produced = @(Get-ChildItem -LiteralPath $clientOut -Filter "XIO-Client-$Version-android-*.apk" -ErrorAction SilentlyContinue)
    if ($produced.Count -eq 0) {
        $present = @(Get-ChildItem -LiteralPath $clientOut -Filter '*.apk' -ErrorAction SilentlyContinue | ForEach-Object Name) -join ', '
        throw "client/build.py не оставил ожидаемых APK в $clientOut (есть: $present)"
    }
    $outputs = New-Object System.Collections.Generic.List[string]
    foreach ($item in $produced) {
        $target = Join-Path $OutDir $item.Name
        Copy-Item -LiteralPath $item.FullName -Destination $target -Force
        $signer = Assert-Apk -Path $target
        Add-Artifact -Path $target -Step 'android-client' -SignerSha256 $signer | Out-Null
        $outputs.Add($item.Name) | Out-Null
    }
    if ($produced.Count -ne 4) { Write-Warn "client/build.py дал $($produced.Count) APK вместо 4 — проверьте client/verify.py" }
    return New-StepRecord -Name 'android-client' -Status 'built' -Outputs $outputs.ToArray()
}

function Invoke-WindowsStep {
    Write-Step 'windows — Windows Full ZIP'
    $appDir = Join-Path $RepoRoot 'app'
    $bundle = Join-Path $appDir 'build/windows/x64/runner/Release'
    $zipPath = Join-Path $OutDir "XIO-Full-$Version-windows-x64.zip"
    $wintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
    $wintunSha = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

    if ($DryRun) {
        Write-Sub ((Format-CommandLine $script:Tools.Flutter @('pub', 'get')) + '   [в app/]')
        Write-Sub ((Format-CommandLine $script:Tools.Flutter @('build', 'windows', '--release')) + '   [в app/]')
        Write-Sub ((Format-CommandLine $script:Tools.Go @('build', '-trimpath', '-ldflags=-s -w', '-o', '<bundle>/libexec/xio-tunnel.exe', './cmd/xio-desktop')) + '   [в protocol/rivet]')
        Write-Sub "  wintun 0.14.1: $wintunUrl (sha256 $wintunSha)"
        Write-Sub "  -> $zipPath"
        return New-StepRecord -Name 'windows' -Status 'dry-run' -Note 'план'
    }

    $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('pub', 'get') -WorkDir $appDir
    if ($code -ne 0) { throw "flutter pub get завершился с кодом $code" }
    if ($Analyze) {
        $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('analyze') -WorkDir $appDir
        if ($code -ne 0) { throw "flutter analyze завершился с кодом $code" }
    }
    # flutter test на этом ПК сломан (WDAC блокирует dartaotruntime): тесты гоняем
    # на Debian через work/flutter-test-debian.ps1, см. tools/release/README.md.
    $code = Invoke-Native -Exe $script:Tools.Flutter -Arguments @('build', 'windows', '--release') -WorkDir $appDir
    if ($code -ne 0) { throw "flutter build windows --release завершился с кодом $code" }
    if (-not (Test-Path -LiteralPath (Join-Path $bundle 'XIO.exe'))) { throw "Windows-сборка не создала $bundle/XIO.exe" }

    $helper = Join-Path $bundle 'libexec'
    New-Item -ItemType Directory -Force -Path $helper | Out-Null
    $code = Invoke-Native -Exe $script:Tools.Go -Arguments @('build', '-trimpath', '-ldflags=-s -w', '-o', (Join-Path $helper 'xio-tunnel.exe'), './cmd/xio-desktop') -WorkDir (Join-Path $RepoRoot 'protocol/rivet')
    if ($code -ne 0) { throw "go build xio-tunnel.exe завершился с кодом $code" }

    $cache = Join-Path $RepoRoot '.build-support/windows-native'
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    $wintunZip = Join-Path $cache 'wintun-0.14.1.zip'
    if (-not (Test-Path -LiteralPath $wintunZip)) {
        Write-Sub "скачивание Wintun 0.14.1 -> $wintunZip"
        try { Invoke-WebRequest -Uri $wintunUrl -OutFile $wintunZip -UseBasicParsing } catch { throw "не удалось скачать Wintun: $($_.Exception.Message)" }
    }
    if ((Get-Sha256 -Path $wintunZip) -ne $wintunSha) { throw "sha256 архива Wintun не совпал с ожидаемым ($wintunSha): $wintunZip" }
    Expand-Archive -LiteralPath $wintunZip -DestinationPath $cache -Force
    Copy-Item -LiteralPath (Join-Path $cache 'wintun/bin/amd64/wintun.dll') -Destination $helper -Force
    Copy-Item -LiteralPath (Join-Path $cache 'wintun/LICENSE.txt') -Destination (Join-Path $helper 'WINTUN-LICENSE.txt') -Force

    foreach ($name in 'LICENSE', 'COPYRIGHT', 'CROSS-PLATFORM-0.19.ru.md') {
        $source = Join-Path $RepoRoot $name
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $bundle -Force }
    }

    # Плоский ZIP: XIO.exe и data/ лежат в корне, как в выпусках 0.24.x.
    $portable = Join-Path $Stage 'windows/XIO'
    if (Test-Path -LiteralPath $portable) { Remove-Item -LiteralPath $portable -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $portable | Out-Null
    Copy-Item -Path (Join-Path $bundle '*') -Destination $portable -Recurse -Force
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -Path (Join-Path $portable '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem } catch { }
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try { $names = @($zip.Entries | ForEach-Object FullName) } finally { $zip.Dispose() }
    foreach ($required in 'XIO.exe', 'libexec/xio-tunnel.exe', 'libexec/wintun.dll', 'libexec/WINTUN-LICENSE.txt', 'data/flutter_assets/AssetManifest.bin') {
        if ($names -notcontains $required) { throw "В ZIP нет обязательного элемента: $required" }
    }
    if (@($names | Where-Object { $_.StartsWith('data/flutter_assets/assets/') }).Count -eq 0) {
        Write-Warn 'в ZIP нет data/flutter_assets/assets/*: проверьте app/assets перед сборкой'
    }

    $asset = Add-Artifact -Path $zipPath -Step 'windows'
    return New-StepRecord -Name 'windows' -Status 'built' -Outputs @($asset.Name) -Note ("{0} элементов в ZIP" -f $names.Count)
}

function Resolve-LinuxArtifact {
    param([Parameter(Mandatory)][string]$Dir, [Parameter(Mandatory)][string]$Name)
    $tail = $Name -replace '^XIO-\d+\.\d+\.\d+-', ''
    foreach ($candidate in @((Join-Path $Dir $Name), (Join-Path $Dir "XIO-Full-$Version-$tail"))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $present = @(Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue | ForEach-Object Name) -join ', '
    throw "В $Dir нет $Name (есть: $present). Ubuntu-пакеты собираются командой sh tools/build-linux.sh на Debian."
}

function Assert-DebAndTar {
    param([Parameter(Mandatory)][string]$Deb, [Parameter(Mandatory)][string]$Tar)
    foreach ($path in $Deb, $Tar) {
        if ((Get-Item -LiteralPath $path).Length -lt 1MB) { throw "Подозрительно маленький файл: $path" }
    }
    $debHead = Read-FileHead -Path $Deb -Count 8
    if ([Text.Encoding]::ASCII.GetString($debHead) -ne "!<arch>`n") { throw "Файл не похож на .deb (нет магии !<arch>): $Deb" }
    $tarHead = Read-FileHead -Path $Tar -Count 2
    if ($tarHead[0] -ne 0x1F -or $tarHead[1] -ne 0x8B) { throw "Файл не похож на .tar.gz (нет gzip-магии): $Tar" }
}

function Read-FileHead {
    param([Parameter(Mandatory)][string]$Path, [int]$Count)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] $Count
        $read = $stream.Read($buffer, 0, $Count)
        if ($read -lt $Count) { throw "Не удалось прочитать $Count байт из $Path" }
        return $buffer
    } finally { $stream.Dispose() }
}

function Invoke-LinuxStep {
    Write-Step 'linux — Ubuntu .deb + .tar.gz'
    $debName = "XIO-$Version-ubuntu-amd64.deb"
    $tarName = "XIO-$Version-ubuntu-x64.tar.gz"
    $debOut = Join-Path $OutDir $debName
    $tarOut = Join-Path $OutDir $tarName

    if ($LinuxArtifacts) {
        if ($DryRun) {
            Write-Sub "импорт из $LinuxArtifacts`: $debName, $tarName -> $OutDir"
            return New-StepRecord -Name 'linux' -Status 'dry-run' -Note 'импорт'
        }
        Copy-Item -LiteralPath (Resolve-LinuxArtifact -Dir $LinuxArtifacts -Name $debName) -Destination $debOut -Force
        Copy-Item -LiteralPath (Resolve-LinuxArtifact -Dir $LinuxArtifacts -Name $tarName) -Destination $tarOut -Force
        Assert-DebAndTar -Deb $debOut -Tar $tarOut
        $assetDeb = Add-Artifact -Path $debOut -Step 'linux'
        $assetTar = Add-Artifact -Path $tarOut -Step 'linux'
        return New-StepRecord -Name 'linux' -Status 'imported' -Outputs @($assetDeb.Name, $assetTar.Name) -Note "источник: $LinuxArtifacts"
    }

    if ($DryRun) {
        Write-Sub 'sh tools/build-linux.sh   [в корне репозитория; нужен Linux + GTK3 + flutter]'
        Write-Sub "  -> <repo>/releases/$debName, <repo>/releases/$tarName -> $OutDir"
        return New-StepRecord -Name 'linux' -Status 'dry-run' -Note 'план'
    }
    if ($IsWindows) { throw 'Внутренняя ошибка: шаг linux на Windows без -LinuxArtifacts (см. предполётные проверки)' }

    $scriptPath = Join-Path $RepoRoot 'tools/build-linux.sh'
    if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Нет $scriptPath" }
    $code = Invoke-Native -Exe 'sh' -Arguments @($scriptPath) -WorkDir $RepoRoot
    if ($code -ne 0) { throw "tools/build-linux.sh завершился с кодом $code" }

    $producedDeb = Join-Path $RepoRoot "releases/$debName"
    $producedTar = Join-Path $RepoRoot "releases/$tarName"
    foreach ($path in $producedDeb, $producedTar) {
        if (-not (Test-Path -LiteralPath $path)) { throw "build-linux.sh не создал $path (проверьте version в app/pubspec.yaml)" }
    }
    Copy-Item -LiteralPath $producedDeb -Destination $debOut -Force
    Copy-Item -LiteralPath $producedTar -Destination $tarOut -Force
    Assert-DebAndTar -Deb $debOut -Tar $tarOut
    $assetDeb = Add-Artifact -Path $debOut -Step 'linux'
    $assetTar = Add-Artifact -Path $tarOut -Step 'linux'
    return New-StepRecord -Name 'linux' -Status 'built' -Outputs @($assetDeb.Name, $assetTar.Name)
}

# --- манифест и суммы --------------------------------------------------------

function Write-SumsFile {
    param([Parameter(Mandatory)][string]$Path)
    $lines = @($script:Assets | Sort-Object Name | ForEach-Object { "$($_.Sha256)  $($_.Name)" })
    [IO.File]::WriteAllText($Path, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
}

function Get-GitInfo {
    $info = [pscustomobject]@{ Branch = ''; Commit = ''; Dirty = $null }
    try {
        $info.Commit = @(& git -C $RepoRoot rev-parse HEAD 2>$null)[0]
        $info.Branch = @(& git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null)[0]
        $info.Dirty = @(& git -C $RepoRoot status --porcelain 2>$null).Count
    } catch { }
    return $info
}

function Write-Manifest {
    param([Parameter(Mandatory)][string]$Path)
    $git = Get-GitInfo
    $manifest = [ordered]@{
        schema   = 1
        version  = $Version
        builtAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        builtOn  = [ordered]@{
            host     = [Environment]::MachineName
            platform = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
            ps       = $PSVersionTable.PSVersion.ToString()
        }
        repo     = [ordered]@{
            branch = $git.Branch
            commit = $git.Commit
            dirty  = $git.Dirty
        }
        versions = [ordered]@{
            app     = $script:Pubspec.Raw
            flutter = $script:Versions.Flutter
            dart    = $script:Versions.Dart
            go      = $script:Versions.Go
            python  = $script:Versions.Python
        }
        steps    = @($script:Steps)
        assets   = @($script:Assets | Sort-Object Name | ForEach-Object {
                [ordered]@{ name = $_.Name; step = $_.Step; bytes = $_.Bytes; sha256 = $_.Sha256; signerSha256 = $_.SignerSha256 }
            })
        limits   = @(
            'Артефакты собраны локально; установка на устройство и живое подключение не проверялись.',
            'Ubuntu-пакеты проверены по магии формата; запуск GUI не проверялся.'
        )
    }
    $json = ($manifest | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($Path, $json + "`n", (New-Object Text.UTF8Encoding($false)))
}

function Show-Summary {
    Write-Step 'Итог'
    if ($DryRun) {
        Write-Sub 'DryRun: ничего не собрано; показан только план.'
        return
    }
    if ($script:Assets.Count -eq 0) { Write-Warn 'ни одного артефакта не собрано (все шаги пропущены?)' }
    $total = [long]($script:Assets | Measure-Object -Property Bytes -Sum).Sum
    Write-Host ("    {0} файл(ов), {1}" -f $script:Assets.Count, (Format-Bytes -Bytes $total))
    foreach ($asset in ($script:Assets | Sort-Object Name)) {
        Write-Host ("    {0,-46} {1,14}  {2}" -f $asset.Name, (Format-Bytes -Bytes $asset.Bytes), $asset.Sha256)
    }
    Write-Sub ''
    Write-Sub "каталог: $OutDir"
    Write-Sub "manifest.json: $(Join-Path $OutDir 'manifest.json')"
    Write-Sub "суммы: $(Join-Path $OutDir "SHA256SUMS-$Version.txt")"
}

# --- основная программа ------------------------------------------------------

$script:Assets = New-Object System.Collections.Generic.List[object]
$script:Steps = New-Object System.Collections.Generic.List[object]
$script:Versions = [pscustomobject]@{ Flutter = ''; Dart = ''; Go = ''; Python = '' }
$script:Pubspec = $null
$script:Tools = [pscustomobject]@{ Flutter = $null; Python = $null; Go = $null; Curl = $null; ApkSigner = $null; Zipalign = $null }

if (-not $RepoRoot) { $RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot "releases/$Version" }
$OutDir = [IO.Path]::GetFullPath($OutDir)
$Stage = Join-Path $OutDir '.stage'

$stepOrder = @('server', 'android-full', 'android-client', 'windows', 'linux')
$skipSet = New-Object System.Collections.Generic.List[string]
foreach ($item in $Skip) {
    foreach ($name in ($item -split ',')) {
        $trimmed = $name.Trim().ToLowerInvariant()
        if ($trimmed -and -not $skipSet.Contains($trimmed)) { $skipSet.Add($trimmed) | Out-Null }
    }
}
if ($AndroidOnly) {
    foreach ($name in 'windows', 'linux') { if (-not $skipSet.Contains($name)) { $skipSet.Add($name) | Out-Null } }
}
$unknownSkip = @($skipSet | Where-Object { $stepOrder -notcontains $_ })
if ($unknownSkip.Count -gt 0) { Write-Err "Неизвестные шаги в -Skip: $($unknownSkip -join ', '). Допустимо: $($stepOrder -join ', ')"; exit 1 }
$Skipped = $skipSet

Write-Host "XIO release build: $Version" -ForegroundColor White
if ($DryRun) { Write-Host 'режим DryRun: без сборки и без записи' -ForegroundColor Yellow }

try {
    Assert-ReleaseInputs
    Initialize-Directories

    foreach ($name in $stepOrder) {
        if ($Skipped.Contains($name)) {
            Write-Host ''
            Write-Warn "шаг $name пропущен (-Skip)"
            $script:Steps.Add((New-StepRecord -Name $name -Status 'skipped' -Note '-Skip')) | Out-Null
            continue
        }
        $started = Get-Date
        $record = switch ($name) {
            'server' { Invoke-ServerStep }
            'android-full' { Invoke-AndroidFullStep }
            'android-client' { Invoke-AndroidClientStep }
            'windows' { Invoke-WindowsStep }
            'linux' { Invoke-LinuxStep }
        }
        if ($record -and $record.PSObject.Properties.Name -contains 'seconds') {
            $record.seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
        }
        if ($record) { $script:Steps.Add($record) | Out-Null }
    }

    if ($SignApks -and -not $DryRun) {
        Write-Step 'подпись APK (tools/release/sign-apk.ps1)'
        $apks = @($script:Assets | Where-Object { $_.Name.EndsWith('.apk') } | ForEach-Object Path)
        if ($apks.Count -eq 0) {
            Write-Warn 'APK не собраны — подписывать нечего'
        } else {
            $pwshExe = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
            if (-not (Test-Path -LiteralPath $pwshExe)) { $pwshExe = 'pwsh' }
            # Пароли передаются дочернему процессу только через окружение: их нет
            # ни в argv (виден в диспетчере задач), ни в выводе.
            $argv = @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'sign-apk.ps1'), '-Apk', ($apks -join ','))
            if ($BuildTools) { $argv += @('-BuildTools', $BuildTools) }
            $envNames = 'XIO_KEYSTORE', 'XIO_KEY_ALIAS', 'XIO_STORE_PASSWORD', 'XIO_KEY_PASSWORD'
            $savedEnv = @{}
            foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
            try {
                if ($Keystore) { $env:XIO_KEYSTORE = $Keystore }
                if ($KeyAlias) { $env:XIO_KEY_ALIAS = $KeyAlias }
                if ($StorePassword) { $env:XIO_STORE_PASSWORD = $StorePassword }
                if ($KeyPassword) { $env:XIO_KEY_PASSWORD = $KeyPassword }
                $code = Invoke-Native -Exe $pwshExe -Arguments $argv
            } finally {
                foreach ($name in $envNames) {
                    if ($null -eq $savedEnv[$name]) { Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue }
                    else { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name]) }
                }
            }
            if ($code -ne 0) { throw "sign-apk.ps1 завершился с кодом $code" }
            # Подпись меняет байты: пересчитываем размеры и суммы.
            foreach ($asset in @($script:Assets)) {
                if (-not $asset.Name.EndsWith('.apk')) { continue }
                $item = Get-Item -LiteralPath $asset.Path
                $asset.Bytes = $item.Length
                $asset.Sha256 = Get-Sha256 -Path $asset.Path
                $asset.SignerSha256 = (Assert-Apk -Path $asset.Path)
                Write-Sub "$($asset.Name) пересчитан после подписи: $($asset.Sha256)"
            }
        }
    }

    if ($DryRun -and $SignApks) { Write-Warn 'после сборки будет вызван tools/release/sign-apk.ps1 (-SignApks)' }

    if (-not $DryRun) {
        Write-Step 'SHA256SUMS и manifest.json'
        $sumsPath = Join-Path $OutDir "SHA256SUMS-$Version.txt"
        Write-SumsFile -Path $sumsPath
        Write-Ok "суммы: $sumsPath"
        $manifestPath = Join-Path $OutDir 'manifest.json'
        Write-Manifest -Path $manifestPath
        Write-Ok "манифест: $manifestPath"
    }

    Show-Summary
    exit 0
} catch {
    Write-Host ''
    Write-Err $_.Exception.Message
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
    exit 1
} finally {
    try { Restore-ServerAssets } catch { Write-Warn "не удалось вернуть app/assets: $($_.Exception.Message)" }
}
