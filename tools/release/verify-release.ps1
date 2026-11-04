#Requires -Version 7.0
<#
.SYNOPSIS
    Проверка опубликованного релиза XIO: скачать ассеты и сверить sha256 с суммами.

.DESCRIPTION
    Берёт релиз по тегу, находит в нём SHA256SUMS-<ver>.txt (или локальный
    -SumsFile), скачивает перечисленные ассеты через curl.exe по одному,
    считает sha256 потоком и печатает таблицу OK/FAIL. Расхождения digest,
    размера, состояния ассета, а также пропавшие и лишние файлы — повод для
    кода выхода 1.

    Токен нужен для приватных форков; для публичного rukazax/xio_vpn достаточно
    -Public (анонимные запросы). Токен берётся из -Token, $env:GITHUB_TOKEN,
    $env:GH_TOKEN или %USERPROFILE%\.dsh\secrets\github.json и не печатается.

.PARAMETER Tag
    Тег релиза, например v0.24.1.

.PARAMETER Repo
    Репозиторий owner/name. По умолчанию rukazax/xio_vpn.

.PARAMETER Assets
    Проверить только эти имена (по умолчанию — всё, что перечислено в суммах).

.PARAMETER SumsFile
    Локальный файл сумм вместо скачивания SHA256SUMS-*.txt из релиза.

.PARAMETER WorkDir
    Куда скачивать. По умолчанию временный каталог; чистится перед запуском.

.PARAMETER KeepDownloads
    Не удалять скачанные файлы после проверки.

.PARAMETER Public
    Не использовать токен (анонимные запросы).

.PARAMETER DryRun
    Ничего не скачивать: показать, что и с чем будет сверяться (нужен -SumsFile).

.EXAMPLE
    pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -Public

.EXAMPLE
    pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -SumsFile releases/0.24.1/SHA256SUMS-0.24.1.txt -Public

.NOTES
    Коды выхода: 0 — всё совпало, 1 — есть FAIL или ошибка.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$Repo = 'rukazax/xio_vpn',
    [string[]]$Assets = @(),
    [string]$SumsFile,
    [string]$WorkDir,
    [switch]$KeepDownloads,
    [switch]$Public,
    [switch]$DryRun,
    [int]$MaxAttempts = 3,
    [string]$Token,
    [string]$TokenFile
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

function Get-Sha256Streamed {
    param([Parameter(Mandatory)][string]$Path)
    $bufferSize = 4MB
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] $bufferSize
        while (($read = $stream.Read($buffer, 0, $bufferSize)) -gt 0) {
            [void]$hasher.TransformBlock($buffer, 0, $read, $null, 0)
        }
        [void]$hasher.TransformFinalBlock($buffer, 0, 0)
        return ([BitConverter]::ToString($hasher.Hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $hasher.Dispose()
    }
}

function Read-Token {
    param([string]$Explicit, [string]$File)
    if ($Explicit) { return $Explicit.Trim() }
    foreach ($name in 'GITHUB_TOKEN', 'GH_TOKEN') {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { return $value.Trim() }
    }
    if (-not $File) {
        $File = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.dsh\secrets\github.json' } else { Join-Path $HOME '.dsh/secrets/github.json' }
    }
    if (-not (Test-Path -LiteralPath $File)) { throw "Нет токена: задайте -Token, `$env:GITHUB_TOKEN или файл $File" }
    $json = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json
    foreach ($field in 'token', 'access_token') {
        if ($json.PSObject.Properties.Name -contains $field) {
            $value = [string]$json.$field
            if ($value) { return $value.Trim() }
        }
    }
    throw "В $File нет поля token или access_token"
}

function Invoke-GitHubApi {
    param([Parameter(Mandatory)][string]$Uri)
    $headers = @{
        Accept                 = 'application/vnd.github+json'
        'User-Agent'           = 'xio-release-verify'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    if ($script:Token) { $headers['Authorization'] = "Bearer $script:Token" }
    $response = Invoke-WebRequest -Method GET -Uri $Uri -Headers $headers -SkipHttpErrorCheck -ErrorAction Stop -TimeoutSec 120
    $text = [string]$response.Content
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { } }
    return [pscustomobject]@{ Status = [int]$response.StatusCode; Json = $json; Text = $text }
}

function Invoke-Download {
    <# Скачивание через curl.exe с повторами; токен — только в файле заголовков. #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [string]$HeaderFile,
        [int]$MaxAttempts = 3
    )
    $delay = 3
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
        $curlArgs = @('--silent', '--show-error', '--location', '--fail-with-body',
            '--connect-timeout', '30', '--retry', '0',
            '--header', 'Accept: application/octet-stream')
        if ($HeaderFile) { $curlArgs += @('--header', "@$HeaderFile") }
        $curlArgs += @('--output', $Destination, $Uri)
        & curl.exe @curlArgs 2>&1 | Out-Host
        $code = $LASTEXITCODE
        if ($code -eq 0 -and (Test-Path -LiteralPath $Destination) -and (Get-Item -LiteralPath $Destination).Length -gt 0) {
            return
        }
        if ($attempt -eq $MaxAttempts) { throw "Не удалось скачать $Uri (curl $code) после $MaxAttempts попыток" }
        Write-Warn "curl вернул $code, повтор через $delay с"
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min($delay * 2, 30)
    }
}

function Read-SumsFile {
    <# Разбирает SHA256SUMS: '<sha256>  <имя>' построчно. #>
    param([Parameter(Mandatory)][string]$Path)
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $lineNo++
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { throw "Строка $lineNo в $Path не похожа на сумму sha256: $trimmed" }
        $map[$Matches[2].Trim()] = $Matches[1].ToLowerInvariant()
    }
    if ($map.Count -eq 0) { throw "В $Path нет ни одной суммы" }
    return $map
}

# --- основная программа ------------------------------------------------------

$script:Token = ''
if (-not $Repo -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "Неверный -Repo '$Repo': нужен owner/name" }
$version = if ($Tag -match '(\d+\.\d+\.\d+)') { $Matches[1] } else { $Tag }
if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) "xio-verify-$Tag" }
$WorkDir = [IO.Path]::GetFullPath($WorkDir)

if (-not $DryRun) {
    if (-not $Public) {
        $script:Token = Read-Token -Explicit $Token -File $TokenFile
        if (-not $script:Token) { Write-Warn 'токен не получен: запросы пойдут анонимно (годится только для публичного репозитория)' }
    }
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { throw 'curl.exe не найден в PATH' }
}

Write-Host "XIO release verify: $Tag" -ForegroundColor White
Write-Sub "репозиторий: $Repo"
Write-Sub "режим:       $(if ($Public) { 'анонимный (-Public)' } else { 'с токеном' })"

$headerFile = $null
$tempDir = $null

try {
    # 1. Где взять ожидаемые суммы.
    if ($DryRun -and -not $SumsFile) {
        throw 'DryRun требует -SumsFile: без сети список ассетов взять негде'
    }

    $expected = $null
    $sumsOrigin = ''
    if ($SumsFile) {
        if (-not (Test-Path -LiteralPath $SumsFile)) { throw "Нет файла сумм: $SumsFile" }
        $expected = Read-SumsFile -Path (Resolve-Path -LiteralPath $SumsFile).Path
        $sumsOrigin = (Resolve-Path -LiteralPath $SumsFile).Path
        Write-Ok "суммы: $sumsOrigin"
    }

    $releaseAssetMap = @{}
    $release = $null

    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
        Get-ChildItem -LiteralPath $WorkDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

        if ($script:Token) {
            $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("xio-verify-hdr-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
            $headerFile = Join-Path $tempDir 'curl-headers.txt'
            $content = "Authorization: Bearer $script:Token`n" + "Accept: application/octet-stream`n" + "User-Agent: xio-release-verify`n"
            [IO.File]::WriteAllText($headerFile, $content, (New-Object Text.UTF8Encoding($false)))
        }

        Write-Step 'Релиз'
        $response = Invoke-GitHubApi -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag"
        if ($response.Status -eq 404) { throw "Релиз $Tag не найден в $Repo (HTTP 404)" }
        if ($response.Status -ne 200) { throw "Не удалось прочитать релиз $Tag (HTTP $($response.Status)): $($response.Text)" }
        $release = $response.Json
        foreach ($asset in @($release.assets)) { $releaseAssetMap[[string]$asset.name] = $asset }
        Write-Ok "релиз: $($release.html_url) — ассетов $($releaseAssetMap.Count)"

        # Суммы: локальный файл или SHA256SUMS-*.txt из релиза.
        if (-not $expected) {
            $sumsAsset = $null
            $preferred = "SHA256SUMS-$version.txt"
            if ($releaseAssetMap.ContainsKey($preferred)) { $sumsAsset = $releaseAssetMap[$preferred] }
            if (-not $sumsAsset) {
                $sumsAsset = @($release.assets | Where-Object { $_.name -like 'SHA256SUMS-*.txt' -or $_.name -eq 'SHA256SUMS' }) | Select-Object -First 1
            }
            if (-not $sumsAsset) { throw "В релизе $Tag нет SHA256SUMS-*.txt: передайте -SumsFile" }
            $sumsLocal = Join-Path $WorkDir ([string]$sumsAsset.name)
            Write-Step "Скачивание сумм: $($sumsAsset.name)"
            $downloadUri = if ($sumsAsset.browser_download_url) { [string]$sumsAsset.browser_download_url } else { "https://api.github.com/repos/$Repo/releases/assets/$($sumsAsset.id)" }
            Invoke-Download -Uri $downloadUri -Destination $sumsLocal -HeaderFile $headerFile -MaxAttempts $MaxAttempts
            $expected = Read-SumsFile -Path $sumsLocal
            $sumsOrigin = "релиз: $($sumsAsset.name)"
            Write-Ok "сумм в файле: $($expected.Count)"
        }
    }

    # 2. Какие ассеты проверяем.
    $names = @()
    if ($Assets.Count -gt 0) {
        $names = @($Assets | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else {
        $names = @($expected.Keys)
    }
    if ($names.Count -eq 0) { throw 'Список ассетов пуст' }

    $unknown = @($names | Where-Object { -not $expected.Contains($_) })
    if ($unknown.Count -gt 0) { throw "В суммах нет: $($unknown -join ', ')" }

    Write-Step 'Сверка'
    Write-Sub "суммы: $sumsOrigin"
    Write-Host ("    {0,-46} {1,14} {2,18} {3,18} {4}" -f 'АССЕТ', 'РАЗМЕР', 'ОЖИДАЕТСЯ', 'ПОЛУЧЕНО', 'ИТОГ')

    $failures = New-Object System.Collections.Generic.List[string]
    $checked = 0
    $totalBytes = [long]0

    foreach ($name in $names) {
        $expectSha = $expected[$name]
        $shortExpected = $expectSha.Substring(0, 16) + '…'

        if ($DryRun) {
            Write-Host ("    {0,-46} {1,14} {2,18} {3,18} {4}" -f $name, '(не скачан)', $shortExpected, '-', 'PLAN')
            continue
        }

        $remoteAsset = $releaseAssetMap[$name]
        $destination = Join-Path $WorkDir $name
        $status = 'OK'
        $actualSha = ''
        $bytes = [long]0

        if (-not $remoteAsset) {
            $status = 'FAIL (нет в релизе)'
        } else {
            try {
                $downloadUri = if ($remoteAsset.browser_download_url) { [string]$remoteAsset.browser_download_url } else { "https://api.github.com/repos/$Repo/releases/assets/$($remoteAsset.id)" }
                Invoke-Download -Uri $downloadUri -Destination $destination -HeaderFile $headerFile -MaxAttempts $MaxAttempts
                $bytes = (Get-Item -LiteralPath $destination).Length
                $actualSha = Get-Sha256Streamed -Path $destination
                if ($remoteAsset.state -and [string]$remoteAsset.state -ne 'uploaded') { $status = "FAIL (state=$($remoteAsset.state))" }
                elseif ([long]$remoteAsset.size -ne $bytes) { $status = 'FAIL (размер не совпал с API)' }
                elseif ($actualSha -ne $expectSha) { $status = 'FAIL (sha256)' }
                elseif ([string]$remoteAsset.digest -and [string]$remoteAsset.digest -ne "sha256:$actualSha") { $status = 'FAIL (digest API)' }
            } catch {
                $status = 'FAIL (скачивание)'
                Write-Err "$name`: $($_.Exception.Message)"
            }
        }

        if ($status -ne 'OK') { $failures.Add("$name — $status") | Out-Null }
        $checked++
        $totalBytes += $bytes
        $shortActual = if ($actualSha) { $actualSha.Substring(0, 16) + '…' } else { '-' }
        $shownBytes = if ($bytes -gt 0) { Format-Bytes -Bytes $bytes } else { '-' }
        $color = if ($status -eq 'OK') { 'Green' } else { 'Red' }
        Write-Host ("    {0,-46} {1,14} {2,18} {3,18} {4}" -f $name, $shownBytes, $shortExpected, $shortActual, $status) -ForegroundColor $color
    }

    if (-not $DryRun) {
        $known = @{}
        foreach ($name in $names) { $known[$name] = $true }
        $extra = @($releaseAssetMap.Keys | Where-Object { -not $known.ContainsKey($_) })
        if ($extra.Count -gt 0 -and $Assets.Count -eq 0) { Write-Warn ("в релизе есть ассеты вне списка: " + ($extra -join ', ')) }
    }

    Write-Step 'Итог'
    if ($DryRun) {
        Write-Sub "DryRun: проверено бы $($names.Count) ассет(ов); ничего не скачано."
        exit 0
    }
    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Err $failure }
        throw "Проверка не прошла: $($failures.Count) из $checked"
    }
    Write-Ok ("все совпало: {0} ассет(ов), {1}" -f $checked, (Format-Bytes -Bytes $totalBytes))
    Write-Sub "релиз: $($release.html_url)"
    exit 0
} catch {
    Write-Host ''
    Write-Err $_.Exception.Message
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
    exit 1
} finally {
    if (-not $KeepDownloads -and (Test-Path -LiteralPath $WorkDir)) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($KeepDownloads) {
        Write-Sub "скачанное оставлено в $WorkDir"
    }
    if ($tempDir -and (Test-Path -LiteralPath $tempDir)) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}
