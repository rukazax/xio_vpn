#Requires -Version 7.0
<#
.SYNOPSIS
    Публикация выпуска XIO в GitHub Releases: релиз, ассеты, SHA256SUMS, проверка.

.DESCRIPTION
    Создаёт (или обновляет) релиз по тегу, загружает файлы из -AssetsDir через
    curl.exe с повторами и экспоненциальной паузой, генерирует и прикладывает
    SHA256SUMS-<ver>.txt, затем заново читает релиз и сверяет для каждого ассета
    состояние uploaded, размер и digest (sha256). Скрипт падает, если хоть один
    ассет не совпал.

    Токен берётся из -Token, затем из $env:GITHUB_TOKEN / $env:GH_TOKEN, затем из
    файла -TokenFile (по умолчанию %USERPROFILE%\.dsh\secrets\github.json, поля
    token или access_token). Токен НЕ печатается и не передаётся в argv curl:
    заголовок авторизации читается curl'ом из временного файла, который удаляется
    в finally.

    Почему один запрос на ассет, а не HTTP-чанки: GitHub Releases не поддерживает
    докачку ассета по Content-Range (см. «Upload a release asset» в REST API —
    тело запроса целиком). Надёжность даёт не диапазон, а потоковая передача
    curl (файл не читается в память), повторные попытки на уровне ассета и
    сверка digest после загрузки. Хеш считается потоком, блоками по -ChunkSizeMB.

.PARAMETER Tag
    Тег релиза, например v0.24.1.

.PARAMETER NotesFile
    Файл с текстом заметок (markdown). Если не задан, берётся
    docs/release-notes-<ver>.md, иначе короткая заглушка.

.PARAMETER AssetsDir
    Каталог с ассетами (его пишет tools/release/build-all.ps1).

.PARAMETER Repo
    Репозиторий owner/name. По умолчанию rukazax/xio_vpn.

.PARAMETER DryRun
    Не обращаться к сети: показать тег, заметки, список ассетов и суммы.

.PARAMETER Name
    Имя релиза. По умолчанию — тег без префикса v («0.24.1»).

.PARAMETER Prerelease / Draft
    Помечают релиз. При обновлении существующего релиза применяются, только если
    switch передан явно.

.PARAMETER TargetCommitish
    Ветка/коммит для нового тега. По умолчанию GitHub берёт ветку по умолчанию.

.PARAMETER Version
    Версия для имени суммы. По умолчанию выводится из тега (v0.24.1 -> 0.24.1).

.PARAMETER SumsFile
    Готовый файл сумм. По умолчанию генерируется в -AssetsDir как
    SHA256SUMS-<ver>.txt.

.PARAMETER OnExisting
    Что делать, если ассет с таким именем уже есть: Replace (по умолчанию; удалить
    и загрузить заново, если digest отличается), Skip (оставить как есть) или
    Fail (остановиться).

.PARAMETER MaxAttempts
    Число попыток загрузки одного ассета. По умолчанию 5.

.PARAMETER RetryDelaySec
    Базовая пауза между попытками (дальше удваивается). По умолчанию 5.

.PARAMETER ChunkSizeMB
    Размер блока при потоковом чтении файла для sha256. По умолчанию 4 МиБ.

.EXAMPLE
    pwsh -NoProfile -File tools/release/publish.ps1 -Tag v0.24.1 -NotesFile docs/release-notes-0.24.1.md -AssetsDir releases/0.24.1 -DryRun

.EXAMPLE
    pwsh -NoProfile -File tools/release/publish.ps1 -Tag v0.24.1 -NotesFile docs/release-notes-0.24.1.md -AssetsDir releases/0.24.1 -Prerelease

.NOTES
    Коды выхода: 0 — релиз опубликован и все ассеты сверены, 1 — ошибка.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$NotesFile,
    [Parameter(Mandatory)][string]$AssetsDir,
    [string]$Repo = 'rukazax/xio_vpn',
    [switch]$DryRun,
    [string]$Name,
    [switch]$Prerelease,
    [switch]$Draft,
    [string]$TargetCommitish,
    [string]$Version,
    [string]$SumsFile,
    [ValidateSet('Replace', 'Skip', 'Fail')][string]$OnExisting = 'Replace',
    [int]$MaxAttempts = 5,
    [int]$RetryDelaySec = 5,
    [int]$ChunkSizeMB = 4,
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
    <# sha256 файла, прочитанного блоками: память не зависит от размера ассета. #>
    param([Parameter(Mandatory)][string]$Path, [int]$ChunkSizeMB = 4)
    $bufferSize = [Math]::Max(64KB, $ChunkSizeMB * 1MB)
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
    <# Возвращает токен из параметра/окружения/файла. Значение никогда не печатается. #>
    param([string]$Explicit, [string]$File)
    if ($Explicit) { return $Explicit.Trim() }
    foreach ($name in 'GITHUB_TOKEN', 'GH_TOKEN') {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { return $value.Trim() }
    }
    if (-not $File) {
        $File = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.dsh\secrets\github.json' } else { Join-Path $HOME '.dsh/secrets/github.json' }
    }
    if (-not (Test-Path -LiteralPath $File)) {
        throw "Нет токена: задайте -Token, `$env:GITHUB_TOKEN или файл $File"
    }
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
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body,
        [string]$Accept = 'application/vnd.github+json'
    )
    $headers = @{
        Authorization          = "Bearer $script:Token"
        Accept                 = $Accept
        'User-Agent'           = 'xio-release-publish'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    $request = @{
        Method             = $Method
        Uri                = $Uri
        Headers            = $headers
        SkipHttpErrorCheck = $true
        ErrorAction        = 'Stop'
        TimeoutSec         = 120
    }
    if ($null -ne $Body) {
        $request['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $request['ContentType'] = 'application/json; charset=utf-8'
    }
    $response = Invoke-WebRequest @request
    $text = [string]$response.Content
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { } }
    return [pscustomobject]@{ Status = [int]$response.StatusCode; Json = $json; Text = $text }
}

function Get-ReleaseAssets {
    param([Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][long]$ReleaseId)
    $all = New-Object System.Collections.Generic.List[object]
    $page = 1
    while ($true) {
        $uri = "https://api.github.com/repos/$Repo/releases/$ReleaseId/assets?per_page=100&page=$page"
        $response = Invoke-GitHubApi -Uri $uri
        if ($response.Status -ne 200) { throw "Не удалось прочитать список ассетов релиза (HTTP $($response.Status))" }
        $items = @($response.Json)
        foreach ($item in $items) { $all.Add($item) | Out-Null }
        if ($items.Count -lt 100) { break }
        $page++
    }
    return $all.ToArray()
}

function Remove-ReleaseAsset {
    param([Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][long]$AssetId, [Parameter(Mandatory)][string]$AssetName)
    $response = Invoke-GitHubApi -Method DELETE -Uri "https://api.github.com/repos/$Repo/releases/assets/$AssetId"
    if ($response.Status -ne 204) { throw "Не удалось удалить ассет $AssetName (HTTP $($response.Status)): $($response.Text)" }
    Write-Sub "удалён старый ассет: $AssetName"
}

function New-CurlHeaderFile {
    <# Заголовки curl (включая Bearer) в файле: токен не попадает в argv. #>
    param([Parameter(Mandatory)][string]$Directory)
    $path = Join-Path $Directory 'curl-headers.txt'
    $content = "Authorization: Bearer $script:Token`n" +
    "Accept: application/vnd.github+json`n" +
    "User-Agent: xio-release-publish`n"
    [IO.File]::WriteAllText($path, $content, (New-Object Text.UTF8Encoding($false)))
    return $path
}

function Test-TransientCurlCode {
    param([int]$Code)
    return $Code -in 6, 7, 16, 18, 28, 35, 52, 55, 56, 92
}

function Send-AssetUpload {
    <# Загрузка одного ассета: curl.exe, повторные попытки, удаление битого ассета. #>
    param(
        [Parameter(Mandatory)][string]$UploadUrl,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$HeaderFile,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][long]$ReleaseId,
        [int]$MaxAttempts,
        [int]$BaseDelaySec
    )
    $name = Split-Path $Path -Leaf
    $uri = "$UploadUrl?name=$([uri]::EscapeDataString($name))&label="
    $bodyFile = Join-Path (Split-Path $HeaderFile -Parent) 'curl-body.txt'
    $delay = $BaseDelaySec

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if (Test-Path -LiteralPath $bodyFile) { Remove-Item -LiteralPath $bodyFile -Force }
        $curlArgs = @(
            '--silent', '--show-error', '--location',
            '--connect-timeout', '30',
            '--speed-limit', '10240', '--speed-time', '300',
            '--header', "@$HeaderFile",
            '--header', 'Content-Type: application/octet-stream',
            '--retry', '0',
            '--data-binary', "@$Path",
            '--output', $bodyFile,
            '--write-out', '%{http_code}',
            $uri
        )
        $httpText = (& curl.exe @curlArgs) -join ''
        $curlCode = $LASTEXITCODE
        $http = 0
        if ($httpText -match '(\d{3})') { $http = [int]$Matches[1] }
        $body = ''
        if (Test-Path -LiteralPath $bodyFile) { $body = (Get-Content -LiteralPath $bodyFile -Raw -ErrorAction SilentlyContinue) }

        if ($http -eq 201 -and $curlCode -eq 0) {
            Write-Ok "$name загружен (попытка $attempt)"
            return [pscustomobject]@{ Name = $name; Attempts = $attempt; HttpStatus = $http }
        }

        $detail = ''
        if ($body) { $detail = ($body -replace '\s+', ' ').Trim(); if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) } }

        if ($http -eq 401) { throw "GitHub отклонил токен при загрузке $name (HTTP 401). Проверьте scope repo." }
        if ($http -eq 422) {
            # already_exists: удаляем конфликтующий ассет (часто это недокачанный
            # «starter» от прошлой попытки) и пробуем снова.
            Write-Warn "ассет $name уже существует (HTTP 422): удаляю и повторяю"
            $assets = Get-ReleaseAssets -Repo $Repo -ReleaseId $ReleaseId
            $stale = @($assets | Where-Object { $_.name -eq $name })
            foreach ($asset in $stale) { Remove-ReleaseAsset -Repo $Repo -AssetId $asset.id -AssetName $asset.name }
            continue
        }
        if ($http -eq 404) {
            Write-Warn "релиз ещё не виден (HTTP 404), попытка $attempt из $MaxAttempts"
        } elseif ($http -ge 500 -or $http -eq 0 -or (Test-TransientCurlCode -Code $curlCode)) {
            Write-Warn "временная ошибка загрузки $name (curl $curlCode, HTTP $http), попытка $attempt из $MaxAttempts"
        } elseif ($http -ge 400) {
            throw "Загрузка $name отклонена (HTTP $http): $detail"
        }

        if ($attempt -eq $MaxAttempts) {
            throw "Не удалось загрузить $name за $MaxAttempts попыток (curl $curlCode, HTTP $http): $detail"
        }
        Write-Sub "пауза $delay с и повтор"
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min($delay * 2, 60)
    }
    throw "Не удалось загрузить $name"
}

function Get-VersionFromTag {
    param([Parameter(Mandatory)][string]$Tag)
    if ($Tag -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    throw "Из тега '$Tag' не удалось вывести версию: передайте -Version"
}

function Get-AssetFiles {
    <# Файлы, которые пойдут в релиз: всё из каталога, кроме служебного. #>
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$SumsName)
    $excluded = @($SumsName, 'SHA256SUMS', 'SHA256SUMS.txt')
    return @(Get-ChildItem -LiteralPath $Directory -File | Where-Object {
            $_.Name -notlike 'SHA256SUMS-*.txt' -and
            $excluded -notcontains $_.Name -and
            $_.Name -notlike '.publish-*' -and
            $_.Name -notlike '*.log' -and
            $_.Name -notlike '*.tmp'
        } | Sort-Object Name)
}

# --- основная программа ------------------------------------------------------

$script:Token = ''

if (-not $Repo -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "Неверный -Repo '$Repo': нужен owner/name" }
if (-not $Tag) { throw 'Не задан -Tag' }
if (-not (Test-Path -LiteralPath $AssetsDir -PathType Container)) { throw "Нет каталога ассетов: $AssetsDir" }
$AssetsDir = (Resolve-Path -LiteralPath $AssetsDir).Path
if (-not $Version) { $Version = Get-VersionFromTag -Tag $Tag }
$repoRootHint = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $NotesFile) {
    $candidate = Join-Path $repoRootHint "docs/release-notes-$Version.md"
    if (Test-Path -LiteralPath $candidate) { $NotesFile = $candidate }
}
if (-not $NotesFile) {
    Write-Warn "заметки не заданы и docs/release-notes-$Version.md не найден: будет короткий текст"
}
$notes = if ($NotesFile) {
    if (-not (Test-Path -LiteralPath $NotesFile)) { throw "Нет файла заметок: $NotesFile" }
    [IO.File]::ReadAllText($NotesFile)
} else {
    "XIO $Version"
}
$notes = $notes -replace "`r`n", "`n"

$sumsName = "SHA256SUMS-$Version.txt"
if ($SumsFile) {
    if (-not (Test-Path -LiteralPath $SumsFile)) { throw "Нет файла сумм: $SumsFile" }
    $sumsPath = (Resolve-Path -LiteralPath $SumsFile).Path
    $sumsName = Split-Path $sumsPath -Leaf
} else {
    $sumsPath = Join-Path $AssetsDir $sumsName
}

$releaseName = if ($Name) { $Name } else { $Version }
Write-Host "XIO release publish: $Tag" -ForegroundColor White
Write-Sub "репозиторий: $Repo"
Write-Sub "каталог:     $AssetsDir"
Write-Sub "заметки:     $(if ($NotesFile) { $NotesFile } else { '(короткий текст)' })"

# Суммы считаются всегда: они же служат манифестом для verify-release.ps1.
Write-Step 'SHA256SUMS'
$sumLines = New-Object System.Collections.Generic.List[string]
$assets = @(Get-AssetFiles -Directory $AssetsDir -SumsName $sumsName)
if ($assets.Count -eq 0) { throw "В $AssetsDir нет файлов для публикации" }
$records = New-Object System.Collections.Generic.List[object]
foreach ($file in $assets) {
    $sha = Get-Sha256Streamed -Path $file.FullName -ChunkSizeMB $ChunkSizeMB
    $sumLines.Add("$sha  $($file.Name)") | Out-Null
    $records.Add([pscustomobject]@{ Name = $file.Name; Path = $file.FullName; Bytes = $file.Length; Sha256 = $sha }) | Out-Null
    Write-Sub ("{0}  {1}  {2}" -f $sha, $file.Name, (Format-Bytes -Bytes $file.Length))
}
[IO.File]::WriteAllText($sumsPath, (($sumLines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
$records.Add([pscustomobject]@{
        Name   = $sumsName
        Path   = $sumsPath
        Bytes  = (Get-Item -LiteralPath $sumsPath).Length
        Sha256 = Get-Sha256Streamed -Path $sumsPath -ChunkSizeMB $ChunkSizeMB
    }) | Out-Null
Write-Ok "суммы: $sumsPath"

if ($DryRun) {
    Write-Step 'План публикации (DryRun, сеть не используется)'
    Write-Sub "релиз:    $releaseName"
    Write-Sub "тег:      $Tag"
    Write-Sub "предрелиз: $([bool]$Prerelease); черновик: $([bool]$Draft)"
    Write-Sub "заметок:  $(($notes -split "`n").Count) строк, $($notes.Length) символов"
    foreach ($record in ($records | Sort-Object Name)) {
        Write-Sub ("{0,-46} {1,14}  {2}" -f $record.Name, (Format-Bytes -Bytes $record.Bytes), $record.Sha256)
    }
    Write-Sub ''
    Write-Sub 'DryRun: релиз не создавался, ассеты не загружались.'
    exit 0
}

Write-Step 'Токен GitHub'
$tokenFile = $TokenFile
$script:Token = Read-Token -Explicit $Token -File $tokenFile
if (-not $script:Token) { throw 'Пустой токен GitHub' }
Write-Ok 'токен получен (значение не печатается)'

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("xio-publish-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$headerFile = $null

try {
    Write-Step 'Релиз'
    $existing = Invoke-GitHubApi -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag"
    $release = $null
    if ($existing.Status -eq 200) {
        $release = $existing.Json
        Write-Sub "найден существующий релиз id=$($release.id) ($($release.html_url))"
        $patch = @{ name = $releaseName; body = $notes }
        if ($PSBoundParameters.ContainsKey('Prerelease')) { $patch['prerelease'] = [bool]$Prerelease }
        if ($PSBoundParameters.ContainsKey('Draft')) { $patch['draft'] = [bool]$Draft }
        $updated = Invoke-GitHubApi -Method PATCH -Uri "https://api.github.com/repos/$Repo/releases/$($release.id)" -Body $patch
        if ($updated.Status -ne 200) { throw "Не удалось обновить релиз (HTTP $($updated.Status)): $($updated.Text)" }
        $release = $updated.Json
        Write-Ok "релиз обновлён: $($release.html_url)"
    } elseif ($existing.Status -eq 404) {
        $payload = @{
            tag_name = $Tag
            name     = $releaseName
            body     = $notes
            draft    = [bool]$Draft
            prerelease = [bool]$Prerelease
            generate_release_notes = $false
        }
        if ($TargetCommitish) { $payload['target_commitish'] = $TargetCommitish }
        $created = Invoke-GitHubApi -Method POST -Uri "https://api.github.com/repos/$Repo/releases" -Body $payload
        if ($created.Status -ne 201) { throw "Не удалось создать релиз (HTTP $($created.Status)): $($created.Text)" }
        $release = $created.Json
        Write-Ok "релиз создан: $($release.html_url)"
    } else {
        throw "Не удалось прочитать релиз $Tag (HTTP $($existing.Status)): $($existing.Text)"
    }

    if (-not $release.id) { throw 'GitHub не вернул id релиза' }
    $releaseId = [long]$release.id
    $uploadUrl = ([string]$release.upload_url) -replace '\{[^}]*\}$', ''
    if (-not $uploadUrl) { throw 'GitHub не вернул upload_url' }

    Write-Step 'Загрузка ассетов (curl.exe, повторы)'
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        throw 'curl.exe не найден в PATH: он нужен для потоковой загрузки больших файлов (Windows 10+ содержит его в System32)'
    }
    $headerFile = New-CurlHeaderFile -Directory $tempDir
    $remote = Get-ReleaseAssets -Repo $Repo -ReleaseId $releaseId
    $remoteByName = @{}
    foreach ($asset in $remote) { $remoteByName[[string]$asset.name] = $asset }

    foreach ($record in ($records | Sort-Object Name)) {
        Write-Sub "$($record.Name) ($(Format-Bytes -Bytes $record.Bytes))"
        $current = $remoteByName[$record.Name]
        if ($current) {
            $digest = [string]$current.digest
            $sameSize = [long]$current.size -eq $record.Bytes
            $sameDigest = $digest -eq "sha256:$($record.Sha256)"
            if ($current.state -eq 'uploaded' -and $sameSize -and $sameDigest) {
                Write-Ok 'уже загружен с тем же digest — пропуск'
                continue
            }
            switch ($OnExisting) {
                'Skip' {
                    Write-Warn "ассет уже есть (state=$($current.state), размер $($current.size)) — оставлен как есть (-OnExisting Skip)"
                    continue
                }
                'Fail' {
                    throw "Ассет $($record.Name) уже есть в релизе и отличается от локального (-OnExisting Fail)"
                }
                default {
                    Remove-ReleaseAsset -Repo $Repo -AssetId $current.id -AssetName $current.name
                    $remoteByName.Remove($record.Name)
                }
            }
        }
        Send-AssetUpload -UploadUrl $uploadUrl -Path $record.Path -HeaderFile $headerFile -Repo $Repo -ReleaseId $releaseId -MaxAttempts $MaxAttempts -BaseDelaySec $RetryDelaySec | Out-Null
    }

    Write-Step 'Проверка загруженного'
    $uploaded = Get-ReleaseAssets -Repo $Repo -ReleaseId $releaseId
    $uploadedByName = @{}
    foreach ($asset in $uploaded) { $uploadedByName[[string]$asset.name] = $asset }

    $failures = New-Object System.Collections.Generic.List[string]
    Write-Host ("    {0,-46} {1,14} {2,10}  {3}" -f 'АССЕТ', 'РАЗМЕР', 'СОСТОЯНИЕ', 'DIGEST')
    foreach ($record in ($records | Sort-Object Name)) {
        $remoteAsset = $uploadedByName[$record.Name]
        $status = 'OK'
        if (-not $remoteAsset) {
            $status = 'FAIL (нет)'
        } elseif ([string]$remoteAsset.state -ne 'uploaded') {
            $status = "FAIL (state=$($remoteAsset.state))"
        } elseif ([long]$remoteAsset.size -ne $record.Bytes) {
            $status = "FAIL (размер $($remoteAsset.size) <> $($record.Bytes))"
        } elseif (-not [string]$remoteAsset.digest) {
            # digest — единственный способ сверить содержимое без скачивания;
            # без него публикация считается неподтверждённой (проверяйте verify-release.ps1).
            $status = 'FAIL (GitHub не вернул digest)'
        } elseif ([string]$remoteAsset.digest -ne "sha256:$($record.Sha256)") {
            $status = 'FAIL (digest)'
        }
        if ($status -ne 'OK') { $failures.Add("$($record.Name): $status") | Out-Null }
        $shownSize = if ($remoteAsset) { Format-Bytes -Bytes ([long]$remoteAsset.size) } else { '-' }
        $shownDigest = if ($remoteAsset -and $remoteAsset.digest) { ([string]$remoteAsset.digest -replace '^sha256:', '').Substring(0, 16) + '…' } else { '(нет)' }
        $marker = if ($status -eq 'OK') { 'OK  ' } else { 'FAIL' }
        Write-Host ("    {0} {1,-46} {2,14} {3,10}  {4}" -f $marker, $record.Name, $shownSize, $status, $shownDigest) -ForegroundColor $(if ($status -eq 'OK') { 'Green' } else { 'Red' })
    }

    $known = @{}
    foreach ($record in $records) { $known[$record.Name] = $true }
    $extraNames = @($uploaded | Where-Object { -not $known.ContainsKey([string]$_.name) } | ForEach-Object { $_.name })
    if ($extraNames.Count -gt 0) { Write-Warn ("в релизе есть лишние ассеты: " + ($extraNames -join ', ')) }

    Write-Step 'Итог'
    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Err $failure }
        throw "Проверка не прошла: $($failures.Count) ассет(ов) не совпали"
    }
    $totalBytes = [long](($records | Measure-Object -Property Bytes -Sum).Sum)
    Write-Ok ("опубликовано ассетов: {0}, {1}" -f $records.Count, (Format-Bytes -Bytes $totalBytes))
    Write-Sub "релиз: $($release.html_url)"
    exit 0
} catch {
    Write-Host ''
    Write-Err $_.Exception.Message
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
    exit 1
} finally {
    if ($headerFile -and (Test-Path -LiteralPath $headerFile)) { Remove-Item -LiteralPath $headerFile -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}
