#Requires -Version 7.0
<#
.SYNOPSIS
    Подпись APK XIO ключом из параметра или окружения и проверка apksigner verify.

.DESCRIPTION
    Keystore НЕ хардкодится: путь берётся из -Keystore или $env:XIO_KEYSTORE
    (либо из файла свойств через -SigningProperties). Пароли берутся только из
    параметров -StorePassword / -KeyPassword (или переменных окружения
    XIO_STORE_PASSWORD / XIO_KEY_PASSWORD); в вывод они не попадают и в командную
    строку не передаются — apksigner читает их из переменной окружения (env:).

    Перед подписью проверяется выравнивание zipalign -c -P 16 4; если APK не
    выровнен, он выравнивается заново (иначе apksigner 8+ откажется работать).
    После подписи выполняется apksigner verify --verbose --print-certs: нужна
    схема v2, иначе скрипт падает.

.PARAMETER Apk
    Один или несколько APK. Можно списком через запятую: -Apk a.apk,b.apk.

.PARAMETER Keystore
    Путь к .p12/.jks. По умолчанию $env:XIO_KEYSTORE.

.PARAMETER KeyAlias
    Alias ключа. По умолчанию $env:XIO_KEY_ALIAS, иначе x1oDevelopment
    (устаревшее имя ранних сборок; менять нельзя — подпись должна совпасть
    с уже выпущенными APK).

.PARAMETER StorePassword
    Пароль хранилища. По умолчанию $env:XIO_STORE_PASSWORD.

.PARAMETER KeyPassword
    Пароль ключа. По умолчанию $env:XIO_KEY_PASSWORD, иначе равен паролю хранилища.

.PARAMETER SigningProperties
    Необязательный Java properties-файл (.signing/signing.properties) — источник
    storeFile/keyAlias/storePassword/keyPassword для недостающих параметров.
    Значения паролей не печатаются.

.PARAMETER OutDir
    Куда положить подписанные копии. Без параметра APK подписываются на месте.

.PARAMETER BuildTools
    Каталог build-tools с apksigner/zipalign. По умолчанию $env:XIO_ANDROID_BUILD_TOOLS,
    затем $env:ANDROID_HOME/build-tools/<самая новая>.

.PARAMETER VerifyOnly
    Только проверить подпись и выравнивание, ничего не подписывать.

.PARAMETER DryRun
    Показать план и ничего не менять.

.EXAMPLE
    $env:XIO_KEYSTORE = 'C:\keys\x1o-development.p12'
    pwsh -NoProfile -File tools/release/sign-apk.ps1 -Apk "release/XIO-Full-0.24.1-android-arm64-v8a.apk"

.EXAMPLE
    pwsh -NoProfile -File tools/release/sign-apk.ps1 -VerifyOnly -Apk "release/*.apk"

.NOTES
    Коды выхода: 0 — все APK подписаны и проверены, 1 — ошибка.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Apk,
    [string]$Keystore,
    [string]$KeyAlias,
    [string]$StorePassword,
    [string]$KeyPassword,
    [string]$SigningProperties,
    [string]$OutDir,
    [string]$BuildTools,
    [switch]$VerifyOnly,
    [switch]$DryRun
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

function Find-BuildTool {
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

function Invoke-NativeCapture {
    param([Parameter(Mandatory)][string]$Exe, [string[]]$Arguments = @(), [string]$WorkDir)
    if ($WorkDir) { Push-Location -LiteralPath $WorkDir }
    try {
        $text = & $Exe @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $text }
    } finally {
        if ($WorkDir) { Pop-Location }
    }
}

# --- параметры подписи -------------------------------------------------------

function Read-SigningProperties {
    <# Читает Java properties; значения паролей остаются только в памяти. #>
    param([Parameter(Mandatory)][string]$Path)
    $values = @{}
    $baseDir = Split-Path -Parent $Path
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('!')) { continue }
        $index = $trimmed.IndexOf('=')
        if ($index -lt 1) { continue }
        $values[$trimmed.Substring(0, $index).Trim()] = $trimmed.Substring($index + 1).Trim()
    }
    $result = [pscustomobject]@{ Keystore = $null; KeyAlias = $null; StorePassword = $null; KeyPassword = $null }
    if ($values.ContainsKey('storeFile')) {
        $store = $values['storeFile']
        $result.Keystore = if ([IO.Path]::IsPathRooted($store)) { $store } else { Join-Path $baseDir $store }
    }
    if ($values.ContainsKey('keyAlias')) { $result.KeyAlias = $values['keyAlias'] }
    if ($values.ContainsKey('storePassword')) { $result.StorePassword = $values['storePassword'] }
    if ($values.ContainsKey('keyPassword')) { $result.KeyPassword = $values['keyPassword'] }
    return $result
}

function Resolve-SigningSettings {
    $props = $null
    if ($SigningProperties) {
        if (-not (Test-Path -LiteralPath $SigningProperties)) { throw "Нет файла свойств подписи: $SigningProperties" }
        $props = Read-SigningProperties -Path $SigningProperties
    }
    if ($env:XIO_SIGNING_PROPERTIES -and -not $SigningProperties) {
        if (Test-Path -LiteralPath $env:XIO_SIGNING_PROPERTIES) { $props = Read-SigningProperties -Path $env:XIO_SIGNING_PROPERTIES }
    }

    $settings = [pscustomobject]@{ Keystore = $null; KeyAlias = 'x1oDevelopment'; StorePassword = $null; KeyPassword = $null }
    $settings.Keystore = if ($Keystore) { $Keystore } elseif ($env:XIO_KEYSTORE) { $env:XIO_KEYSTORE } elseif ($props) { $props.Keystore } else { $null }
    $settings.KeyAlias = if ($KeyAlias) { $KeyAlias } elseif ($env:XIO_KEY_ALIAS) { $env:XIO_KEY_ALIAS } elseif ($props -and $props.KeyAlias) { $props.KeyAlias } else { 'x1oDevelopment' }
    $settings.StorePassword = if ($StorePassword) { $StorePassword } elseif ($env:XIO_STORE_PASSWORD) { $env:XIO_STORE_PASSWORD } elseif ($props) { $props.StorePassword } else { $null }
    $settings.KeyPassword = if ($KeyPassword) { $KeyPassword } elseif ($env:XIO_KEY_PASSWORD) { $env:XIO_KEY_PASSWORD } elseif ($props -and $props.KeyPassword) { $props.KeyPassword } else { $settings.StorePassword }

    if (-not $VerifyOnly) {
        if (-not $settings.Keystore) { throw 'Не задан keystore: -Keystore <путь> или $env:XIO_KEYSTORE' }
        if (-not (Test-Path -LiteralPath $settings.Keystore)) { throw "Файл keystore не найден: $($settings.Keystore)" }
        if (-not $settings.StorePassword) { throw 'Не задан пароль хранилища: -StorePassword или $env:XIO_STORE_PASSWORD' }
        if (-not $settings.KeyPassword) { throw 'Не задан пароль ключа: -KeyPassword или $env:XIO_KEY_PASSWORD' }
        if (-not $settings.KeyAlias) { throw 'Не задан alias ключа: -KeyAlias' }
    }
    return $settings
}

# --- основная работа ---------------------------------------------------------

function Invoke-ApkSigning {
    <# Подписывает и проверяет APK; возвращает записи о файлах. #>
    $results = New-Object System.Collections.Generic.List[object]
    $settings = Resolve-SigningSettings

    $apksigner = Find-BuildTool -Name 'apksigner'
    $zipalign = Find-BuildTool -Name 'zipalign'
    if (-not $apksigner) { throw 'apksigner не найден: задайте -BuildTools или $env:XIO_ANDROID_BUILD_TOOLS' }
    if (-not $zipalign) { Write-Warn 'zipalign не найден: выравнивание не проверяется' }
    Write-Sub "apksigner: $apksigner"
    if ($zipalign) { Write-Sub "zipalign:  $zipalign" }

    $paths = @($Apk | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($paths.Count -eq 0) { throw 'Не передан ни один APK (-Apk)' }
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "APK не найден: $path" }
    }

    if (-not $VerifyOnly -and -not $DryRun) {
        Write-Sub "keystore: $($settings.Keystore)"
        Write-Sub "alias:    $($settings.KeyAlias)"
        Write-Sub 'пароли:   получены, в вывод не печатаются'
    }

    # Пароли уходят apksigner через env: — их нет ни в argv, ни в логах.
    $storeVar = 'XIO_APK_STORE_PASS_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $keyVar = 'XIO_APK_KEY_PASS_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $oldStore = [Environment]::GetEnvironmentVariable($storeVar)
    $oldKey = [Environment]::GetEnvironmentVariable($keyVar)

    try {
        if (-not $VerifyOnly -and -not $DryRun) {
            [Environment]::SetEnvironmentVariable($storeVar, $settings.StorePassword)
            [Environment]::SetEnvironmentVariable($keyVar, $settings.KeyPassword)
        }

        foreach ($source in $paths) {
            Write-Step "$(Split-Path $source -Leaf)"
            $target = $source
            if ($OutDir -and -not $VerifyOnly) {
                if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
                $target = Join-Path $OutDir (Split-Path $source -Leaf)
                if ($DryRun) { Write-Sub "копирование: $source -> $target" }
                else { Copy-Item -LiteralPath $source -Destination $target -Force }
            }

            if ($DryRun) {
                if (-not $VerifyOnly) {
                    Write-Sub ("план: apksigner sign --ks <keystore> --ks-key-alias {0} --ks-pass env:<скрыто> --key-pass env:<скрыто> `"{1}`"" -f $settings.KeyAlias, $target)
                }
                Write-Sub "план: apksigner verify --verbose --print-certs `"$target`""
                continue
            }

            if (-not $VerifyOnly) {
                if ($zipalign) {
                    $align = Invoke-NativeCapture -Exe $zipalign -Arguments @('-c', '-P', '16', '4', $target)
                    if ($align.Code -ne 0) {
                        Write-Warn 'APK не выровнен по 16 KiB: выравниваю заново'
                        $aligned = "$target.aligned"
                        $fix = Invoke-NativeCapture -Exe $zipalign -Arguments @('-f', '-P', '16', '4', $target, $aligned)
                        if ($fix.Code -ne 0) { throw "zipalign -f не удался для $target`: $($fix.Output.Trim())" }
                        Move-Item -LiteralPath $aligned -Destination $target -Force
                    }
                }

                $sign = Invoke-NativeCapture -Exe $apksigner -Arguments @(
                    'sign',
                    '--ks', $settings.Keystore,
                    '--ks-key-alias', $settings.KeyAlias,
                    '--ks-pass', "env:$storeVar",
                    '--key-pass', "env:$keyVar",
                    '--v1-signing-enabled', 'true',
                    '--v2-signing-enabled', 'true',
                    '--v3-signing-enabled', 'true',
                    $target
                )
                if ($sign.Code -ne 0) { throw "apksigner sign не прошёл для $target (код $($sign.Code))" }
            }

            $verify = Invoke-NativeCapture -Exe $apksigner -Arguments @('verify', '--verbose', '--print-certs', $target)
            if ($verify.Code -ne 0) { throw "apksigner verify не прошёл для $target`:`n$($verify.Output.Trim())" }

            $schemes = [ordered]@{}
            foreach ($scheme in 'v1', 'v2', 'v3', 'v3.1', 'v4') {
                $schemes[$scheme] = ($verify.Output -match "Verified using $scheme scheme[^:]*: true")
            }
            if (-not $schemes['v2']) { throw "APK $target не подтверждён по схеме v2 (нужна для обновления без переустановки)" }
            $cert = ''
            if ($verify.Output -match 'Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]+)') { $cert = $Matches[1] }

            $item = Get-Item -LiteralPath $target
            $record = [pscustomobject]@{
                Name     = $item.Name
                Path     = $item.FullName
                Bytes    = $item.Length
                Sha256   = Get-Sha256 -Path $item.FullName
                Signer   = $cert
                Schemes  = (@($schemes.Keys) | Where-Object { $schemes[$_] }) -join ','
                Verified = $true
            }
            $results.Add($record) | Out-Null
            Write-Ok "$($record.Name) — подпись подтверждена"
            Write-Sub "размер: $(Format-Bytes -Bytes $record.Bytes)"
            Write-Sub "sha256: $($record.Sha256)"
            Write-Sub "сертификат sha256: $($record.Signer)"
            Write-Sub "схемы: $($record.Schemes)"
        }
    } finally {
        [Environment]::SetEnvironmentVariable($storeVar, $oldStore)
        [Environment]::SetEnvironmentVariable($keyVar, $oldKey)
    }

    return $results.ToArray()
}

# --- точка входа -------------------------------------------------------------

try {
    $signed = @(Invoke-ApkSigning)
    Write-Step 'Итог'
    if ($DryRun) {
        Write-Sub 'DryRun: файлы не изменены.'
    } elseif ($VerifyOnly) {
        Write-Ok ("проверено APK: {0}" -f $signed.Count)
    } else {
        Write-Ok ("подписано и проверено APK: {0}" -f $signed.Count)
    }
    exit 0
} catch {
    Write-Host ''
    Write-Err $_.Exception.Message
    exit 1
}
