$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$XioRoot = Split-Path $PSScriptRoot -Parent
$Version = '0.22.0'
Push-Location (Join-Path $XioRoot 'app')
try {
    flutter pub get
    if ($LASTEXITCODE -ne 0) { throw 'Dependency resolution failed' }
    flutter analyze
    if ($LASTEXITCODE -ne 0) { throw 'Analysis failed' }
    flutter test
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    flutter build windows --release
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
    $Bundle = Join-Path $PWD 'build/windows/x64/runner/Release'
    $Helper = Join-Path $Bundle 'libexec'
    New-Item -ItemType Directory -Force -Path $Helper | Out-Null
    Push-Location (Join-Path $XioRoot 'protocol/rivet')
    try {
        go build -trimpath '-ldflags=-s -w' -o (Join-Path $Helper 'xio-tunnel.exe') ./cmd/xio-desktop
        if ($LASTEXITCODE -ne 0) { throw 'VPN helper build failed' }
    } finally { Pop-Location }
    $Cache = Join-Path $XioRoot '.build-support/windows-native'
    New-Item -ItemType Directory -Force -Path $Cache | Out-Null
    $Zip = Join-Path $Cache 'wintun-0.14.1.zip'
    if (!(Test-Path $Zip)) { Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $Zip }
    $ExpectedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
    if ((Get-FileHash $Zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) { throw 'Unexpected Wintun archive hash' }
    Expand-Archive -Path $Zip -DestinationPath $Cache -Force
    Copy-Item (Join-Path $Cache 'wintun/bin/amd64/wintun.dll') $Helper
    Copy-Item (Join-Path $Cache 'wintun/LICENSE.txt') (Join-Path $Helper 'WINTUN-LICENSE.txt')
    Copy-Item (Join-Path $XioRoot 'LICENSE') $Bundle
    Copy-Item (Join-Path $XioRoot 'COPYRIGHT') $Bundle
    Copy-Item (Join-Path $XioRoot 'CROSS-PLATFORM-0.19.ru.md') $Bundle
    $Output = Join-Path $XioRoot 'releases'
    New-Item -ItemType Directory -Force -Path $Output | Out-Null
    $PortableRoot = Join-Path $Cache 'portable'
    if (Test-Path $PortableRoot) { Remove-Item $PortableRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $PortableRoot | Out-Null
    Copy-Item -LiteralPath $Bundle -Destination (Join-Path $PortableRoot 'XIO') -Recurse
    Compress-Archive -Path (Join-Path $PortableRoot 'XIO') -DestinationPath (Join-Path $Output "XIO-$Version-windows-x64.zip") -Force
} finally { Pop-Location }
