# Rebuild every XIO artifact from the current working tree.
# Usage: pwsh -File work/rebuild-all.ps1 [-SkipDesktop]
param([switch]$SkipDesktop)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$key = "$env:USERPROFILE\.ssh\id_ed25519_debian17"
$debian = 'root@192.168.88.17'
$releases = Join-Path $repo 'releases'
$python = 'C:\Users\er-ka\AppData\Local\Programs\Python\Python310\python.exe'
$node = 'C:\Users\er-ka\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe'

function Step($name) { Write-Host "== $name ==" -ForegroundColor Cyan }

Step 'server bundle on Debian'
$tar = Join-Path $env:TEMP 'xio-src.tgz'
if (Test-Path $tar) { Remove-Item $tar -Force }
& tar.exe -czf $tar -C $repo server tools deploy app/lib app/pubspec.yaml app/assets
& scp -o BatchMode=yes -q -i $key $tar "${debian}:/tmp/xio-src.tgz"
& ssh -o BatchMode=yes -i $key $debian @'
set -e
rm -rf /root/xio-linux/server /root/xio-linux/tools /root/xio-linux/deploy /root/xio-linux/app/lib /root/xio-linux/app/assets
tar -xzf /tmp/xio-src.tgz -C /root/xio-linux
cd /root/xio-linux
export PATH=/opt/go1.27.3/bin:$PATH
python3 tools/build-rivet.py --go /opt/go1.27.3/bin/go 2>&1 | tail -2
python3 tools/package-server.py --output-dir /root/xio-assets-build 2>&1 | tail -1
tar -tzf /root/xio-assets-build/xio-server.tar.gz | wc -l
'@
if ($LASTEXITCODE -ne 0) { throw 'packaging failed' }

Step 'copy bundle into app/assets and releases'
$src = Join-Path $env:TEMP 'xio-assets-build'
Remove-Item $src -Recurse -Force -ErrorAction SilentlyContinue
& scp -o BatchMode=yes -q -r -i $key "${debian}:/root/xio-assets-build/*" $src
$dst = Join-Path $repo 'app\assets'
foreach ($f in 'xio-server.tar.gz','xio-server-release.json','xio-admin.py','xio-bootstrap.sh','xio-stack.py','xio-network-stack.py','xio-mesh-stack.py','mesh-pins.json','xio-server-update.py') {
  Copy-Item (Join-Path $src $f) (Join-Path $dst $f) -Force
}
if (Test-Path (Join-Path $src 'xio_vici')) { Copy-Item (Join-Path $src 'xio_vici\*') (Join-Path $dst 'xio_vici') -Recurse -Force }
Copy-Item (Join-Path $src 'xio-server.tar.gz') (Join-Path $releases 'xio-server-0.24.1.tar.gz') -Force

if (-not $SkipDesktop) {
  Step 'windows bundle'
  $env:Path = "C:\dev\flutter\bin;$env:Path"
  Push-Location (Join-Path $repo 'app')
  try { & flutter build windows --release 2>&1 | Select-Object -Last 1 } finally { Pop-Location }
  # The desktop helper embeds the Go engine. Cross-compile it on Debian: the local
  # Windows toolchain is unusable here (Smart App Control blocks the Go toolchain
  # binary itself once go.mod asks for a newer version).
  & ssh -o BatchMode=yes -i $key $debian 'set -e; export PATH=/opt/go1.27.3/bin:$PATH; cd /root/xio-linux/protocol/rivet; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/xio-tunnel.exe ./cmd/xio-desktop; stat -c "helper %s" /tmp/xio-tunnel.exe'
  if ($LASTEXITCODE -ne 0) { throw 'helper cross-build failed' }
  & scp -o BatchMode=yes -q -i $key "${debian}:/tmp/xio-tunnel.exe" (Join-Path $repo 'app\build\windows\x64\runner\Release\libexec\xio-tunnel.exe')
  if ($LASTEXITCODE -ne 0) { throw 'helper copy failed' }
  $zip = Join-Path $releases 'XIO-Full-0.24.1-windows-x64.zip'
  if (Test-Path $zip) { Remove-Item $zip -Force }
  Compress-Archive -Path (Join-Path $repo 'app\build\windows\x64\runner\Release\*') -DestinationPath $zip -CompressionLevel Optimal

  Step 'ubuntu bundles on Debian'
  & ssh -o BatchMode=yes -i $key $debian @'
set -e
export PATH=/opt/flutter/bin:/opt/go1.27.3/bin:$PATH
cd /root/xio-linux/app
flutter build linux --release 2>&1 | tail -1
mkdir -p build/linux/x64/release/bundle/libexec
cd /root/xio-linux/protocol/rivet
go build -trimpath -ldflags="-s -w" -o /root/xio-linux/app/build/linux/x64/release/bundle/libexec/xio-tunnel ./cmd/xio-desktop
cd /root/xio-linux
python3 tooling/cross-platform/package-ubuntu.py 2>&1 | tail -1
'@
  if ($LASTEXITCODE -ne 0) { throw 'ubuntu build failed' }
  & scp -o BatchMode=yes -q -i $key "${debian}:/root/xio-linux/releases/XIO-0.24.1-ubuntu-amd64.deb" (Join-Path $releases 'XIO-0.24.1-ubuntu-amd64.deb')
  & scp -o BatchMode=yes -q -i $key "${debian}:/root/xio-linux/releases/XIO-0.24.1-ubuntu-x64.tar.gz" (Join-Path $releases 'XIO-0.24.1-ubuntu-x64.tar.gz')
}

Step 'checksums'
$names = 'XIO-Full-0.24.1-windows-x64.zip','XIO-0.24.1-ubuntu-amd64.deb','XIO-0.24.1-ubuntu-x64.tar.gz','xio-server-0.24.1.tar.gz'
$lines = foreach ($n in $names) { (Get-FileHash (Join-Path $releases $n) -Algorithm SHA256).Hash.ToLower() + '  ' + $n }
$lines -join "`n" | Set-Content (Join-Path $releases 'SHA256SUMS-0.24.1.txt') -Encoding ASCII
Get-Content (Join-Path $releases 'SHA256SUMS-0.24.1.txt')

Step 'tests on Debian'
& ssh -o BatchMode=yes -i $key $debian 'cd /root/xio-linux/server/managed && python3 -m unittest test_admin 2>&1 | tail -3; cd /root/xio-linux/tools && python3 -m unittest test_package_server 2>&1 | tail -3'
