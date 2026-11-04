param(
    [string]$AndroidJar = "",
    [string]$KotlinCache = (Join-Path $HOME ".gradle/caches/modules-2/files-2.1"),
    [string]$OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) ("xio-dualstack-jvm-" + [guid]::NewGuid().ToString("N")))
)
$ErrorActionPreference = "Stop"
# Only standalone javac/Kotlin JVM compilation; no Gradle, Flutter build or VPN.
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
if (!$AndroidJar) {
    $sdk = $env:ANDROID_HOME
    if (!$sdk) { $sdk = $env:ANDROID_SDK_ROOT }
    if (!$sdk) { throw "Pass -AndroidJar <Android API android.jar> (no SDK installation is attempted)." }
    $AndroidJar = Join-Path $sdk "platforms/android-36/android.jar"
}
if (!(Test-Path -LiteralPath $AndroidJar)) { throw "Android API jar not found." }
$versions = @(
    "org.jetbrains.kotlin/kotlin-compiler-embeddable/2.4.0",
    "org.jetbrains.kotlin/kotlin-build-tools-api/2.4.0",
    "org.jetbrains.kotlin/kotlin-stdlib/2.4.0",
    "org.jetbrains.kotlin/kotlin-script-runtime/2.4.0",
    "org.jetbrains.kotlin/kotlin-reflect/1.6.10",
    "org.jetbrains.kotlin/kotlin-daemon-embeddable/2.4.0",
    "org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.0",
    "org.jetbrains/annotations/13.0"
)
$jars = @($versions | ForEach-Object {
    $files = @(Get-ChildItem (Join-Path $KotlinCache $_) -Recurse -Filter *.jar)
    if ($files.Count -eq 0) { throw "Missing pinned Kotlin dependency: $_. No download is attempted." }
    $files | Select-Object -ExpandProperty FullName
})
$separator = [System.IO.Path]::PathSeparator
$compilerCp = $jars -join $separator
$stdlib = @(Get-ChildItem (Join-Path $KotlinCache "org.jetbrains.kotlin/kotlin-stdlib/2.4.0") -Recurse -Filter *.jar)[0].FullName
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
Push-Location $root
try {
    & javac --release 17 -d $OutputDirectory app/android/app/src/main/java/app/xio/xio/IpRoutes.java app/integration_test/dualstack_ip_routes_test.java
    if ($LASTEXITCODE -ne 0) { throw "javac failed: exit=$LASTEXITCODE" }
    & java -Xmx256m -cp $OutputDirectory app.xio.xio.dualstack_ip_routes_test
    if ($LASTEXITCODE -ne 0) { throw "CIDR checks failed: exit=$LASTEXITCODE" }
    & java -cp $compilerCp org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -jvm-target 17 -no-stdlib -no-reflect -classpath "$AndroidJar$separator$stdlib" -d $OutputDirectory app/android/app/src/main/kotlin/app/xio/xio/PhysicalNetwork.kt app/integration_test/dualstack_physical_network_test.kt
    if ($LASTEXITCODE -ne 0) { throw "Kotlin compile failed: exit=$LASTEXITCODE" }
    & java -cp "$OutputDirectory$separator$stdlib$separator$AndroidJar" app.xio.xio.Dualstack_physical_network_testKt
    if ($LASTEXITCODE -ne 0) { throw "Physical DNS checks failed: exit=$LASTEXITCODE" }
    Write-Output "XIO_DUALSTACK_JVM_PASS output=$OutputDirectory (standalone source/unit checks, not a device VPN PASS)"
} finally {
    Pop-Location
}
