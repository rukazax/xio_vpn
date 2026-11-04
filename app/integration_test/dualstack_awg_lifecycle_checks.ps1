param(
    [int]$Repeat = 20,
    [string]$OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) ("xio-awg-lifecycle-" + [guid]::NewGuid().ToString("N")))
)
$ErrorActionPreference = "Stop"
# Pure JVM lifecycle gate: production helper + focused tests only. No AAR,
# Android, gomobile, native library, Gradle or device is touched.
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$helper = Join-Path $root "vendor/amneziawg/android/src/main/java/org/amnezia/awg/backend/AwgActivationLifecycle.java"
$backend = Join-Path $root "vendor/amneziawg/android/src/main/java/org/amnezia/awg/backend/GoBackend.java"
$publication = Join-Path $root "vendor/amneziawg/android/src/main/java/org/amnezia/awg/backend/AwgServicePublication.java"
$test = Join-Path $root "app/integration_test/dualstack_awg_lifecycle_test.java"
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
Push-Location $root
try {
    & javac --release 17 -d $OutputDirectory $helper $publication $test
    if ($LASTEXITCODE -ne 0) { throw "javac failed: exit=$LASTEXITCODE" }

    # Readback integration: real backend must own the helper state, not the
    # removed fields. This is a wiring check, not a vendor Java compile claim.
    $source = Get-Content -Raw -LiteralPath $backend
    foreach ($required in @(
        "new AwgActivationLifecycle<",
        "activation.begin(tunnel)",
        "activation.matches(tunnel)",
        "activation.attach(",
        "activation.adoptService(",
        "activation.commit(",
        "activation.fail(",
        "activation.down()",
        "activation.destroyService(",
        "activation.retireService(",
        "servicePublication.publish(",
        "servicePublication.retire(",
        "activation.cancelPending()",
        "releaseService(",
        "finishTeardown(",
        "execution.done()",
        "teardown.complete()"
    )) {
        if (-not $source.Contains($required)) { throw "backend integration missing: $required" }
    }
    foreach ($removed in @("currentTunnelHandle", "activationCancelled", "activationLock", "currentTunnel", "AwgActivationLifecycle.Down<")) {
        if ($source.Contains($removed)) { throw "backend still references removed lifecycle field: $removed" }
    }
    if ($source -match "else if\s*\(state == State\.DOWN && tunnel == activation\.tunnel\(\)") {
        throw "public DOWN predicate must use activation.matches(tunnel)"
    }

    for ($i = 0; $i -lt $Repeat; $i++) {
        & java -cp $OutputDirectory org.amnezia.awg.backend.dualstack_awg_lifecycle_test
        if ($LASTEXITCODE -ne 0) { throw "lifecycle regression failed: exit=$LASTEXITCODE iteration=$i" }
    }
    Write-Output "XIO_AWG_LIFECYCLE_PASS repeats=$Repeat helper-tests-only; full vendor Java/AAR compile remains parent-owned"
} finally {
    Pop-Location
}
