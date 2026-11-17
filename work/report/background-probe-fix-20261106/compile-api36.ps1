$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/../../..").Path
$cache='C:/Users/er-ka/.gradle/caches/modules-2/files-2.1'
$compiler="$cache/org.jetbrains.kotlin/kotlin-compiler-embeddable/2.2.21/b13aed5cf8412f9ee9d1e4db21bdcfebcc24f606/kotlin-compiler-embeddable-2.2.21.jar"
$stdlib="$cache/org.jetbrains.kotlin/kotlin-stdlib/2.2.21/fa374a986e128314c3db00a20aae55f72a258511/kotlin-stdlib-2.2.21.jar"
$script="$cache/org.jetbrains.kotlin/kotlin-script-runtime/2.2.21/e9b021c4e335e4ed7a7e3b32285249ae6bb3a6c8/kotlin-script-runtime-2.2.21.jar"
$reflect="$cache/org.jetbrains.kotlin/kotlin-reflect/2.2.21/17bc47f5dfe27c2351538e711f0afe377b0de6b2/kotlin-reflect-2.2.21.jar"
$coroutines="$cache/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.0/ac1dc37a30a93150b704022f8d895ee1bd3a36b3/kotlinx-coroutines-core-jvm-1.8.0.jar"
$annotations="$cache/org.jetbrains/annotations/13.0/919f0dfe192fb4e063e7dacadee7f8bb9a2672a9/annotations-13.0.jar"
$android='C:/dev/android-sdk/platforms/android-36/android.jar'
$out="$PSScriptRoot/api36-classes"
New-Item -ItemType Directory -Force $out | Out-Null
& C:/dev/jdk-21/bin/javac.exe --release 17 -d $out "$root/app/android/app/src/main/java/app/xio/xio/ConnectionBudget.java" "$root/app/android/app/src/main/java/app/xio/xio/BackgroundVerificationOptions.java"
if($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$compilerPath=@($compiler,$stdlib,$script,$reflect,$coroutines,$annotations) -join ';'
$classPath=@($android,$out,$stdlib,$annotations) -join ';'
& C:/dev/jdk-21/bin/java.exe -cp $compilerPath org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -jvm-target 17 -classpath $classPath -d $out "$PSScriptRoot/CompileOnlyAndroidCollaborators.kt" "$root/app/android/app/src/main/kotlin/app/xio/xio/ConnectionProbe.kt" "$root/app/android/app/src/main/kotlin/app/xio/xio/VpnControlService.kt"
if($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output 'API36: actual VpnControlService + unchanged ConnectionProbe + production Java helper COMPILE PASS (compile-only collaborator signatures; no APK/runtime/device claim)'
