param([string]$AndroidJar="C:/dev/android-sdk/platforms/android-36/android.jar", [int]$Repeat=1, [string]$AarPath="")
$ErrorActionPreference="Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
$root=(Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$cache=Join-Path $HOME ".gradle/caches/modules-2/files-2.1"
$jars=@($AndroidJar)
foreach($p in @("androidx.annotation/annotation-jvm/1.10.0","androidx.collection/collection/1.1.0","com.google.code.findbugs/jsr305/3.0.2","org.jetbrains.kotlin/kotlin-stdlib/2.4.0")) {
 $jars+=@(Get-ChildItem (Join-Path $cache $p) -Recurse -Filter *.jar | Select-Object -ExpandProperty FullName)
}
$out=Join-Path ([System.IO.Path]::GetTempPath()) ("xio-awg-endpoint-jvm-"+[guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location $root
try {
 $zip=[System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $(if($AarPath){$AarPath}else{"app/android/app/libs/rivet.aar"})))
 try {
  $stream=$zip.GetEntry("classes.jar").Open()
  $file=[System.IO.File]::Create((Join-Path $out "rivet-classes.jar"))
  try{$stream.CopyTo($file)}finally{$file.Dispose();$stream.Dispose()}
 }finally{$zip.Dispose()}
 $jars+=(Join-Path $out "rivet-classes.jar")
 $cp=$jars -join [System.IO.Path]::PathSeparator
 $sources=@(Get-ChildItem vendor/amneziawg/android/src/main/java -Recurse -Filter *.java | Select-Object -ExpandProperty FullName)
 & javac --release 17 -cp $cp -d $out @sources app/integration_test/dualstack_awg_endpoint_test.java
 if($LASTEXITCODE -ne 0){throw "production javac failed: $LASTEXITCODE"}
 for($i=0;$i -lt $Repeat;$i++) {
  & java -cp "$out$([System.IO.Path]::PathSeparator)$cp" org.amnezia.awg.config.dualstack_awg_endpoint_test
  if($LASTEXITCODE -ne 0){throw "JVM regression failed: $LASTEXITCODE"}
 }
 Write-Output "XIO_AWG_ALL_JAVA_COMPILE_PASS sources=$($sources.Count) repeats=$Repeat (not APK/device PASS)"
}finally{Pop-Location}
