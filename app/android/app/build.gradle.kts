import java.util.Properties
import java.util.Base64
import org.gradle.api.tasks.compile.JavaCompile
import java.util.zip.ZipFile
import java.io.File
import java.nio.file.FileVisitOption
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.util.EnumSet


plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val clientOnly = (project.findProperty("dart-defines") as String?).orEmpty().split(",").any {
    runCatching { String(Base64.getDecoder().decode(it)) == "XIO_CLIENT_ONLY=true" }.getOrDefault(false)
}

// Diagnostic ("test") build: screenshots stay possible and the app keeps a
// persistent on-device log that can be uploaded to the panel. Off by default;
// every release build must be produced without this property.
val testBuild = (project.findProperty("xioTestBuild") as String?) == "true"

// Registered once per variant so the task container is not mutated from inside
// another task's configureEach (Gradle forbids that). The strip runs on the
// Flutter asset output after compileFlutterBuild<Variant> and before the merge
// task that copies it into the APK, because merge/compress snapshot their input
// file lists and deleting merged files afterwards breaks their work actions.
//
// Symlink safety: a lexical prefix check is not containment. The payload and
// every ancestor under the build root must be real, non-symlink directories;
// the payload must canonicalise under the canonical build root; a NOFOLLOW
// prescan rejects every symlink (and non-regular file) before anything is
// deleted; each deletion rechecks the file and its parent's real path. Any
// linked root/ancestor/entry fails closed and leaves the tree untouched.
fun Project.registerClientAssetStrip(variant: String, keep: Set<String>): TaskProvider<Task> =
    tasks.register("stripClientOnly${variant}Assets") {
        dependsOn("compileFlutterBuild${variant}")
        outputs.upToDateWhen { false }
        doLast {
            val root = layout.buildDirectory.get().asFile.absoluteFile
            val rootPath = root.toPath().normalize()
            if (Files.isSymbolicLink(rootPath)) {
                throw GradleException("XIO client-only: build root is a symlink, refusing: $rootPath")
            }
            val buildReal = try {
                rootPath.toRealPath()
            } catch (failure: java.io.IOException) {
                throw GradleException("XIO client-only: build root cannot be resolved: $rootPath", failure)
            }
            val payload = rootPath.resolve("intermediates/flutter/${variant.lowercase()}/flutter_assets/assets").normalize()
            if (!payload.startsWith(rootPath)) {
                throw GradleException("XIO client-only: payload path escapes the build root: $payload")
            }
            var cursor = rootPath
            for (component in rootPath.relativize(payload)) {
                cursor = cursor.resolve(component)
                if (Files.isSymbolicLink(cursor)) {
                    throw GradleException("XIO client-only: linked path component in payload: $cursor")
                }
                if (!Files.isDirectory(cursor, LinkOption.NOFOLLOW_LINKS)) {
                    throw GradleException("XIO client-only: Flutter asset payload path missing or not a real directory: $cursor")
                }
            }
            val payloadReal = try {
                payload.toRealPath()
            } catch (failure: java.io.IOException) {
                throw GradleException("XIO client-only: payload cannot be resolved: $payload", failure)
            }
            if (payloadReal != buildReal.resolve(rootPath.relativize(payload)).normalize()) {
                throw GradleException("XIO client-only: payload canonical path is not the build path: $payloadReal")
            }

            val filesToDelete = ArrayList<Path>()
            val directories = ArrayList<Path>()
            try {
                Files.walkFileTree(
                    payload,
                    EnumSet.noneOf(FileVisitOption::class.java),
                    Int.MAX_VALUE,
                    object : SimpleFileVisitor<Path>() {
                        override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                            if (attrs.isSymbolicLink || Files.isSymbolicLink(dir)) {
                                throw GradleException("XIO client-only: linked directory in payload: $dir")
                            }
                            if (dir != payload) directories.add(dir)
                            return FileVisitResult.CONTINUE
                        }

                        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                            if (attrs.isSymbolicLink || Files.isSymbolicLink(file)) {
                                throw GradleException("XIO client-only: linked entry in payload: $file")
                            }
                            if (!attrs.isRegularFile) {
                                throw GradleException("XIO client-only: non-regular entry in payload: $file")
                            }
                            val top = payload.relativize(file).toString()
                                .replace(File.separatorChar, '/').substringBefore('/')
                            if (top !in keep) filesToDelete.add(file)
                            return FileVisitResult.CONTINUE
                        }

                        override fun visitFileFailed(file: Path, failure: java.io.IOException): FileVisitResult {
                            throw GradleException("XIO client-only: cannot inspect payload entry: $file", failure)
                        }
                    },
                )
            } catch (failure: GradleException) {
                throw failure
            } catch (failure: java.io.IOException) {
                throw GradleException("XIO client-only: payload prescan failed; nothing deleted", failure)
            }

            keep.forEach { top ->
                val keepPath = payload.resolve(top)
                if (Files.isSymbolicLink(keepPath) || !Files.isDirectory(keepPath, LinkOption.NOFOLLOW_LINKS)) {
                    throw GradleException("XIO client-only: essential asset '$top' missing or linked in $payload; nothing deleted")
                }
            }

            var removedBytes = 0L
            var removedFiles = 0
            filesToDelete.forEach { file ->
                val parentReal = try {
                    file.parent.toRealPath()
                } catch (failure: java.io.IOException) {
                    throw GradleException("XIO client-only: payload parent cannot be resolved: ${file.parent}", failure)
                }
                if (!parentReal.startsWith(payloadReal)) {
                    throw GradleException("XIO client-only: refusing to delete outside the canonical payload: $file")
                }
                if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                    throw GradleException("XIO client-only: payload entry changed to a link/non-regular file: $file")
                }
                val size = try { Files.size(file) } catch (failure: java.io.IOException) { throw GradleException("XIO client-only: cannot size $file", failure) }
                try {
                    Files.delete(file)
                } catch (failure: java.io.IOException) {
                    throw GradleException("XIO client-only: cannot delete payload file: $file", failure)
                }
                removedBytes += size
                removedFiles++
            }
            directories.sortedByDescending { it.nameCount }.forEach { directory ->
                val top = payload.relativize(directory).toString()
                    .replace(File.separatorChar, '/').substringBefore('/')
                if (top in keep) return@forEach
                if (Files.isSymbolicLink(directory)) {
                    throw GradleException("XIO client-only: directory changed to a link: $directory")
                }
                val empty = try {
                    Files.list(directory).use { entries -> !entries.findAny().isPresent }
                } catch (failure: java.io.IOException) {
                    throw GradleException("XIO client-only: cannot inspect directory: $directory", failure)
                }
                if (empty) {
                    try {
                        Files.delete(directory)
                    } catch (failure: java.io.IOException) {
                        throw GradleException("XIO client-only: cannot delete empty directory: $directory", failure)
                    }
                }
            }
            logger.lifecycle(
                "XIO client-only: dropped $removedFiles server payload files " +
                    "(${removedBytes / 1048576} MiB) from Flutter asset output for $variant"
            )
        }
    }
android {
    buildFeatures { buildConfig = true }
    namespace = "app.xio.xio"
    // Compress native engines in the distributable APK; Android extracts them
    // on installation. This keeps a multi-engine ARM64 update below bot limits.
    packaging { jniLibs { useLegacyPackaging = true } }
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "30.0.16248370"

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = if (clientOnly) "app.xio.client" else "app.xio.xio"
        buildConfigField("boolean", "CLIENT_ONLY", clientOnly.toString())
        buildConfigField("boolean", "TEST_BUILD", testBuild.toString())
        val playBuild = (project.findProperty("dart-defines") as String?).orEmpty().split(",").filter { it.isNotEmpty() }.any {
            runCatching { String(Base64.getDecoder().decode(it)) == "XIO_PLAY_BUILD=true" }.getOrDefault(false)
        }
        manifestPlaceholders["externalUpdates"] = (!playBuild && !clientOnly).toString()
        manifestPlaceholders["installPermission"] = if (playBuild || clientOnly) "app.xio.xio.permission.NO_EXTERNAL_INSTALL" else "android.permission.REQUEST_INSTALL_PACKAGES"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 26
        targetSdk = 36
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    val signingFile = rootProject.file("../../.signing/signing.properties")
    if (signingFile.exists()) {
        val signing = Properties().apply { signingFile.inputStream().use { load(it) } }
        // Имя конфигурации произвольно: подпись определяют storeFile/keyAlias из
        // signing.properties, а сам алиас исторической подписи хранится в keystore.
        signingConfigs.create("xioRelease") {
            storeFile = file(signing.getProperty("storeFile"))
            storePassword = signing.getProperty("storePassword")
            keyAlias = signing.getProperty("keyAlias")
            keyPassword = signing.getProperty("keyPassword")
        }
    }
    buildTypes {
        release {
            // Keep JNI interfaces while removing unreachable Java/Kotlin and resources.
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            isMinifyEnabled = true
            isShrinkResources = true
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.findByName("xioRelease")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation(files("libs/rivet.aar"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
    implementation(project(":amneziawg"))
}

// Flutter 3.47.7 omits dev-only Android plugin dependencies in release, but its
// generated Java registrant still refers to integration_test. Remove ONLY that
// generated registration before release javac; do not ship the test plugin.
tasks.withType<JavaCompile>().configureEach {
    if (name.contains("Release")) {
        doFirst {
            val registry = file("src/main/java/io/flutter/plugins/GeneratedPluginRegistrant.java")
            if (registry.exists()) {
                val source = registry.readText()
                if (source.contains("dev.flutter.plugins.integration_test.IntegrationTestPlugin")) {
                    val block = Regex("""(?s)    try \{\s*flutterEngine\.getPlugins\(\)\.add\(new dev\.flutter\.plugins\.integration_test\.IntegrationTestPlugin\(\)\);\s*\} catch \(Exception e\) \{\s*Log\.e\(TAG, "Error registering plugin integration_test,[^"]*", e\);\s*\}""")
                    val filtered = source.replace(block, "    // Dev-only integration_test is excluded from this release.")
                    check(!filtered.contains("dev.flutter.plugins.integration_test.IntegrationTestPlugin")) {
                        "Flutter changed the generated registrant; review the dev-plugin release workaround."
                    }
                    registry.writeText(filtered)
                }
            }
        }
    }
}

// A client-only build must never carry the managed-server payload. The client
// entrypoint (lib/client_main.dart) cannot reach managed_service.dart, the only
// code that loads those files, so the 21 MB archive and its helper scripts are
// pure ballast. client/build.py registers this by staging a pubspec without
// them; this block makes an ad-hoc `flutter build apk
// --dart-define=XIO_CLIENT_ONLY=true` equally lean, so the ballast cannot come
// back through the manual path. The keep-list is the contract client/verify.py
// enforces on the produced APK.
//
// Ordering: a merge-task doLast can run before AGP writes its merged output, and
// deleting files inside compress/package actions breaks their already-snapshotted
// inputs. For each compress task this block registers a matching strip task that
// depends only on that variant's merge task; compression then depends on the
// strip. The strip resolves payload roots from the actual intermediates tree
// (never a case-sensitive variant name), deletes only inside the owned build
// directory, and fails closed if a payload root or an essential keep-list top is
// missing. A package doLast verifies the APK itself.
if (clientOnly) {
    val keepAssetTops = setOf("help", "licenses", "l10n", "security", "fonts")
    val payloadPrefix = "assets/flutter_assets/assets/"

    val stripDebugAssets = project.registerClientAssetStrip("Debug", keepAssetTops)
    val stripReleaseAssets = project.registerClientAssetStrip("Release", keepAssetTops)
    tasks.matching { it.name == "mergeDebugAssets" }.configureEach { dependsOn(stripDebugAssets) }
    tasks.matching { it.name == "mergeReleaseAssets" }.configureEach { dependsOn(stripReleaseAssets) }
    tasks.matching { it.name == "packageDebug" || it.name == "packageRelease" }.configureEach {
        doLast {
            // Verify only the APK(s) this package task produced for the current
            // variant. Never scan outputs/flutter-apk: that directory can hold a
            // stale Full copy from an earlier build (CA2). A missing primary
            // artifact fails closed instead of validating an old fallback.
            val variant = name.removePrefix("package").lowercase()
            val apkRoot = layout.buildDirectory.get().asFile.absoluteFile
            val primaryDir = apkRoot.resolve("outputs/apk/$variant")
            val apks = LinkedHashSet<File>()
            outputs.files.files
                .filter { it.isFile && it.name.endsWith(".apk") }
                .filter { it.toPath().toAbsolutePath().normalize().startsWith(primaryDir.toPath().toAbsolutePath().normalize()) }
                .forEach { apks.add(it) }
            if (primaryDir.isDirectory) {
                primaryDir.walkTopDown()
                    .filter { it.isFile && it.name.endsWith(".apk") }
                    .forEach { apks.add(it) }
            }
            check(apks.isNotEmpty()) {
                "XIO client-only: package '$name' produced no APK under $primaryDir; " +
                    "refusing to validate a stale fallback artifact"
            }
            apks.forEach { apk ->
                val entries = mutableListOf<String>()
                ZipFile(apk).use { zip ->
                    val iterator = zip.entries()
                    while (iterator.hasMoreElements()) entries.add(iterator.nextElement().name)
                }
                val offenders = entries.filter { it.startsWith(payloadPrefix) }
                    .map { it.removePrefix(payloadPrefix).substringBefore('/') }
                    .filter { it !in keepAssetTops }
                    .distinct()
                check(offenders.isEmpty()) {
                    "XIO client-only APK ${apk.name} still contains server payload tops: $offenders"
                }
                keepAssetTops.forEach { top ->
                    check(entries.any { it.startsWith(payloadPrefix + top + "/") }) {
                        "XIO client-only APK ${apk.name} is missing essential asset '$top'"
                    }
                }
                logger.lifecycle("XIO client-only: verified lean APK ${apk.name} (${entries.size} entries)")
            }
        }
    }
}
// A release without MAIN/LAUNCHER installs successfully but has no app icon.
// Validate the native declarations even when icons were not regenerated.
val verifyLauncherAliases by tasks.registering {
    val manifest = file("src/main/AndroidManifest.xml")
    inputs.file(manifest)
    doLast {
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        val document = factory.newDocumentBuilder().parse(manifest)
        val ns = "http://schemas.android.com/apk/res/android"
        val nodes = document.getElementsByTagName("activity-alias")
        val aliases = (0 until nodes.length).map { nodes.item(it) as org.w3c.dom.Element }
        val expected = listOf("green", "white").flatMap { color ->
            listOf("dark", "clear").flatMap { background ->
                listOf(0, 90, 180, 270).map { ".launcher.${color}_${background}_$it" }
            }
        }.toSet()
        check(aliases.size == 16 && aliases.map { it.getAttributeNS(ns, "name") }.toSet() == expected) { "Missing XIO launcher aliases; run tools/generate-icons.py" }
        check(aliases.count { it.getAttributeNS(ns, "enabled") == "true" } == 1) { "Exactly one default launcher required" }
        aliases.forEach { alias ->
            check(alias.getAttributeNS(ns, "targetActivity") == ".MainActivity" && alias.getAttributeNS(ns, "exported") == "true")
            fun contains(tag: String, value: String): Boolean {
                val values = alias.getElementsByTagName(tag)
                return (0 until values.length).any { (values.item(it) as org.w3c.dom.Element).getAttributeNS(ns, "name") == value }
            }
            check(contains("action", "android.intent.action.MAIN") && contains("category", "android.intent.category.LAUNCHER")) { "Launcher intent missing" }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyLauncherAliases) }
