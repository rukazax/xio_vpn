import java.util.Properties
import java.util.Base64
import org.gradle.api.tasks.compile.JavaCompile

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val clientOnly = (project.findProperty("dart-defines") as String?).orEmpty().split(",").any {
    runCatching { String(Base64.getDecoder().decode(it)) == "XIO_CLIENT_ONLY=true" }.getOrDefault(false)
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
        signingConfigs.create("x1oDevelopment") {
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
            signingConfig = signingConfigs.findByName("x1oDevelopment")
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
