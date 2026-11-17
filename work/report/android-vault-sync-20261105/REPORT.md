# Android encrypted-vault sync admission — 2026-11-05

[Source](../../../app/android/app/src/main/kotlin/app/xio/xio/ConfigVault.kt) SHA256 `311c0983c143bd34c986109a6d615220bec3e80db85579c7ece5e7df4a29e326`.

Before normal credential-write ACK, encrypted temp bytes are flushed and FileDescriptor-synced, same-directory rename is checked, then the distinct vault / no_backup / app-data parent directories are opened using public Android API, fstat-checked as directories, fsynced and closed. This also syncs new private directory links, child to parent. An exception blocks the success return; a late failure after rename can leave the new encrypted record visible while reporting failure. There is no automatic rollback or plaintext/log change. Callers must await successful persistence before remote mutation.

Independent read-only worker compiled **only this exact file**, no Gradle/APK/JNI. Existing Kotlin2.4.0 (matching project settings), explicit cached compiler-POM dependencies, JDK21.0.13, Android36 public SDK JAR; JVM target17; `-no-jdk -no-stdlib -no-reflect` plus explicit SDK/stdlib/annotation application classpath. [Full manifest and command](final/result.json), [compiler log](final/compile.log), [Java version](final/java-version.log), [Kotlin version](final/kotlin-version.log), [actual bytecode inspection](final/javap.log), [evidence driver](compile_vault.py). Compiler/javap/driver exits **0**. All source, eight dependency JARs, SDK metadata and class outputs rehashed after compilation unchanged.

Output class: 9279 bytes, SHA256 `9b15824f90e31e2af7ac4c556aca6bce691538feeb413fb364a61ae9a2a47364`; Kotlin module 24 bytes, SHA256 `06d262cf732152000d8cb1453e8dc1209b37fa4411e5c4d202265ff0d18ec16d`. Class files are not committed or installed. Actual bytecode confirms file sync precedes rename and every directory-sync/close precedes normal return. Selected API history is compatible with minSDK26; no API26 SDK JAR/runtime was available, so this is static compatibility evidence only.

## Honest negative / correction

A preliminary implementation used `OsConstants.O_DIRECTORY`, incorrectly assumed public. Actual cached Kotlin/public SDK compilation **failed**, catching the absent public field. Parent replaced it with `O_RDONLY` and public `Os.fstat` / `OsConstants.S_ISDIR`, not reflection, numeric architecture flags or a hidden-API bypass. [Failed manifest](initial-failed/result.json) binds that earlier source SHA `b8f6b371a15790608b48547f1de3166182fe2f067ba0f80b06c512c55d3a61c4`; [actual compiler error](initial-failed/compile.log) retained. Only final SHA above is accepted.

## Not verified

No Android code/app execution, phone/USB action, actual filesystem/SELinux directory-fsync support, power-loss/controller behavior, Android Keystore/TEE persistence, concurrent writer/deletion semantics, native binding or whole-app compile, APK generation/signature/install, live VPN or release acceptance. No dependencies downloaded, no system/network/policy changes. This strengthens write admission at source level; compilation is **not a device durability proof**. Journal Dart tests separately use fake I/O and do not establish these runtime properties. Apple unchanged/deferred.
