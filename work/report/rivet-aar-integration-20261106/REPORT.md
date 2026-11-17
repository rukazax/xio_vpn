# Accepted RIVET binding integration — 2026-11-06

## Scope

Replace only the bundled [rivet.aar](../../../../app/android/app/libs/rivet.aar) at source baseline `595def6ab24590002458c0a5fa4f8020d5c8a86f`, plus retain evidence. No manual-mode product changes, release publication, device action or runtime claim.

- Old SHA256: `cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7`.
- Accepted SHA256: `7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c`, 36,548,360 bytes.
- Java binding SHA256: `8f1849333170c09c3e874c740bfc932a89adb177f454d131cf7caa86d5741400`.
- Native payload: arm64-v8a, armeabi-v7a, x86_64; exact ELF/hash/API/JNI evidence retained.

## Independent acceptance

[Reviewer report](REVIEW-RIVET-AAR-20261106.md), original SHA256 `bdc963ef86f1e5cc26dec463eab42f82ebc444dc621b36cc1f1666ab891cf609`, gives SCOPED ACCEPT. Reviewer recreated the exact source archive, verified 1,842 native inputs, and ran actual Full and Client Kotlin/Javac compilers independently. Both exited zero; both application compiler tasks executed, not cache hits. The coordinator also verified artifact/entry hashes, ZIP CRC, unique entries and exact ABI/ELF architecture set.

- [Full compiler raw log](review-rivet-aar-20261106/logs/full-gradle.txt): SHA256 `3ce782ebaddc7f1e89524db89bc16b701d2419bd6d093d4bf1028a1e09bdc82a`.
- [Client compiler raw log](review-rivet-aar-20261106/logs/client-gradle.txt): SHA256 `312bfa631595f089d0319297e7f0fce869e0994d6ff379e9c0eccc6e31d42ac6`.
- [Author report](ANDROID-RIVET-AAR-20261106.md): native build and old-AAR negative controls. Negative controls stop at Kotlin failure; application Javac does not run there.

## Evidence retention

Reports and textual evidence/scripts/manifests were copied byte-for-byte into this directory; `.gitattributes` disables newline normalization. `INTEGRATION-SHA256.json` inventories retained files. Original reports retain original artifact links: source archive, extracted binaries and some external fixtures are deliberately not duplicated in Git. The accepted AAR is the canonical product file linked above. Original complete bundles remain under `xio_vpn/work/agent-rivet-aar-20261106` and `xio_vpn/work/review-rivet-aar-20261106`, and corresponding owned `/srv/archives/` roots on Debian. Missing copied binary/archive links are not extra proof claims.

## Limits

Compiler replay targets arm64 and excludes Dart/assets. Static payload verification covers all three ABIs. No APK/AAB, signing, manifest/assets packaging, install, device, VPN/runtime or release acceptance. No assertion of complete native binary reproducibility or that build-root paths explain every binary difference. The pending manual-mode composition requires new exact-composition compilation and independent acceptance.
