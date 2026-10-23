# XIO 0.22 native runtime sources / Исходники нативного runtime

Exact source inputs for the Android AAR and server runtimes built for XIO 0.22. SHA256 fingerprint is in the top-level vendor-metadata/rivet-build.json. Original upstream licenses are included. The Xray synchronization patch is included under vendor/xray and documented in top-level patches/xray; vendor/tun2socks excludes optional proxy registration.

Use the top-level protocol/rivet to rebuild the current source; it is byte-identical to this snapshot at release. The build uses Go 1.27.2, Android SDK/NDK and gomobile. Top-level tools/build-rivet.py applies/verifies the Xray patch, runs race-enabled tests and builds server binaries plus Android bindings. It also uses tools/prepare-mobile-go.py for the existing CLOCK_BOOTTIME runtime compatibility patch. These tools, pinned dependency source ZIPs in vendor/go-source-cache, and the AAR are included in the full source ZIP. SDKs and signing secrets are not included.

Точный комплект исходников Android AAR и серверных runtime версии 0.22. Отпечаток указан в основном vendor-metadata/rivet-build.json. Полный исходный архив содержит зависимости, инструменты сборки и сведения о лицензиях. SDK и закрытые ключи подписи не поставляются. Старый снимок 0.18 оставлен только для воспроизведения прежних релизов.
