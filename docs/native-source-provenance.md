# Native source provenance / Происхождение нативных исходников

XIO 0.20 uses the updated shared Flutter UI and the existing platform-specific network components. The Android AAR is byte-identical to the released 0.18 AAR. Its exact corresponding module and modified compatibility forks are included in the full source release under `native-sources/android-runtime-0.18`. The original owned-source fingerprint was verified. The top-level `protocol/rivet` contains the later desktop/iOS source.

The full source release also includes the pinned Go dependency source ZIPs. All entries required by the older Android runtime were compared byte-for-byte. To rebuild that runtime, follow the README in its directory and copy the top-level `vendor/go-source-cache` there first. SDKs and private signing keys are separate.

A packaging rule that excluded any directory named build also omitted five upstream source/resource files. The corrected full source archive restores these files in current vendor sources and in the matching historical Android runtime source. This correction changes source packaging, not installed VPN engines.

В XIO 0.20 обновлён общий Flutter-интерфейс и сохранены существующие нативные сетевые компоненты платформ. Android AAR побайтно совпадает с выпущенным AAR 0.18. Его точный модуль и изменённые совместимые forks включены в полный исходный архив в `native-sources/android-runtime-0.18`. Исходный отпечаток собственного кода проверен. Основной `protocol/rivet` содержит более поздние исходники настольных клиентов и iOS.

В полный комплект входят закреплённые ZIP-архивы Go-зависимостей. Все записи, нужные прежнему Android runtime, побайтно сверены. Для его пересборки следуйте README в указанном каталоге, предварительно скопировав туда основной `vendor/go-source-cache`. SDK и закрытые ключи подписи поставляются отдельно.

Правило, исключавшее любой каталог build, также удаляло из архива пять файлов исходников/ресурсов upstream. Исправленный полный исходный архив восстанавливает их в текущем vendor и в точном исходном комплекте Android runtime. Исправление меняет упаковку исходников, а не установленные VPN-движки.
