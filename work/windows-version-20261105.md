# PE-версия `XIO.exe` в 0.24.2 — что и чем проверено (2026-11-05)

Предмет: в пакете `XIO-Full-0.24.2-windows-x64.zip` версия `XIO.exe` должна
совпадать с `app/pubspec.yaml` (`0.24.2+5019`), а не с той сборкой, откуда взят
готовый Windows-раннер.

## Что было и что стало

| Артефакт | Размер | SHA-256 | FileVersion |
|---|---|---|---|
| `XIO.exe` из пакета 0.24.1 | 79 360 Б | `140ea6b4f15734504d9b0d06add689b6ed7d3cecd32b0802df2d12331883c36c` | `0.24.1+5018` |
| `XIO.exe` из пакета 0.24.2 | 79 360 Б | `67a279586c3f41f2779bbbe1cf08a2d323af4cd702d31457f433e0d12274669a` | `0.24.2+5019` |

`XIO-Full-0.24.2-windows-x64.zip` — 55 068 158 Б,
SHA-256 `bc7fb27d821ee9fd151f0f987a31e2c20a6151f8aae12b2111ef29e39a2af6ed`
(этот же digest отдаёт GitHub-ассет релиза 433728341).

## 1. Штамповка воспроизводима

`tooling/cross-platform/pe-version.py` на копии старого exe:

```text
$ python3 tooling/cross-platform/pe-version.py /tmp/stamped.exe --stamp --version 0.24.2+5019
$ sha256sum /tmp/stamped.exe
67a279586c3f41f2779bbbe1cf08a2d323af4cd702d31457f433e0d12274669a  /tmp/stamped.exe
```

Побайтово совпало с `XIO.exe` из выпуска: штамповка детерминирована, «на глаз»
ничего не дописывалось.

## 2. Меняются только 8 байт и только в VERSIONINFO

Сравнение старого (`0.24.1+5018`) и нового (`0.24.2+5019`) exe:

```text
размеры: 79 360 = 79 360
различий: 8 байт
  0x12c74 0x12c76 0x12c7c 0x12c7e   — VS_FIXEDFILEINFO (FILEVERSION/PRODUCTVERSION, 16-битные поля)
  0x12d5a 0x12d64                   — строка FileVersion  ("0.24.1+5018" -> "0.24.2+5019")
  0x12e9e 0x12ea8                   — строка ProductVersion
все — в секции .rsrc (.text/.rdata/.data/.pdata/.reloc не тронуты)
```

Разбор/сборка ресурса без потерь:

```text
$ python3 tooling/cross-platform/pe-version.py XIO.exe --self-test
{"resourceSize": 688, "rebuiltSize": 688, "identical": true, "trailingBytes": 0}
```

`--print` на выпущенном exe:

```text
FILEVERSION:     0.24.2.5019
PRODUCTVERSION:  0.24.2.5019
FileVersion:     0.24.2+5019
ProductVersion:  0.24.2+5019
```

## 3. Версия берётся из pubspec, а не из константы

`build-windows-on-linux.py` читает `version: X.Y.Z+B` из `app/pubspec.yaml`
(регэксп `^version:`), вызывает `pe-version.py --stamp` и тут же читает ресурс
обратно (`assert seen['FileVersion']==pe_version and seen['fileVersion']==pe_quad`).
Проверка источника — штамповка с подменённым pubspec:

```text
$ printf 'name: xio\nversion: 9.9.9+999\n' > /tmp/pubspec.yaml
$ python3 tooling/cross-platform/pe-version.py /tmp/exe.exe --stamp --pubspec /tmp/pubspec.yaml
FILEVERSION:     9.9.9.999
FileVersion:     9.9.9+999
```

Значит версия — производная от pubspec, константа в коде ни при чём.

## 4. Чтение независимыми инструментами

Windows (Win32-API, то же, что Свойства → Подробно), exe извлечён из **опубликованного** ZIP:

```text
FileVersion    : 0.24.2+5019
ProductVersion : 0.24.2+5019
OriginalFilename: XIO.exe
```

Debian, binutils (GNU, свой разбор PE, не наш скрипт):

```text
$ objdump -p new.exe | head -1
new.exe:     формат файла pei-x86-64
$ strings -el new.exe | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$'
0.24.2+5019
0.24.2+5019
$ strings -el old.exe | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$'
0.24.1+5018
0.24.1+5018
```

Debian, `pefile` 2024.8.26 (Python 3.13.5, отдельная библиотека):

```text
old.exe: fileVersion=0.24.1.5018 productVersion=0.24.1.5018
new.exe: fileVersion=0.24.2.5019 productVersion=0.24.2.5019
         resourceTypes=[3 (icon),14 (group icon),16 (version),24 (manifest)]
         fileOS=0x4 (VOS__WINDOWS32), fileType=1 (VFT_APP), warnings=[]
```

## 5. Альтернатива `rcedit` (проверена, в выпуске не использовалась)

`rcedit` v2.0.0 (`sha256 3e7801db1a5edbec91b49a24a094aad776cb4515488ea5a4ca2289c400eade2a`)
под wine 10.0 на Debian:

```text
$ wine rcedit-x64.exe rc.exe --set-file-version 0.24.2.5019 --set-product-version 0.24.2.5019 \
      --set-version-string FileVersion 0.24.2+5019 --set-version-string ProductVersion 0.24.2+5019
strings -el rc.exe -> 0.24.2+5019 (две строки)
pefile            -> fileVersion=0.24.2.5019 productVersion=0.24.2.5019
```

Значения те же, но байтовый результат другой: относительно исходного exe
изменилось 19 703 Б (вся секция `.rsrc` перезаписана с другим выравниванием),
размер файла и секции не изменились, иконка и манифест на месте. Поэтому в
релизном скрипте используется `pe-version.py` (8 байт), а `rcedit` остаётся
запасным вариантом на случай кода 2 «НУЖНА ПЕРЕЛИНКОВКА».

## 6. Что НЕ проверено

* Живой запуск `XIO.exe` на этом ПК — SAC блокирует неподписанные exe (машинная
  политика, не дефект пакета). Запуск под wine на Debian отрабатывает пробник
  (`verification/update-022-windows-extraction.json`: `peVersion=0.24.2+5019`,
  `archiveExtractionPassed=true`), но это не нативный Windows и не драйвер/UAC.
* Authenticode-подпись: exe не подписан, PE-чексумма в файле равна 0 (её и не
  было), поэтому правка ресурса ничего не инвалидирует.
* Нативная сборка из `Runner.rc` на Windows-хосте (недоступна из-за SAC) — там
  версия приходит из `FLUTTER_VERSION_*`, проверка описана в §3.4.
