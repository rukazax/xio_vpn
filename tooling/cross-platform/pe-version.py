#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Прочитать или перепроштамповать VERSIONINFO (PE-ресурс 16) в Windows-бинарнике.

Зачем: Windows-runner для `XIO.exe` приходит готовым (--runner в
build-windows-on-linux.py), поэтому версия в PE-ресурсе — это версия той сборки,
из которой раннер взяли, а не текущего выпуска. В 0.24.2 так и вышло: пакет
0.24.2+5019, а `XIO.exe` внутри — 0.24.1+5018.

Модуль не перелинковывает файл: он находит ресурс VERSIONINFO в уже собранном
PE и заменяет в нём
  * VS_FIXEDFILEINFO (FILEVERSION / PRODUCTVERSION — четыре 16-битных числа),
  * строки FileVersion / ProductVersion в StringFileInfo.
Размер ресурса при этом не уменьшается: новый блок дополняется нулями до старого
размера (или растёт в свободный хвост секции .rsrc, если места хватает).
Windows ищет данные по Size из IMAGE_RESOURCE_DATA_ENTRY, а внутри блока — по
wLength корневого узла, поэтому хвостовые нули безопасны.

Если строка версии стала настолько длиннее, что в секции нет места, скрипт
честно падает с кодом 2 — тогда нужен раннер, собранный из Runner.rc
(нативная сборка на Windows или `x86_64-w64-mingw32-g++` из
`tooling/cross-platform/windows_runner.cpp`, см. docs/release-process.ru.md).

Примеры:
  pe-version.py --print releases/XIO.exe
  pe-version.py --print releases/XIO.exe --json
  pe-version.py --stamp releases/XIO.exe --pubspec app/pubspec.yaml
  pe-version.py releases/XIO.exe --expect 0.24.2+5019
  pe-version.py --self-test releases/XIO.exe
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

RT_VERSION = 16
VS_FIXEDFILEINFO_SIGNATURE = 0xFEEF04BD
#: Смещения внутри VS_FIXEDFILEINFO (52 байта).
OFF_FILE_MS, OFF_FILE_LS, OFF_PRODUCT_MS, OFF_PRODUCT_LS = 8, 12, 16, 20


class PeError(RuntimeError):
    """Файл не является PE или в нём нет пригодного VERSIONINFO."""


class NoRoomError(PeError):
    """Новый блок версии не влезает в секцию .rsrc — нужна перелинковка."""


# --- PE: заголовки и карта секций -------------------------------------------


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int


@dataclass
class ResourceLeaf:
    rva: int
    size: int
    code_page: int


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_sections(data: bytes) -> List[Section]:
    if data[:2] != b"MZ":
        raise PeError("нет сигнатуры MZ (это не PE-файл)")
    pe = _u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        raise PeError("нет сигнатуры PE (это не PE-файл)")
    coff = pe + 4
    count = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise PeError(f"неизвестный magic optional header: 0x{magic:04x}")
    table = opt + opt_size
    sections: List[Section] = []
    for index in range(count):
        base = table + index * 40
        name = data[base : base + 8].rstrip(b"\0").decode("latin-1")
        sections.append(
            Section(
                name=name,
                virtual_size=_u32(data, base + 8),
                virtual_address=_u32(data, base + 12),
                raw_size=_u32(data, base + 16),
                raw_pointer=_u32(data, base + 20),
            )
        )
    return sections


def rva_to_offset(sections: List[Section], rva: int) -> int:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            if delta >= section.raw_size:
                raise PeError(f"RVA 0x{rva:x} указывает за сырые данные секции {section.name}")
            return section.raw_pointer + delta
    raise PeError(f"RVA 0x{rva:x} не принадлежит ни одной секции")


def _resource_dir_root(data: bytes, sections: List[Section]) -> int:
    pe = _u32(data, 0x3C)
    opt = pe + 4 + 20
    magic = _u16(data, opt)
    directories = opt + (96 if magic == 0x10B else 112)
    rva = _u32(data, directories + 2 * 8)
    if not rva:
        raise PeError("в файле нет таблицы ресурсов")
    return rva_to_offset(sections, rva)


def find_version_leaf(data: bytes, sections: List[Section]) -> ResourceLeaf:
    """Найти IMAGE_RESOURCE_DATA_ENTRY ресурса RT_VERSION/1 (любой язык)."""
    base = _resource_dir_root(data, sections)

    def entries(dir_offset: int):
        named = _u16(data, dir_offset + 12)
        ids = _u16(data, dir_offset + 14)
        start = dir_offset + 16
        for index in range(named + ids):
            entry = start + index * 8
            name = _u32(data, entry)
            target = _u32(data, entry + 4)
            yield name, target

    for name, target in entries(base):
        if name & 0x80000000 or name != RT_VERSION:
            continue
        if not target & 0x80000000:
            continue
        for _name, second in entries(base + (target & 0x7FFFFFFF)):
            if not second & 0x80000000:
                continue
            for _lang, leaf in entries(base + (second & 0x7FFFFFFF)):
                if leaf & 0x80000000:
                    continue  # вложенность глубже языка не встречается
                at = base + leaf
                return ResourceLeaf(
                    rva=_u32(data, at),
                    size=_u32(data, at + 4),
                    code_page=_u32(data, at + 8),
                )
    raise PeError("ресурс VERSIONINFO (тип 16, id 1) не найден")


# --- VERSIONINFO: дерево и сериализация -------------------------------------


@dataclass
class Node:
    key: str
    value: bytes = b""
    value_length: int = 0
    value_type: int = 0
    children: List["Node"] = field(default_factory=list)
    #: wValueLength как он записан в файле (для строк — в WCHAR, для бинарника — в байтах)
    text: Optional[str] = None

    def child(self, key: str) -> Optional["Node"]:
        for item in self.children:
            if item.key == key:
                return item
        return None


def _pad4(size: int) -> int:
    return (size + 3) & ~3


def parse_node(data: bytes, offset: int, limit: int, depth: int = 0) -> Node:
    if depth > 6:
        raise PeError("слишком глубокая вложенность VERSIONINFO")
    if offset + 6 > limit:
        raise PeError("обрыв структуры VERSIONINFO")
    length = _u16(data, offset)
    value_length = _u16(data, offset + 2)
    value_type = _u16(data, offset + 4)
    if length < 6 or offset + length > limit:
        raise PeError(f"некорректная длина узла VERSIONINFO: {length}")
    cursor = offset + 6
    end = offset + length
    chars = []
    while cursor + 1 < end:
        char = _u16(data, cursor)
        cursor += 2
        if char == 0:
            break
        chars.append(chr(char))
    cursor = _pad4(cursor)
    node = Node(key="".join(chars), value_length=value_length, value_type=value_type)
    if value_type == 1 and value_length:
        byte_length = value_length * 2
        node.text = data[cursor : cursor + byte_length].decode("utf-16-le").rstrip("\0")
        node.value = data[cursor : cursor + byte_length]
        cursor += byte_length
    else:
        node.value = data[cursor : cursor + value_length]
        cursor += value_length
    cursor = _pad4(cursor)
    while cursor + 6 <= end:
        child_length = _u16(data, cursor)
        if child_length == 0:
            break
        child = parse_node(data, cursor, end, depth + 1)
        node.children.append(child)
        cursor = _pad4(cursor + child_length)
    return node


def serialize_node(node: Node) -> bytes:
    """Собрать узел обратно. Длина узла — ровно его байты, без хвостового выравнивания:
    выравнивание до 4 добавляет родитель (как это делает windres/MSVC)."""
    key = node.key.encode("utf-16-le") + b"\0\0"
    # Пустой wValueLength — у контейнеров (StringFileInfo, StringTable, VarFileInfo):
    # они не пишут ни байта значения, за ними сразу идут дочерние структуры.
    if node.value_length == 0:
        value, value_length = b"", 0
    elif node.text is not None:
        value = node.text.encode("utf-16-le") + b"\0\0"
        value_length = len(node.text) + 1
    else:
        value = node.value
        value_length = node.value_length
    body = bytearray()
    body += b"\0" * 6  # wLength/wValueLength/wType заполняются ниже
    body += key
    body += b"\0" * (_pad4(len(body)) - len(body))
    body += value
    if node.children:
        body += b"\0" * (_pad4(len(body)) - len(body))
        for child in node.children:
            body += serialize_node(child)
            body += b"\0" * (_pad4(len(body)) - len(body))
    struct.pack_into("<HHH", body, 0, len(body), value_length, node.value_type)
    return bytes(body)


# --- Версия -----------------------------------------------------------------


def version_parts(version: str) -> Tuple[int, int, int, int]:
    """'0.24.2+5019' → (0, 24, 2, 5019)."""
    match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)(?:\+(\d+))?\s*", version)
    if not match:
        raise ValueError(f"версия {version!r} не в формате X.Y.Z+B")
    major, minor, patch, build = (int(group) if group else 0 for group in match.groups())
    for number in (major, minor, patch, build):
        if number > 0xFFFF:
            raise ValueError(f"версия {version!r} не помещается в 16-битные поля FILEVERSION")
    return major, minor, patch, build


def read_version(path: Path) -> dict:
    data = path.read_bytes()
    sections = read_sections(data)
    leaf = find_version_leaf(data, sections)
    offset = rva_to_offset(sections, leaf.rva)
    root = parse_node(data, offset, offset + leaf.size)
    if root.key != "VS_VERSION_INFO":
        raise PeError(f"ожидался VS_VERSION_INFO, получено {root.key!r}")
    fixed = root.value
    if len(fixed) < 52 or struct.unpack_from("<I", fixed, 0)[0] != VS_FIXEDFILEINFO_SIGNATURE:
        raise PeError("VS_FIXEDFILEINFO отсутствует или повреждён")
    file_ms, file_ls, product_ms, product_ls = struct.unpack_from("<IIII", fixed, OFF_FILE_MS)

    def quad(ms: int, ls: int) -> str:
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

    strings = {}
    table = root.child("StringFileInfo")
    if table:
        for block in table.children:
            for item in block.children:
                strings[item.key] = item.text
    return {
        "file": str(path),
        "fileVersion": quad(file_ms, file_ls),
        "productVersion": quad(product_ms, product_ls),
        "FileVersion": strings.get("FileVersion"),
        "ProductVersion": strings.get("ProductVersion"),
        "resourceSize": leaf.size,
        "resourceOffset": offset,
    }


def stamp_version(path: Path, version: str) -> dict:
    """Записать версию из `version` (X.Y.Z+B) в PE-ресурс файла `path`."""
    major, minor, patch, build = version_parts(version)
    data = bytearray(path.read_bytes())
    sections = read_sections(bytes(data))
    leaf = find_version_leaf(bytes(data), sections)
    offset = rva_to_offset(sections, leaf.rva)
    root = parse_node(bytes(data), offset, offset + leaf.size)

    fixed = bytearray(root.value)
    struct.pack_into("<I", fixed, OFF_FILE_MS, (major << 16) | minor)
    struct.pack_into("<I", fixed, OFF_FILE_LS, (patch << 16) | build)
    struct.pack_into("<I", fixed, OFF_PRODUCT_MS, (major << 16) | minor)
    struct.pack_into("<I", fixed, OFF_PRODUCT_LS, (patch << 16) | build)
    root.value = bytes(fixed)
    root.text = None

    table = root.child("StringFileInfo")
    if table is None or not table.children:
        raise PeError("в VERSIONINFO нет StringFileInfo — нечего штамповать")
    for block in table.children:
        for item in block.children:
            if item.key in ("FileVersion", "ProductVersion"):
                item.text = version
            elif item.key == "OriginalFilename" and item.text is None:
                item.text = path.name

    blob = serialize_node(root)
    section = next(
        (item for item in sections if item.raw_pointer <= offset < item.raw_pointer + item.raw_size),
        None,
    )
    if section is None:
        raise PeError("ресурс VERSIONINFO лежит вне сырых данных секции")
    room = section.raw_pointer + section.raw_size - offset
    if len(blob) > room:
        raise NoRoomError(
            f"новая версия {version} требует {len(blob)} Б, а в секции .rsrc под ресурс "
            f"осталось {room} Б (было {leaf.size}) — нужен раннер, собранный из Runner.rc"
        )
    # IMAGE_RESOURCE_DATA_ENTRY.Size — единственное поле каталога, которое меняется.
    entry = next(
        (at for at in _data_entry_offsets(bytes(data), sections) if _u32(bytes(data), at) == leaf.rva),
        None,
    )
    if entry is None:
        raise PeError("не найден IMAGE_RESOURCE_DATA_ENTRY для VERSIONINFO")
    # Хвост ресурса дополняется нулями только до СТАРОГО размера (или до нового,
    # если блок вырос): за пределами ресурса в секции .rsrc лежат другие ресурсы,
    # и трогать их нельзя.
    written = max(leaf.size, len(blob))
    data[offset : offset + len(blob)] = blob
    data[offset + len(blob) : offset + written] = b"\0" * (written - len(blob))
    struct.pack_into("<I", data, entry + 4, len(blob))
    path.write_bytes(bytes(data))
    result = read_version(path)
    if (result["FileVersion"] or "") != version:
        raise PeError(f"после штамповки FileVersion={result['FileVersion']!r}, ожидалось {version!r}")
    if result["productVersion"] != result["fileVersion"]:
        raise PeError("FILEVERSION и PRODUCTVERSION разошлись после штамповки")
    return result


def _data_entry_offsets(data: bytes, sections: List[Section]) -> List[int]:
    """Смещения всех IMAGE_RESOURCE_DATA_ENTRY в файле."""
    base = _resource_dir_root(data, sections)
    result: List[int] = []
    seen = set()

    def walk(dir_offset: int, depth: int) -> None:
        if depth > 3 or dir_offset in seen:
            return
        seen.add(dir_offset)
        named = _u16(data, dir_offset + 12)
        ids = _u16(data, dir_offset + 14)
        start = dir_offset + 16
        for index in range(named + ids):
            entry = start + index * 8
            target = _u32(data, entry + 4)
            if target & 0x80000000:
                walk(base + (target & 0x7FFFFFFF), depth + 1)
            else:
                result.append(base + target)

    walk(base, 0)
    return result


def self_test(path: Path) -> dict:
    """Разобрать и заново собрать ресурс: байты должны совпасть с исходными."""
    data = path.read_bytes()
    sections = read_sections(data)
    leaf = find_version_leaf(data, sections)
    offset = rva_to_offset(sections, leaf.rva)
    original = data[offset : offset + leaf.size]
    root = parse_node(data, offset, offset + leaf.size)
    rebuilt = serialize_node(root)
    return {
        "file": str(path),
        "resourceSize": leaf.size,
        "rebuiltSize": len(rebuilt),
        "identical": rebuilt == original[: len(rebuilt)],
        "trailingBytes": leaf.size - len(rebuilt),
    }


def pubspec_version(pubspec: Path) -> str:
    text = pubspec.read_text(encoding="utf-8")
    match = re.search(r"^version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\+[0-9]+)?)\s*$", text, re.M)
    if not match:
        raise ValueError(f"в {pubspec} нет строки 'version: X.Y.Z+B'")
    version = match.group(1)
    if "+" not in version:
        version += "+0"
    return version


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="VERSIONINFO в PE: чтение и перепроштамповка версии.")
    parser.add_argument("file", type=Path, help="PE-файл (например XIO.exe)")
    parser.add_argument("--print", dest="do_print", action="store_true", help="показать версию из ресурса")
    parser.add_argument("--json", action="store_true", help="вывод в JSON")
    parser.add_argument("--stamp", action="store_true", help="записать версию в ресурс")
    parser.add_argument("--pubspec", type=Path, help="взять версию из app/pubspec.yaml")
    parser.add_argument("--version", help="версия явно: X.Y.Z+B")
    parser.add_argument("--expect", metavar="VERSION", help="код 1, если версия в файле другая")
    parser.add_argument("--self-test", action="store_true", help="проверить точность разбора/сборки ресурса")
    args = parser.parse_args(argv)
    if not any((args.do_print, args.json, args.stamp, args.expect, args.self_test)):
        parser.error("нужно указать --print, --json, --stamp, --expect или --self-test")

    try:
        if args.self_test:
            report = self_test(args.file)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["identical"] else 1

        if args.stamp:
            version = args.version or (pubspec_version(args.pubspec) if args.pubspec else None)
            if not version:
                parser.error("--stamp требует --version или --pubspec")
            report = stamp_version(args.file, version)
            report["stamped"] = version
        else:
            report = read_version(args.file)

        if args.do_print or args.json or not (args.stamp or args.expect):
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(f"file:            {report['file']}")
                print(f"FILEVERSION:     {report['fileVersion']}")
                print(f"PRODUCTVERSION:  {report['productVersion']}")
                print(f"FileVersion:     {report['FileVersion']}")
                print(f"ProductVersion:  {report['ProductVersion']}")
                print(f"resource:        rva offset {report['resourceOffset']}, {report['resourceSize']} Б")

        if args.expect:
            actual = read_version(args.file)
            if (actual["FileVersion"] or "").strip() != args.expect.strip():
                print(
                    f"ВЕРСИЯ НЕ СОВПАЛА: в {args.file} FileVersion={actual['FileVersion']!r}, "
                    f"ожидалось {args.expect!r}",
                    file=sys.stderr,
                )
                return 1
        return 0
    except NoRoomError as error:
        print(f"НУЖНА ПЕРЕЛИНКОВКА: {error}", file=sys.stderr)
        return 2
    except (PeError, ValueError) as error:
        print(f"ОШИБКА: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
