#!/usr/bin/env python3
"""Build the XIO CJK fallback font (subset of Noto Sans CJK SC Regular).

The release bundle used to ship the full 16.4 MB Noto Sans CJK SC OTF.  The
application only needs the CJK *fallback*: UI strings from `app/assets/l10n`,
plus everyday Chinese/Japanese/Korean text that users type themselves (server
names, tunnel names, filters).  Everything else — CJK Ext A/B/C, the
compatibility ideographs and the other rarely used blocks — is dropped.

Character policy (see `build_corpus`):

* every character of every `app/assets/l10n/*.json` locale and of the Dart
  sources (`app/lib`, `app/test`, `app/integration_test`, `app/assets/help`);
* the standard everyday CJK sets that every OS font ships: GB2312 (Simplified
  Chinese), JIS X 0208 (Japanese) and KS X 1001 (Korean) — so user-typed
  Chinese, Japanese and Korean names keep rendering from the bundled font and
  do not depend on system fallback;
* the full Hangul Syllables block (Korean can spell any syllable);
* kana, CJK punctuation, half/full-width forms, Bopomofo, CJK compatibility
  forms, Latin/Cyrillic/Greek basics and common punctuation/symbols.

Usage (from the repository root):

    pip install fonttools
    python tools/subset-cjk-font.py                 # regenerate the subset font
    python tools/subset-cjk-font.py --check         # verify without writing
    python tools/subset-cjk-font.py --mode minimal  # only l10n/source characters

`--check` exits non-zero when the committed subset no longer covers the corpus
(for example after a new locale string was added) or is not the same size as a
freshly generated one.
"""

from __future__ import annotations

import argparse
import glob
import json
import unicodedata
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = os.path.join(REPO, "app", "fonts-src", "NotoSansCJKsc-Regular.otf")
SUBSET = os.path.join(REPO, "app", "assets", "fonts", "NotoSansCJKsc-Regular.otf")

# Blocks that always stay, whatever their size.  The CJK ideograph blocks are
# added separately by the corpus builder.
KEEP_RANGES = [
    (0x20, 0x7E),      # basic Latin
    (0xA0, 0xFF),      # Latin-1 supplement
    (0x100, 0x17F),    # Latin Extended-A
    (0x180, 0x24F),    # Latin Extended-B
    (0x300, 0x36F),    # combining marks
    (0x370, 0x3FF),    # Greek
    (0x400, 0x4FF),    # Cyrillic
    (0x500, 0x52F),    # Cyrillic supplement
    (0x2000, 0x206F),  # general punctuation
    (0x20A0, 0x20CF),  # currency
    (0x2100, 0x214F),  # letterlike symbols
    (0x2150, 0x218F),  # number forms
    (0x2190, 0x21FF),  # arrows
    (0x2200, 0x22FF),  # mathematical operators
    (0x2500, 0x257F),  # box drawing
    (0x25A0, 0x25FF),  # geometric shapes
    (0x2600, 0x26FF),  # misc symbols
    (0x2700, 0x27BF),  # dingbats
    (0x2E80, 0x2EFF),  # CJK radicals supplement
    (0x2F00, 0x2FDF),  # Kangxi radicals
    (0x3000, 0x303F),  # CJK punctuation
    (0x3040, 0x309F),  # hiragana
    (0x30A0, 0x30FF),  # katakana
    (0x3100, 0x312F),  # bopomofo
    (0x3130, 0x318F),  # hangul compatibility jamo
    (0x3190, 0x319F),  # kanbun
    (0x31C0, 0x31EF),  # CJK strokes / katakana extensions
    (0x3200, 0x32FF),  # enclosed CJK letters/months
    (0x3300, 0x33FF),  # CJK compatibility
    (0xAC00, 0xD7A3),  # hangul syllables (full block)
    (0xF900, 0xFAFF),  # CJK compatibility ideographs
    (0xFE10, 0xFE1F),  # vertical forms
    (0xFE30, 0xFE4F),  # CJK compatibility forms
    (0xFF00, 0xFFEF),  # half/full-width forms
]

# Layout features are kept complete: only characters are dropped, so shaping
# cannot regress.  The cost of keeping them is a few hundred kilobytes.
LAYOUT_FEATURES = ["*"]


def _decode_set(codec: str) -> set[str]:
    out: set[str] = set()
    for hi in range(0xA1, 0xFF):
        for lo in range(0xA1, 0xFF):
            try:
                ch = bytes([hi, lo]).decode(codec)
            except Exception:
                continue
            if len(ch) == 1:
                out.add(ch)
    return out


def everyday_cjk() -> set[str]:
    """GB2312 + JIS X 0208 + KS X 1001 — the everyday CJK character sets."""
    chars: set[str] = set()
    for codec in ("gb2312", "euc_jp", "euc_kr"):
        chars |= _decode_set(codec)
    return chars


def l10n_chars() -> set[str]:
    chars: set[str] = set()
    for path in sorted(glob.glob(os.path.join(REPO, "app/assets/l10n/*.json"))):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, str):
                chars |= set(node)
    return chars


def source_chars() -> set[str]:
    chars: set[str] = set()
    patterns = [
        "app/lib/**/*.dart",
        "app/test/**/*.dart",
        "app/integration_test/**/*.dart",
        "app/assets/help/*.json",
        "app/assets/help/*.txt",
    ]
    for pattern in patterns:
        for path in glob.glob(os.path.join(REPO, pattern), recursive=True):
            with open(path, encoding="utf-8", errors="replace") as fh:
                chars |= set(fh.read())
    return chars


def expand_ranges(pairs) -> set[str]:
    chars: set[str] = set()
    for lo, hi in pairs:
        chars |= {chr(cp) for cp in range(lo, hi + 1)}
    return chars


def build_corpus(mode: str = "everyday") -> tuple[set[str], dict[str, int]]:
    core = l10n_chars() | source_chars()
    chars = set(core)
    prov = {"l10n+source chars": len(core)}
    if mode == "minimal":
        chars |= expand_ranges([p for p in KEEP_RANGES if p[0] < 0x3000])
    else:
        cjk = everyday_cjk()
        prov["everyday CJK set (GB2312/JIS0208/KSX1001)"] = len(cjk)
        chars |= cjk
        chars |= expand_ranges(KEEP_RANGES)
    # Control characters (newlines from the sources, etc.) have no glyphs.
    chars = {c for c in chars if unicodedata.category(c)[0] != "C"}
    return chars, prov


def subset_font(master: str, out: str, chars: set[str]) -> dict:
    from fontTools import subset

    opts = subset.Options()
    opts.layout_features = LAYOUT_FEATURES
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    opts.recalc_bounds = True
    opts.hinting = True
    opts.desubroutinize = False
    opts.recalc_timestamp = False
    font = subset.load_font(master, opts)
    subsetter = subset.Subsetter(options=opts)
    subsetter.populate(text="".join(sorted(chars)))
    subsetter.subset(font)
    subset.save_font(font, out, opts)
    return {"glyphs": font["maxp"].numGlyphs}


def coverage(subset_path: str, master_path: str, chars: set[str]) -> tuple[list[str], list[str]]:
    """Compare the subset with the master font for the requested characters.

    Returns (missing, absent):
      missing — characters the master renders but the subset does not (a real
                regression: the glyph would disappear from the UI);
      absent  — characters the master never had (the subset is not to blame;
                those come from another fallback family or from a block the
                master simply does not cover).
    """
    from fontTools.pens.boundsPen import BoundsPen
    from fontTools.ttLib import TTFont

    def load(path):
        font = TTFont(path, lazy=False)
        glyph_set = font.getGlyphSet()
        cache: dict[str, bool] = {}

        def renders(glyph_name: str) -> bool:
            if glyph_name not in cache:
                pen = BoundsPen(glyph_set)
                try:
                    glyph_set[glyph_name].draw(pen)
                except Exception:
                    pen.bounds = None
                cache[glyph_name] = pen.bounds is not None
            return cache[glyph_name]

        return font.getBestCmap(), renders

    master_cmap, master_renders = load(master_path)
    subset_cmap, subset_renders = load(subset_path)

    missing: list[str] = []
    absent: list[str] = []
    for ch in sorted(chars):
        cp = ord(ch)
        master_glyph = master_cmap.get(cp)
        if master_glyph is None or not master_renders(master_glyph):
            absent.append(ch)
            continue
        subset_glyph = subset_cmap.get(cp)
        if subset_glyph is None or not subset_renders(subset_glyph):
            missing.append(ch)
    return missing, absent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("everyday", "minimal"), default="everyday",
                    help="everyday (default): everyday CJK sets; minimal: only shipped strings")
    ap.add_argument("--master", default=MASTER, help="pristine Noto Sans CJK SC Regular OTF")
    ap.add_argument("--out", default=SUBSET, help="subset file to write")
    ap.add_argument("--check", action="store_true", help="verify the committed subset, do not write")
    args = ap.parse_args()

    try:
        from fontTools import subset  # noqa: F401
        from fontTools.ttLib import TTFont  # noqa: F401
    except ImportError as exc:
        print(f"error: working fonttools is required (python -m pip install fonttools): {exc}",
              file=sys.stderr)
        return 2

    chars, prov = build_corpus(args.mode)
    print(f"corpus ({args.mode}): {len(chars)} characters")
    for name, count in prov.items():
        print(f"  {name}: {count}")

    if not os.path.exists(args.master):
        print(f"error: master font not found: {args.master}", file=sys.stderr)
        print("The pristine font is kept in app/fonts-src/ and is not bundled.", file=sys.stderr)
        return 2

    if args.check:
        if not os.path.exists(args.out):
            print(f"error: subset not found: {args.out}", file=sys.stderr)
            return 2
        from fontTools.ttLib import TTFont

        font = TTFont(args.out, lazy=False)
        size = os.path.getsize(args.out)
        missing, absent = coverage(args.out, args.master, chars)
        print(f"subset: {args.out} ({size} bytes, {font['maxp'].numGlyphs} glyphs)")
        print(f"  characters the master does not cover (skipped): {len(absent)}")
        if missing:
            print(f"FAIL: {len(missing)} corpus characters lost from the subset:", file=sys.stderr)
            print("  " + " ".join(f"U+{ord(c):04X}" for c in missing[:40]), file=sys.stderr)
            return 1
        print("OK: every corpus character the master renders also renders from the subset")
        return 0

    if os.path.abspath(args.out) == os.path.abspath(args.master):
        print("error: refusing to overwrite the master font", file=sys.stderr)
        return 2

    info = subset_font(args.master, args.out, chars)
    before = os.path.getsize(args.master)
    after = os.path.getsize(args.out)
    missing, absent = coverage(args.out, args.master, chars)
    print(f"subset: {args.out}")
    print(f"  glyphs: {info['glyphs']}")
    print(f"  size: {before} -> {after} bytes ({before / 1048576:.2f} -> {after / 1048576:.2f} MiB, "
          f"-{(before - after) / 1048576:.2f} MiB)")
    print(f"  characters the master does not cover (skipped): {len(absent)}")
    if missing:
        print(f"FAIL: {len(missing)} characters lost after subsetting", file=sys.stderr)
        return 1
    print("OK: coverage verified against the master font")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

