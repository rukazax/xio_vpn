#!/usr/bin/env python3
"""Documentation self-check for the XIO repository.

Checks, without any third-party dependency:

1. every relative link and image target in the audited markdown exists;
2. every in-page anchor resolves to a heading of the target file
   (GitHub slug rules, Cyrillic included);
3. every ```mermaid block parses as the flowchart subset used by this repository;
4. every SVG under docs/ is well-formed XML and has no external references
   (no <script>, no <image href>, no xlink:href, no @import, no url(http...)).

Usage:
    python3 docs/check-docs-links.py            # files this task owns
    python3 docs/check-docs-links.py --all      # the whole documentation tree
    python3 docs/check-docs-links.py README.md docs/features.md

Exit code 0 when the audited files are clean, 1 otherwise. Findings in files
that this task did not touch are reported as warnings, so a pre-existing defect
does not block the check but is still visible.
"""

from __future__ import annotations

import os
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files owned by this task: an error here fails the run.
AUDITED = [
    "README.md",
    "README.ru.md",
    "docs/features.md",
    "docs/features.ru.md",
    "docs/screenshots/README.md",
    "docs/landing/architecture.mmd",
]

SKIP_DIRS = {"vendor", "history", "native-sources", "patches", "publishing", "research", ".git"}

FENCE = re.compile(r"^```(\w*)\s*$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*([^)\s]+?)(?:\s+\"[^\"]*\")?\s*\)")
HTML_REF = re.compile(r"""\b(?:src|href)\s*=\s*"([^"]+)\"""")
INLINE_CODE = re.compile(r"`[^`\n]*`")


# --------------------------------------------------------------------- helpers
def rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def github_slug(text: str) -> str:
    """Reproduce GitHub's heading anchor for the subset used here."""
    text = text.strip()
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links -> label
    text = text.replace("`", "").replace("*", "")
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = text.lower().replace(" ", "-")
    return text


def split_markdown(text: str):
    """Return (prose, fenced) where fenced maps language -> list of block bodies."""
    prose_lines: list[str] = []
    fenced: list[tuple[str, str, int]] = []
    current: list[str] | None = None
    lang = ""
    start = 0
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE.match(line)
        if current is None:
            if match:
                current = []
                lang = (match.group(1) or "").lower()
                start = number
            else:
                prose_lines.append(line)
        else:
            if match:
                fenced.append((lang, "\n".join(current), start))
                current = None
            else:
                current.append(line)
    if current is not None:  # unterminated fence
        fenced.append((lang, "\n".join(current), start))
    return "\n".join(prose_lines), fenced


def anchors_of(path: str) -> set[str]:
    text = read(path)
    prose, _ = split_markdown(text)
    seen: dict[str, int] = {}
    out: set[str] = set()
    for line in prose.splitlines():
        match = HEADING.match(line)
        if not match:
            continue
        slug = github_slug(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        out.add(slug if count == 0 else "%s-%d" % (slug, count))
    return out


# ---------------------------------------------------------------------- mermaid
NODE_ID = r"[A-Za-z0-9_\u0400-\u04FF][A-Za-z0-9_\u0400-\u04FF.-]*"
SHAPES = [
    r'\[\[.*?\]\]',            # subroutine
    r'\(\(.*?\)\)',            # circle
    r'\[\(.*?\)\]',            # stadium
    r'\[\/.*?\/\]',            # parallelogram
    r'\[\\.*?\\\]',            # parallelogram alt
    r'\{\{.*?\}\}',            # hexagon
    r'\[.*?\]',                # rectangle
    r'\(.*?\)',                # rounded
    r'\{.*?\}',                # rhombus
    r'>.*?\]',                 # asymmetric
]
NODE = r'(?:%s)(?:%s)?' % (NODE_ID, "|".join(SHAPES))
EDGE = r'(?:-->|-\.->|---|==>|--x|--o|~~~)'
EDGE_WITH_LABEL = r'%s(?:\|[^|]*\|)?' % EDGE
CHAIN = r'%s(?:\s*%s\s*%s)*' % (NODE, EDGE_WITH_LABEL, NODE)
STATEMENT = re.compile(r"^\s*%s\s*;?\s*$|^\s*%s\s*$" % (CHAIN, NODE))
SUBGRAPH = re.compile(r'^\s*subgraph\s+%s\s*(?:\[[^\]]*\])?\s*$' % NODE_ID)
DIRECTION = re.compile(r"^\s*direction\s+(TB|TD|BT|LR|RL)\s*$")
STYLE_LINE = re.compile(r"^\s*(classDef|class|style|linkStyle|click|accTitle|accDescr)\b")
HEADER = re.compile(r"^\s*(flowchart|graph)\s+(LR|TD|TB|RL|BT)\s*$")


def check_mermaid(block: str, where: str, fail) -> None:
    """Validate the flowchart subset; unknown lines are reported, not guessed."""
    lines = [line for line in block.splitlines() if line.strip() and not line.strip().startswith("%%")]
    if not lines:
        fail("%s: empty Mermaid block" % where)
        return
    if not HEADER.match(lines[0]):
        fail("%s: Mermaid must start with 'flowchart LR|TD|TB|RL|BT' or 'graph ...'" % where)
        return

    open_subgraphs: list[str] = []
    for number, line in enumerate(lines[1:], start=2):
        stripped = line.strip()
        if stripped == "end":
            if not open_subgraphs:
                fail("%s: '%s' closes a subgraph that was never opened" % (where, stripped))
            else:
                open_subgraphs.pop()
            continue
        match = SUBGRAPH.match(line)
        if match:
            open_subgraphs.append(stripped)
            continue
        if DIRECTION.match(line) or STYLE_LINE.match(line):
            continue
        if stripped.count('"') % 2:
            fail("%s: unbalanced quote in Mermaid line: %s" % (where, stripped))
            continue
        if STATEMENT.match(line):
            continue
        fail("%s: cannot parse Mermaid line: %s" % (where, stripped))

    if open_subgraphs:
        fail("%s: %d subgraph(s) without 'end'" % (where, len(open_subgraphs)))


# ------------------------------------------------------------------- collectors
def resolve(base_file: str, target: str):
    """Return (absolute_path, anchor|None) or None for external links."""
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return None
    path = unquote(parts.path)
    anchor = unquote(parts.fragment) if parts.fragment else None
    if not path:
        return base_file, anchor
    if path.startswith("/"):
        absolute = os.path.join(ROOT, path.lstrip("/"))
    else:
        absolute = os.path.normpath(os.path.join(os.path.dirname(base_file), path))
    return absolute, anchor


def scan_markdown(path: str, strict: bool, errors, warnings, stats) -> None:
    text = read(path)
    prose, fenced = split_markdown(text)
    where_base = rel(path)

    for lang, body, line_no in fenced:
        if lang == "mermaid":
            stats["mermaid"] += 1
            check_mermaid(
                body,
                "%s:%d" % (where_base, line_no),
                errors.append if strict else warnings.append,
            )

    # headings of this file for local anchors
    local_anchors = anchors_of(path)
    anchor_cache: dict[str, set[str]] = {path: local_anchors}

    flat = INLINE_CODE.sub(" ", prose)
    targets = [(m.group(1), "link") for m in MD_LINK.finditer(flat)]
    targets += [(m.group(1), "ref") for m in HTML_REF.finditer(flat)]

    for target, kind in targets:
        if target.startswith("#") and kind == "ref":
            continue
        resolved = resolve(path, target)
        if resolved is None:
            stats["external"] += 1
            continue
        absolute, anchor = resolved
        stats["internal"] += 1
        if not os.path.exists(absolute):
            errors.append("%s: missing target %r" % (where_base, target))
            continue
        if os.path.isdir(absolute):
            continue
        if anchor and absolute.endswith(".md"):
            if absolute not in anchor_cache:
                anchor_cache[absolute] = anchors_of(absolute)
            if anchor not in anchor_cache[absolute]:
                message = "%s: anchor #%s not found in %s" % (
                    where_base,
                    anchor,
                    rel(absolute),
                )
                (errors if strict else warnings).append(message)
        if absolute.endswith(".md") and strict and absolute != path:
            # audited files must not point at markdown outside the repo docs
            if not os.path.isfile(absolute):
                errors.append("%s: %r is not a file" % (where_base, target))


def scan_svg(path: str, errors, stats) -> None:
    stats["svg"] += 1
    name = rel(path)
    text = read(path)
    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        errors.append("%s: not well-formed XML (%s)" % (name, exc))
        return
    lowered = text.lower()
    for needle, why in (
        ("<script", "script element"),
        ("<image", "embedded image"),
        ("xlink:href", "xlink reference"),
        ("@import", "CSS import"),
        ("font-face", "embedded font"),
    ):
        if needle in lowered:
            errors.append("%s: external dependency (%s)" % (name, why))
    for match in re.finditer(r"url\(([^)]*)\)", text):
        if "http" in match.group(1).lower():
            errors.append("%s: url() points outside the file" % name)


def collect(with_all: bool) -> list[str]:
    files: list[str] = []
    for name in AUDITED:
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            files.append(path)
    if with_all:
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in names:
                if name.endswith(".md"):
                    path = os.path.join(base, name)
                    if path not in files:
                        files.append(path)
    return files


def main(argv: list[str]) -> int:
    with_all = "--all" in argv
    explicit = [a for a in argv[1:] if not a.startswith("-")]
    if explicit:
        targets = [os.path.abspath(a) for a in explicit]
    else:
        targets = collect(with_all)

    audited = {os.path.join(ROOT, name) for name in AUDITED}
    errors: list[str] = []
    warnings: list[str] = []
    stats = {"internal": 0, "external": 0, "mermaid": 0, "svg": 0, "files": 0}

    for path in targets:
        if not os.path.isfile(path):
            errors.append("no such file: %s" % path)
            continue
        stats["files"] += 1
        strict = path in audited or explicit and path in {os.path.abspath(a) for a in explicit}
        if path.endswith(".mmd"):
            body = read(path)
            stats["mermaid"] += 1
            check_mermaid(body, rel(path), errors.append if strict else warnings.append)
        elif path.endswith(".md"):
            scan_markdown(path, strict, errors, warnings, stats)

    svg_dir = os.path.join(ROOT, "docs")
    for base, dirs, names in os.walk(svg_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            if name.endswith(".svg"):
                scan_svg(os.path.join(base, name), errors, stats)

    print("files: %d · internal links: %d · external: %d · mermaid blocks: %d · svg: %d"
          % (stats["files"], stats["internal"], stats["external"], stats["mermaid"], stats["svg"]))
    for item in warnings:
        print("WARN  " + item)
    for item in errors:
        print("ERROR " + item)
    print("result: %d error(s), %d warning(s)" % (len(errors), len(warnings)))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
