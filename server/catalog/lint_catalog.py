#!/usr/bin/env python3
"""Lint a XIO whitelist catalog artifact (contract §12, criteria 2 and 7)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lint_catalog.py")
    parser.add_argument("file", help="whitelist-YYYYMMDD.json to check")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    document = json.loads(Path(args.file).read_text(encoding="utf-8"))
    problems = catalog.lint_document(document)
    if problems:
        for problem in problems:
            sys.stderr.write(f"FAIL {problem}\n")
        return catalog.EXIT_IO
    if not args.quiet:
        counts = document.get("counts", {})
        sys.stdout.write(
            f"OK {counts.get('eligible')}/{counts.get('unique')} "
            f"content {document.get('contentSha256')}\n"
        )
    return catalog.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
