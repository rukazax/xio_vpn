#!/usr/bin/env python3
"""Offline catalogue integrity and bundled-font coverage (fontTools optional)."""
from pathlib import Path
import json, re, hashlib
root = Path(__file__).resolve().parent.parent
codes = 'ru en de es fr it pt zh ja ko tr hi ar'.split()
folder = root / 'app/assets/l10n'
source = json.loads((folder / 'ru.json').read_text())
placeholders = lambda s: sorted(re.findall(r'\{\d+\}', s))
fonts = sorted(p for p in (root/'app/assets/fonts').iterdir() if p.suffix in {'.ttf', '.otf'})
try:
    from fontTools.ttLib import TTFont
    glyphs = set().union(*(set(TTFont(p).getBestCmap()) for p in fonts))
except ImportError:
    glyphs = None
rows = []
for code in codes:
    path = folder / f'{code}.json'
    data = json.loads(path.read_text())
    assert data.keys() == source.keys(), f'{code}: missing/extra messages'
    for key, value in data.items():
        assert isinstance(value, str) and value.strip(), (code, key)
        assert placeholders(key) == placeholders(value), (code, key, 'placeholders')
        assert 'ZXQ' not in value, (code, key, 'translation marker')
        if code == 'ru': assert key == value
        else: assert not re.search('[А-Яа-яЁё]', value), (code, key, 'source text left over')
        if glyphs is not None:
            assert all(c.isspace() or ord(c) in glyphs for c in value), (code, key, 'missing glyph')
    rows.append({'language': code, 'messages': len(data), 'placeholdersValid': True,
                 'bundledGlyphCoverage': glyphs is not None, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
result = {'catalogues': rows, 'fontFiles': [{'file': p.name, 'bytes': p.stat().st_size,
          'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in fonts],
          'note': 'Structural checks and glyph coverage do not establish native-speaker translation quality.'}
version = re.search(r'^version: ([0-9]+\.[0-9]+)', (root/'app/pubspec.yaml').read_text(), re.M).group(1)
(root/f'verification/l10n-catalogues-{version}.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
print(f'{len(codes)} languages × {len(source)} messages: catalogue integrity passed; font coverage={glyphs is not None}')
