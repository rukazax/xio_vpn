"""Launcher declarations independent of service attribute order and formatting."""
import re
import xml.etree.ElementTree as ET

ANDROID = '{http://schemas.android.com/apk/res/android}'
VARIANTS = [f'{color}_{background}_{angle}' for color in ('green', 'white')
            for background in ('dark', 'clear') for angle in (0, 90, 180, 270)]


def validate_manifest(source):
    app = ET.fromstring(source).find('application')
    assert app is not None, 'Missing application'
    aliases = app.findall('activity-alias')
    expected = {'.launcher.' + name for name in VARIANTS}
    assert {a.get(ANDROID + 'name') for a in aliases} == expected and len(aliases) == 16, 'Missing or duplicate XIO launcher aliases'
    assert sum(a.get(ANDROID + 'enabled') == 'true' for a in aliases) == 1, 'Exactly one launcher must be enabled by default'
    for a in aliases:
        assert a.get(ANDROID + 'targetActivity') == '.MainActivity'
        assert a.get(ANDROID + 'exported') == 'true'
        assert a.get(ANDROID + 'icon', '').startswith('@mipmap/xio_')
        assert any(f.find("action[@" + ANDROID + "name='android.intent.action.MAIN']") is not None and
                   f.find("category[@" + ANDROID + "name='android.intent.category.LAUNCHER']") is not None
                   for f in a.findall('intent-filter')), 'Missing launcher intent'


def install_aliases(source):
    # Anchor to the target activity itself; adding attributes to a service must
    # never silently delete every launcher, as happened in the 0.16 generator.
    source = re.sub(r'\s*<activity-alias\b[^>]*>.*?</activity-alias>', '', source, flags=re.S)
    matches = list(re.finditer(r'<activity\b[^>]*android:name="\.MainActivity"[^>]*>.*?</activity>', source, re.S))
    if len(matches) != 1:
        raise ValueError('Expected exactly one MainActivity; manifest left unchanged')
    activity = matches[0]
    def keep_other_intents(match):
        text = match.group()
        return '' if 'android.intent.action.MAIN' in text and 'android.intent.category.LAUNCHER' in text else text
    main = re.sub(r'<intent-filter\b[^>]*>.*?</intent-filter>', keep_other_intents, activity.group(), flags=re.S)
    aliases = ''.join(f'''
        <activity-alias android:name=".launcher.{name}" android:targetActivity=".MainActivity" android:enabled="{'true' if i == 0 else 'false'}" android:exported="true" android:label="XIO" android:icon="@mipmap/xio_{name}">
            <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
        </activity-alias>''' for i, name in enumerate(VARIANTS))
    result = source[:activity.start()] + main + aliases + source[activity.end():]
    validate_manifest(result)
    return result
