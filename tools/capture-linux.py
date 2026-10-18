#!/usr/bin/env python3
"""Smoke-test the native Linux bundle in an isolated Xvfb display (Pillow needed)."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import time
from PIL import ImageGrab

root = Path(__file__).resolve().parent.parent
bundle = root / 'app/build/linux/x64/release/bundle'
version = re.search(r'^version: ([0-9]+\.[0-9]+)', (root/'app/pubspec.yaml').read_text(), re.M).group(1)
display = subprocess.Popen(['Xvfb', '-displayfd', '1', '-screen', '0', '1280x940x24', '-nolisten', 'tcp'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
app = None
try:
    number = display.stdout.readline().strip()
    if not number:
        raise RuntimeError('Xvfb did not initialize')
    with tempfile.TemporaryDirectory(prefix='x1o-smoke-') as data:
        env = dict(os.environ, DISPLAY=':'+number, GDK_BACKEND='x11', LIBGL_ALWAYS_SOFTWARE='1', XDG_DATA_HOME=data)
        with (root/f'verification/linux-run-{version}.log').open('w') as log:
            app = subprocess.Popen([str(bundle/'XIO')], cwd=bundle, env=env, stdout=log, stderr=subprocess.STDOUT)
            time.sleep(4)
            if app.poll() is not None:
                raise RuntimeError('Native Linux app exited during startup')
            screenshot = ImageGrab.grab(xdisplay=':'+number)
            screenshot.save(root/f'verification/linux-native-{version}.png')
            print('Native Linux window captured; process remained alive without touching host routes.')
finally:
    if app is not None and app.poll() is None:
        app.terminate()
        app.wait(timeout=8)
    display.terminate()
    display.wait(timeout=8)
