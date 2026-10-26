#!/usr/bin/env python3
"""Run the production CIDR algebra checks without Android, network or root."""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess

root = Path(__file__).resolve().parent.parent
with TemporaryDirectory(prefix='xio-cidr-') as out:
    sources = [root/'app/android/app/src/main/java/app/xio/xio/IpRoutes.java',
               root/'app/android/app/src/test/java/app/xio/xio/IpRoutesCheck.java']
    subprocess.run(['javac', '--release', '17', '-d', out, *map(str, sources)], check=True)
    subprocess.run(['java', '-Xmx256m', '-cp', out, 'app.xio.xio.IpRoutesCheck'], check=True)
