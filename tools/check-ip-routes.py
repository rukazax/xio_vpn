#!/usr/bin/env python3
"""Run the production CIDR algebra checks without Android, network or root."""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess

root = Path(__file__).resolve().parent.parent
with TemporaryDirectory(prefix='x1o-cidr-') as out:
    sources = [root/'app/android/app/src/main/java/app/x1o/x1o/IpRoutes.java',
               root/'app/android/app/src/test/java/app/x1o/x1o/IpRoutesCheck.java']
    subprocess.run(['javac', '--release', '17', '-d', out, *map(str, sources)], check=True)
    subprocess.run(['java', '-Xmx256m', '-cp', out, 'app.x1o.x1o.IpRoutesCheck'], check=True)
