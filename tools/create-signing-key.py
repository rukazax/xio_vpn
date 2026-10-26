#!/usr/bin/env python3
"""Create a LOCAL development signing identity. Never archive .signing/."""
from pathlib import Path
import os
import secrets
import shutil
import subprocess

root = Path(__file__).resolve().parent.parent
directory = root / '.signing'
directory.mkdir(mode=0o700, exist_ok=True)
store = directory / 'xio-development.p12'
if store.exists():
    raise SystemExit('Existing signing key retained; refusing to replace it.')
java_home = os.environ.get('JAVA_HOME')
keytool = str(Path(java_home) / 'bin' / ('keytool.exe' if os.name == 'nt' else 'keytool')) if java_home else shutil.which('keytool')
if not keytool:
    raise SystemExit('Install a JDK and put keytool on PATH or set JAVA_HOME.')
password = secrets.token_urlsafe(36)
password_file = directory / 'key-password'
password_file.write_text(password)
password_file.chmod(0o600)
subprocess.run([keytool, '-genkeypair', '-alias', 'x1oDevelopment', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '3650', '-storetype', 'PKCS12', '-keystore', str(store), '-storepass:file', str(password_file), '-keypass:file', str(password_file), '-dname', 'CN=xio Development, O=xio'], check=True)
store.chmod(0o600)
properties = directory / 'signing.properties'
properties.write_text(f'storeFile={store.as_posix()}\nstorePassword={password}\nkeyPassword={password}\nkeyAlias=x1oDevelopment\n')
properties.chmod(0o600)
print('Development signing key created. Back up .signing privately; never publish it.')
