#!/usr/bin/env python3
"""Local unit-fixture runner. Never starts Linux services or accesses a VPS.

Windows shims exist only in this test process; production modules stay Linux-only.
"""
import os
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parent.parent


def linux_only(*args, **kwargs):
    raise AssertionError('Unmocked Linux-only operation in local unit fixture')


if os.name == 'nt':
    import msvcrt
    def fixture_flock(file, operation):
        if operation != 2:
            raise AssertionError('Unsupported fixture flock operation')
        # Real Win32 byte-range lock; closing the fixture file releases it.
        # This tests policy concurrency, NOT Linux flock implementation semantics.
        position = file.tell()
        file.seek(0)
        msvcrt.locking(file.fileno(), msvcrt.LK_LOCK, 1)
        file.seek(position)
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, flock=fixture_flock))
    sys.modules.setdefault('pwd', types.SimpleNamespace(getpwnam=linux_only))
    import socketserver
    if not hasattr(socketserver, 'UnixStreamServer'):
        class UnavailableUnixStreamServer:
            __init__ = linux_only
        socketserver.UnixStreamServer = UnavailableUnixStreamServer
    if not hasattr(os, 'geteuid'):
        os.geteuid = linux_only


def main():
    sys.path.insert(0, str(ROOT / 'server/managed'))
    suite = unittest.TestLoader().discover(str(ROOT / 'server/managed'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
