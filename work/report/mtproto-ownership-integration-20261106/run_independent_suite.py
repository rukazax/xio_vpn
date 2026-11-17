"""Execute all original tests; only fixture-root literals adapted in memory."""
import hashlib
import os
from pathlib import Path
import sys

base = Path(__file__).resolve().parent
source = base / 'xio-mtproto-setup.sh'
tests = base / 'test_ownership.py'
assert hashlib.sha256(source.read_bytes()).hexdigest() == 'fda86965e827652e0df86e76a4f1562f4a602a578c598c0c3b6443e1d1836ff3'
original = tests.read_bytes()
assert hashlib.sha256(original).hexdigest() == 'eeb44ebb4b1ea22815b790bc4426fc44d33cee6f5c7049d5b0f17f742bb5674b'
old = '/srv/archives/agent-mtproto-ownership-fix-20261106'
new = '/srv/archives/agent-mtproto-ownership-review-20261106'
text = original.decode()
assert text.count(old) == 2
adapted = text.replace(old, new)
os.environ['XIO_TEST_ROOT'] = new
print('commit=5801b32da95a8e86b9949dec03dca430374b92e4', flush=True)
print('original_test_sha256=' + hashlib.sha256(original).hexdigest(), flush=True)
print('adaptation=two fixture-root literals only (docstring and AUTHORIZED)', flush=True)
print('in_memory_test_sha256=' + hashlib.sha256(adapted.encode()).hexdigest(), flush=True)
sys.argv = [str(tests)]
__file__ = str(tests)
exec(compile(adapted, str(tests), 'exec'), globals())
