"""Focused C1d-a immutable capsule IO tests (stdlib, owned roots)."""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuance_primitives as c1a  # noqa: E402
import issuance_store as store  # noqa: E402
import issuance_authority as c1c  # noqa: E402
from test_issuance_primitives import capsule_raw  # noqa: E402

BASE = Path(os.environ["XIO_C1D_A_TEST_ROOT"]).resolve()
UID = "1" * 32


class Abort(BaseException):
    pass


class CapsuleIoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=BASE, prefix="c1d-a-"))
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.auth = c1c.snapshot_from_deployment({
            "owner": "xio-managed-v1",
            "id": "d" * 32,
            "users": {},
        })
        self.ctx = c1c.ActorContext(None, "owner-cli")

    def make_store(self, faults=None):
        return store.PosixIssuanceStore(self.root, self.auth, faults)

    @contextmanager
    def leased(self, faults=None):
        factory = self.make_store(faults)
        handle = factory.for_uid(UID, self.ctx)
        try:
            with handle.exclusive():
                yield factory, handle
        finally:
            try:
                handle.close()
            finally:
                factory.close()

    def raw(self, length: int = 64, capsule_id: str = "c" * 32) -> bytes:
        return capsule_raw(length, capsule_id)

    def publish(self, raw: bytes | None = None):
        value = self.raw() if raw is None else raw
        with self.leased() as (_factory, handle):
            ref = handle.publish_capsule(value)
        return value, ref

    def read(self):
        with self.leased() as (_factory, handle):
            return handle.read_capsule()

    def _r7_create_error(self, error):
        native = os.open
        calls = []

        def opened(name, flags, *args, **kwargs):
            if str(name).startswith("." + UID + ".tmp."):
                calls.append(name)
                raise error
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle), patch.object(os, "open", opened):
            with self.assertRaises(store.StoreError) as caught:
                handle.publish_capsule(self.raw())
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.target().exists())
        self.assertEqual(list(self.target().parent.glob("." + UID + ".tmp.*")), [])
        return caught.exception

    def test_r7_native_temp_create_actual_errno_eexist_is_finite(self):
        error = self._r7_create_error(OSError(errno.EEXIST, "create collision"))
        self.assertNotIsInstance(error, store.StoreCommitUncertain)
        self.assertEqual(error.code, "CAPSULE_IO")

    def test_r7_native_temp_create_enoent_is_uncertain_not_probe_absence(self):
        error = self._r7_create_error(OSError(errno.ENOENT, "create no parent"))
        self.assertIsInstance(error, store.StoreCommitUncertain)

    def test_r7_native_temp_create_opaque_storeerror_identity(self):
        sentinel = store.StoreError("STORE_IO")
        self.assertIs(self._r7_create_error(sentinel), sentinel)

    def test_r7_native_temp_positive_partial_writes_complete(self):
        native = os.write
        calls = []

        def write(fd, raw):
            count = native(fd, raw[:7])
            calls.append(count)
            return count

        raw = self.raw()
        with self.leased() as (_factory, handle), patch.object(os, "write", write):
            self.assertEqual(handle.publish_capsule(raw), c1a.CapsuleRef.from_raw(raw))
        self.assertGreater(len(calls), 1)
        self.assertEqual(sum(calls), len(raw))
        self.assertEqual(self.target().read_bytes(), raw)

    def test_r7_native_temp_zero_progress_stops_once(self):
        with self.leased() as (_factory, handle), patch.object(os, "write", return_value=0) as write:
            with self.assertRaises(store.StoreCommitUncertain):
                handle.publish_capsule(self.raw())
            self.assertEqual(write.call_count, 1)
            self.assertIsNone(handle._temp_pending)
        self.assertFalse(self.target().exists())
        self.assertEqual(list(self.target().parent.glob("." + UID + ".tmp.*")), [])

    def test_r7_temp_native_fsync_error_is_uncertain(self):
        native = os.fsync
        hit = []
        with self.leased() as (factory, handle):
            def fsync(fd):
                if fd != factory._fds["records"] and not hit:
                    hit.append(fd)
                    raise OSError(errno.EIO, "temp fsync")
                return native(fd)
            with patch.object(os, "fsync", fsync):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
            self.assertEqual(len(hit), 1)
            self.assertIsNone(handle._temp_pending)
        self.assertFalse(self.target().exists())

    def test_r7_temp_cut_oserror_identity(self):
        sentinel = OSError(errno.EIO, "opaque temp cut")
        class Cut:
            def cut(self, point):
                if point == "after_temp_file_fsync":
                    raise sentinel
        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(OSError) as caught:
                handle.publish_capsule(self.raw())
            self.assertIs(caught.exception, sentinel)
            self.assertIsNone(handle._temp_pending)

    def test_r7_preexisting_pending_is_not_overwritten_or_cleaned(self):
        pending = ("foreign-pending", (123, 456))
        with self.leased() as (_factory, handle):
            handle._temp_pending = pending
            with patch.object(handle, "_cleanup_temp") as cleanup:
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
                cleanup.assert_not_called()
            self.assertIs(handle._temp_pending, pending)
        self.assertFalse(self.target().exists())

    def test_initial_native_open_plain_storeerror_is_not_absence(self):
        sentinel = store.StoreError("RECORD_MISSING")
        native = os.open

        def opened(name, flags, *args, **kwargs):
            if str(name) == UID + ".capsule" and kwargs.get("dir_fd") is not None:
                raise sentinel
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle):
            with patch.object(os, "open", opened):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertIs(caught.exception, sentinel)
        self.assertFalse(self.target().exists())

    def test_initial_existing_open_eio_is_finite(self):
        raw = self.raw()
        self.publish(raw)
        native = os.open

        def opened(name, flags, *args, **kwargs):
            if str(name) == UID + ".capsule" and kwargs.get("dir_fd") is not None:
                raise OSError(errno.EIO, "test-open")
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle):
            with patch.object(os, "open", opened):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(raw)
        self.assertNotIsInstance(caught.exception, store.StoreCommitUncertain)
        self.assertEqual(caught.exception.code, "CAPSULE_IO")
        self.assertEqual(self.target().read_bytes(), raw)

    def test_initial_open_qualified_fnf_eio_is_not_absence(self):
        sentinel = FileNotFoundError(errno.EIO, "qualified-synthetic")
        native = os.open

        def opened(name, flags, *args, **kwargs):
            if str(name) == UID + ".capsule" and kwargs.get("dir_fd") is not None:
                raise sentinel
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle):
            with patch.object(os, "open", opened):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertEqual(caught.exception.code, "CAPSULE_IO")
        self.assertFalse(self.target().exists())

    def test_postlink_open_eio_is_uncertain(self):
        native = os.open

        def opened(name, flags, *args, **kwargs):
            if str(name) == UID + ".capsule" and kwargs.get("dir_fd") is not None \
                    and self.target().exists():
                raise OSError(errno.EIO, "postlink-open")
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle):
            with patch.object(os, "open", opened):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_temp_false_is_uncertain(self):
        with self.leased() as (_factory, handle):
            with patch.object(handle, "_temp_matches", return_value=False):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
        self.assertFalse(self.target().exists())

    def test_visible_target_native_open_eio_is_initial_finite(self):
        raw = self.raw()
        self.publish(raw)
        native = os.open

        def opened(name, flags, *args, **kwargs):
            if str(name) == UID + ".capsule" and kwargs.get("dir_fd") is not None:
                raise OSError(errno.EIO, "test-open")
            return native(name, flags, *args, **kwargs)

        with self.leased() as (_factory, handle):
            with patch.object(os, "open", opened):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(raw)
        self.assertNotIsInstance(caught.exception, store.StoreCommitUncertain)
        self.assertEqual(caught.exception.code, "CAPSULE_IO")
        self.assertEqual(self.target().read_bytes(), raw)

    def target(self) -> Path:
        return self.root / "records" / (UID + ".capsule")

    def is_cap_fd(self, fd: int) -> bool:
        try:
            return os.readlink(f"/proc/self/fd/{fd}") == str(self.target())
        except OSError:
            return False

    def test_new_target_fsync_oserror_is_uncertain(self):
        native = os.fsync

        def fsync(fd):
            if self.is_cap_fd(fd):
                raise OSError("test-new-fsync")
            return native(fd)

        with self.leased() as (_factory, handle):
            with patch.object(os, "fsync", fsync):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_new_target_read_oserror_is_uncertain(self):
        native = os.read

        def read(fd, amount):
            if self.is_cap_fd(fd):
                raise OSError("test-new-read")
            return native(fd, amount)

        with self.leased() as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_new_target_fsync_plain_storeerror_identity(self):
        sentinel = store.StoreError("STORE_IO")
        native = os.fsync

        def fsync(fd):
            if self.is_cap_fd(fd):
                raise sentinel
            return native(fd)

        with self.leased() as (_factory, handle):
            with patch.object(os, "fsync", fsync):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_new_target_read_plain_storeerror_identity(self):
        sentinel = store.StoreError("STORE_IO")
        native = os.read

        def read(fd, amount):
            if self.is_cap_fd(fd):
                raise sentinel
            return native(fd, amount)

        with self.leased() as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_new_postfence_lseek_plain_storeerror_identity(self):
        sentinel = store.StoreError("STORE_IO")
        native = os.lseek
        state = {"fenced": False}

        def lseek(fd, offset, whence):
            if self.is_cap_fd(fd):
                if state["fenced"]:
                    raise sentinel
                state["fenced"] = True
            return native(fd, offset, whence)

        with self.leased() as (_factory, handle):
            with patch.object(os, "lseek", lseek):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), self.raw())

    def test_existing_final_read_plain_storeerror_identity(self):
        raw = self.raw()
        self.publish(raw)
        sentinel = store.StoreError("STORE_IO")
        native = os.read
        reads = []

        def read(fd, amount):
            if self.is_cap_fd(fd):
                reads.append(1)
                if len(reads) == 2:
                    raise sentinel
            return native(fd, amount)

        with self.leased() as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(raw)
        self.assertIs(caught.exception, sentinel)

    def test_existing_postfence_lseek_plain_storeerror_identity(self):
        raw = self.raw()
        self.publish(raw)
        sentinel = store.StoreError("STORE_IO")
        native = os.lseek
        seeks = []

        def lseek(fd, offset, whence):
            if self.is_cap_fd(fd):
                seeks.append(1)
                if len(seeks) == 2:
                    raise sentinel
            return native(fd, offset, whence)

        with self.leased() as (_factory, handle):
            with patch.object(os, "lseek", lseek):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(raw)
        self.assertIs(caught.exception, sentinel)

    def test_observational_read_plain_storeerror_identity(self):
        raw = self.raw()
        self.publish(raw)
        sentinel = store.StoreError("STORE_IO")
        native = os.read

        def read(fd, amount):
            if self.is_cap_fd(fd):
                raise sentinel
            return native(fd, amount)

        with self.leased() as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreError) as caught:
                    handle.read_capsule()
        self.assertIs(caught.exception, sentinel)

    def test_publish_and_read_exact_bytes_and_ref(self):
        raw = self.raw()
        ref = self.publish(raw)[1]
        self.assertEqual(len(ref.capsule_id), 32)
        self.assertEqual(ref.envelope_sha256,
                         __import__("hashlib").sha256(raw).hexdigest())
        self.assertNotEqual(ref.ciphertext_sha256, ref.envelope_sha256)
        got, got_ref = self.read()
        self.assertEqual(got, raw)
        self.assertEqual(got_ref, ref)
        info = self.target().stat()
        self.assertEqual(info.st_mode & 0o777, 0o600)

    def test_exact_bytes_only(self):
        for value in (bytearray(self.raw()), memoryview(self.raw()), "text", 1, None):
            with self.leased() as (_factory, handle):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(value)
            self.assertEqual(caught.exception.code, "CAPSULE_INVALID")
            self.assertFalse(self.target().exists())

        class BytesSubclass(bytes):
            pass

        with self.leased() as (_factory, handle):
            with self.assertRaises(store.StoreError) as caught:
                handle.publish_capsule(BytesSubclass(self.raw()))
        self.assertEqual(caught.exception.code, "CAPSULE_INVALID")

    def test_invalid_and_oversize_reject_before_write(self):
        with self.leased() as (_factory, handle):
            for value, code in ((b"not-json", "CAPSULE_INVALID"),
                                (b"x" * (c1a.C0_MAX_ENVELOPE + 1),
                                 "CAPSULE_TOO_LARGE")):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(value)
                self.assertEqual(caught.exception.code, code)
                self.assertFalse(self.target().exists())

    def test_missing_read_and_publish_requires_active_lease(self):
        with self.assertRaises(store.StoreError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "CAPSULE_MISSING")
        factory = self.make_store()
        handle = factory.for_uid(UID, self.ctx)
        try:
            with self.assertRaises(store.StoreError) as caught:
                handle.publish_capsule(self.raw())
            self.assertEqual(caught.exception.code, "NO_EXCLUSION")
        finally:
            handle.close()
            factory.close()

    def test_pending_record_is_refused_without_io(self):
        with self.leased() as (factory, handle):
            pending = Path(factory.root) / "pending" / (UID + ".pending")
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            for call in (lambda: handle.read_capsule(),
                         lambda: handle.publish_capsule(self.raw())):
                with self.assertRaises(store.PendingRecovery):
                    call()
            self.assertFalse(self.target().exists())

    def test_different_existing_bytes_conflict_and_are_not_overwritten(self):
        raw = self.raw(64)
        self.publish(raw)
        other = self.raw(32, "d" * 32)
        with self.leased() as (_factory, handle):
            with self.assertRaises(store.StoreError) as caught:
                handle.publish_capsule(other)
        self.assertEqual(caught.exception.code, "CAPSULE_CONFLICT")
        self.assertEqual(self.target().read_bytes(), raw)
        self.assertEqual(self.read()[0], raw)

    def test_equal_existing_bytes_fresh_fence(self):
        raw = self.raw()
        first = self.publish(raw)[1]
        second = self.publish(raw)[1]
        self.assertEqual(first, second)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_leaf_type_permissions_and_symlink(self):
        raw = self.raw()
        with self.leased():
            pass
        self.target().parent.mkdir(exist_ok=True)
        self.target().write_bytes(raw)
        self.target().chmod(0o644)
        with self.assertRaises(store.StoreError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "CAPSULE_PERMISSIONS")
        self.target().unlink()
        outside = self.root / "outside-capsule"
        outside.write_bytes(raw)
        self.target().symlink_to(outside)
        with self.assertRaises(store.StoreError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "CAPSULE_TYPE")
        self.target().unlink()
        os.mkfifo(self.target())
        with self.assertRaises(store.StoreError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "CAPSULE_TYPE")

    def test_closed_handle_and_wrong_thread(self):
        factory = self.make_store()
        handle = factory.for_uid(UID, self.ctx)
        try:
            with handle.exclusive():
                pass
            handle.close()
            with self.assertRaises(store.StoreError) as caught:
                handle.read_capsule()
            self.assertEqual(caught.exception.code, "STORE_CLOSED")
        finally:
            factory.close()

        factory = self.make_store()
        handle = factory.for_uid(UID, self.ctx)
        errors = []
        try:
            with handle.exclusive():
                def worker():
                    try:
                        handle.read_capsule()
                    except BaseException as error:
                        errors.append(error)
                thread = threading.Thread(target=worker)
                thread.start()
                thread.join()
            self.assertTrue(errors)
            self.assertIsInstance(errors[0], store.StoreError)
            self.assertEqual(errors[0].code, "WRONG_CONTEXT")
        finally:
            handle.close()
            factory.close()

    def test_initial_probe_transfer_has_no_fd_leak(self):
        self.publish()
        before = set(os.listdir("/proc/self/fd"))
        self.read()
        after = set(os.listdir("/proc/self/fd"))
        self.assertEqual(before, after)

    def test_public_read_is_observational_not_fsync_receipt(self):
        raw = self.raw()
        self.publish(raw)
        with self.leased() as (_factory, handle):
            with patch.object(os, "fsync", side_effect=OSError("TEST_FSYNC")):
                got, ref = handle.read_capsule()
        self.assertEqual(got, raw)
        self.assertEqual(ref, c1a.CapsuleRef.from_raw(raw))

    def test_inherited_handle_in_child_is_wrong_context(self):
        factory = self.make_store()
        handle = factory.for_uid(UID, self.ctx)
        try:
            with handle.exclusive():
                pid = os.fork()
                if pid == 0:
                    try:
                        handle.read_capsule()
                    except store.StoreError as error:
                        os._exit(0 if error.code == "WRONG_CONTEXT" else 1)
                    except BaseException:
                        os._exit(2)
                    os._exit(3)
                _waited, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            handle.close()
            factory.close()

    def test_existing_fence_uncertain_sentinel_identity_is_preserved(self):
        raw = self.raw()
        self.publish(raw)
        sentinel = store.StoreError("CAPSULE_UNCERTAIN")
        with self.leased() as (_factory, handle):
            with patch.object(handle, "_entry_matches_fd", side_effect=sentinel):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(raw)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_existing_fence_close_eio_is_uncertain(self):
        raw = self.raw()
        self.publish(raw)
        native = os.close
        fired = []

        def close(fd):
            native(fd)
            if not fired:
                fired.append(fd)
                raise OSError("TEST_CLOSE")

        with self.leased() as (_factory, handle):
            with patch.object(os, "close", close):
                with self.assertRaises(store.StoreCommitUncertain) as caught:
                    handle.publish_capsule(raw)
        self.assertTrue(fired)
        self.assertEqual(caught.exception.code, "CAPSULE_UNCERTAIN")
        self.assertEqual(self.target().read_bytes(), raw)

    def test_after_link_callback_store_error_is_not_wrapped(self):
        raw = self.raw()
        sentinel = store.StoreError("CALLBACK_ORDINARY")

        class Cut:
            def cut(self, point):
                if point == "capsule_after_link":
                    raise sentinel

        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(store.StoreError) as caught:
                handle.publish_capsule(raw)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_temp_cleanup_cancellation_beats_ordinary_primary(self):
        raw = self.raw()
        cancel = Abort("cleanup-cancel")

        class Cut:
            def cut(self, point):
                if point == "capsule_after_link":
                    raise store.StoreError("ORDINARY_PRIMARY")

        with self.leased(Cut()) as (_factory, handle):
            with patch.object(handle, "_cleanup_temp", side_effect=cancel):
                with self.assertRaises(Abort) as caught:
                    handle.publish_capsule(raw)
        self.assertIs(caught.exception, cancel)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_existing_fence_fsync_failure_is_uncertain(self):
        raw = self.raw()
        self.publish(raw)
        with self.leased() as (_factory, handle):
            with patch.object(os, "fsync", side_effect=OSError("TEST_FSYNC")):
                with self.assertRaises(store.StoreCommitUncertain) as caught:
                    handle.publish_capsule(raw)
        self.assertEqual(caught.exception.code, "CAPSULE_UNCERTAIN")
        self.assertEqual(self.target().read_bytes(), raw)

    def test_final_inode_rebind_is_uncertain(self):
        raw = self.raw()
        self.publish(raw)
        with self.leased() as (_factory, handle):
            with patch.object(handle, "_entry_matches_fd", side_effect=[
                    True, False, False, False, False, False]):
                with self.assertRaises(store.StoreCommitUncertain) as caught:
                    handle.publish_capsule(raw)
        self.assertEqual(caught.exception.code, "CAPSULE_UNCERTAIN")
        self.assertEqual(self.target().read_bytes(), raw)

    def test_true_link_eexist_adopts_equal_existing(self):
        raw = self.raw()
        capsule = self.target()

        class Race:
            def __init__(self):
                self.once = False

            def cut(self, point):
                if point == "capsule_before_link" and not self.once:
                    self.once = True
                    capsule.parent.mkdir(parents=True, exist_ok=True)
                    capsule.write_bytes(raw)
                    capsule.chmod(0o600)

        with self.leased(Race()) as (_factory, handle):
            ref = handle.publish_capsule(raw)
            self.assertEqual(ref, c1a.CapsuleRef.from_raw(raw))
            self.assertFalse(list(capsule.parent.glob("*.tmp-*")))
        self.assertEqual(capsule.read_bytes(), raw)

    class _WinnerRace:
        def __init__(self, data, target):
            self.data = data
            self.target_ref = target
            self.once = False

        def cut(self, point):
            if point == "capsule_before_link" and not self.once:
                self.once = True
                self.target_ref.parent.mkdir(parents=True, exist_ok=True)
                self.target_ref.write_bytes(self.data)
                self.target_ref.chmod(0o600)

    def _winner_failure(self, data, native_error):
        race = self._WinnerRace(data, self.target())
        native = os.read

        def read(fd, amount):
            if native_error is not None and self.is_cap_fd(fd):
                raise native_error
            return native(fd, amount)

        with self.leased(race) as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(self.raw())
        self.assertEqual(self.target().read_bytes(), data)

    def test_winner_first_read_eio_is_uncertain(self):
        self._winner_failure(b"x" * 32, OSError(errno.EIO, "winner-read"))

    def test_winner_first_read_overflow_is_uncertain(self):
        self._winner_failure(b"x" * (c1a.C0_MAX_ENVELOPE + 1), None)

    def test_winner_first_read_parser_failure_is_uncertain(self):
        self._winner_failure(b"!", None)

    def test_winner_first_read_opaque_storeerror_identity(self):
        sentinel = store.StoreError("CAPSULE_IO")
        race = self._WinnerRace(b"x" * 32, self.target())
        native = os.read

        def read(fd, amount):
            if self.is_cap_fd(fd):
                raise sentinel
            return native(fd, amount)

        with self.leased(race) as (_factory, handle):
            with patch.object(os, "read", read):
                with self.assertRaises(store.StoreError) as caught:
                    handle.publish_capsule(self.raw())
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.target().read_bytes(), b"x" * 32)


    def test_after_link_cut_preserves_primary_and_target(self):
        raw = self.raw()

        class Cut:
            def cut(self, point):
                if point == "capsule_after_link":
                    raise Abort("test")

        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(Abort):
                handle.publish_capsule(raw)
        self.assertEqual(self.target().read_bytes(), raw)
        self.assertFalse(list(self.target().parent.glob("*.tmp-*")))

    def test_after_link_oserror_is_uncertain(self):
        raw = self.raw()

        class Cut:
            def cut(self, point):
                if point == "capsule_after_link":
                    raise OSError("test-after-link")

        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(store.StoreCommitUncertain):
                handle.publish_capsule(raw)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_after_link_fileexists_callback_is_uncertain(self):
        raw = self.raw()

        class Cut:
            def cut(self, point):
                if point == "capsule_after_link":
                    raise FileExistsError("test-after-link")

        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(store.StoreCommitUncertain):
                handle.publish_capsule(raw)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_temp_failure_before_assignment_uses_pending_cleanup_once(self):
        class Cut:
            def cut(self, point):
                if point == "after_temp_file_fsync":
                    raise Abort("temp")

        with self.leased(Cut()) as (_factory, handle):
            with self.assertRaises(Abort):
                handle.publish_capsule(self.raw())
        self.assertFalse(self.target().exists())
        self.assertFalse(list(self.target().parent.glob("*.tmp-*")))

    def test_cleanup_false_is_uncertain_and_keeps_target(self):
        raw = self.raw()
        with self.leased() as (_factory, handle):
            with patch.object(handle, "_cleanup_temp", return_value=False):
                with self.assertRaises(store.StoreCommitUncertain):
                    handle.publish_capsule(raw)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_unexpected_cleanup_exception_is_not_relabelled(self):
        raw = self.raw()
        with self.leased() as (_factory, handle):
            with patch.object(handle, "_cleanup_temp",
                              side_effect=RuntimeError("test")):
                with self.assertRaises(RuntimeError):
                    handle.publish_capsule(raw)
        self.assertEqual(self.target().read_bytes(), raw)

    def test_ambient_caller_exception_does_not_change_operation(self):
        raw = self.raw()
        try:
            raise RuntimeError("caller")
        except RuntimeError:
            with self.leased() as (_factory, handle):
                ref = handle.publish_capsule(raw)
        self.assertEqual(ref, c1a.CapsuleRef.from_raw(raw))
        self.assertEqual(self.read()[0], raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
