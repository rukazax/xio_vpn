"""Dedicated passive POSIX store tests (stdlib, owned roots, fake authority)."""

from __future__ import annotations

import json
import fcntl
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuance_primitives as c1a  # noqa: E402
import issuance_store as store  # noqa: E402
from test_issuance_primitives import TestRecordState, sha  # noqa: E402

BASE = Path(os.environ["XIO_C1B_TEST_ROOT"]).resolve()


class Faults:
    def __init__(self, *points):
        self.points = set(points)

    def cut(self, point):
        if point in self.points:
            raise RuntimeError("TEST-ONLY fault " + point)


class Auth:
    def __init__(self, principal):
        self.principal = principal
        self.calls = []

    def resolve(self, uid, operation_id, actor_context):
        self.calls.append((uid, operation_id, actor_context, os.getpid()))
        return self.principal


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=BASE, prefix="c1b-store-"))
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.root, True)
        self.record = TestRecordState().make()
        self.raw = self.record.to_json()
        self.owner = c1a.Principal(None, "owner", False)
        self.auth = Auth(self.owner)
        self.factories = []

    def tearDown(self):
        for factory in reversed(self.factories):
            try:
                factory.close()
            except Exception:
                pass

    def open(self, faults=None, *, timeout=1.0):
        factory = store.PosixIssuanceStore(self.root, self.auth, faults,
                                           lock_timeout=timeout)
        self.factories.append(factory)
        return factory.for_uid(self.record.uid, "synthetic-authenticated-actor")

    def create(self, handle, raw=None):
        with handle.exclusive():
            return handle.create(self.raw if raw is None else raw)


class StoreTests(Base):
    def test_actual_advance_positive_and_stale(self):
        handle = self.open()
        self.create(handle)
        result = c1a.advance_record(
            handle, self.record.uid, sha(self.raw), 0, "cancel_request",
            principal=self.owner, expected_operation_id=self.record.operation_id)
        self.assertIsNotNone(result.record)
        # read is only legal under exclusion; verify by a fresh transaction.
        with handle.exclusive():
            raw, raw_hash, current = handle.read(self.record.uid)
        self.assertEqual(current.revision, 1)
        self.assertEqual(raw_hash, sha(raw))
        self.assertTrue(current.cancellation["requested"])
        stale = c1a.advance_record(
            handle, self.record.uid, sha(self.raw), 0, "backend_applied",
            principal=self.owner, backends={"awg": "appliedVerified"})
        self.assertIsNone(stale.record)

    def test_cas_uncertain_propagates_and_reopens(self):
        handle = self.open(Faults("after_replace"))
        self.create(handle)
        with self.assertRaises(store.StoreCommitUncertain):
            c1a.advance_record(
                handle, self.record.uid, sha(self.raw), 0, "cancel_request",
                principal=self.owner)
        with self.assertRaises(store.PendingRecovery):
            with handle.exclusive():
                handle.read(self.record.uid)
        fresh = self.open()
        with self.assertRaises(store.PendingRecovery):
            with fresh.exclusive():
                fresh.read(self.record.uid)
        receipt = fresh.recover()
        self.assertEqual(receipt.status, "durable")
        with fresh.exclusive():
            raw, _, current = fresh.read(self.record.uid)
        self.assertTrue(current.cancellation["requested"])
        self.assertTrue(raw)

    def test_pre_replace_clean_failure_keeps_old_record(self):
        handle = self.open(Faults("before_replace"))
        self.create(handle)
        with self.assertRaises(store.StoreError):
            c1a.advance_record(handle, self.record.uid, sha(self.raw), 0,
                               "cancel_request", principal=self.owner)
        with handle.exclusive():
            raw, _, current = handle.read(self.record.uid)
        self.assertEqual(raw, self.raw)
        self.assertEqual(current.revision, 0)
        self.assertFalse((self.root / "pending" / (self.record.uid + ".pending")).exists())

    def test_marker_unlink_fsync_failure_record_durable_marker_absent(self):
        handle = self.open()
        self.create(handle)
        handle.factory.faults = Faults("after_marker_unlink")
        with self.assertRaises(store.StoreCommitUncertain):
            c1a.advance_record(handle, self.record.uid, sha(self.raw), 0,
                               "cancel_request", principal=self.owner)
        pending = self.root / "pending" / (self.record.uid + ".pending")
        self.assertFalse(pending.exists())
        fresh = self.open()
        with fresh.exclusive():
            _, _, current = fresh.read(self.record.uid)
        self.assertEqual(current.revision, 1)

    def test_create_uncertain_reopen_and_conflict(self):
        handle = self.open(Faults("create_after_record_dir_fsync"))
        with self.assertRaises(store.StoreCommitUncertain):
            self.create(handle)
        self.assertTrue((self.root / "pending" / (self.record.uid + ".pending")).exists())
        fresh = self.open()
        self.assertEqual(fresh.recover().status, "durable")
        with self.assertRaises(store.StoreError) as raised:
            self.create(fresh)
        self.assertEqual(raised.exception.code, "EXISTS")

    def test_create_is_no_clobber(self):
        first = self.open()
        self.create(first)
        second = self.open()
        with self.assertRaises(store.StoreError) as raised:
            self.create(second)
        self.assertEqual(raised.exception.code, "EXISTS")

    def test_cas_rejects_stale_identity_revision_and_noncanonical(self):
        handle = self.open()
        self.create(handle)
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.compare_and_swap(self.record.uid, "0" * 64,
                                        self.record.copy(revision=1).to_json())
        self.assertEqual(raised.exception.code, "STALE_RECORD")
        bad = json.dumps(json.loads(self.raw), indent=2).encode()
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.compare_and_swap(self.record.uid, sha(self.raw), bad)
        self.assertIn(raised.exception.code, ("RECORD_INVALID", "NONCANONICAL_RECORD"))
        with self.assertRaises(store.StoreError):
            with handle.exclusive():
                handle.compare_and_swap(self.record.uid, sha(self.raw),
                                        self.record.copy(revision=2).to_json())

    def test_marker_schema_and_recovery_fence(self):
        handle = self.open()
        self.create(handle)
        pending = self.root / "pending" / (self.record.uid + ".pending")
        pending.write_bytes(b'{"bad":1}')
        os.chmod(pending, 0o600)
        with self.assertRaises(store.PendingRecovery):
            with handle.exclusive():
                handle.read(self.record.uid)
        with self.assertRaises(store.StoreError) as raised:
            handle.recover()
        self.assertIn(raised.exception.code, ("MARKER_INVALID", "MARKER_UID"))
        self.assertTrue(pending.exists())

    def test_path_symlink_fifo_and_permissions(self):
        handle = self.open()
        self.create(handle)
        target = self.root / "records" / (self.record.uid + ".record")
        outside = self.root / "outside"
        outside.write_bytes(b"x")
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.read(self.record.uid)
        self.assertEqual(raised.exception.code, "PATH_SYMLINK")
        target.unlink()
        os.mkfifo(target, 0o600)
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.read(self.record.uid)
        self.assertEqual(raised.exception.code, "STORE_TYPE")
        target.unlink()
        target.write_bytes(self.raw)
        os.chmod(target, 0o644)
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.read(self.record.uid)
        self.assertEqual(raised.exception.code, "STORE_PERMISSIONS")

    def test_authority_under_lock_and_denial(self):
        handle = self.open()
        self.create(handle)
        result = c1a.advance_record(handle, self.record.uid, sha(self.raw), 0,
                                    "cancel_request", principal=self.owner)
        self.assertIsNotNone(result.record)
        self.assertEqual(len(self.auth.calls), 1)
        denied_root = Path(tempfile.mkdtemp(dir=BASE, prefix="c1b-deny-"))
        denied_root.chmod(0o700)
        self.addCleanup(shutil.rmtree, denied_root, True)
        denied = store.PosixIssuanceStore(denied_root, Auth(None), None)
        self.factories.append(denied)
        deny_handle = denied.for_uid(self.record.uid, "actor")
        with deny_handle.exclusive():
            deny_handle.create(self.raw)
        with self.assertRaises(store.StoreError) as raised:
            c1a.advance_record(deny_handle, self.record.uid, sha(self.raw), 0,
                               "cancel_request", principal=self.owner)
        self.assertEqual(raised.exception.code, "AUTHORITY_INVALID")

    def test_same_object_and_factory_locking(self):
        handle = self.open()
        self.create(handle)
        with self.assertRaises(store.StoreError):
            handle.read(self.record.uid)
        with handle.exclusive():
            with self.assertRaises(store.StoreError):
                with handle.exclusive():
                    pass
            second = self.open(timeout=0.05)
            errors = []

            def contend():
                try:
                    with second.exclusive():
                        pass
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=contend)
            thread.start()
            thread.join(2)
            self.assertTrue(errors)
            self.assertEqual(errors[0].code, "LOCK_TIMEOUT")

    def test_close_active_and_timeout(self):
        handle = self.open()
        self.create(handle)
        with handle.exclusive():
            with self.assertRaises(store.StoreError) as raised:
                handle.close()
            self.assertEqual(raised.exception.code, "BUSY")
            with self.assertRaises(store.StoreError):
                self.factories[0].close()

    def test_fork_inherited_handle_is_wrong_context(self):
        handle = self.open()
        self.create(handle)
        with handle.exclusive():
            pid = os.fork()
            if pid == 0:
                try:
                    handle.read(self.record.uid)
                    os._exit(2)
                except store.StoreError as error:
                    os._exit(0 if error.code in ("WRONG_CONTEXT", "NO_EXCLUSION") else 3)
                finally:
                    os._exit(4)
            _, status = os.waitpid(pid, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_child_birth_reopens_and_faults(self):
        with self.assertRaises(Exception):
            store.PosixIssuanceStore(self.root, self.auth,
                                     Faults("after_child_fsync"))
        fresh = store.PosixIssuanceStore(self.root, self.auth, None)
        self.factories.append(fresh)

    def test_root_symlink_permissions_and_canonical_existing(self):
        bad_root = self.root / "badroot"
        bad_root.symlink_to(self.root)
        with self.assertRaises(store.StoreError):
            store.PosixIssuanceStore(bad_root, self.auth, None)
        os.chmod(self.root, 0o755)
        with self.assertRaises(store.StoreError):
            store.PosixIssuanceStore(self.root, self.auth, None)
        os.chmod(self.root, 0o700)
        handle = self.open()
        self.create(handle)
        record_path = self.root / "records" / (self.record.uid + ".record")
        record_path.write_bytes(json.dumps(json.loads(self.raw), indent=2).encode())
        with self.assertRaises(store.StoreError) as raised:
            with handle.exclusive():
                handle.read(self.record.uid)
        self.assertIn(raised.exception.code, ("RECORD_INVALID", "NONCANONICAL_RECORD"))

    def test_recover_old_and_third_hash(self):
        handle = self.open()
        self.create(handle)
        current = self.raw
        candidate = self.record.copy(revision=1).to_json()
        marker = self.root / "pending" / (self.record.uid + ".pending")
        marker.write_bytes(json.dumps({
            "schema": 1, "mode": "replace", "uid": self.record.uid,
            "oldSha256": sha(current), "candidateSha256": sha(candidate),
            "revision": 1}, sort_keys=True, separators=(",", ":")).encode())
        os.chmod(marker, 0o600)
        receipt = handle.recover()
        self.assertEqual(receipt.status, "not_committed")
        marker.write_bytes(json.dumps({
            "schema": 1, "mode": "replace", "uid": self.record.uid,
            "oldSha256": "e" * 64, "candidateSha256": "f" * 64,
            "revision": 1}, sort_keys=True, separators=(",", ":")).encode())
        os.chmod(marker, 0o600)
        with self.assertRaises(store.StoreError):
            handle.recover()
        self.assertTrue(marker.exists())

    def test_lock_fd_cloexec_and_fork_close_only(self):
        handle = self.open()
        self.create(handle)
        with handle.exclusive():
            flags = fcntl.fcntl(handle._lock_fd, fcntl.F_GETFD)
            self.assertTrue(flags & fcntl.FD_CLOEXEC)
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(handle._lock_fd)
                finally:
                    os._exit(0)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.WEXITSTATUS(status), 0)
            second = self.open(timeout=0.05)
            with self.assertRaises(store.StoreError) as raised:
                with second.exclusive():
                    pass
            self.assertEqual(raised.exception.code, "LOCK_TIMEOUT")

    def test_owned_child_process_recovers_uncertain_record(self):
        handle = self.open(Faults("after_replace"))
        self.create(handle)
        with self.assertRaises(store.StoreCommitUncertain):
            c1a.advance_record(handle, self.record.uid, sha(self.raw), 0,
                               "cancel_request", principal=self.owner)
        pid = os.fork()
        if pid == 0:
            try:
                child = store.PosixIssuanceStore(self.root, self.auth, None)
                child_handle = child.for_uid(self.record.uid, "child")
                receipt = child_handle.recover()
                os._exit(0 if receipt.status == "durable" else 2)
            except BaseException:
                os._exit(3)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        with handle.exclusive():
            _, _, current = handle.read(self.record.uid)
        self.assertTrue(current.cancellation["requested"])

    def test_import_and_capability_are_passive(self):
        cap = json.loads(c1a.internal_capability())
        self.assertFalse(cap["complete"])
        for name in ("put", "read", "resume", "needsMaterialReply", "cancel",
                     "ackDelivery", "readCapsule"):
            self.assertFalse(cap["actions"][name])


if __name__ == "__main__":
    unittest.main()
