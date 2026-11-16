"""Passive POSIX UID-record store adapter for the accepted C1a primitives.

Test-only bounded component: no production imports, no live authority/native
effect, no capability advertisement. Stdlib only.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

import issuance_primitives as c1a


MAX_MARKER = 4096
_UID = re.compile(r"[0-9a-f]{32}\Z")
_MARKER_KEYS = {"schema", "mode", "uid", "oldSha256", "candidateSha256", "revision"}


class StoreError(Exception):
    """Finite adapter error; no secret/path payload."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class PendingRecovery(StoreError):
    def __init__(self) -> None:
        super().__init__("PENDING_RECOVERY")


class StoreCommitUncertain(StoreError):
    pass


class _CapsuleAbsent(Exception):
    """Private known initial native-open absence (not an old-helper code)."""


class _CapsuleReadFailure(Exception):
    """Private provenance marker for capsule-owned read/parser failures."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class AuthorityView(Protocol):
    def resolve(self, uid: str, operation_id: str, actor_context: Any) -> c1a.Principal:
        ...


@dataclass(frozen=True)
class StoreReceipt:
    status: str
    code: str = ""
    raw_sha256: str = ""
    bytes_written: int = 0
    revision: int = 0


def _uid(uid: Any) -> str:
    if type(uid) is not str or _UID.fullmatch(uid) is None:
        raise StoreError("UID_INVALID")
    return uid


def _sha(raw: bytes) -> str:
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def _is_cancel(error: BaseException | None) -> bool:
    return error is not None and isinstance(error, BaseException) \
        and not isinstance(error, Exception)


def _choose_unwind(primary: BaseException | None,
                   outcomes: list[BaseException],
                   code: str = "STORE_IO") -> tuple[BaseException | None, bool]:
    if _is_cancel(primary):
        return primary, False
    for outcome in outcomes:
        if _is_cancel(outcome):
            return outcome, True
    if primary is not None:
        return primary, False
    for outcome in outcomes:
        if not isinstance(outcome, OSError):
            return outcome, True
    for outcome in outcomes:
        if isinstance(outcome, OSError):
            return StoreError(code), True
    return None, False


def _close_all_owned(raw: list[int], primary: BaseException | None,
                     code: str = "STORE_IO") -> None:
    outcomes: list[BaseException] = []
    for fd in raw:
        try:
            os.close(fd)
        except BaseException as error:
            outcomes.append(error)
    chosen, do_raise = _choose_unwind(primary, outcomes, code)
    if do_raise:
        raise chosen


def _canonical_marker(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _marker_value(uid: str, mode: str, old: str | None, candidate: str,
                  revision: int) -> dict[str, Any]:
    return {
        "schema": 1,
        "mode": mode,
        "uid": uid,
        "oldSha256": old,
        "candidateSha256": candidate,
        "revision": revision,
    }


def _validate_marker(value: Any, uid: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _MARKER_KEYS:
        raise StoreError("MARKER_INVALID")
    if value["schema"] != 1 or type(value["schema"]) is not int:
        raise StoreError("MARKER_INVALID")
    if value["mode"] not in ("create", "replace"):
        raise StoreError("MARKER_INVALID")
    if value["uid"] != uid:
        raise StoreError("MARKER_UID")
    old = value["oldSha256"]
    candidate = value["candidateSha256"]
    if type(candidate) is not str or re.fullmatch(r"[0-9a-f]{64}", candidate) is None:
        raise StoreError("MARKER_INVALID")
    if value["mode"] == "create":
        if old is not None:
            raise StoreError("MARKER_INVALID")
    elif type(old) is not str or re.fullmatch(r"[0-9a-f]{64}", old) is None:
        raise StoreError("MARKER_INVALID")
    revision = value["revision"]
    if type(revision) is not int or not 0 <= revision <= c1a.MAX_SAFE_INTEGER:
        raise StoreError("MARKER_INVALID")
    return dict(value)


class _Temp:
    def __init__(self, name: str):
        self.name = name


class PosixIssuanceStore:
    """Factory for UID-bound handles; owns explicit root/child descriptors."""

    def __init__(self, root: Path, authority: AuthorityView,
                 faults: Any | None = None, *, lock_timeout: float = 1.0):
        self.root = Path(root)
        self.authority = authority
        self.faults = faults
        self.lock_timeout = float(lock_timeout)
        if not (self.lock_timeout > 0 and self.lock_timeout <= 60):
            raise StoreError("TIMEOUT_INVALID")
        self._closed = False
        self._owner_pid = os.getpid()
        self._lifecycle = threading.Lock()
        self._handles: set["UidRecordStore"] = set()
        self._root_fd = -1
        self._fds: dict[str, int] = {}
        self._ids: dict[str, tuple[int, int]] = {}
        try:
            self._open_root()
        except BaseException as error:
            self._close_fds(error)
            raise

    def _cut(self, point: str) -> None:
        if self.faults is not None:
            self.faults.cut(point)

    def _close_fds(self, primary: BaseException | None = None) -> None:
        raw: list[int] = []
        for fd in self._fds.values():
            if fd >= 0:
                raw.append(fd)
        self._fds.clear()
        if self._root_fd >= 0:
            raw.append(self._root_fd)
            self._root_fd = -1
        _close_all_owned(raw, primary, "STORE_IO")

    def _open_root(self) -> None:
        if not self.root.is_absolute():
            raise StoreError("ROOT_INVALID")
        try:
            fd = os.open(str(self.root),
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise StoreError("ROOT_INVALID") from error
        primary = None
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreError("ROOT_INVALID") from error
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() \
                    or stat.S_IMODE(info.st_mode) != 0o700:
                raise StoreError("ROOT_PERMISSIONS")
            self._root_fd = fd
            self._ids["root"] = (info.st_dev, info.st_ino)
            fd = -1
            for name in ("records", "locks", "pending"):
                self._ensure_child(name)
            return
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "ROOT_INVALID")
                if do_raise:
                    raise chosen

    def _ensure_child(self, name: str) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(name, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, 0o700, dir_fd=self._root_fd)
            except FileExistsError:
                raise StoreError("BIRTH_UNCERTAIN")
            except OSError as error:
                raise StoreError("BIRTH_UNCERTAIN") from error
            self._cut("after_child_mkdir")
            try:
                os.fsync(self._root_fd)
            except OSError as error:
                raise StoreError("BIRTH_UNCERTAIN") from error
            self._cut("after_child_parent_fsync")
            try:
                fd = os.open(name, flags, dir_fd=self._root_fd)
            except OSError as error:
                raise StoreError("BIRTH_UNCERTAIN") from error
        except OSError as error:
            raise StoreError("CHILD_INVALID") from error
        primary = None
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreError("CHILD_INVALID") from error
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() \
                    or stat.S_IMODE(info.st_mode) != 0o700:
                raise StoreError("CHILD_PERMISSIONS")
            try:
                os.fsync(fd)
                os.fsync(self._root_fd)
                self._cut("after_child_fsync")
            except OSError as error:
                raise StoreError("BIRTH_UNCERTAIN") from error
            self._fds[name] = fd
            self._ids[name] = (info.st_dev, info.st_ino)
            fd = -1
            return
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "BIRTH_UNCERTAIN")
                if do_raise:
                    raise chosen

    def _check_open(self) -> None:
        if self._closed:
            raise StoreError("STORE_CLOSED")
        if os.getpid() != self._owner_pid:
            raise StoreError("WRONG_CONTEXT")

    def _check_children(self) -> None:
        for name, fd in self._fds.items():
            try:
                entry = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
                held = os.fstat(fd)
            except OSError as error:
                raise StoreError("CHILD_REBOUND") from error
            if (entry.st_dev, entry.st_ino) != (held.st_dev, held.st_ino):
                raise StoreError("CHILD_REBOUND")
            if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() \
                    or stat.S_IMODE(entry.st_mode) != 0o700:
                raise StoreError("CHILD_PERMISSIONS")

    def for_uid(self, uid: str, actor_context: Any) -> "UidRecordStore":
        if os.getpid() != self._owner_pid:
            raise StoreError("WRONG_CONTEXT")
        with self._lifecycle:
            self._check_open()
            uid = _uid(uid)
            handle = UidRecordStore(self, uid, actor_context)
            self._handles.add(handle)
            return handle

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            raise StoreError("WRONG_CONTEXT")
        with self._lifecycle:
            self._check_open()
            if any(handle.active or handle._acquiring or handle._reserved
                   for handle in list(self._handles)):
                raise StoreError("BUSY")
            self._closed = True
            self._close_fds()

    def _path_names(self, uid: str) -> tuple[str, str, str]:
        return uid + ".record", uid + ".lock", uid + ".pending"


class UidRecordStore:
    """RecordStore-compatible handle bound to one UID."""

    def __init__(self, factory: PosixIssuanceStore, uid: str, actor_context: Any):
        self.factory = factory
        self.uid = uid
        self.actor_context = actor_context
        self._state = threading.Lock()
        self._active = False
        self._acquiring = False
        self._reserved = False
        self._owner_pid = os.getpid()
        self._active_pid = 0
        self._active_thread = 0
        self._lock_fd = -1
        self._closed = False
        self._temp_pending: tuple[str, tuple[int, int]] | None = None
        self._txn = 0

    @property
    def active(self) -> bool:
        return self._active

    def _require_active(self) -> None:
        if self._closed or self.factory._closed:
            raise StoreError("STORE_CLOSED")
        if os.getpid() != self._owner_pid or os.getpid() != self.factory._owner_pid:
            raise StoreError("WRONG_CONTEXT")
        if not self._active:
            raise StoreError("NO_EXCLUSION")
        if os.getpid() != self._active_pid:
            raise StoreError("WRONG_CONTEXT")
        if threading.get_ident() != self._active_thread:
            raise StoreError("WRONG_CONTEXT")
        self.factory._check_children()
        self._check_lock_binding()

    def _check_lock_binding(self) -> None:
        if self._lock_fd < 0:
            raise StoreError("NO_EXCLUSION")
        name = self.factory._path_names(self.uid)[1]
        try:
            entry = os.stat(name, dir_fd=self.factory._fds["locks"],
                            follow_symlinks=False)
            held = os.fstat(self._lock_fd)
        except OSError as error:
            raise StoreError("LOCK_REBOUND") from error
        if (entry.st_dev, entry.st_ino) != (held.st_dev, held.st_ino):
            raise StoreError("LOCK_REBOUND")

    def _require_uid(self, uid: str) -> None:
        if uid != self.uid:
            raise StoreError("WRONG_UID")

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            raise StoreError("WRONG_CONTEXT")
        with self.factory._lifecycle:
            if self._active or self._acquiring or self._reserved:
                raise StoreError("BUSY")
            self._closed = True
            self.factory._handles.discard(self)

    @contextmanager
    def exclusive(self):
        if os.getpid() != self._owner_pid or os.getpid() != self.factory._owner_pid:
            raise StoreError("WRONG_CONTEXT")
        lock_fd = -1
        state_acquired = False
        with self.factory._lifecycle:
            if self._closed or self.factory._closed:
                raise StoreError("STORE_CLOSED")
            if self._active or self._acquiring or self._reserved:
                raise StoreError("NO_EXCLUSION")
            self._reserved = True
        primary = None
        try:
            if not self._state.acquire(blocking=False):
                raise StoreError("NO_EXCLUSION")
            state_acquired = True
            with self.factory._lifecycle:
                if self._closed or self.factory._closed:
                    raise StoreError("STORE_CLOSED")
            self._acquiring = True
            self.factory._check_children()
            record_name, lock_name, _ = self.factory._path_names(self.uid)
            try:
                lock_fd = os.open(lock_name,
                                  os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=self.factory._fds["locks"])
            except OSError as error:
                raise StoreError("LOCK_OPEN_FAILED") from error
            try:
                info = os.fstat(lock_fd)
                entry = os.stat(lock_name, dir_fd=self.factory._fds["locks"],
                                follow_symlinks=False)
            except OSError as error:
                raise StoreError("LOCK_IO") from error
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise StoreError("LOCK_REBOUND")
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                    or stat.S_IMODE(info.st_mode) != 0o600:
                raise StoreError("LOCK_PERMISSIONS")
            deadline = time.monotonic() + self.factory.lock_timeout
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise StoreError("LOCK_TIMEOUT")
                    time.sleep(0.005)
                except OSError as error:
                    raise StoreError("LOCK_IO") from error
            self._active = True
            self._acquiring = False
            self._active_pid = os.getpid()
            self._active_thread = threading.get_ident()
            self._lock_fd = lock_fd
            self._txn += 1
            primary = None
            try:
                yield self
            finally:
                self._active = False
                self._active_pid = 0
                self._active_thread = 0
                self._lock_fd = -1
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if lock_fd >= 0:
                    raw_fd = lock_fd
                    lock_fd = -1
                    _close_all_owned([raw_fd], primary, "LOCK_IO")
            finally:
                self._acquiring = False
                try:
                    if state_acquired:
                        self._state.release()
                finally:
                    with self.factory._lifecycle:
                        self._reserved = False

    def _leaf(self, name: str, parent: str, flags: int) -> int:
        try:
            fd = os.open(name, flags, dir_fd=self.factory._fds[parent])
        except OSError as error:
            if error.errno == errno.ENOENT:
                raise StoreError("RECORD_MISSING") from error
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise StoreError("PATH_SYMLINK") from error
            raise StoreError("STORE_IO") from error
        primary = None
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreError("STORE_IO") from error
            if not stat.S_ISREG(info.st_mode):
                raise StoreError("STORE_TYPE")
            try:
                entry = os.stat(name, dir_fd=self.factory._fds[parent],
                                follow_symlinks=False)
            except OSError as error:
                raise StoreError("STORE_REBOUND") from error
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise StoreError("STORE_REBOUND")
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise StoreError("STORE_PERMISSIONS")
            result = fd
            fd = -1
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                if do_raise:
                    raise chosen

    def _pending_exists(self) -> bool:
        name = self.factory._path_names(self.uid)[2]
        try:
            os.stat(name, dir_fd=self.factory._fds["pending"], follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError as error:
            raise StoreError("STORE_IO") from error

    def _read_record_bound(self) -> tuple[bytes, c1a.Record, int, tuple[int, int]]:
        name = self.factory._path_names(self.uid)[0]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = self._leaf(name, "records", flags)
        primary = None
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                try:
                    chunk = os.read(fd, 65536)
                except OSError as error:
                    raise StoreError("STORE_IO") from error
                if not chunk:
                    break
                total += len(chunk)
                if total > c1a.MAX_RECORD:
                    raise StoreError("RECORD_TOO_LARGE")
                chunks.append(chunk)
            raw = b"".join(chunks)
            try:
                record = c1a.decode_record(raw)
            except c1a.PrimitiveError as error:
                raise StoreError("RECORD_INVALID") from error
            if record.uid != self.uid:
                raise StoreError("RECORD_UID")
            try:
                canonical = record.to_json()
            except c1a.PrimitiveError as error:
                raise StoreError("RECORD_INVALID") from error
            if canonical != raw:
                raise StoreError("NONCANONICAL_RECORD")
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreError("STORE_IO") from error
            result = (raw, record, fd, (info.st_dev, info.st_ino))
            fd = -1
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw_fd)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                if do_raise:
                    raise chosen

    def _capsule_name(self) -> str:
        return self.uid + ".capsule"

    def _read_capsule_fd(self, fd: int) -> tuple[bytes, c1a.CapsuleRef]:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, c1a.C0_MAX_ENVELOPE + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > c1a.C0_MAX_ENVELOPE:
                    raise _CapsuleReadFailure("CAPSULE_TOO_LARGE")
                chunks.append(chunk)
        except OSError as error:
            raise _CapsuleReadFailure("CAPSULE_IO") from error
        raw = b"".join(chunks)
        try:
            ref = c1a.CapsuleRef.from_raw(raw)
        except c1a.PrimitiveError as error:
            if error.code in ("CAPSULE_TOO_LARGE", "CAPSULE_NOT_COMPACT_C1",
                              "JSON_TOO_LARGE"):
                raise _CapsuleReadFailure("CAPSULE_TOO_LARGE") from error
            raise _CapsuleReadFailure("CAPSULE_INVALID") from error
        return raw, ref

    def _capsule_acquire(self, phase: str) -> int:
        """One live native capsule acquisition; ENOENT-only private absence."""
        if phase not in ("read", "publish", "published", "winner"):
            raise ValueError("capsule phase")
        name = self._capsule_name()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        records_fd = self.factory._fds["records"]
        primary = None
        fd = -1
        try:
            try:
                fd = os.open(name, flags, dir_fd=records_fd)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    if phase in ("published", "winner"):
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                    raise StoreError("CAPSULE_IO") from error
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                raise _CapsuleAbsent()
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR) \
                        and phase in ("read", "publish"):
                    raise StoreError("CAPSULE_TYPE") from error
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                raise StoreError("CAPSULE_IO") from error
            try:
                info = os.fstat(fd)
            except OSError as error:
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                raise StoreError("CAPSULE_IO") from error
            if not stat.S_ISREG(info.st_mode):
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                raise StoreError("CAPSULE_TYPE")
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                raise StoreError("CAPSULE_PERMISSIONS")
            try:
                entry = os.stat(name, dir_fd=records_fd, follow_symlinks=False)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    if phase in ("published", "winner"):
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                    raise StoreError("CAPSULE_IO") from error
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                raise StoreError("CAPSULE_REBOUND")
            except OSError as error:
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                raise StoreError("CAPSULE_IO") from error
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                if phase in ("published", "winner"):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                raise StoreError("CAPSULE_REBOUND")
            result = fd
            fd = -1
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcome = self._capsule_close(raw_fd)
                if outcome is not None:
                    self._capsule_settle(primary, [outcome],
                                         effect=phase in ("published", "winner"))

    def _capsule_close(self, fd: int) -> BaseException | None:
        if fd < 0:
            return None
        try:
            os.close(fd)
        except BaseException as error:
            return error
        return None

    def _capsule_settle(self, primary: BaseException | None,
                        outcomes: list[BaseException | tuple[str, BaseException | None]],
                        *, effect: bool) -> None:
        """Elect once; raw entries are the existing native-close callers."""
        if not outcomes or _is_cancel(primary):
            return
        recorded = [("native", item) if isinstance(item, BaseException) else item
                    for item in outcomes]
        for origin, error in recorded:
            if _is_cancel(error):
                raise error
        if primary is not None:
            return
        for origin, error in recorded:
            if error is not None and not isinstance(error, OSError):
                raise error
        for origin, error in recorded:
            if origin == "opaque":
                raise error
            if effect:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            raise StoreError("STORE_IO") from error

    def _capsule_existing(self, raw: bytes, ref: c1a.CapsuleRef,
                          fd: int, *, effect: bool) -> c1a.CapsuleRef:
        primary = None
        outcomes: list[BaseException] = []
        try:
            try:
                current_raw, current_ref = self._read_capsule_fd(fd)
            except _CapsuleReadFailure as error:
                if effect:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                raise StoreError(error.code) from error
            if current_raw != raw or current_ref != ref:
                raise StoreError("CAPSULE_CONFLICT")
            try:
                os.fsync(fd)
                os.fsync(self.factory._fds["records"])
            except OSError as error:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            if not self._entry_matches_fd(self._capsule_name(), "records", fd):
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
            self.factory._check_children()
            self._check_lock_binding()
            try:
                os.lseek(fd, 0, os.SEEK_SET)
            except OSError as error:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            try:
                final_raw, final_ref = self._read_capsule_fd(fd)
            except _CapsuleReadFailure as error:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            if final_raw != raw or final_ref != ref:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
            if not self._entry_matches_fd(self._capsule_name(), "records", fd):
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
            self.factory._check_children()
            self._check_lock_binding()
            return ref
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcome = self._capsule_close(raw_fd)
                if outcome is not None:
                    outcomes.append(outcome)
            self._capsule_settle(primary, outcomes, effect=True)

    def _capsule_new(self, raw: bytes, ref: c1a.CapsuleRef) -> c1a.CapsuleRef:
        if self._temp_pending is not None:
            raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
        temp: tuple[str, tuple[int, int]] | None = None
        temp_owned = False
        temp_fd = -1
        target_fd = -1
        effect = False
        published = False
        primary = None
        outcomes: list[tuple[str, BaseException | None]] = []
        try:
            name = "." + self.uid + ".tmp." + str(os.getpid()) + "." + os.urandom(8).hex()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                temp_fd = os.open(name, flags, 0o600, dir_fd=self.factory._fds["records"])
            except OSError as error:
                if error.errno == errno.EEXIST:
                    raise StoreError("CAPSULE_IO") from error
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            effect = True
            try:
                info = os.fstat(temp_fd)
            except OSError as error:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            temp = (name, (info.st_dev, info.st_ino))
            self._temp_pending = temp
            temp_owned = True
            view = memoryview(raw)
            written = 0
            while written < len(view):
                try:
                    progress = os.write(temp_fd, view[written:])
                except OSError as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                if progress == 0:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                if progress < 0 or progress > len(view) - written:
                    raise ValueError("capsule write progress")
                written += progress
            try:
                os.fsync(temp_fd)
            except OSError as error:
                raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
            self.factory._cut("after_temp_file_fsync")
            raw_fd = temp_fd
            temp_fd = -1
            outcome = self._capsule_close(raw_fd)
            if outcome is not None:
                outcomes.append(("native", outcome))
            if not outcomes:
                # Transfer the registered alias only after the TEMP close succeeds.
                self._temp_pending = None
                self.factory._cut("capsule_before_link")
                self.factory._check_children()
                self._check_lock_binding()
                if not self._temp_matches(temp):
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                published_id = temp[1]
                try:
                    os.link(temp[0], self._capsule_name(),
                            src_dir_fd=self.factory._fds["records"],
                            dst_dir_fd=self.factory._fds["records"],
                            follow_symlinks=False)
                except FileExistsError:
                    temp_owned = False
                    try:
                        settled = self._cleanup_temp(temp)
                    except BaseException as error:
                        outcomes.append(("opaque", error))
                    else:
                        if not settled:
                            outcomes.append(("false", None))
                    if not outcomes:
                        try:
                            probe = self._capsule_acquire("winner")
                        except _CapsuleAbsent:
                            raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                        # No outer owned cleanup remains; transfer to its sole owner.
                        self._capsule_existing(raw, ref, probe, effect=True)
                except OSError as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                else:
                    published = True
            if published:
                try:
                    self.factory._cut("capsule_after_link")
                except OSError as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                try:
                    target_fd = self._capsule_acquire("published")
                except _CapsuleAbsent:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                try:
                    info = os.fstat(target_fd)
                except OSError as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                if (info.st_dev, info.st_ino) != published_id:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                try:
                    current_raw, current_ref = self._read_capsule_fd(target_fd)
                except _CapsuleReadFailure as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                if current_raw != raw or current_ref != ref:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                try:
                    os.fsync(target_fd)
                except OSError as error:
                    raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                temp_owned = False
                try:
                    settled = self._cleanup_temp(temp)
                except BaseException as error:
                    outcomes.append(("opaque", error))
                else:
                    if not settled:
                        outcomes.append(("false", None))
                if not outcomes:
                    if not self._entry_matches_fd(self._capsule_name(), "records", target_fd):
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                    self.factory._check_children()
                    self._check_lock_binding()
                    try:
                        os.lseek(target_fd, 0, os.SEEK_SET)
                    except OSError as error:
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                    try:
                        final_raw, final_ref = self._read_capsule_fd(target_fd)
                    except _CapsuleReadFailure as error:
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN") from error
                    if final_raw != raw or final_ref != ref:
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                    if not self._entry_matches_fd(self._capsule_name(), "records", target_fd):
                        raise StoreCommitUncertain("CAPSULE_UNCERTAIN")
                    self.factory._check_children()
                    self._check_lock_binding()
        except BaseException as error:
            primary = error
            raise
        finally:
            if temp_fd >= 0:
                raw_fd = temp_fd
                temp_fd = -1
                outcome = self._capsule_close(raw_fd)
                if outcome is not None:
                    outcomes.append(("native", outcome))
            if target_fd >= 0:
                raw_fd = target_fd
                target_fd = -1
                outcome = self._capsule_close(raw_fd)
                if outcome is not None:
                    outcomes.append(("native", outcome))
            if temp_owned:
                temp_owned = False
                try:
                    settled = self._cleanup_temp(temp)
                except BaseException as error:
                    outcomes.append(("opaque", error))
                else:
                    if not settled:
                        outcomes.append(("false", None))
            self._capsule_settle(primary, outcomes, effect=effect)
        return ref

    def read_capsule(self) -> tuple[bytes, c1a.CapsuleRef]:
        self._require_active()
        if self._pending_exists():
            raise PendingRecovery()
        self.factory._check_children()
        self._check_lock_binding()
        primary = None
        outcomes: list[BaseException] = []
        fd = -1
        try:
            try:
                fd = self._capsule_acquire("read")
            except _CapsuleAbsent:
                raise StoreError("CAPSULE_MISSING")
            try:
                raw, ref = self._read_capsule_fd(fd)
            except _CapsuleReadFailure as error:
                raise StoreError(error.code) from error
            if not self._entry_matches_fd(self._capsule_name(), "records", fd):
                raise StoreError("CAPSULE_REBOUND")
            self.factory._check_children()
            self._check_lock_binding()
            return raw, ref
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcome = self._capsule_close(raw_fd)
                if outcome is not None:
                    outcomes.append(outcome)
            self._capsule_settle(primary, outcomes, effect=False)

    def publish_capsule(self, raw: bytes) -> c1a.CapsuleRef:
        self._require_active()
        if self._pending_exists():
            raise PendingRecovery()
        if type(raw) is not bytes:
            raise StoreError("CAPSULE_INVALID")
        if len(raw) > c1a.C0_MAX_ENVELOPE:
            raise StoreError("CAPSULE_TOO_LARGE")
        try:
            ref = c1a.CapsuleRef.from_raw(raw)
        except c1a.PrimitiveError as error:
            if error.code in ("CAPSULE_TOO_LARGE", "CAPSULE_NOT_COMPACT_C1",
                              "JSON_TOO_LARGE"):
                raise StoreError("CAPSULE_TOO_LARGE") from error
            raise StoreError("CAPSULE_INVALID") from error
        self.factory._check_children()
        self._check_lock_binding()
        try:
            fd = self._capsule_acquire("publish")
        except _CapsuleAbsent:
            return self._capsule_new(raw, ref)
        return self._capsule_existing(raw, ref, fd, effect=False)

    def _read_private(self) -> tuple[bytes, c1a.Record]:
        raw, record, fd, _ = self._read_record_bound()
        outcomes: list[BaseException] = []
        try:
            os.close(fd)
        except BaseException as error:
            outcomes.append(error)
        chosen, do_raise = _choose_unwind(None, outcomes, "STORE_IO")
        if do_raise:
            raise chosen
        return raw, record

    def _read_public(self) -> tuple[bytes, c1a.Record]:
        if self._pending_exists():
            raise PendingRecovery()
        return self._read_private()

    def read(self, uid: str) -> tuple[bytes, str, c1a.Record]:
        self._require_active()
        self._require_uid(uid)
        raw, record = self._read_public()
        return raw, _sha(raw), record

    def current_principal(self, uid: str, operation_id: str) -> c1a.Principal:
        self._require_active()
        self._require_uid(uid)
        try:
            principal = self.factory.authority.resolve(uid, operation_id,
                                                       self.actor_context)
        except Exception as error:
            raise StoreError("AUTHORITY_UNAVAILABLE") from error
        if principal is None or not c1a._validate_principal(principal):
            raise StoreError("AUTHORITY_INVALID")
        return principal

    def _create_marker(self, mode: str, old: str | None, candidate: str,
                       revision: int) -> tuple[int, int]:
        name = self.factory._path_names(self.uid)[2]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(name, flags, 0o600, dir_fd=self.factory._fds["pending"])
        except FileExistsError as error:
            raise PendingRecovery() from error
        except OSError as error:
            raise StoreError("MARKER_OPEN_FAILED") from error
        primary = None
        try:
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                        or stat.S_IMODE(info.st_mode) != 0o600:
                    raise StoreError("MARKER_PERMISSIONS")
                data = _canonical_marker(_marker_value(self.uid, mode, old, candidate,
                                                       revision))
                if len(data) > MAX_MARKER:
                    raise StoreError("MARKER_TOO_LARGE")
                view = memoryview(data)
                written = 0
                while written < len(view):
                    written += os.write(fd, view[written:])
                os.fsync(fd)
                self.factory._cut("after_marker_file_fsync")
                os.fsync(self.factory._fds["pending"])
                self.factory._cut("after_marker_dir_fsync")
                return info.st_dev, info.st_ino
            except StoreError:
                raise
            except Exception as error:
                raise StoreCommitUncertain("MARKER_BARRIER") from error
        except BaseException as error:
            primary = error
            raise
        finally:
            outcomes: list[BaseException] = []
            try:
                os.close(fd)
            except BaseException as error:
                outcomes.append(error)
            chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
            if do_raise:
                raise chosen

    def _marker_identity(self) -> tuple[int, int]:
        name = self.factory._path_names(self.uid)[2]
        try:
            info = os.stat(name, dir_fd=self.factory._fds["pending"],
                           follow_symlinks=False)
        except OSError as error:
            raise StoreError("STORE_IO") from error
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                or stat.S_IMODE(info.st_mode) != 0o600:
            raise StoreError("MARKER_PERMISSIONS")
        return info.st_dev, info.st_ino

    def _remove_marker(self, expected: tuple[int, int], marker_fd: int = -1) -> None:
        name = self.factory._path_names(self.uid)[2]
        if marker_fd >= 0:
            if self._marker_identity() != expected:
                raise StoreError("MARKER_REBOUND")
            if not self._entry_matches_fd(name, "pending", marker_fd):
                raise StoreError("MARKER_REBOUND")
        elif self._marker_identity() != expected:
            raise StoreError("MARKER_REBOUND")
        try:
            os.unlink(name, dir_fd=self.factory._fds["pending"])
        except OSError as error:
            raise StoreError("MARKER_UNLINK_FAILED") from error
        self.factory._cut("after_marker_unlink")
        try:
            os.fsync(self.factory._fds["pending"])
        except OSError as error:
            raise StoreCommitUncertain("PENDING_DIR_FSYNC") from error
        self.factory._cut("after_pending_dir_fsync")

    def _cleanup_marker(self, expected: tuple[int, int] | None) -> bool:
        if expected is None:
            return True
        try:
            if self._pending_exists():
                self._remove_marker(expected)
            return True
        except Exception:
            return False

    def _write_temp(self, raw: bytes) -> tuple[str, tuple[int, int]]:
        name = "." + self.uid + ".tmp." + str(os.getpid()) + "." + os.urandom(8).hex()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=self.factory._fds["records"])
        primary = None
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreCommitUncertain("TEMP_UNREGISTERED") from error
            ident = (info.st_dev, info.st_ino)
            self._temp_pending = (name, ident)
            view = memoryview(raw)
            written = 0
            while written < len(view):
                written += os.write(fd, view[written:])
            os.fsync(fd)
            self.factory._cut("after_temp_file_fsync")
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw_fd)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                if do_raise:
                    raise chosen
        self._temp_pending = None
        return name, ident

    def _temp_matches(self, temp: tuple[str, tuple[int, int]]) -> bool:
        name, ident = temp
        try:
            entry = os.stat(name, dir_fd=self.factory._fds["records"],
                            follow_symlinks=False)
        except OSError:
            return False
        return (entry.st_dev, entry.st_ino) == ident

    def _cleanup_temp(self, temp: tuple[str, tuple[int, int]] | None) -> bool:
        if temp is None:
            return True
        if not self._temp_matches(temp):
            self._temp_pending = None
            return False
        name, _ = temp
        try:
            os.unlink(name, dir_fd=self.factory._fds["records"])
            os.fsync(self.factory._fds["records"])
        except OSError:
            return False
        self._temp_pending = None
        return True

    def _cleanup_pending_temp(self) -> bool:
        temp = self._temp_pending
        if temp is None:
            return True
        return self._cleanup_temp(temp)

    def _validate_new(self, raw: bytes, current: c1a.Record | None,
                      create: bool) -> c1a.Record:
        if type(raw) is not bytes or len(raw) > c1a.MAX_RECORD:
            raise StoreError("RECORD_INVALID")
        try:
            new = c1a.decode_record(raw)
        except c1a.PrimitiveError as error:
            raise StoreError("RECORD_INVALID") from error
        if new.uid != self.uid:
            raise StoreError("RECORD_UID")
        try:
            if new.to_json() != raw:
                raise StoreError("NONCANONICAL_RECORD")
        except c1a.PrimitiveError as error:
            raise StoreError("RECORD_INVALID") from error
        if create:
            if new.revision != 0:
                raise StoreError("CREATE_REVISION")
        else:
            if current is None:
                raise StoreError("RECORD_MISSING")
            if new.identity() != current.identity():
                raise StoreError("IDENTITY_CHANGED")
            if new.revision != current.revision + 1:
                raise StoreError("REVISION_INVALID")
        return new

    def create(self, raw: bytes) -> StoreReceipt:
        self._require_active()
        name = self.factory._path_names(self.uid)[0]
        try:
            os.stat(name, dir_fd=self.factory._fds["records"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise StoreError("STORE_IO") from error
        else:
            raise StoreError("EXISTS")
        new = self._validate_new(raw, None, create=True)
        marker: tuple[int, int] | None = None
        temp: tuple[str, tuple[int, int]] | None = None
        linked = False
        try:
            self.factory._cut("create_before_marker")
            marker = self._create_marker("create", None, _sha(raw), 0)
            temp = self._write_temp(raw)
            self.factory._cut("create_before_link")
            self.factory._check_children()
            self._check_lock_binding()
            if not self._temp_matches(temp):
                raise StoreError("TEMP_REBOUND")
            try:
                os.link(temp[0], name, src_dir_fd=self.factory._fds["records"],
                        dst_dir_fd=self.factory._fds["records"],
                        follow_symlinks=False)
            except FileExistsError as error:
                raise StoreError("EXISTS") from error
            linked = True
            if not self._temp_matches(temp):
                raise StoreCommitUncertain("TEMP_REBOUND")
            published_id = temp[1]
            os.unlink(temp[0], dir_fd=self.factory._fds["records"])
            temp = None
            os.fsync(self.factory._fds["records"])
            self.factory._cut("create_after_record_dir_fsync")
            if not self._entry_matches_identity(
                    self.factory._path_names(self.uid)[0], "records", published_id):
                raise StoreCommitUncertain("PUBLISHED_REBOUND")
            readback, _, readback_fd, readback_id = self._read_record_bound()
            primary = None
            try:
                if _sha(readback) != _sha(raw):
                    raise StoreCommitUncertain("READBACK_MISMATCH")
                if readback_id != published_id or not self._entry_matches_fd(
                        self.factory._path_names(self.uid)[0], "records",
                        readback_fd):
                    raise StoreCommitUncertain("READBACK_REBOUND")
                self.factory._check_children()
                self._check_lock_binding()
                self._remove_marker(marker)
                marker = None
                self.factory._check_children()
                self._check_lock_binding()
                if not self._entry_matches_identity(
                        self.factory._path_names(self.uid)[0], "records",
                        published_id):
                    raise StoreCommitUncertain("POST_UNLINK_REBOUND")
            except BaseException as error:
                primary = error
                raise
            finally:
                outcomes: list[BaseException] = []
                try:
                    os.close(readback_fd)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                if do_raise:
                    raise chosen
            return StoreReceipt("durable", raw_sha256=_sha(raw),
                                bytes_written=len(raw), revision=0)
        except StoreError as error:
            if linked:
                raise StoreCommitUncertain("CREATE_UNCERTAIN") from error
            ct = self._cleanup_temp(temp)
            cp = self._cleanup_pending_temp()
            cm = self._cleanup_marker(marker)
            if ct and cp and cm:
                raise
            raise StoreCommitUncertain("CREATE_UNCERTAIN") from error
        except StoreCommitUncertain:
            raise
        except Exception as error:
            if linked:
                raise StoreCommitUncertain("CREATE_UNCERTAIN") from error
            ct = self._cleanup_temp(temp)
            cp = self._cleanup_pending_temp()
            cm = self._cleanup_marker(marker)
            if ct and cp and cm:
                raise StoreError("CREATE_FAILED") from error
            raise StoreCommitUncertain("CREATE_UNCERTAIN") from error

    def compare_and_swap(self, uid: str, expected_raw_sha256: str,
                         data: bytes) -> None:
        self._require_active()
        self._require_uid(uid)
        current_raw, current, current_fd, current_id = self._read_record_bound()
        primary_outer = None
        try:
            if _sha(current_raw) != expected_raw_sha256:
                raise StoreError("STALE_RECORD")
            if not self._entry_matches_fd(
                    self.factory._path_names(self.uid)[0], "records", current_fd):
                raise StoreError("RECORD_REBOUND")
            self._validate_new(data, current, create=False)
            marker: tuple[int, int] | None = None
            temp: tuple[str, tuple[int, int]] | None = None
            replaced = False
            try:
                self.factory._cut("before_marker")
                marker = self._create_marker("replace", _sha(current_raw), _sha(data),
                                            current.revision + 1)
                self.factory._cut("before_temp")
                temp = self._write_temp(data)
                self.factory._cut("before_replace")
                self.factory._check_children()
                self._check_lock_binding()
                if not self._entry_matches_fd(
                        self.factory._path_names(self.uid)[0], "records", current_fd):
                    raise StoreError("RECORD_REBOUND")
                if not self._temp_matches(temp):
                    raise StoreError("TEMP_REBOUND")
                published_id = temp[1]
                os.replace(temp[0], self.factory._path_names(self.uid)[0],
                           src_dir_fd=self.factory._fds["records"],
                           dst_dir_fd=self.factory._fds["records"])
                temp = None
                replaced = True
                self.factory._cut("after_replace")
                if not self._entry_matches_identity(
                        self.factory._path_names(self.uid)[0], "records",
                        published_id):
                    raise StoreCommitUncertain("PUBLISHED_REBOUND")
                os.fsync(self.factory._fds["records"])
                self.factory._cut("after_record_dir_fsync")
                if not self._entry_matches_identity(
                        self.factory._path_names(self.uid)[0], "records",
                        published_id):
                    raise StoreCommitUncertain("PUBLISHED_REBOUND")
                readback, _, readback_fd, readback_id = self._read_record_bound()
                primary = None
                try:
                    if _sha(readback) != _sha(data):
                        raise StoreCommitUncertain("READBACK_MISMATCH")
                    if readback_id != published_id or not self._entry_matches_fd(
                            self.factory._path_names(self.uid)[0], "records",
                            readback_fd):
                        raise StoreCommitUncertain("READBACK_REBOUND")
                    self.factory._check_children()
                    self._check_lock_binding()
                    self._remove_marker(marker)
                    marker = None
                    self.factory._check_children()
                    self._check_lock_binding()
                    if not self._entry_matches_identity(
                            self.factory._path_names(self.uid)[0], "records",
                            published_id):
                        raise StoreCommitUncertain("POST_UNLINK_REBOUND")
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    outcomes: list[BaseException] = []
                    try:
                        os.close(readback_fd)
                    except BaseException as error:
                        outcomes.append(error)
                    chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                    if do_raise:
                        raise chosen
                return None
            except StoreError as error:
                if replaced:
                    raise StoreCommitUncertain("AFTER_REPLACE")
                ct = self._cleanup_temp(temp)
                cp = self._cleanup_pending_temp()
                cm = self._cleanup_marker(marker)
                if ct and cp and cm:
                    raise
                raise StoreCommitUncertain("CLEANUP_RESIDUE") from error
            except StoreCommitUncertain:
                raise
            except Exception as error:
                if replaced:
                    raise StoreCommitUncertain("AFTER_REPLACE") from error
                ct = self._cleanup_temp(temp)
                cp = self._cleanup_pending_temp()
                cm = self._cleanup_marker(marker)
                if ct and cp and cm:
                    raise StoreError("COMMIT_FAILED") from error
                raise StoreCommitUncertain("CLEANUP_RESIDUE") from error
        except BaseException as error:
            primary_outer = error
            raise
        finally:
            _close_all_owned([current_fd], primary_outer, "STORE_IO")

    def _entry_matches_fd(self, name: str, parent: str, fd: int) -> bool:
        try:
            entry = os.stat(name, dir_fd=self.factory._fds[parent],
                            follow_symlinks=False)
            held = os.fstat(fd)
        except OSError:
            return False
        return (entry.st_dev, entry.st_ino) == (held.st_dev, held.st_ino)

    def _entry_matches_identity(self, name: str, parent: str,
                                identity: tuple[int, int]) -> bool:
        try:
            entry = os.stat(name, dir_fd=self.factory._fds[parent],
                            follow_symlinks=False)
        except OSError:
            return False
        return (entry.st_dev, entry.st_ino) == identity

    def _read_marker(self) -> tuple[dict[str, Any], int, tuple[int, int]]:
        name = self.factory._path_names(self.uid)[2]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            fd = os.open(name, flags, dir_fd=self.factory._fds["pending"])
        except FileNotFoundError as error:
            raise StoreError("NO_PENDING") from error
        except OSError as error:
            raise StoreError("MARKER_OPEN_FAILED") from error
        primary = None
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise StoreError("STORE_IO") from error
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                    or stat.S_IMODE(info.st_mode) != 0o600:
                raise StoreError("MARKER_PERMISSIONS")
            try:
                raw = os.read(fd, MAX_MARKER + 1)
                extra = os.read(fd, 1)
            except OSError as error:
                raise StoreError("STORE_IO") from error
            if len(raw) > MAX_MARKER or extra:
                raise StoreError("MARKER_TOO_LARGE")
            try:
                value = c1a.strict_json(raw, max_bytes=MAX_MARKER)
            except c1a.PrimitiveError as error:
                raise StoreError("MARKER_INVALID") from error
            value = _validate_marker(value, self.uid)
            if _canonical_marker(value) != raw:
                raise StoreError("MARKER_INVALID")
            result = (value, fd, (info.st_dev, info.st_ino))
            fd = -1
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            if fd >= 0:
                raw_fd = fd
                fd = -1
                outcomes: list[BaseException] = []
                try:
                    os.close(raw_fd)
                except BaseException as error:
                    outcomes.append(error)
                chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
                if do_raise:
                    raise chosen

    def recover(self) -> StoreReceipt:
        if self._active:
            return self._recover_locked()
        with self.exclusive():
            return self._recover_locked()

    def _recover_locked(self) -> StoreReceipt:
        self._require_active()
        marker, marker_fd, marker_id = self._read_marker()
        record_fd = -1
        primary = None
        try:
            candidate = marker["candidateSha256"]
            old = marker["oldSha256"]
            mode = marker["mode"]
            try:
                raw, record, record_fd, record_id = self._read_record_bound()
                current_hash = _sha(raw)
                current_revision = record.revision
            except StoreError as error:
                if error.code != "RECORD_MISSING":
                    raise
                raw = b""
                current_hash = None
                current_revision = None
            if current_hash == candidate:
                if current_revision != marker["revision"]:
                    raise StoreError("RECOVERY_REVISION")
                if mode == "create" and current_revision != 0:
                    raise StoreError("RECOVERY_REVISION")
                if record_fd < 0 or not self._entry_matches_fd(
                        self.factory._path_names(self.uid)[0], "records", record_fd):
                    raise StoreError("RECOVERY_RECORD_REBOUND")
                try:
                    os.fsync(record_fd)
                    os.fsync(self.factory._fds["records"])
                except OSError as error:
                    raise StoreCommitUncertain("RECOVERY_BARRIER") from error
                if not self._entry_matches_fd(
                        self.factory._path_names(self.uid)[0], "records", record_fd):
                    raise StoreError("RECOVERY_RECORD_REBOUND")
                self.factory._check_children()
                self._check_lock_binding()
                self._remove_marker(marker_id, marker_fd)
                try:
                    self.factory._check_children()
                    self._check_lock_binding()
                    if not self._entry_matches_fd(
                            self.factory._path_names(self.uid)[0], "records", record_fd):
                        raise StoreError("RECOVERY_RECORD_REBOUND")
                except StoreError as error:
                    raise StoreCommitUncertain("POST_UNLINK_REBOUND") from error
                return StoreReceipt("durable", raw_sha256=candidate,
                                    bytes_written=len(raw),
                                    revision=marker["revision"])
            expected_old = old if mode == "replace" else None
            if current_hash == expected_old or (mode == "create" and current_hash is None):
                if mode == "replace":
                    if current_revision is None or marker["revision"] != current_revision + 1:
                        raise StoreError("RECOVERY_REVISION")
                    if record_fd < 0 or not self._entry_matches_fd(
                            self.factory._path_names(self.uid)[0], "records", record_fd):
                        raise StoreError("RECOVERY_RECORD_REBOUND")
                else:
                    if marker["revision"] != 0:
                        raise StoreError("RECOVERY_REVISION")
                    try:
                        os.stat(self.factory._path_names(self.uid)[0],
                                dir_fd=self.factory._fds["records"],
                                follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        raise StoreError("STORE_IO") from error
                    else:
                        raise StoreError("RECOVERY_RECORD_REBOUND")
                self.factory._check_children()
                self._check_lock_binding()
                self._remove_marker(marker_id, marker_fd)
                try:
                    self.factory._check_children()
                    self._check_lock_binding()
                    if mode == "replace":
                        if record_fd < 0 or not self._entry_matches_fd(
                                self.factory._path_names(self.uid)[0], "records",
                                record_fd):
                            raise StoreError("RECOVERY_RECORD_REBOUND")
                    else:
                        try:
                            os.stat(self.factory._path_names(self.uid)[0],
                                    dir_fd=self.factory._fds["records"],
                                    follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        except OSError as error:
                            raise StoreError("STORE_IO") from error
                        else:
                            raise StoreError("RECOVERY_RECORD_REBOUND")
                except StoreError as error:
                    raise StoreCommitUncertain("POST_UNLINK_REBOUND") from error
                return StoreReceipt("not_committed", raw_sha256=current_hash or "",
                                    bytes_written=0)
            raise StoreError("RECOVERY_FENCED")
        except BaseException as error:
            primary = error
            raise
        finally:
            outcomes: list[BaseException] = []
            for fd in (record_fd, marker_fd):
                if fd < 0:
                    continue
                try:
                    os.close(fd)
                except BaseException as error:
                    outcomes.append(error)
            chosen, do_raise = _choose_unwind(primary, outcomes, "STORE_IO")
            if do_raise:
                raise chosen
