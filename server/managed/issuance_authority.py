"""Passive C1c authority snapshot projection.

Read-only mapping of the authoritative deployment registry into the accepted
C1a Principal/RegistryEntry types and the accepted C1b AuthorityView shape.
This module performs no I/O, writes no authority and is not a transport
authenticator. Importing it must remain pure.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import issuance_primitives as c1a

MAX_USERS = 10_000
_KEY_NAMES = frozenset(("wireguard", "awg"))
_UID_RE = re.compile(r"[0-9a-f]{32}\Z")
_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
_OWNER_MARKER = "xio-managed-v1"
_FACTORY_TOKEN = object()

_ERROR_CODES = frozenset((
    "SNAPSHOT_SHAPE",
    "SNAPSHOT_OWNER",
    "SNAPSHOT_ID",
    "SNAPSHOT_USERS",
    "SNAPSHOT_ROW",
    "SNAPSHOT_ROLE",
    "SNAPSHOT_SLOT",
    "SNAPSHOT_KEYS",
    "SNAPSHOT_KEY_TEXT",
    "SNAPSHOT_KEY_ZERO",
    "SNAPSHOT_KEY_CONFLICT",
    "SNAPSHOT_LIMIT",
    "SNAPSHOT_CREATED_BY",
    "SNAPSHOT_TOO_LARGE",
))


class AuthoritySnapshotError(Exception):
    """Finite local authority-snapshot failure; no path or registry payload."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            raise ValueError("unknown authority snapshot code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ActorContext:
    """Trusted-caller context; values alone do not authenticate the caller."""

    actor: str | None
    transport: str


@dataclass(frozen=True)
class _User:
    uid: str
    revoked: bool
    slot: int
    role: str
    keys: tuple[tuple[str, str], ...]
    created_by: str | None
    user_limit: int


def _fail(code: str) -> None:
    raise AuthoritySnapshotError(code)


def _is_uid(value: Any) -> bool:
    return type(value) is str and _UID_RE.fullmatch(value) is not None


def _require_uid(value: Any, code: str = "SNAPSHOT_SHAPE") -> str:
    if not _is_uid(value):
        _fail(code)
    return value


def _decode_key(value: Any) -> tuple[bytes, str]:
    if type(value) is not str or len(value) != 44 or value[-1] != "=":
        _fail("SNAPSHOT_KEY_TEXT")
    body = value[:-1]
    if any(character not in _B64_ALPHABET for character in body):
        _fail("SNAPSHOT_KEY_TEXT")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _fail("SNAPSHOT_KEY_TEXT")
    if len(raw) != 32:
        _fail("SNAPSHOT_KEY_TEXT")
    if not any(raw):
        _fail("SNAPSHOT_KEY_ZERO")
    return raw, base64.b64encode(raw).decode("ascii")


def _row(uid: str, value: Any, seen_keys: set[bytes],
         active_slots: set[int]) -> _User:
    if not isinstance(value, Mapping):
        _fail("SNAPSHOT_ROW")
    try:
        revoked = value["revoked"]
        role = value["role"]
        slot = value["slot"]
        keys_value = value["keys"]
        created_by = value["createdBy"]
        user_limit = value["userLimit"]
    except KeyError:
        _fail("SNAPSHOT_ROW")

    if type(revoked) is not bool:
        _fail("SNAPSHOT_ROW")
    if type(role) is not str or role not in ("user", "admin"):
        _fail("SNAPSHOT_ROLE")
    if type(slot) is not int or isinstance(slot, bool) or not 2 <= slot <= 254:
        _fail("SNAPSHOT_SLOT")
    if not isinstance(keys_value, Mapping) or len(keys_value) > 2:
        _fail("SNAPSHOT_KEYS")
    if created_by is not None and not _is_uid(created_by):
        _fail("SNAPSHOT_CREATED_BY")
    if type(user_limit) is not int or isinstance(user_limit, bool) \
            or not 0 <= user_limit <= 250:
        _fail("SNAPSHOT_LIMIT")
    if role == "user" and user_limit != 0:
        _fail("SNAPSHOT_LIMIT")

    keys: list[tuple[str, str]] = []
    for name, value_key in keys_value.items():
        if type(name) is not str or name not in _KEY_NAMES:
            _fail("SNAPSHOT_KEYS")
        raw, canonical = _decode_key(value_key)
        if raw in seen_keys:
            _fail("SNAPSHOT_KEY_CONFLICT")
        seen_keys.add(raw)
        keys.append((name, canonical))
    keys.sort(key=lambda item: item[0])

    if not revoked:
        if slot in active_slots:
            _fail("SNAPSHOT_SLOT")
        active_slots.add(slot)

    return _User(uid=uid, revoked=revoked, slot=slot, role=role,
                 keys=tuple(keys), created_by=created_by,
                 user_limit=user_limit)


def snapshot_from_deployment(d: Any) -> "DeploymentAuthority":
    """Validate and copy the consumed public authority subset.

    The source mapping is never retained, mutated or repaired. Extra fields are
    ignored; malformed consumed data rejects the whole snapshot.
    """
    if not isinstance(d, Mapping):
        _fail("SNAPSHOT_SHAPE")
    try:
        owner = d["owner"]
    except KeyError:
        _fail("SNAPSHOT_OWNER")
    if type(owner) is not str or owner != _OWNER_MARKER:
        _fail("SNAPSHOT_OWNER")
    try:
        deployment_id = d["id"]
    except KeyError:
        _fail("SNAPSHOT_ID")
    if type(deployment_id) is not str or not deployment_id:
        _fail("SNAPSHOT_ID")
    try:
        encoded_id = deployment_id.encode("utf-8")
    except UnicodeError:
        _fail("SNAPSHOT_ID")
    if len(encoded_id) > 128:
        _fail("SNAPSHOT_ID")
    try:
        users = d["users"]
    except KeyError:
        _fail("SNAPSHOT_USERS")
    if not isinstance(users, Mapping):
        _fail("SNAPSHOT_USERS")
    if len(users) > MAX_USERS:
        _fail("SNAPSHOT_TOO_LARGE")

    seen_keys: set[bytes] = set()
    active_slots: set[int] = set()
    entries: list[_User] = []
    seen_uids: set[str] = set()
    for uid, value in users.items():
        if not _is_uid(uid):
            _fail("SNAPSHOT_ROW")
        if uid in seen_uids:
            _fail("SNAPSHOT_ROW")
        seen_uids.add(uid)
        entries.append(_row(uid, value, seen_keys, active_slots))
    entries.sort(key=lambda item: item.uid)
    return DeploymentAuthority(_FACTORY_TOKEN, deployment_id, tuple(entries))


class DeploymentAuthority:
    """Immutable read-only snapshot; construct only via snapshot_from_deployment."""

    __slots__ = ("_deployment_id", "_users", "_by_uid")

    def __init__(self, token: Any, deployment_id: str,
                 users: tuple[_User, ...]):
        if token is not _FACTORY_TOKEN:
            raise TypeError(
                "DeploymentAuthority must be built by snapshot_from_deployment"
            )
        self._deployment_id = deployment_id
        self._users = users
        self._by_uid = MappingProxyType({entry.uid: entry for entry in users})

    @property
    def deployment_id(self) -> str:
        return self._deployment_id

    def resolve(self, uid: str, operation_id: str,
                actor_context: ActorContext) -> c1a.Principal:
        target = _require_uid(uid)
        operation = _require_uid(operation_id)
        del target, operation
        if type(actor_context) is not ActorContext:
            _fail("SNAPSHOT_SHAPE")
        actor = actor_context.actor
        transport = actor_context.transport
        if actor is None:
            if transport != "owner-cli":
                _fail("SNAPSHOT_SHAPE")
            return c1a.Principal(uid=None, role="owner", revoked=False)
        if not _is_uid(actor) or transport != "delegate-cli":
            _fail("SNAPSHOT_SHAPE")
        entry = self._by_uid.get(actor)
        if entry is not None and entry.role == "admin" and not entry.revoked:
            return c1a.Principal(uid=actor, role="delegate", revoked=False)
        return c1a.Principal(uid=actor, role="delegate", revoked=True)

    def registry_entries(self) -> dict[str, c1a.RegistryEntry]:
        return {
            entry.uid: c1a.RegistryEntry(
                uid=entry.uid,
                revoked=entry.revoked,
                slot=entry.slot,
                keys=tuple(value for _name, value in entry.keys),
                role=entry.role,
                created_by=entry.created_by,
            )
            for entry in self._users
        }

    def delegate_limit(self, actor: str) -> int:
        if actor is None:
            _fail("SNAPSHOT_ROLE")
        if type(actor) is not str or not _is_uid(actor):
            _fail("SNAPSHOT_SHAPE")
        entry = self._by_uid.get(actor)
        if entry is None or entry.role != "admin" or entry.revoked:
            _fail("SNAPSHOT_ROLE")
        return entry.user_limit
