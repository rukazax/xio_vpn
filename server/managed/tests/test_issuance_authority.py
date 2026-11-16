"""Dedicated passive C1c authority snapshot tests (stdlib, owned roots)."""

from __future__ import annotations

import base64
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuance_primitives as c1a  # noqa: E402
import issuance_store as c1b  # noqa: E402
import issuance_authority as authority  # noqa: E402

BASE = Path(os.environ["XIO_C1C_TEST_ROOT"]).resolve()
ADMIN = "a" * 32
OTHER = "b" * 32
REVOKED = "c" * 32
OP = "d" * 32


def key(number: int) -> str:
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


def row(role: str = "admin", *, slot: int = 2, revoked: bool = False,
        keys: dict[str, str] | None = None, created_by: str | None = None,
        user_limit: int = 1, **extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "revoked": revoked,
        "role": role,
        "slot": slot,
        "keys": {"awg": key(1)} if keys is None else keys,
        "createdBy": created_by,
        "userLimit": 1 if role == "admin" else 0,
    }
    if role == "admin":
        value["userLimit"] = user_limit
    value.update(extra)
    return value


def deployment(*, users: dict[str, object] | None = None,
               **extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "owner": "xio-managed-v1",
        "id": "deployment-1",
        "users": {
            ADMIN: row(),
            OTHER: row("user", slot=3, keys={"awg": key(2)}),
            REVOKED: row("user", slot=4, revoked=True, keys={"awg": key(3)}),
        },
    }
    if users is not None:
        value["users"] = users
    value.update(extra)
    return value


class AuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = deployment()
        self.auth = authority.snapshot_from_deployment(self.base)
        self.owner = authority.ActorContext(None, "owner-cli")
        self.delegate = authority.ActorContext(ADMIN, "delegate-cli")

    def assertCode(self, code: str, call) -> None:
        with self.assertRaises(authority.AuthoritySnapshotError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_import_is_pure_and_public_factory_returns_snapshot(self):
        self.assertEqual(self.auth.deployment_id, "deployment-1")
        self.assertNotIn("admin", sys.modules)

    def test_owner_and_delegate_principals(self):
        self.assertEqual(self.auth.resolve(OTHER, OP, self.owner),
                         c1a.Principal(None, "owner", False))
        self.assertEqual(self.auth.resolve(OTHER, OP, self.delegate),
                         c1a.Principal(ADMIN, "delegate", False))

    def test_unknown_revoked_and_nonadmin_are_valid_revoked_delegates(self):
        for uid in (REVOKED, OTHER, "f" * 32):
            principal = self.auth.resolve(OTHER, OP,
                                           authority.ActorContext(uid, "delegate-cli"))
            self.assertEqual(principal, c1a.Principal(uid, "delegate", True))

    def test_target_and_operation_do_not_elevate(self):
        principal = self.auth.resolve(ADMIN, OP, self.delegate)
        self.assertEqual(principal, c1a.Principal(ADMIN, "delegate", False))
        self.assertEqual(self.auth.resolve("f" * 32, "e" * 32, self.owner),
                         c1a.Principal(None, "owner", False))

    def test_invalid_context_cross_product(self):
        cases = (
            None,
            authority.ActorContext(None, "delegate-cli"),
            authority.ActorContext(ADMIN, "owner-cli"),
            authority.ActorContext(ADMIN, "other-cli"),
            authority.ActorContext(True, "delegate-cli"),
            authority.ActorContext("", "delegate-cli"),
            authority.ActorContext("A" * 32, "delegate-cli"),
            authority.ActorContext("a" * 31, "delegate-cli"),
            authority.ActorContext(1, "delegate-cli"),
        )
        for context in cases:
            self.assertCode("SNAPSHOT_SHAPE",
                            lambda context=context: self.auth.resolve(OTHER, OP, context))

    def test_target_and_operation_shapes(self):
        for uid in (None, True, 1, "", "A" * 32, "a" * 31, "a" * 33,
                    "00000000-0000-0000-0000-000000000000"):
            self.assertCode("SNAPSHOT_SHAPE",
                            lambda uid=uid: self.auth.resolve(uid, OP, self.owner))
        for operation in (None, True, 1, "", "D" * 32, "d" * 31, "d" * 33):
            self.assertCode("SNAPSHOT_SHAPE",
                            lambda operation=operation: self.auth.resolve(
                                OTHER, operation, self.owner))

    def test_owner_context_still_requires_valid_target(self):
        self.assertCode("SNAPSHOT_SHAPE",
                        lambda: self.auth.resolve(None, OP, self.owner))

    def test_snapshot_schema_owner_id_users(self):
        for value in (None, [], "x", 1):
            self.assertCode("SNAPSHOT_SHAPE",
                            lambda value=value: authority.snapshot_from_deployment(value))
        cases = (
            ("SNAPSHOT_OWNER", {"owner": "wrong"}),
            ("SNAPSHOT_OWNER", {"owner": None}),
            ("SNAPSHOT_ID", {"id": ""}),
            ("SNAPSHOT_ID", {"id": 1}),
            ("SNAPSHOT_ID", {"id": "x" * 129}),
            ("SNAPSHOT_USERS", {"users": []}),
            ("SNAPSHOT_USERS", {"users": None}),
        )
        for code, patch in cases:
            value = deployment()
            value.update(patch)
            self.assertCode(code, lambda value=value: authority.snapshot_from_deployment(value))

    def test_malformed_consumed_row_rejects_whole_snapshot(self):
        cases = (
            ("revoked", 1, "SNAPSHOT_ROW"),
            ("role", "owner", "SNAPSHOT_ROLE"),
            ("slot", True, "SNAPSHOT_SLOT"),
            ("slot", 1, "SNAPSHOT_SLOT"),
            ("slot", 255, "SNAPSHOT_SLOT"),
            ("keys", [], "SNAPSHOT_KEYS"),
            ("keys", {"rivet-h3": key(9)}, "SNAPSHOT_KEYS"),
            ("createdBy", "bad", "SNAPSHOT_CREATED_BY"),
            ("userLimit", True, "SNAPSHOT_LIMIT"),
            ("userLimit", 251, "SNAPSHOT_LIMIT"),
        )
        for field, value, code in cases:
            users = {ADMIN: row(), OTHER: row("user", slot=3, keys={"awg": key(2)})}
            users[OTHER][field] = value
            self.assertCode(code, lambda users=users: authority.snapshot_from_deployment(
                deployment(users=users)))
        users = {ADMIN: row()}
        del users[ADMIN]["createdBy"]
        self.assertCode("SNAPSHOT_ROW",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))

    def test_nonadmin_limit_must_be_zero(self):
        users = {ADMIN: row("user")}
        users[ADMIN]["userLimit"] = 1
        self.assertCode("SNAPSHOT_LIMIT",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))

    def test_active_slots_unique_revoked_reuse_allowed(self):
        users = {ADMIN: row(slot=2), OTHER: row("user", slot=2, keys={"awg": key(2)})}
        self.assertCode("SNAPSHOT_SLOT",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))
        users = {
            ADMIN: row(slot=2),
            REVOKED: row("user", slot=2, revoked=True, keys={"awg": key(3)}),
        }
        self.assertEqual(authority.snapshot_from_deployment(
            deployment(users=users)).registry_entries()[REVOKED].slot, 2)

    def test_key_padding_and_zero_rules(self):
        canonical = key(1)
        self.assertEqual(len(canonical), 44)
        self.assertTrue(canonical.endswith("="))
        for replacement in (canonical[:-1], canonical[:-2] + "==",
                            "!" + canonical[1:], canonical[:-1] + "A"):
            users = {ADMIN: row(keys={"awg": replacement})}
            self.assertCode("SNAPSHOT_KEY_TEXT",
                            lambda users=users: authority.snapshot_from_deployment(
                                deployment(users=users)))
        zero = base64.b64encode(b"\0" * 32).decode("ascii")
        users = {ADMIN: row(keys={"awg": zero})}
        self.assertCode("SNAPSHOT_KEY_ZERO",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))

    def test_padded_pad_bit_alias_normalizes_and_conflicts(self):
        raw = bytes([1]) * 32
        canonical = base64.b64encode(raw).decode("ascii")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        index = alphabet.index(canonical[-2])
        alias = canonical[:-2] + alphabet[index ^ 3] + "="
        self.assertNotEqual(alias, canonical)
        self.assertEqual(base64.b64decode(alias, validate=True), raw)
        users = {ADMIN: row(keys={"awg": alias})}
        entries = authority.snapshot_from_deployment(deployment(users=users)).registry_entries()
        self.assertEqual(entries[ADMIN].keys, (canonical,))
        users = {
            ADMIN: row(keys={"awg": canonical}),
            OTHER: row("user", slot=3, keys={"awg": alias}),
        }
        self.assertCode("SNAPSHOT_KEY_CONFLICT",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))

    def test_same_row_cross_protocol_and_active_revoked_history_duplicates(self):
        users = {ADMIN: row(keys={"wireguard": key(1), "awg": key(1)})}
        self.assertCode("SNAPSHOT_KEY_CONFLICT",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))
        users = {
            ADMIN: row(keys={"awg": key(1)}),
            REVOKED: row("user", slot=4, revoked=True, keys={"awg": key(1)}),
        }
        self.assertCode("SNAPSHOT_KEY_CONFLICT",
                        lambda: authority.snapshot_from_deployment(deployment(users=users)))

    def test_awg_only_and_empty_key_maps_are_valid(self):
        awg = authority.snapshot_from_deployment(
            deployment(users={ADMIN: row(keys={"awg": key(1)})}))
        self.assertEqual(awg.registry_entries()[ADMIN].keys, (key(1),))
        empty = authority.snapshot_from_deployment(
            deployment(users={ADMIN: row(keys={})}))
        self.assertEqual(empty.registry_entries()[ADMIN].keys, ())
        self.assertEqual(empty.registry_entries()[ADMIN].slot, 2)

    def test_ten_thousand_budget_and_over_budget(self):
        users: dict[str, object] = {}
        for index in range(10_000):
            uid = f"{index:032x}"
            users[uid] = row("user", slot=2, revoked=index != 0, keys={})
        self.assertEqual(len(authority.snapshot_from_deployment(
            deployment(users=users)).registry_entries()), 10_000)
        uid = f"{10_000:032x}"
        users[uid] = row("user", slot=2, revoked=True, keys={})
        self.assertCode("SNAPSHOT_TOO_LARGE",
                        lambda: authority.snapshot_from_deployment(
                            deployment(users=users)))

    def test_registry_projection_is_copied_and_read_only(self):
        self.base["users"][ADMIN]["keys"]["awg"] = key(9)
        self.assertEqual(self.auth.registry_entries()[ADMIN].keys, (key(1),))
        returned = self.auth.registry_entries()
        returned.clear()
        self.assertIn(ADMIN, self.auth.registry_entries())
        with self.assertRaises(Exception):
            self.auth.registry_entries()[ADMIN].keys = ()

    def test_source_nested_mutation_does_not_change_snapshot(self):
        auth = authority.snapshot_from_deployment(self.base)
        self.base["users"][ADMIN]["slot"] = 2
        self.base["users"][ADMIN]["keys"]["awg"] = key(9)
        self.assertEqual(auth.resolve(OTHER, OP, self.delegate),
                         c1a.Principal(ADMIN, "delegate", False))
        self.assertEqual(auth.registry_entries()[ADMIN].slot, 2)
        self.assertEqual(auth.registry_entries()[ADMIN].keys, (key(1),))

    def test_deployment_id_read_only_and_direct_constructor_rejected(self):
        with self.assertRaises(AttributeError):
            self.auth.deployment_id = "other"
        for call in (lambda: authority.DeploymentAuthority(),
                     lambda: authority.DeploymentAuthority(object(), "id", ())):
            with self.assertRaises(TypeError):
                call()

    def test_extra_secret_fields_not_retained_or_repr_exposed(self):
        secret = "TEST_ONLY_SECRET_VALUE"
        users = {ADMIN: row(stack={"private": secret}, token=secret)}
        auth = authority.snapshot_from_deployment(deployment(users=users))
        self.assertNotIn(secret, repr(auth))
        for entry in auth.registry_entries().values():
            self.assertNotIn(secret, repr(entry))

    def test_delegate_limit_zero_is_zero_and_denials_are_finite(self):
        users = {ADMIN: row(user_limit=0)}
        auth = authority.snapshot_from_deployment(deployment(users=users))
        self.assertEqual(auth.delegate_limit(ADMIN), 0)
        self.assertCode("SNAPSHOT_ROLE", lambda: auth.delegate_limit(None))
        self.assertCode("SNAPSHOT_ROLE", lambda: auth.delegate_limit(OTHER))
        self.assertCode("SNAPSHOT_ROLE", lambda: auth.delegate_limit(REVOKED))
        self.assertCode("SNAPSHOT_SHAPE", lambda: auth.delegate_limit(True))

    def test_c1a_authorize_uses_actual_principal(self):
        record = SimpleNamespace(actor=ADMIN)
        self.assertTrue(c1a.authorize(record, c1a.Principal(None, "owner", False)))
        self.assertTrue(c1a.authorize(record, c1a.Principal(ADMIN, "delegate", False)))
        self.assertFalse(c1a.authorize(record, c1a.Principal(OTHER, "delegate", False)))
        self.assertFalse(c1a.authorize(record, c1a.Principal(ADMIN, "delegate", True)))

    def c1b_root(self) -> Path:
        root = Path(tempfile.mkdtemp(dir=BASE, prefix="c1c-store-"))
        root.chmod(0o700)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def test_c1b_current_principal_uses_actual_adapter(self):
        root = self.c1b_root()
        store = c1b.PosixIssuanceStore(root, self.auth)
        try:
            handle = store.for_uid(OTHER, self.delegate)
            with handle.exclusive():
                self.assertEqual(handle.current_principal(OTHER, OP), self.auth.resolve(
                    OTHER, OP, self.delegate))
            handle2 = store.for_uid(OTHER, self.owner)
            with handle2.exclusive():
                self.assertEqual(handle2.current_principal(OTHER, OP),
                                 c1a.Principal(None, "owner", False))
        finally:
            store.close()

    def test_c1b_maps_resolver_error_to_authority_unavailable(self):
        root = self.c1b_root()
        store = c1b.PosixIssuanceStore(root, self.auth)
        try:
            handle = store.for_uid(OTHER, authority.ActorContext(None, "delegate-cli"))
            with handle.exclusive():
                with self.assertRaises(c1b.StoreError) as caught:
                    handle.current_principal(OTHER, OP)
            self.assertEqual(caught.exception.code, "AUTHORITY_UNAVAILABLE")
        finally:
            store.close()

    def test_c1b_invalid_none_principal_remains_authority_invalid(self):
        class NoneAuthority:
            def resolve(self, uid, operation_id, actor_context):
                return None

        root = self.c1b_root()
        store = c1b.PosixIssuanceStore(root, NoneAuthority())
        try:
            handle = store.for_uid(OTHER, self.owner)
            with handle.exclusive():
                with self.assertRaises(c1b.StoreError) as caught:
                    handle.current_principal(OTHER, OP)
            self.assertEqual(caught.exception.code, "AUTHORITY_INVALID")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
