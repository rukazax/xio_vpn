"""Dedicated passive C1a primitive tests (stdlib unittest, fake adapters)."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuance_primitives as p  # noqa: E402


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n"


def synthetic_cert(body: bytes = b"C" * 64) -> str:
    encoded = base64.b64encode(body).decode("ascii")
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines)
            + "\n-----END CERTIFICATE-----\n")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def uid(index: int = 1) -> str:
    return ("%032x" % index)


def capsule_raw(ciphertext_length: int = 64, capsule_id: str | None = None,
                recipient: bytes | None = None) -> bytes:
    payload = {
        "v": 1,
        "alg": p.CAPSULE_ALG,
        "capsuleId": capsule_id or ("c" * 32),
        "recipientPublicKey": b64(recipient or (b"\x01" * 32)),
        "ciphertext": b64(b"x" * ciphertext_length),
    }
    return json.dumps(payload, separators=(",", ":")).encode("ascii")


def display_request(display: str = "Тест 😀", protocols: list[str] | None = None,
                    admin: bool = False, user_limit: int = 0) -> dict:
    protocols = protocols or ["awg"]
    public_keys = {}
    if "awg" in protocols:
        public_keys["awg"] = b64(b"\x02" * 32)
    if "wireguard" in protocols:
        public_keys["wireguard"] = b64(b"\x03" * 32)
    commitments = {}
    if "rivet-s1" in protocols or "rivet-h3" in protocols:
        commitments["rivet.deviceSecret"] = sha(b"\x04" * 32)
        commitments["rivet.entryToken"] = sha(b"\x05" * 32)
    if "xray" in protocols:
        commitments["stack.xrayUuid"] = sha(b"11111111-2222-3333-4444-555555555555")
    if "shadowsocks" in protocols:
        commitments["stack.shadowsocksKey"] = sha(b"\x06" * 32)
    request = {
        "nameSha256": sha(display.encode("utf-8")),
        "publicKeys": public_keys,
        "admin": admin,
        "userLimit": user_limit,
        "protocols": protocols,
        "commitments": commitments,
    }
    if admin:
        public = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"\x07" * 32
        request["adminPublicKey"] = "ssh-ed25519 " + b64(public)
    return {
        "schema": 1,
        "operationId": uid(100),
        "uid": uid(1),
        "displayName": display,
        "request": request,
    }


def put_bytes(**kwargs) -> bytes:
    return json.dumps(display_request(**kwargs), ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def witness() -> p.CAConfigWitness:
    mapping = {
        "dir": "/synthetic/pki",
        "database": "/synthetic/pki/index",
        "new_certs_dir": "/synthetic/pki/certs",
        "serial": "/synthetic/pki/serial",
        "crlnumber": "/synthetic/pki/crlnumber",
        "certificate": "/synthetic/pki/ca.crt",
        "private_key": "/synthetic/pki/ca.key",
    }
    options = {
        "unique_subject": False,
        "default_days": 730,
        "default_crl_days": 365,
        "default_md": "sha256",
        "policy": "policy",
    }
    return p.config_witness(b"[ca]\nunique_subject = no\n", mapping, options)


class FakeAdapter:
    """Conspicuously TEST-ONLY X.509 evidence adapter."""

    def __init__(self, spki_der: bytes, certs: dict[bytes, p.CertificateInfo] | None = None):
        self.spki_der = spki_der
        self.certs = certs or {}
        self.calls = 0

    def csr_spki_der(self, csr_pem: bytes) -> bytes:
        self.calls += 1
        return self.spki_der

    def certificate_info(self, cert_pem: bytes) -> p.CertificateInfo:
        self.calls += 1
        if cert_pem not in self.certs:
            raise AssertionError("unregistered synthetic certificate")
        return self.certs[cert_pem]


class Faults:
    def __init__(self, point: str | None = None):
        self.point = point
        self.seen: list[str] = []

    def cut(self, point: str) -> None:
        self.seen.append(point)
        if point == self.point:
            raise RuntimeError("fault")


def temp_root() -> Path:
    base = os.environ.get("XIO_C1A_TEST_ROOT")
    return Path(tempfile.mkdtemp(prefix="c1a-test-", dir=base))


class TestStrictJSON(unittest.TestCase):
    def test_duplicate_keys_every_level(self):
        with self.assertRaises(p.PrimitiveError) as raised:
            p.strict_json(b'{"a":1,"a":2}')
        self.assertEqual(raised.exception.code, "JSON_DUPLICATE_KEY")
        with self.assertRaises(p.PrimitiveError):
            p.strict_json(b'{"a":{"b":1,"b":2}}')

    def test_trailing_and_float_and_depth(self):
        for raw, code in [
            (b'{"a":1}{}', "JSON_INVALID"),
            (b'{"a":1.5}', "JSON_FLOAT"),
            (b'{"a":NaN}', "JSON_NONFINITE"),
            (b"[" * 17 + b"]" * 17, "JSON_DEPTH"),
        ]:
            with self.assertRaises(p.PrimitiveError) as raised:
                p.strict_json(raw)
            self.assertEqual(raised.exception.code, code)

    def test_node_limit(self):
        raw = b"[" + b",".join([b"0"] * 4097) + b"]"
        with self.assertRaises(p.PrimitiveError) as raised:
            p.strict_json(raw)
        self.assertEqual(raised.exception.code, "JSON_NODES")

    def test_oversize_before_parse(self):
        with self.assertRaises(p.PrimitiveError) as raised:
            p.strict_json(b"0" * (p.MAX_REQUEST_INPUT + 1))
        self.assertEqual(raised.exception.code, "JSON_TOO_LARGE")


class TestRequest(unittest.TestCase):
    def test_unicode_name_and_canonical_request(self):
        raw = put_bytes(display="Тест 😀", protocols=["awg", "rivet-s1"])
        command = p.parse_put_command(raw)
        self.assertEqual(command.display_name, "Тест 😀")
        self.assertNotIn("Тест".encode("utf-8"), command.request.canonical())
        self.assertEqual(command.request.name_sha256, sha("Тест 😀".encode("utf-8")))
        self.assertLessEqual(len(command.request.canonical()), p.MAX_CANONICAL_REQUEST)

    def test_unknown_duplicate_bool_and_scope(self):
        mutated = display_request()
        mutated["request"]["admin"] = 1
        with self.assertRaises(p.PrimitiveError) as raised:
            p.parse_put_command(json.dumps(mutated).encode())
        self.assertEqual(raised.exception.code, "ADMIN_TYPE")

        duplicated = put_bytes().replace(b'"protocols":["awg"]',
                                         b'"protocols":["awg","awg"]')
        with self.assertRaises(p.PrimitiveError):
            p.parse_put_command(duplicated)

        bad_scope = display_request(protocols=["awg", "rivet-s1"])
        bad_scope["request"]["commitments"].pop("rivet.entryToken")
        with self.assertRaises(p.PrimitiveError) as raised:
            p.parse_put_command(json.dumps(bad_scope).encode())
        self.assertEqual(raised.exception.code, "COMMITMENTS_SCOPE")

        extra = display_request(protocols=["awg"])
        extra["request"]["commitments"]["rivet.deviceSecret"] = sha(b"x")
        with self.assertRaises(p.PrimitiveError):
            p.parse_put_command(json.dumps(extra).encode())

    def test_name_hash_mismatch_and_ascii_regression(self):
        mutated = display_request()
        mutated["request"]["nameSha256"] = sha(b"other")
        with self.assertRaises(p.PrimitiveError) as raised:
            p.parse_put_command(json.dumps(mutated).encode())
        self.assertEqual(raised.exception.code, "NAME_HASH_MISMATCH")
        # Cyrillic/emoji must remain accepted (no ASCII narrowing).
        p.parse_put_command(put_bytes(display="Иван 🚀"))

    def test_protocol_and_mesh_rejection(self):
        for protocols in (["mesh"], ["unknown"], ["awg", "mesh"]):
            with self.assertRaises(p.PrimitiveError) as raised:
                p.parse_put_command(put_bytes(protocols=protocols))
            self.assertEqual(raised.exception.code, "PROTOCOL_UNSUPPORTED")

    def test_public_key_canonical(self):
        mutated = display_request()
        mutated["request"]["publicKeys"]["awg"] = b64(b"\x02" * 31)
        with self.assertRaises(p.PrimitiveError):
            p.parse_put_command(json.dumps(mutated).encode())


class TestMaterial(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(p.material_commitment("rivet.deviceSecret", b64(b"\x04" * 32)),
                         sha(b"\x04" * 32))
        self.assertEqual(p.material_commitment("rivet.entryToken", b64(b"\x05" * 32)),
                         sha(b"\x05" * 32))
        self.assertEqual(p.material_commitment("stack.shadowsocksKey", b64(b"\x06" * 32)),
                         sha(b"\x06" * 32))
        self.assertEqual(p.material_commitment("stack.cloakUid", b64(b"\x08" * 16)),
                         sha(b"\x08" * 16))
        xray = "11111111-2222-3333-4444-555555555555"
        self.assertEqual(p.material_commitment("stack.xrayUuid", xray),
                         sha(xray.encode()))

    def test_noncanonical_and_limits(self):
        with self.assertRaises(p.PrimitiveError):
            p.material_commitment("rivet.deviceSecret", b64(b"\x04" * 32).rstrip("="))
        with self.assertRaises(p.PrimitiveError) as raised:
            p.material_commitment("stack.ikePassword", "x" * 129)
        self.assertEqual(raised.exception.code, "MATERIAL_SIZE")
        with self.assertRaises(p.PrimitiveError):
            p.material_commitment("stack.xrayUuid", "not-a-uuid")


class TestCapsule(unittest.TestCase):
    def context(self):
        return {
            "schema": 1, "version": 1, "purpose": p.CAPSULE_PURPOSE,
            "operation": "op-1", "uid": uid(1), "server": "srv",
            "deployment": "dep", "actor": "owner",
            "requestDigest": "a" * 64, "profileSetDigest": "b" * 64,
        }

    def test_plaintext_canonical_and_escaping(self):
        artifacts = {"ikev2.password": "p<>&/\"\\\n"}
        raw = p.encode_capsule_plaintext(self.context(), artifacts)
        self.assertIn(b"<>&/", raw)
        self.assertIn(b"\\n", raw)
        self.assertEqual(raw.count(b"ikev2.password"), 1)

    def test_plaintext_bounds(self):
        artifacts = {
            "openvpn.client-key": "a" * 4096,
            "openvpn.tls-crypt-v2-client": "b" * 4096,
            "ikev2.password": "c" * 128,
            "cloak.uid": "d" * 32,
        }
        raw = p.encode_capsule_plaintext(self.context(), artifacts)
        self.assertLessEqual(len(raw), p.C1_PLAINTEXT_MAX)
        escaped = {
            "openvpn.client-key": "\"" * 4096,
            "openvpn.tls-crypt-v2-client": "\\" * 4096,
            "ikev2.password": "\"" * 128,
            "cloak.uid": "\\" * 32,
        }
        raw = p.encode_capsule_plaintext(self.context(), escaped)
        self.assertLessEqual(len(raw), p.C1_PLAINTEXT_MAX)
        artifacts["openvpn.client-key"] = "a" * 4097
        with self.assertRaises(p.PrimitiveError):
            p.encode_capsule_plaintext(self.context(), artifacts)

    def test_first_pin_and_progress_bounds(self):
        ref = p.CapsuleRef.from_raw(capsule_raw(64))
        pin = p.FirstPin(uid(100), uid(1), ref, sha(b"request"), sha(b"context"),
                         sha(b"csr"), "e" * 64, uid(1), 1)
        self.assertLessEqual(len(pin.encode()), p.MAX_FIRST_PIN)
        progress = p.ProgressReceipt(
            operation_id=uid(100), uid=uid(1), phase="applying",
            capsule=ref, csr_sha256=sha(b"csr"), spki_sha256="e" * 64,
            csr_cn=uid(1), cert_pem=synthetic_cert(), cert_sha256=sha(synthetic_cert().encode()),
            serial="1001", ca_sha256="a" * 64,
            backends={name: "notStarted" for name in p.BACKEND_NAMES},
            material_request=("stack.ikePassword",), updated_at=2)
        self.assertLessEqual(len(progress.encode()), p.MAX_PROGRESS)
        oversized = p.ProgressReceipt(
            operation_id=uid(100), uid=uid(1), phase="applying", capsule=ref,
            csr_sha256=sha(b"csr"), spki_sha256="e" * 64, csr_cn=uid(1),
            cert_pem="-----BEGIN CERTIFICATE-----\n" + "C" * 8200
            + "\n-----END CERTIFICATE-----\n",
            cert_sha256=sha(b"cert"), serial="1001", ca_sha256="a" * 64,
            backends={name: "notStarted" for name in p.BACKEND_NAMES})
        with self.assertRaises(p.PrimitiveError):
            oversized.encode()

    def test_ref_distinct_digests_and_fetch(self):
        raw = capsule_raw(100)
        ref = p.CapsuleRef.from_raw(raw)
        self.assertEqual(ref.envelope_sha256, sha(raw))
        self.assertEqual(ref.ciphertext_sha256, sha(b"x" * 100))
        self.assertNotEqual(ref.envelope_sha256, ref.ciphertext_sha256)
        self.assertLessEqual(len(ref.first_pin()), p.MAX_FIRST_PIN)
        fetched = p.capsule_fetch_response(ref, raw)
        self.assertLessEqual(len(fetched), p.MAX_CAPSULE_RESPONSE)
        with self.assertRaises(p.PrimitiveError):
            p.capsule_fetch_response(ref, raw.replace(b"c" * 32, b"d" * 32))

    def test_compact_bound(self):
        with self.assertRaises(p.PrimitiveError) as raised:
            p.CapsuleRef.from_raw(capsule_raw(p.C0_MAX_CIPHERTEXT))
        self.assertEqual(raised.exception.code, "CAPSULE_NOT_COMPACT_C1")


class TestDurable(unittest.TestCase):
    def setUp(self):
        self.root = temp_root()
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_durable_write_and_read_cap(self):
        writer = p.DurableWriter(self.root)
        result = writer.write("a/b/file", b"payload", max_bytes=32)
        self.assertTrue(result.durable)
        self.assertEqual(writer.read_bounded("a/b/file", 32), b"payload")
        with self.assertRaises(p.PrimitiveError):
            writer.read_bounded("a/b/file", 3)

    def test_fault_cutpoints(self):
        for point in ("before_temp", "after_write", "after_file_fsync",
                      "after_replace", "after_dir_fsync"):
            root = temp_root()
            self.addCleanup(shutil.rmtree, root, True)
            writer = p.DurableWriter(root, Faults(point))
            try:
                result = writer.write("f", b"x", max_bytes=8)
            except RuntimeError:
                self.assertFalse((root / "f").exists())
                continue
            if point == "after_replace":
                self.assertEqual(result.status, "uncertain")
                self.assertTrue((root / "f").exists())
            elif point == "after_dir_fsync":
                self.assertEqual(result.status, "uncertain")
            else:
                self.assertEqual(result.status, "failed")
                self.assertFalse((root / "f").exists())

    def test_parent_directory_birth_and_faults(self):
        writer = p.DurableWriter(self.root)
        result = writer.write("deep/new/file", b"x", max_bytes=8)
        self.assertTrue(result.durable)
        self.assertTrue((self.root / "deep/new").is_dir())
        failing = p.DurableWriter(self.root, Faults("after_parent_fsync"))
        with self.assertRaises(RuntimeError):
            failing.write("other/deep/file", b"x", max_bytes=8)
        self.assertFalse((self.root / "other/deep/file").exists())

    def test_no_overwrite_and_capsule_first(self):
        writer = p.DurableWriter(self.root)
        self.assertTrue(writer.write("capsule", b"one", max_bytes=8).durable)
        conflict = writer.write("capsule", b"two", max_bytes=8)
        self.assertEqual(conflict.code, "EXISTS")
        capsule, record = p.write_capsule_then_record(
            writer, "new-capsule", b"x", "record", b"y")
        self.assertTrue(capsule.durable and record.durable)
        bad = p.DurableWriter(self.root, Faults("after_write"))
        capsule, record = p.write_capsule_then_record(
            bad, "bad-capsule", b"x", "bad-record", b"y")
        self.assertFalse(capsule.durable)
        self.assertIsNone(record)
        self.assertFalse((self.root / "bad-record").exists())


class TestRecordState(unittest.TestCase):
    def make(self) -> p.Record:
        command = p.parse_put_command(put_bytes(protocols=["awg"]))
        witness_value = witness()
        capsule = p.CapsuleRef.from_raw(capsule_raw(64))
        return p.Record(
            uid=command.uid, operation_id=command.operation_id,
            deployment_id="d" * 32, actor=None, actor_role="owner",
            request_sha256=command.request.sha256(),
            display_name=command.display_name,
            request=json.loads(command.request.canonical()),
            commitments=dict(command.request.commitments), capsule=capsule,
            csr_pem=CSR_PEM,
            csr_sha256=sha(CSR_PEM.encode()), spki_sha256="e" * 64, csr_cn=uid(1),
            ca_config=json.loads(witness_value.encode()),
            phase="prepared",
            backends={name: "notStarted" for name in p.BACKEND_NAMES},
            revision=0,
            cancellation={"requested": False, "confirmed": False, "requestedAt": 0},
            updated_at=1,
        )

    def test_pin_conflict_and_cancel_pending(self):
        record = self.make()
        self.assertTrue(p.pin_capsule(record, record.capsule, 0).accepted)
        other = p.CapsuleRef.from_raw(capsule_raw(32))
        conflict = p.pin_capsule(record, other, 0)
        self.assertEqual(conflict.code, "CONFLICT_CAPSULE")
        self.assertEqual(p.pin_capsule(record, record.capsule, 9).code, "STALE_REVISION")
        cancelled = p.transition(record, 0, "cancel_request", now=2).record
        self.assertEqual(p.transition(cancelled, 1, "complete").code, "CANCEL_REQUESTED")

    def test_record_size_and_no_raw_material(self):
        record = self.make()
        encoded = record.to_json()
        self.assertNotIn(b"SYNTHETIC-PRIVATE-MATERIAL", encoded)
        with self.assertRaises(p.PrimitiveError) as raised:
            p.decode_record(b"0" * (p.MAX_RECORD + 1))
        self.assertEqual(raised.exception.code, "JSON_TOO_LARGE")

    def test_roundtrip_and_replay(self):
        record = self.make()
        decoded = p.decode_record(record.to_json())
        self.assertEqual(decoded.identity(), record.identity())
        self.assertEqual(p.replay_operation(record, record.operation_id,
                                            record.request_sha256), "UNRESOLVED")
        self.assertEqual(p.replay_operation(record, "f" * 32,
                                            record.request_sha256), "CONFLICT_OPERATION")
        self.assertEqual(p.replay_operation(record, record.operation_id, "f" * 64),
                         "CONFLICT_REQUEST")

    def test_cas_cancel_and_terminal(self):
        record = self.make()
        stale = p.transition(record, 3, "cancel_request")
        self.assertEqual(stale.code, "STALE_REVISION")
        cancelled = p.transition(record, 0, "cancel_request", now=2)
        self.assertEqual(cancelled.record.phase, "cancelledRequested")
        incomplete = p.transition(cancelled.record, 1, "cancel_confirm")
        self.assertEqual(incomplete.code, "CANCEL_EVIDENCE_INCOMPLETE")
        confirmed = p.transition(cancelled.record, 1, "cancel_confirm",
                                 complete_absent=True, ca_settled=True, now=3)
        self.assertEqual(confirmed.record.phase, "cancelledConfirmed")
        resurrect = p.transition(confirmed.record, 2, "backend_applied",
                                 backends={"awg": "appliedVerified"})
        self.assertEqual(resurrect.code, "TOMBSTONE")
        self.assertEqual(p.ack_delivery("a" * 64).deleted, False)

    def test_authority(self):
        record = self.make()
        delegate = p.Principal(uid(1), "delegate", False)
        delegated = record.copy(actor=uid(1), actor_role="delegate")
        self.assertTrue(p.authorize(record, p.Principal(None, "owner", False)))
        self.assertFalse(p.authorize(record, p.Principal(None, "owner", True)))
        self.assertFalse(p.authorize(record, p.Principal(uid(9), "delegate", False)))
        self.assertTrue(p.authorize(delegated, delegate))
        # A delegate whose uid happens to equal the target UID is not authorized
        # unless it is the recorded actor.
        self.assertFalse(p.authorize(record, p.Principal(record.uid, "delegate", False)))


class TestReservations(unittest.TestCase):
    def test_quota_slot_key_other_uid(self):
        registry = {
            uid(1): p.RegistryEntry(uid(1), False, 2, (b64(b"\x01" * 32),), "admin", uid(1))
        }
        book = p.AdmissionBook(registry)
        first = book.admit(uid=uid(2), operation_id=uid(20), keys=(b64(b"\x02" * 32),),
                           quota=True, actor=uid(1), user_limit=1)
        self.assertFalse(first.accepted)
        self.assertEqual(first.code, "QUOTA_EXCEEDED")
        second = book.admit(uid=uid(2), operation_id=uid(20), keys=(b64(b"\x02" * 32),),
                            quota=False, actor=uid(1), user_limit=1)
        self.assertTrue(second.accepted)
        other = book.admit(uid=uid(3), operation_id=uid(30), keys=(b64(b"\x02" * 32),),
                           quota=True, actor=uid(1), user_limit=3)
        self.assertEqual(other.code, "KEY_CONFLICT")
        self.assertEqual(book.verify_resume(uid(2), uid(20)).slot, second.slot)
        self.assertFalse(book.release(uid(3), uid(30)))


class TestCA(unittest.TestCase):
    def setUp(self):
        self.ca = "9" * 64
        self.csr = "-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n"
        self.spki = b"\xaa" * 64
        self.witness = witness()
        self.pre = {
            "indexSha256": sha(b""),
            "serial": 1000,
            "serialSha256": sha(b"1000"),
            "crlnumber": 1000,
            "crlnumberSha256": sha(b"1000"),
            "certs": {},
            "staged": {},
        }
        self.intent = p.make_ca_intent(
            operation_id=uid(100), uid=uid(1), csr_sha256=sha(self.csr.encode()),
            spki_sha256=sha(self.spki), expected_cn=uid(1), witness=self.witness,
            ca_certificate_sha256=self.ca, pre_state=self.pre)

    def adapter(self, certs=()):
        mapping = {}
        for body, cn, serial, spki in certs:
            mapping[body] = p.CertificateInfo(cn=cn, serial=serial, spki_der=spki,
                                              issuer_sha256=self.ca, digest=sha(body))
        return FakeAdapter(self.spki, mapping)

    def evidence(self, rows=(), certs=None, staged=None, serial=1000):
        raw = b""
        for row in rows:
            revoked = b"261106000000Z" if row.status == "R" else b""
            raw += (row.status.encode() + b"\t300101000000Z\t" + revoked + b"\t"
                    + row.serial.encode() + b"\tunknown\t/CN=" + row.cn.encode() + b"\n")
        return p.CAEvidence(index_bytes=raw,
                            rows=tuple(rows), certs=certs or {}, staged=staged or {},
                            serial=serial, crlnumber=1000)

    def test_witness_actual_certs_mapping(self):
        self.assertEqual(self.witness.mapping["new_certs_dir"], "/synthetic/pki/certs")
        self.assertEqual(self.witness.ca_config_sha256(),
                         sha(self.witness.encode()))
        bad = dict(self.witness.mapping)
        bad["new_certs_dir"] = "/synthetic/pki/new_certs"
        with self.assertRaises(p.PrimitiveError):
            p.config_witness(b"x", bad, self.witness.options)

    def test_no_marker_and_lease_fence(self):
        adapter = self.adapter()
        self.assertEqual(p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(), lease=p.LeaseState.FREE, csr_pem=self.csr,
            adapter=adapter, marker_present=False, staged_key="k", intent_durable=True, barrier_complete=True).decision, "issue")
        adapter.calls = 0
        for lease in (p.LeaseState.HELD, p.LeaseState.UNKNOWN):
            result = p.reconcile_client_issue(
                kind="client_issue", intent=self.intent, witness=self.witness,
                evidence=self.evidence(), lease=lease, csr_pem=self.csr,
                adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
            self.assertEqual(result.decision, "fenced")
        self.assertEqual(adapter.calls, 0)

    def test_no_effect_clear_and_ambiguity(self):
        adapter = self.adapter()
        clear = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(), lease=p.LeaseState.FREE, csr_pem=self.csr,
            adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(clear.decision, "no_effect_clear")
        advanced = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(serial=1001), lease=p.LeaseState.FREE,
            csr_pem=self.csr, adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(advanced.decision, "repair")
        body = b"synthetic-cert"
        body_orphan = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(certs={"1001": body}), lease=p.LeaseState.FREE,
            csr_pem=self.csr, adapter=self.adapter([(body, uid(1), "1001", self.spki)]),
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(body_orphan.decision, "repair")

    def test_adopt_and_seed_stage(self):
        body = b"synthetic-cert"
        adapter = self.adapter([(body, uid(1), "1001", self.spki)])
        row = p.IndexRow(cn=uid(1), serial="1001", status="V")
        line = (b"V\t300101000000Z\t\t1001\tunknown\t/CN=" + uid(1).encode() + b"\n")
        pre = dict(self.pre)
        pre.update(indexSha256=sha(b""), serial=4097)
        intent = p.make_ca_intent(
            operation_id=uid(100), uid=uid(1), csr_sha256=sha(self.csr.encode()),
            spki_sha256=sha(self.spki), expected_cn=uid(1), witness=self.witness,
            ca_certificate_sha256=self.ca, pre_state=pre)
        adopt = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=self.witness,
            evidence=p.CAEvidence(index_bytes=line, rows=(row,),
                                  certs={"1001": body}, staged={"k": body},
                                  serial=4098, crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=self.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(adopt.decision, "adopt")
        seed = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=self.witness,
            evidence=p.CAEvidence(index_bytes=line, rows=(row,),
                                  certs={"1001": body}, staged={},
                                  serial=4098, crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=self.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(seed.decision, "adopt_seed_stage")

    def test_body_missing_and_duplicates(self):
        adapter = self.adapter([(b"cert", uid(1), "1001", self.spki)])
        row = p.IndexRow(cn=uid(1), serial="1001", status="V")
        missing = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(rows=(row,), serial=1001), lease=p.LeaseState.FREE,
            csr_pem=self.csr, adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(missing.decision, "repair")
        duplicate = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(rows=(row, row), certs={"1001": b"cert"}, serial=1001),
            lease=p.LeaseState.FREE, csr_pem=self.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(duplicate.decision, "repair")

    def test_config_and_csr_mismatch(self):
        adapter = self.adapter()
        other_witness = witness()
        other_witness = p.CAConfigWitness(
            config_sha256="b" * 64, mapping=other_witness.mapping,
            options=other_witness.options)
        with self.assertRaises(p.PrimitiveError) as raised:
            p.reconcile_client_issue(
                kind="client_issue", intent=self.intent, witness=other_witness,
                evidence=self.evidence(), lease=p.LeaseState.FREE,
                csr_pem=self.csr, adapter=adapter, marker_present=False,
                staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(raised.exception.code, "CA_CONFIG_MISMATCH")
        with self.assertRaises(p.PrimitiveError) as raised:
            p.reconcile_client_issue(
                kind="client_issue", intent=self.intent, witness=self.witness,
                evidence=self.evidence(), lease=p.LeaseState.FREE,
                csr_pem=self.csr + "x", adapter=adapter, marker_present=False,
                staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(raised.exception.code, "CSR_HASH_MISMATCH")

    def test_unrelated_body_and_crlnumber_change(self):
        body = b"unrelated"
        adapter = self.adapter([(body, uid(1), "1001", b"\xbb" * 64)])
        body_result = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=self.evidence(certs={"1001": body}), lease=p.LeaseState.FREE,
            csr_pem=self.csr, adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(body_result.decision, "repair")
        crl = p.CAEvidence(index_bytes=b"", rows=(), certs={}, staged={},
                           serial=1000, crlnumber=1001)
        crl_result = p.reconcile_client_issue(
            kind="client_issue", intent=self.intent, witness=self.witness,
            evidence=crl, lease=p.LeaseState.FREE, csr_pem=self.csr,
            adapter=self.adapter(), marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(crl_result.decision, "repair")

    def test_evidence_finite_bounds(self):
        with self.assertRaises(p.PrimitiveError):
            p.CAEvidence(index_bytes=b"", rows=(), certs={
                str(index): b"x" for index in range(1, 130)}, staged={}, serial=1, crlnumber=1)
        with self.assertRaises(p.PrimitiveError):
            p.CAEvidence(index_bytes=b"", rows=(), certs={"1": b"x" * 8193},
                         staged={}, serial=1, crlnumber=1)
        with self.assertRaises(p.PrimitiveError):
            p.CAEvidence(index_bytes=b"", rows=(p.IndexRow(uid(1), "01", "V"),), certs={},
                         staged={}, serial=1, crlnumber=1)

    def test_unsupported_kinds_and_bad_csr(self):
        adapter = self.adapter()
        for kind in p.OTHER_CA_KINDS:
            with self.assertRaises(p.PrimitiveError) as raised:
                p.reconcile_client_issue(
                    kind=kind, intent=self.intent, witness=self.witness,
                    evidence=self.evidence(), lease=p.LeaseState.FREE,
                    csr_pem=self.csr, adapter=adapter, marker_present=False,
                    staged_key="k", intent_durable=True, barrier_complete=True)
            self.assertEqual(raised.exception.code, "UNSUPPORTED_CA_KIND")
        with self.assertRaises(p.PrimitiveError):
            p.reconcile_client_issue(
                kind="client_issue", intent=self.intent, witness=self.witness,
                evidence=self.evidence(), lease=p.LeaseState.FREE,
                csr_pem=self.csr + "x", adapter=adapter, marker_present=False,
                staged_key="k", intent_durable=True, barrier_complete=True)


class TestCapability(unittest.TestCase):
    def test_internal_capability_disabled(self):
        raw = p.internal_capability()
        value = json.loads(raw)
        self.assertEqual(value["implementation"], "c1a")
        self.assertFalse(value["complete"])
        for action in ("put", "read", "resume", "needsMaterialReply", "cancel",
                       "ackDelivery", "readCapsule"):
            self.assertFalse(value["actions"][action])
        self.assertLessEqual(len(raw), 4096)

    def test_ack_never_deletes(self):
        result = p.ack_delivery("a" * 64)
        self.assertFalse(result.accepted)
        self.assertFalse(result.deleted)
        self.assertEqual(result.code, "ACK_TRUST_REQUIRED")


class TestForwardRegressions(unittest.TestCase):
    def test_advance_fresh_read_and_hash_cas(self):
        record = TestRecordState().make()

        class Store:
            def __init__(self):
                self.raw = record.to_json()
                self.sha = sha(self.raw)

            def current_principal(self, uid, operation_id):
                return p.Principal(None, "owner", False)

            @contextlib.contextmanager
            def exclusive(self):
                yield

            def read(self, uid):
                return self.raw, self.sha, p.decode_record(self.raw)

            def compare_and_swap(self, uid, expected, data):
                assert expected == self.sha
                self.raw, self.sha = data, sha(data)

        store = Store()
        old_sha = store.sha
        cancelled = p.advance_record(store, record.uid, old_sha, 0, "cancel_request",
                                     principal=p.Principal(None, "owner", False))
        self.assertIsNotNone(cancelled.record)
        stale = p.advance_record(store, record.uid, old_sha, 0, "backend_applied",
                                 principal=p.Principal(None, "owner", False),
                                 backends={name: "appliedVerified" for name in p.BACKEND_NAMES})
        self.assertIsNone(stale.record)
        self.assertEqual(stale.code, "STALE_RECORD")
        self.assertEqual(p.decode_record(store.raw).phase, "cancelledRequested")

    def test_r4_index_baseline_and_single_append_delta(self):
        ca = TestCA()
        ca.setUp()
        old_uid, target = uid(9), uid(1)
        old_body, new_body = b"old-cert", b"new-cert"
        old_row = p.IndexRow(old_uid, "10", "R")
        new_row = p.IndexRow(target, "1000", "V")

        def line(cn, serial, status):
            revoked = "261106000000Z" if status == "R" else ""
            return (f"{status}\t300101000000Z\t{revoked}\t{serial}\tunknown\t/CN={cn}\n"
                    .encode())

        old_raw, new_raw = line(old_uid, "10", "R"), line(target, "1000", "V")
        pre = dict(ca.pre)
        pre.update(indexSha256=sha(old_raw), serial=int("1000", 16),
                   certs={"10": sha(old_body)})
        intent = p.make_ca_intent(
            operation_id=uid(100), uid=target, csr_sha256=sha(ca.csr.encode()),
            spki_sha256=sha(ca.spki), expected_cn=target, witness=ca.witness,
            ca_certificate_sha256=ca.ca, pre_state=pre)
        adapter = ca.adapter([(old_body, old_uid, "10", b"\xbb" * 64),
                              (new_body, target, "1000", ca.spki)])
        issue = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=old_raw, rows=(old_row,),
                                  certs={"10": old_body}, staged={}, serial=int("1000", 16),
                                  crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=False, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(issue.decision, "issue")
        adopted = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=old_raw + new_raw,
                                  rows=(old_row, new_row),
                                  certs={"10": old_body, "1000": new_body},
                                  staged={"k": new_body}, serial=int("1001", 16),
                                  crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertEqual(adopted.decision, "adopt")
        for hostile in (
            line(target + "deadbeef", "1000", "V"),
            line(target, "1000", "V").rstrip(b"\n") + b"\tEXTRA\n",
            line(target, "1000", "V").rstrip(b"\n"),
            line(target, "1000", "V").replace(b"\n", b"\r\n"),
        ):
            try:
                result = p.reconcile_client_issue(
                    kind="client_issue", intent=intent, witness=ca.witness,
                    evidence=p.CAEvidence(index_bytes=old_raw + hostile,
                                          rows=(old_row, new_row),
                                          certs={"10": old_body, "1000": new_body},
                                          staged={"k": new_body}, serial=int("1001", 16),
                                          crlnumber=1000),
                    lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
                    marker_present=True, staged_key="k",
                    intent_durable=True, barrier_complete=True)
            except p.PrimitiveError:
                continue
            self.assertNotIn(result.decision, ("adopt", "adopt_seed_stage"))
        extra_cert = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=old_raw, rows=(old_row,),
                                  certs={"10": old_body, "12": b"extra"},
                                  staged={}, serial=int("1000", 16), crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr,
            adapter=ca.adapter([(old_body, old_uid, "10", b"\xbb" * 64),
                                (b"extra", uid(8), "12", b"\xcc" * 64)]),
            marker_present=False, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertNotEqual(extra_cert.decision, "issue")
        extra_stage = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=old_raw + new_raw,
                                  rows=(old_row, new_row),
                                  certs={"10": old_body, "1000": new_body},
                                  staged={"unrelated-stage": new_body},
                                  serial=int("1001", 16), crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertNotIn(extra_stage.decision, ("adopt", "adopt_seed_stage"))
        dropped = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=new_raw, rows=(new_row,),
                                  certs={"10": old_body, "1000": new_body},
                                  staged={"k": new_body}, serial=int("1001", 16),
                                  crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertNotIn(dropped.decision, ("adopt", "adopt_seed_stage"))
        revived = p.IndexRow(old_uid, "10", "V")
        revived_raw = line(old_uid, "10", "V")
        revived_result = p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=revived_raw + new_raw,
                                  rows=(revived, new_row),
                                  certs={"10": old_body, "1000": new_body},
                                  staged={"k": new_body}, serial=int("1001", 16),
                                  crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True)
        self.assertNotIn(revived_result.decision, ("adopt", "adopt_seed_stage"))

    def test_r4_invalid_current_authority_denied(self):
        record = TestRecordState().make()

        class Store:
            def __init__(self):
                self.raw = record.to_json()

            @contextlib.contextmanager
            def exclusive(self):
                yield

            def read(self, uid):
                return self.raw, sha(self.raw), p.decode_record(self.raw)

            def current_principal(self, uid, operation_id):
                return p.Principal(None, "unrecognized", False)

            def compare_and_swap(self, uid, expected, data):
                raise AssertionError("must not write")

        result = p.advance_record(Store(), record.uid, sha(record.to_json()), 0,
                                  "cancel_request",
                                  principal=p.Principal(None, "owner", False))
        self.assertIsNone(result.record)
        self.assertEqual(result.code, "AUTHORITY_INVALID")

    def test_r4_postpublication_eexist_is_uncertain(self):
        root = temp_root()
        self.addCleanup(shutil.rmtree, root, True)

        class Cut:
            def cut(self, point):
                if point == "after_replace":
                    raise FileExistsError("after publication")

        result = p.DurableWriter(root, Cut()).write("x", b"published", max_bytes=32)
        self.assertEqual(result.status, "uncertain")
        self.assertEqual((root / "x").read_bytes(), b"published")

    def test_r6_explicit_proof_flags_and_no_effect_baseline(self):
        ca = TestCA()
        ca.setUp()
        body = b"old-unrelated-cert"
        row = p.IndexRow(uid(8), "10", "R")
        raw = (b"R\t300101000000Z\t261106000000Z\t10\tunknown\t/CN="
               + uid(8).encode() + b"\n")
        pre = dict(ca.pre)
        pre.update(indexSha256=sha(raw), certs={"10": sha(body)})
        intent = p.make_ca_intent(
            operation_id=uid(100), uid=uid(1), csr_sha256=sha(ca.csr.encode()),
            spki_sha256=sha(ca.spki), expected_cn=uid(1), witness=ca.witness,
            ca_certificate_sha256=ca.ca, pre_state=pre)
        evidence = p.CAEvidence(index_bytes=raw, rows=(row,),
                                certs={"10": body}, staged={}, serial=1000,
                                crlnumber=1000)
        common = dict(kind="client_issue", intent=intent, witness=ca.witness,
                      evidence=evidence, lease=p.LeaseState.FREE, csr_pem=ca.csr,
                      adapter=ca.adapter([(body, uid(8), "10", b"\xdd" * 64)]),
                      marker_present=True, staged_key="k")
        with self.assertRaises(TypeError):
            p.reconcile_client_issue(**common)
        with self.assertRaises(p.PrimitiveError):
            p.reconcile_client_issue(**common, intent_durable=1,
                                     barrier_complete=True)
        with self.assertRaises(p.PrimitiveError):
            p.reconcile_client_issue(**common, intent_durable=True,
                                     barrier_complete="yes")
        self.assertEqual(p.reconcile_client_issue(
            **common, intent_durable=True, barrier_complete=True).decision,
            "no_effect_clear")
        target = b"target-cert"
        target_result = p.reconcile_client_issue(
            kind="client_issue", intent=ca.intent, witness=ca.witness,
            evidence=p.CAEvidence(index_bytes=b"", rows=(), certs={"1001": target},
                                  staged={}, serial=1000, crlnumber=1000),
            lease=p.LeaseState.FREE, csr_pem=ca.csr,
            adapter=ca.adapter([(target, uid(1), "1001", ca.spki)]),
            marker_present=True, staged_key="k", intent_durable=True,
            barrier_complete=True)
        self.assertEqual(target_result.decision, "repair")

    def test_r7_target_identity_union_and_six_field_grammar(self):
        ca = TestCA()
        ca.setUp()
        old_body = b"target-cn-old-key"
        for marker in (False, True):
            result = p.reconcile_client_issue(
                kind="client_issue", intent=ca.intent, witness=ca.witness,
                evidence=p.CAEvidence(index_bytes=b"", rows=(),
                                      certs={"1001": old_body}, staged={},
                                      serial=1000, crlnumber=1000),
                lease=p.LeaseState.FREE, csr_pem=ca.csr,
                adapter=ca.adapter([(old_body, uid(1), "1001", b"\xee" * 64)]),
                marker_present=marker, staged_key="k", intent_durable=True,
                barrier_complete=True)
            self.assertNotIn(result.decision, ("issue", "no_effect_clear"))
        raw = (b"V\t300101000000Z\t\t1001\tunknown\t/CN=" + uid(1).encode()
               + b"\tEXTRA\n")
        with self.assertRaises(p.PrimitiveError):
            p.reconcile_client_issue(
                kind="client_issue", intent=ca.intent, witness=ca.witness,
                evidence=p.CAEvidence(index_bytes=raw,
                                      rows=(p.IndexRow(uid(1) + "\tEXTRA", "1001", "V"),),
                                      certs={}, staged={}, serial=1000, crlnumber=1000),
                lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=ca.adapter(),
                marker_present=True, staged_key="k",
                intent_durable=True, barrier_complete=True)

    def test_r8_staged_digest_bound_before_identity(self):
        ca = TestCA()
        ca.setUp()
        body = b"foreign-staged-cert"
        pre = dict(ca.pre)
        pre["staged"] = {"old-stage": sha(body)}
        intent = p.make_ca_intent(
            operation_id=uid(100), uid=uid(1), csr_sha256=sha(ca.csr.encode()),
            spki_sha256=sha(ca.spki), expected_cn=uid(1), witness=ca.witness,
            ca_certificate_sha256=ca.ca, pre_state=pre)
        evidence = p.CAEvidence(index_bytes=b"", rows=(), certs={},
                                staged={"old-stage": body}, serial=1000,
                                crlnumber=1000)

        class Adapter:
            def __init__(self, digest):
                self.digest = digest

            def csr_spki_der(self, raw):
                return ca.spki

            def certificate_info(self, raw):
                return p.CertificateInfo(uid(8), "11", b"foreign-key", ca.ca,
                                         self.digest)

        for marker in (False, True):
            result = p.reconcile_client_issue(
                kind="client_issue", intent=intent, witness=ca.witness,
                evidence=evidence, lease=p.LeaseState.FREE, csr_pem=ca.csr,
                adapter=Adapter(sha(body)), marker_present=marker,
                staged_key="k", intent_durable=True, barrier_complete=True)
            self.assertIn(result.decision, ("issue", "no_effect_clear"))
        with self.assertRaises(p.PrimitiveError):
            p.reconcile_client_issue(
                kind="client_issue", intent=intent, witness=ca.witness,
                evidence=evidence, lease=p.LeaseState.FREE, csr_pem=ca.csr,
                adapter=Adapter("0" * 64), marker_present=True,
                staged_key="k", intent_durable=True, barrier_complete=True)

    def test_adapted_v2_stale_snapshot_is_rejected_by_guarded_commit(self):
        """V2's old pure-transition assertion is not the acceptance boundary.

        A pure helper may compute a stale proposal; the actual guarded commit
        must reject it against the fresh raw hash/current authority. This is the
        clearly adapted case for the post-R2 interface.
        """
        record = TestRecordState().make()

        class Store:
            def __init__(self):
                self.raw = record.to_json()
                self.sha = sha(self.raw)

            @contextlib.contextmanager
            def exclusive(self):
                yield

            def read(self, uid):
                return self.raw, self.sha, p.decode_record(self.raw)

            def current_principal(self, uid, operation_id):
                return p.Principal(None, "owner", False)

            def compare_and_swap(self, uid, expected, data):
                assert expected == self.sha
                self.raw, self.sha = data, sha(data)

        store = Store()
        old_sha = store.sha
        proposal = p.transition(record, 0, "cancel_request")
        self.assertIsNotNone(proposal.record, "pure proposal may be computed")
        self.assertIsNotNone(p.advance_record(
            store, record.uid, old_sha, 0, "cancel_request",
            principal=p.Principal(None, "owner", False)).record)
        stale = p.advance_record(
            store, record.uid, old_sha, 0, "backend_applied",
            principal=p.Principal(None, "owner", False),
            backends={name: "appliedVerified" for name in p.BACKEND_NAMES})
        self.assertIsNone(stale.record)
        self.assertEqual(stale.code, "STALE_RECORD")
        self.assertEqual(p.decode_record(store.raw).cancellation["requested"], True)

    def test_record_second_roundtrip_and_nested_ca(self):
        record = TestRecordState().make()
        first = p.decode_record(record.to_json())
        second = p.decode_record(first.to_json())
        self.assertEqual(second.to_json(), first.to_json())
        value = json.loads(first.to_json())
        value["caConfig"]["unexpected"] = "x"
        with self.assertRaises(p.PrimitiveError):
            p.decode_record(json.dumps(value).encode())
        value = json.loads(first.to_json())
        value["commitments"]["rivet.deviceSecret"] = "a" * 64
        with self.assertRaises(p.PrimitiveError):
            p.decode_record(json.dumps(value).encode())

    def test_cancel_repair_and_unknown_effect_fences(self):
        record = TestRecordState().make()
        cancelled = p.transition(record, 0, "cancel_request").record
        repaired = p.transition(cancelled, 1, "repair").record
        blocked = p.transition(repaired, 2, "backend_applied",
                               backends={name: "appliedVerified" for name in p.BACKEND_NAMES})
        self.assertIsNone(blocked.record)
        unknown = p.transition(TestRecordState().make(), 0, "backend_applied",
                               backends={"awg": "applyUnknown"}).record
        self.assertIsNone(p.transition(unknown, 1, "reject").record)
        self.assertIsNotNone(p.transition(unknown, 1, "reject",
                                          no_effect_proved=True).record)

    def test_reservation_release_requires_terminal_or_no_effect(self):
        book = p.AdmissionBook({})
        book.admit(uid=uid(2), operation_id=uid(20), keys=("k",), quota=False,
                   actor=None, user_limit=1)
        self.assertFalse(book.release(uid(2), uid(20)))
        self.assertTrue(book.release(uid(2), uid(20), terminal=True))

    def test_ca_status_marker_and_prestate_loss(self):
        ca = TestCA()
        ca.setUp()
        body = b"cert"
        adapter = ca.adapter([(body, uid(1), "1001", ca.spki)])
        revoked = p.IndexRow(uid(1), "1001", "R")
        self.assertEqual(p.reconcile_client_issue(
            kind="client_issue", intent=ca.intent, witness=ca.witness,
            evidence=ca.evidence(rows=(revoked,), certs={"1001": body}, serial=4098),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True).decision, "repair")
        orphan = p.IndexRow(uid(1), "1001", "V")
        self.assertEqual(p.reconcile_client_issue(
            kind="client_issue", intent=ca.intent, witness=ca.witness,
            evidence=ca.evidence(rows=(orphan,), certs={"1001": body}, serial=4098),
            lease=p.LeaseState.FREE, csr_pem=ca.csr, adapter=adapter,
            marker_present=False, staged_key="k", intent_durable=True, barrier_complete=True).decision, "repair")
        pre = dict(ca.pre)
        pre["certs"] = {"1001": sha(body)}
        intent = p.make_ca_intent(
            operation_id=uid(100), uid=uid(1), csr_sha256=sha(ca.csr.encode()),
            spki_sha256=sha(ca.spki), expected_cn=uid(1), witness=ca.witness,
            ca_certificate_sha256=ca.ca, pre_state=pre)
        self.assertEqual(p.reconcile_client_issue(
            kind="client_issue", intent=intent, witness=ca.witness,
            evidence=ca.evidence(), lease=p.LeaseState.FREE, csr_pem=ca.csr,
            adapter=adapter, marker_present=True, staged_key="k", intent_durable=True, barrier_complete=True).decision, "repair")

    def test_durable_fresh_instance_refences_existing_ancestry(self):
        root = temp_root()
        self.addCleanup(shutil.rmtree, root, True)
        failing = p.DurableWriter(root, Faults("after_parent_create"))
        with self.assertRaises(RuntimeError):
            failing.write("new/deep/file", b"x", max_bytes=8)
        self.assertTrue((root / "new").is_dir())
        fresh = p.DurableWriter(root)
        seen: list[str] = []
        original = fresh._fsync_dir
        fresh._fsync_dir = lambda directory: (seen.append(str(directory)), original(directory))[1]
        result = fresh.write("new/deep/file", b"x", max_bytes=8)
        self.assertTrue(result.durable)
        self.assertIn(str(root), seen)

    def test_dialect_hardening(self):
        with self.assertRaises(p.PrimitiveError):
            p.material_commitment("stack.ikePassword", "😀" * 128)
        with self.assertRaises(p.PrimitiveError) as raised:
            p._validate_display_name("\ud800")
        self.assertEqual(raised.exception.code, "NAME_UNICODE")
        with self.assertRaises(p.PrimitiveError):
            p.ProgressReceipt(
                operation_id=uid(100), uid=uid(1), phase="applying",
                capsule=p.CapsuleRef.from_raw(capsule_raw(8)),
                csr_sha256=sha(b"csr"), spki_sha256="e" * 64, csr_cn=uid(1),
                cert_pem="NOT-A-CERT", cert_sha256="a" * 64, serial="1",
                ca_sha256="a" * 64,
                backends={name: "notStarted" for name in p.BACKEND_NAMES}).encode()


if __name__ == "__main__":
    unittest.main()
