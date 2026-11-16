"""Passive C1a issuance primitives (internal/test-only).

This module implements only the bounded passive contracts authorized by the
parent C1a brief. It performs no production wiring, no real CA/native effect, no
subprocess, no network access and no import-time I/O. Native X.509/CSR evidence
is an injected adapter contract; the fake adapters live in the dedicated tests.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence


SCHEMA = 1
MAX_REQUEST_INPUT = 32768
MAX_RECORD = 131072
MAX_INTENT = 32768
MAX_CANONICAL_REQUEST = 8192
MAX_CSR = 4096
MAX_SPKI = 2048
MAX_CERT = 8192
MAX_CAPSULE_RESPONSE = 61440
MAX_FIRST_PIN = 4096
MAX_PROGRESS = 16384
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4096
MAX_DISPLAY_CODEPOINTS = 80
MAX_DISPLAY_BYTES = 320
MAX_SAFE_INTEGER = 9007199254740991

C0_MAX_PLAINTEXT = 32768
C0_MAX_CIPHERTEXT = 32816
C0_MAX_ENVELOPE = 45056
C0_MAX_ARTIFACT = 8192

C1_ARTIFACT_CAPS = {
    "openvpn.client-key": 4096,
    "openvpn.tls-crypt-v2-client": 4096,
    "ikev2.password": 128,
    "cloak.uid": 32,
}
C1_PLAINTEXT_MAX = 17934
C1_CIPHERTEXT_MAX = 17982
C1_COMPACT_ENVELOPE_MAX = 24169
C1_OUTER_BASE64_MAX = 32228

CAPSULE_ALG = "nacl-box-sealed-x25519-xsalsa20-poly1305-b2b24"
CAPSULE_PURPOSE = "owner-issuance/delivery"
CAPSULE_FIELDS = ("v", "alg", "capsuleId", "recipientPublicKey", "ciphertext")
CONTEXT_FIELDS = (
    "schema", "purpose", "version", "operation", "uid", "server", "deployment",
    "actor", "requestDigest", "profileSetDigest",
)
REQUEST_DOMAIN = b"xio/issuance/v1/request\n"
PROTOCOLS = (
    "wireguard", "awg", "rivet-h3", "rivet-s1", "xray", "shadowsocks",
    "openvpn", "cloak", "ikev2",
)
MESH_PROTOCOL = "mesh"
CLIENT_MATERIALS = (
    "rivet.deviceSecret", "rivet.entryToken", "stack.xrayUuid",
    "stack.shadowsocksKey",
)
SERVER_MATERIALS = (
    "csrPem", "stack.tlsCryptV2", "stack.openvpnPrivateKey", "stack.ikePassword",
    "stack.cloakUid",
)
MATERIAL_IDS = CLIENT_MATERIALS + SERVER_MATERIALS

CA_CONFIG_KIND = "XIO-CA-CONFIG-WITNESS-1"
CA_MAPPING_FIELDS = (
    "dir", "database", "new_certs_dir", "serial", "crlnumber", "certificate",
    "private_key",
)
CA_OPTION_FIELDS = (
    "unique_subject", "default_days", "default_crl_days", "default_md", "policy",
)
CA_OPERATION_KINDS = ("client_issue",)
OTHER_CA_KINDS = (
    "bootstrap", "server_certificate", "revoke", "gencrl", "remove",
)
BACKEND_NAMES = ("delegation", "awg", "rivet", "stackCA", "stackActivate")
BACKEND_STATES = (
    "notStarted", "staged", "applyUnknown", "appliedVerified", "failed",
    "repairRequired",
)
PHASES = (
    "prepared", "applying", "needsMaterial", "complete", "cancelledRequested",
    "cancelledConfirmed", "rejected", "repairRequired",
)
TERMINAL_PHASES = ("complete", "cancelledConfirmed", "rejected")
_FALSE = (False,)


class PrimitiveError(Exception):
    """Finite internal error code; never carries payload bytes or secrets."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PrimitiveError(code)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        _fail(code)


def _is_hex(value: str, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(
        c in "0123456789abcdef" for c in value
    )


def _require_hex(value: Any, length: int, code: str) -> str:
    _require(type(value) is str and _is_hex(value, length), code)
    return value


def _require_int(value: Any, code: str, minimum: int = 0,
                 maximum: int = MAX_SAFE_INTEGER) -> int:
    _require(type(value) is int and minimum <= value <= maximum, code)
    return value


def _require_bool(value: Any, code: str) -> bool:
    _require(type(value) is bool, code)
    return value


def _require_str(value: Any, code: str, max_bytes: int,
                 allow_lf: bool = False) -> str:
    _require(type(value) is str, code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(code)
    _require(len(encoded) <= max_bytes, code)
    for byte in encoded:
        if byte == 0x0A and allow_lf:
            continue
        _require(0x20 <= byte <= 0x7E, code)
    return value


def _canonical_json(value: Any) -> bytes:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)
    return text.encode("ascii")


# ---------------------------------------------------------------- strict JSON

def _reject_constant(value: str) -> None:
    _fail("JSON_NONFINITE")


def _reject_float(value: str) -> None:
    _fail("JSON_FLOAT")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(isinstance(key, str), "JSON_KEY_TYPE")
        _require(key not in result, "JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _prescan_depth(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            _require(depth <= MAX_JSON_DEPTH, "JSON_DEPTH")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            _require(depth >= 0, "JSON_UNBALANCED")
    _require(not in_string and depth == 0, "JSON_UNBALANCED")


def _node_count(value: Any) -> int:
    count = 0
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        count += 1
        _require(count <= MAX_JSON_NODES, "JSON_NODES")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return count


def strict_json(raw: bytes, *, max_bytes: int = MAX_REQUEST_INPUT) -> Any:
    _require(isinstance(raw, (bytes, bytearray)), "JSON_TYPE")
    _require(len(raw) <= max_bytes, "JSON_TOO_LARGE")
    _prescan_depth(raw)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError:
        _fail("JSON_ENCODING")
    except json.JSONDecodeError:
        _fail("JSON_INVALID")
    _node_count(value)
    return value


def exact_object(value: Any, fields: Sequence[str], *, optional: Sequence[str] = ()) -> dict[str, Any]:
    _require(type(value) is dict, "OBJECT_TYPE")
    required = set(fields)
    allowed = required | set(optional)
    _require(set(value) <= allowed, "UNKNOWN_FIELD")
    _require(required <= set(value), "MISSING_FIELD")
    return value


# --------------------------------------------------------------------- request

@dataclass(frozen=True)
class PublicRequest:
    name_sha256: str
    public_keys: Mapping[str, str]
    admin: bool
    user_limit: int
    admin_public_key: str | None
    protocols: tuple[str, ...]
    commitments: Mapping[str, str]

    def canonical(self) -> bytes:
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "nameSha256": self.name_sha256,
            "publicKeys": dict(self.public_keys),
            "admin": self.admin,
            "userLimit": self.user_limit,
            "protocols": list(self.protocols),
            "commitments": dict(self.commitments),
        }
        if self.admin_public_key is not None:
            payload["adminPublicKey"] = self.admin_public_key
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_CANONICAL_REQUEST, "REQUEST_CANONICAL_TOO_LARGE")
        return encoded

    def sha256(self) -> str:
        return _sha256_hex(REQUEST_DOMAIN + self.canonical())


@dataclass(frozen=True)
class PutCommand:
    operation_id: str
    uid: str
    display_name: str
    request: PublicRequest


def _validate_display_name(value: Any) -> str:
    _require(type(value) is str, "NAME_TYPE")
    _require(1 <= len(value) <= MAX_DISPLAY_CODEPOINTS, "NAME_LENGTH")
    try:
        encoded_name = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail("NAME_UNICODE")
    _require(len(encoded_name) <= MAX_DISPLAY_BYTES, "NAME_BYTES")
    _require(value == value.strip(), "NAME_WHITESPACE")
    for char in value:
        code = ord(char)
        _require(code >= 0x20 and code != 0x7F, "NAME_CONTROL")
    return value


def _required_client_materials(protocols: Sequence[str]) -> tuple[str, ...]:
    required: list[str] = []
    if "rivet-h3" in protocols or "rivet-s1" in protocols:
        required.extend(("rivet.deviceSecret", "rivet.entryToken"))
    if "xray" in protocols:
        required.append("stack.xrayUuid")
    if "shadowsocks" in protocols:
        required.append("stack.shadowsocksKey")
    return tuple(required)


def _required_public_keys(protocols: Sequence[str]) -> tuple[str, ...]:
    required: list[str] = []
    if "wireguard" in protocols:
        required.append("wireguard")
    if "awg" in protocols:
        required.append("awg")
    return tuple(required)


def _parse_public_request(value: Any, display_name: str) -> PublicRequest:
    _require(type(value) is dict, "REQUEST_TYPE")
    optional = ("adminPublicKey", "schema")
    fields = exact_object(
        value,
        ("nameSha256", "publicKeys", "admin", "userLimit", "protocols", "commitments"),
        optional=optional,
    )
    if "schema" in fields:
        _require(_require_int(fields["schema"], "REQUEST_SCHEMA") == SCHEMA, "REQUEST_SCHEMA")
    name_sha = _require_hex(fields["nameSha256"], 64, "NAME_HASH")
    _require(name_sha == _sha256_hex(display_name.encode("utf-8")), "NAME_HASH_MISMATCH")

    public_keys_value = fields["publicKeys"]
    _require(type(public_keys_value) is dict, "PUBLIC_KEYS_TYPE")
    protocols_value = fields["protocols"]
    _require(type(protocols_value) is list and protocols_value, "PROTOCOLS_TYPE")
    protocols: list[str] = []
    for item in protocols_value:
        _require(type(item) is str and item in PROTOCOLS, "PROTOCOL_UNSUPPORTED")
        _require(item not in protocols, "PROTOCOL_DUPLICATE")
        protocols.append(item)
    required_keys = set(_required_public_keys(protocols))
    _require(set(public_keys_value) == required_keys, "PUBLIC_KEYS_SCOPE")
    public_keys: dict[str, str] = {}
    for protocol, encoded in public_keys_value.items():
        public_keys[protocol] = _canonical_base64(encoded, 32, "PUBLIC_KEY_INVALID")

    admin = _require_bool(fields["admin"], "ADMIN_TYPE")
    user_limit = _require_int(fields["userLimit"], "USER_LIMIT", 0, 250)
    _require(admin or user_limit == 0, "USER_LIMIT_FORBIDDEN")
    admin_public_key = fields.get("adminPublicKey")
    if admin:
        _require(isinstance(admin_public_key, str), "ADMIN_KEY_REQUIRED")
        _validate_admin_public_key(admin_public_key)
    else:
        _require(admin_public_key is None, "ADMIN_KEY_FORBIDDEN")

    commitments_value = fields["commitments"]
    _require(type(commitments_value) is dict, "COMMITMENTS_TYPE")
    required_commitments = set(_required_client_materials(protocols))
    _require(set(commitments_value) == required_commitments, "COMMITMENTS_SCOPE")
    commitments: dict[str, str] = {}
    for kind, digest in commitments_value.items():
        _require(kind in CLIENT_MATERIALS, "MATERIAL_UNSUPPORTED")
        commitments[kind] = _require_hex(digest, 64, "COMMITMENT_INVALID")

    return PublicRequest(
        name_sha256=name_sha,
        public_keys=public_keys,
        admin=admin,
        user_limit=user_limit,
        admin_public_key=admin_public_key if admin else None,
        protocols=tuple(protocols),
        commitments=commitments,
    )


def parse_put_command(raw: bytes) -> PutCommand:
    value = strict_json(raw, max_bytes=MAX_REQUEST_INPUT)
    fields = exact_object(value, ("schema", "operationId", "uid", "displayName", "request"))
    _require(_require_int(fields["schema"], "SCHEMA") == SCHEMA, "SCHEMA")
    operation_id = _require_hex(fields["operationId"], 32, "OPERATION_ID")
    uid = _require_hex(fields["uid"], 32, "UID")
    display_name = _validate_display_name(fields["displayName"])
    request = _parse_public_request(fields["request"], display_name)
    return PutCommand(operation_id=operation_id, uid=uid, display_name=display_name, request=request)


def _validate_admin_public_key(value: str) -> None:
    _require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]{64,80}", value) is not None,
             "ADMIN_KEY_FORMAT")
    try:
        blob = base64.b64decode(value.split()[1], validate=True)
    except Exception:
        _fail("ADMIN_KEY_FORMAT")
    _require(len(blob) == 51 and blob[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
             "ADMIN_KEY_FORMAT")


def _canonical_base64_any(value: Any, max_length: int, code: str) -> str:
    _require(type(value) is str, code)
    # Reject encoded oversize before any decoded allocation.
    max_encoded = 4 * ((max_length + 2) // 3)
    _require(len(value) <= max_encoded, code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        _fail(code)
    _require(base64.b64encode(decoded).decode("ascii") == value, code)
    _require(len(decoded) <= max_length, code)
    return value


def _canonical_base64(value: Any, length: int, code: str) -> str:
    encoded = _canonical_base64_any(value, length, code)
    _require(len(base64.b64decode(encoded)) == length, code)
    return encoded


# --------------------------------------------------------------------- material

def canonical_material(kind: str, value: str) -> tuple[bytes, str]:
    _require(kind in MATERIAL_IDS, "MATERIAL_UNSUPPORTED")
    _require(type(value) is str, "MATERIAL_TYPE")
    if kind in ("rivet.deviceSecret", "rivet.entryToken", "stack.shadowsocksKey"):
        encoded = _canonical_base64(value, 32, "MATERIAL_BASE64")
        raw = base64.b64decode(encoded)
        return raw, _sha256_hex(raw)
    if kind == "stack.cloakUid":
        encoded = _canonical_base64(value, 16, "MATERIAL_BASE64")
        raw = base64.b64decode(encoded)
        return raw, _sha256_hex(raw)
    if kind == "stack.xrayUuid":
        _require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                              value) is not None, "MATERIAL_UUID")
        return value.encode("ascii"), _sha256_hex(value.encode("ascii"))
    if kind == "stack.ikePassword":
        raw = value.encode("utf-8")
        _require(1 <= len(raw) <= 128, "MATERIAL_SIZE")
        for byte in raw:
            _require(byte == 0x0A or 0x20 <= byte <= 0x7E, "MATERIAL_PRINTABLE")
        return raw, _sha256_hex(raw)
    if kind in ("csrPem", "stack.tlsCryptV2", "stack.openvpnPrivateKey"):
        limit = MAX_CSR if kind == "csrPem" else C1_ARTIFACT_CAPS["openvpn.tls-crypt-v2-client" if kind == "stack.tlsCryptV2" else "openvpn.client-key"]
        _require(1 <= len(value.encode("utf-8")) <= limit, "MATERIAL_SIZE")
        raw = value.encode("utf-8")
        for byte in raw:
            _require(byte == 0x0A or 0x20 <= byte <= 0x7E, "MATERIAL_PRINTABLE")
        return raw, _sha256_hex(raw)
    _fail("MATERIAL_UNSUPPORTED")


def material_commitment(kind: str, value: str) -> str:
    return canonical_material(kind, value)[1]


# ----------------------------------------------------------------------- capsule

def _validate_context(context: Mapping[str, Any]) -> dict[str, Any]:
    _require(type(context) is dict and set(context) == set(CONTEXT_FIELDS), "CONTEXT_FIELDS")
    result: dict[str, Any] = {}
    _require(_require_int(context["schema"], "CONTEXT_SCHEMA") == 1, "CONTEXT_SCHEMA")
    _require(_require_int(context["version"], "CONTEXT_VERSION") == 1, "CONTEXT_VERSION")
    _require(context["purpose"] == CAPSULE_PURPOSE, "CONTEXT_PURPOSE")
    result["schema"] = 1
    result["version"] = 1
    result["purpose"] = CAPSULE_PURPOSE
    result["operation"] = _require_str(context["operation"], "CONTEXT_OPERATION", 64)
    _require(re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", result["operation"]) is not None,
             "CONTEXT_OPERATION")
    uid = _require_hex(context["uid"], 32, "CONTEXT_UID")
    _require(re.fullmatch(r"[a-f0-9]{32}([a-f0-9]{32})?", uid) is not None, "CONTEXT_UID")
    result["uid"] = uid
    for field_name in ("server", "deployment", "actor"):
        result[field_name] = _require_str(context[field_name], "CONTEXT_FIELD", 128)
        _require(len(result[field_name]) > 0, "CONTEXT_FIELD")
    for digest in ("requestDigest", "profileSetDigest"):
        result[digest] = _require_hex(context[digest], 64, "CONTEXT_DIGEST")
    return result


def _quote_ascii(value: str) -> str:
    output = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            output.append('\\"')
        elif char == "\\":
            output.append("\\\\")
        elif code == 0x08:
            output.append("\\b")
        elif code == 0x09:
            output.append("\\t")
        elif code == 0x0A:
            output.append("\\n")
        elif code == 0x0C:
            output.append("\\f")
        elif code == 0x0D:
            output.append("\\r")
        elif code < 0x20:
            output.append("\\u00%02x" % code)
        else:
            output.append(char)
    output.append('"')
    return "".join(output)


def encode_capsule_plaintext(context: Mapping[str, Any], artifacts: Mapping[str, str]) -> bytes:
    validated = _validate_context(context)
    _require(type(artifacts) is dict, "ARTIFACTS_TYPE")
    _require(set(artifacts) <= set(C1_ARTIFACT_CAPS), "ARTIFACT_UNSUPPORTED")
    _require(artifacts, "ARTIFACT_EMPTY")
    for kind, value in artifacts.items():
        _require(type(value) is str and value, "ARTIFACT_VALUE")
        _require(len(value.encode("utf-8")) <= C1_ARTIFACT_CAPS[kind], "ARTIFACT_SIZE")
        for byte in value.encode("utf-8"):
            _require(byte == 0x0A or 0x20 <= byte <= 0x7E, "ARTIFACT_PRINTABLE")
    artifact_keys = sorted(artifacts)
    artifacts_text = "{" + ",".join(
        _quote_ascii(key) + ":" + _quote_ascii(artifacts[key]) for key in artifact_keys
    ) + "}"
    values = {
        "artifacts": artifacts_text,
        "actor": _quote_ascii(validated["actor"]),
        "deployment": _quote_ascii(validated["deployment"]),
        "operation": _quote_ascii(validated["operation"]),
        "profileSetDigest": _quote_ascii(validated["profileSetDigest"]),
        "purpose": _quote_ascii(validated["purpose"]),
        "requestDigest": _quote_ascii(validated["requestDigest"]),
        "schema": str(validated["schema"]),
        "server": _quote_ascii(validated["server"]),
        "uid": _quote_ascii(validated["uid"]),
        "version": str(validated["version"]),
    }
    encoded = "{" + ",".join(
        _quote_ascii(key) + ":" + values[key] for key in sorted(values)
    ) + "}"
    raw = encoded.encode("utf-8")
    _require(len(raw) <= C1_PLAINTEXT_MAX, "CAPSULE_PLAINTEXT_TOO_LARGE")
    return raw


@dataclass(frozen=True)
class CapsuleRef:
    capsule_id: str
    ciphertext_sha256: str
    envelope_sha256: str
    size: int

    @classmethod
    def from_raw(cls, raw: bytes) -> "CapsuleRef":
        _require(isinstance(raw, (bytes, bytearray)), "CAPSULE_TYPE")
        _require(len(raw) <= C0_MAX_ENVELOPE, "CAPSULE_TOO_LARGE")
        value = strict_json(bytes(raw), max_bytes=C0_MAX_ENVELOPE)
        fields = exact_object(value, CAPSULE_FIELDS)
        _require(_require_int(fields["v"], "CAPSULE_VERSION") == 1, "CAPSULE_VERSION")
        _require(fields["alg"] == CAPSULE_ALG, "CAPSULE_ALG")
        capsule_id = _require_hex(fields["capsuleId"], 32, "CAPSULE_ID")
        _canonical_base64(fields["recipientPublicKey"], 32, "CAPSULE_RECIPIENT")
        ciphertext = _canonical_base64_any(fields["ciphertext"], C0_MAX_CIPHERTEXT, "CAPSULE_CIPHERTEXT")
        decoded = base64.b64decode(ciphertext, validate=True)
        _require(len(decoded) <= C0_MAX_CIPHERTEXT, "CAPSULE_TOO_LARGE")
        _require(len(raw) <= C1_COMPACT_ENVELOPE_MAX, "CAPSULE_NOT_COMPACT_C1")
        return cls(
            capsule_id=capsule_id,
            ciphertext_sha256=_sha256_hex(decoded),
            envelope_sha256=_sha256_hex(bytes(raw)),
            size=len(raw),
        )

    def first_pin(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "capsuleId": self.capsule_id,
            "ciphertextSha256": self.ciphertext_sha256,
            "envelopeSha256": self.envelope_sha256,
            "size": self.size,
        }
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_FIRST_PIN, "FIRST_PIN_TOO_LARGE")
        return encoded


@dataclass(frozen=True)
class FirstPin:
    operation_id: str
    uid: str
    capsule: CapsuleRef
    request_sha256: str
    context_sha256: str
    csr_sha256: str
    spki_sha256: str
    csr_cn: str
    created_at: int

    def encode(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "operationId": _require_hex(self.operation_id, 32, "PIN_OP"),
            "uid": _require_hex(self.uid, 32, "PIN_UID"),
            "phase": "prepared",
            "capsule": {
                "capsuleId": self.capsule.capsule_id,
                "ciphertextSha256": self.capsule.ciphertext_sha256,
                "envelopeSha256": self.capsule.envelope_sha256,
                "size": self.capsule.size,
            },
            "requestSha256": _require_hex(self.request_sha256, 64, "PIN_REQUEST"),
            "contextSha256": _require_hex(self.context_sha256, 64, "PIN_CONTEXT"),
            "csrSha256": _require_hex(self.csr_sha256, 64, "PIN_CSR"),
            "spkiSha256": _require_hex(self.spki_sha256, 64, "PIN_SPKI"),
            "csrCn": _require_str(self.csr_cn, "PIN_CN", 128),
            "createdAt": _require_int(self.created_at, "PIN_TIME"),
        }
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_FIRST_PIN, "FIRST_PIN_TOO_LARGE")
        return encoded


def _validate_cert_pem(value: Any) -> str:
    _require(type(value) is str, "PROGRESS_CERT_SIZE")
    raw = value.encode("utf-8")
    _require(1 <= len(raw) <= MAX_CERT, "PROGRESS_CERT_SIZE")
    header = "-----BEGIN CERTIFICATE-----\n"
    footer = "-----END CERTIFICATE-----\n"
    _require(value.startswith(header) and value.endswith(footer), "PROGRESS_CERT_FORM")
    body = value[len(header):-len(footer)]
    _require(body and "\r" not in body and body.endswith("\n"), "PROGRESS_CERT_FORM")
    lines = body.split("\n")[:-1]
    _require(all(1 <= len(line) <= 64 for line in lines), "PROGRESS_CERT_FORM")
    _require(all(len(line) == 64 for line in lines[:-1]), "PROGRESS_CERT_FORM")
    compact = "".join(lines)
    _require(re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None, "PROGRESS_CERT_FORM")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except Exception:
        _fail("PROGRESS_CERT_FORM")
    # Canonical PEM: re-encoding must reproduce the exact body (pad bits and
    # line layout), without ASN.1 parsing.
    _require(base64.b64encode(decoded).decode("ascii") == compact,
             "PROGRESS_CERT_FORM")
    return value


@dataclass(frozen=True)
class ProgressReceipt:
    operation_id: str
    uid: str
    phase: str
    capsule: CapsuleRef
    csr_sha256: str
    spki_sha256: str
    csr_cn: str
    cert_pem: str | None
    cert_sha256: str | None
    serial: str | None
    ca_sha256: str | None
    backends: Mapping[str, str]
    material_request: Sequence[str] = ()
    fence: str | None = None
    updated_at: int = 0

    def encode(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "operationId": _require_hex(self.operation_id, 32, "PROGRESS_OP"),
            "uid": _require_hex(self.uid, 32, "PROGRESS_UID"),
            "phase": self.phase,
            "capsule": {
                "capsuleId": self.capsule.capsule_id,
                "ciphertextSha256": self.capsule.ciphertext_sha256,
                "envelopeSha256": self.capsule.envelope_sha256,
                "size": self.capsule.size,
            },
            "csrSha256": _require_hex(self.csr_sha256, 64, "PROGRESS_CSR"),
            "spkiSha256": _require_hex(self.spki_sha256, 64, "PROGRESS_SPKI"),
            "csrCn": _require_str(self.csr_cn, "PROGRESS_CN", 128),
            "backends": dict(self.backends),
            "materialRequest": list(self.material_request),
            "updatedAt": _require_int(self.updated_at, "PROGRESS_TIME"),
        }
        _require(self.phase in PHASES, "PROGRESS_PHASE")
        _require(set(self.backends) <= set(BACKEND_NAMES), "PROGRESS_BACKENDS")
        for state in self.backends.values():
            _require(state in BACKEND_STATES, "PROGRESS_BACKENDS")
        for kind in self.material_request:
            _require(kind in MATERIAL_IDS, "PROGRESS_MATERIAL")
        if self.cert_pem is not None:
            cert_pem = _validate_cert_pem(self.cert_pem)
            _require(_sha256_hex(cert_pem.encode("utf-8")) == self.cert_sha256,
                     "PROGRESS_CERT_DIGEST")
            payload["certPem"] = cert_pem
            payload["certSha256"] = _require_hex(self.cert_sha256, 64, "PROGRESS_CERT_HASH")
            _require(type(self.serial) is str and
                     re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", self.serial) is not None,
                     "PROGRESS_SERIAL")
            payload["serial"] = self.serial
            payload["caSha256"] = _require_hex(self.ca_sha256, 64, "PROGRESS_CA")
        if self.fence is not None:
            payload["fence"] = _require_str(self.fence, "PROGRESS_FENCE", 64)
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_PROGRESS, "PROGRESS_TOO_LARGE")
        return encoded


def capsule_fetch_response(ref: CapsuleRef, raw: bytes) -> bytes:
    _require(len(raw) <= C0_MAX_ENVELOPE, "CAPSULE_TOO_LARGE")
    _require(_sha256_hex(bytes(raw)) == ref.envelope_sha256, "CAPSULE_RAW_MISMATCH")
    response = {
        "schema": SCHEMA,
        "capsuleId": ref.capsule_id,
        "ciphertextSha256": ref.ciphertext_sha256,
        "envelopeSha256": ref.envelope_sha256,
        "size": ref.size,
        "envelopeBytesB64": base64.b64encode(raw).decode("ascii"),
    }
    encoded = _canonical_json(response)
    _require(len(encoded) <= MAX_CAPSULE_RESPONSE, "CAPSULE_RESPONSE_TOO_LARGE")
    _require(len(base64.b64encode(raw)) <= C1_OUTER_BASE64_MAX, "CAPSULE_OUTER_TOO_LARGE")
    return encoded


# ------------------------------------------------------------------ durable IO

class FaultInjector(Protocol):
    def cut(self, point: str) -> None:
        ...


@dataclass(frozen=True)
class DurableWriteResult:
    path: str
    status: str  # durable | failed | uncertain
    sha256: str
    bytes_written: int
    code: str = ""

    @property
    def durable(self) -> bool:
        return self.status == "durable"


class DurableWriter:
    """Explicit-root durable writes; no defaults, no import-time I/O."""

    def __init__(self, root: Path, faults: FaultInjector | None = None):
        self.root = Path(os.path.realpath(root))
        _require(self.root.is_dir(), "ROOT_INVALID")
        _require(not self.root.is_symlink(), "ROOT_SYMLINK")
        self._faults = faults

    def _cut(self, point: str) -> None:
        if self._faults is not None:
            self._faults.cut(point)

    def _resolve(self, relative: str) -> Path:
        _require(type(relative) is str and relative and not relative.startswith("/"), "PATH_INVALID")
        parts = Path(relative).parts
        _require(parts and all(part not in ("", ".", "..") for part in parts), "PATH_INVALID")
        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                continue
            _require(not stat.S_ISLNK(info.st_mode), "PATH_SYMLINK")
            if index < len(parts) - 1:
                _require(stat.S_ISDIR(info.st_mode), "PATH_NOT_DIRECTORY")
        _require(current == self.root or self.root in current.parents, "PATH_ESCAPE")
        return current

    def _fsync_dir(self, directory: Path) -> None:
        descriptor = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def ensure_directory(self, relative: str) -> None:
        target = self._resolve(relative)
        missing: list[Path] = []
        current = target
        while current != self.root and not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._cut("after_parent_create")
            self._fsync_dir(directory.parent)
            self._cut("after_parent_fsync")

    def refence_ancestry(self, relative_parent: str) -> None:
        """Unconditionally fence existing ancestry to the trusted root.

        No marker or in-memory flag may skip this: a directory visible after a
        failed predecessor fsync is not proof that its birth entry is durable.
        """
        target = self.root if relative_parent == "" else self._resolve(relative_parent)
        _require(target.is_dir(), "ANCESTRY_MISSING")
        self._fsync_dir(self.root)
        current = self.root
        for part in target.relative_to(self.root).parts:
            current = current / part
            _require(current.is_dir(), "ANCESTRY_MISSING")
            self._fsync_dir(current)

    def _cleanup(self, temp: Path) -> bool:
        try:
            temp.unlink(missing_ok=True)
            return True
        except Exception:
            return False

    def write(self, relative: str, data: bytes, *, max_bytes: int,
              mode: int = 0o600) -> DurableWriteResult:
        _require(isinstance(data, (bytes, bytearray)), "DATA_TYPE")
        _require(len(data) <= max_bytes, "DATA_TOO_LARGE")
        target = self._resolve(relative)
        parent_relative = "" if target.parent == self.root else str(
            target.parent.relative_to(self.root))
        if parent_relative:
            self.ensure_directory(parent_relative)
            target = self._resolve(relative)
        if target.exists():
            return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0, "EXISTS")
        # Fresh sessions and rare issuance writes unconditionally re-fence the
        # ancestry; no marker can skip this after an uncertain predecessor.
        self.refence_ancestry(parent_relative)
        self._cut("before_temp")
        temp_name = f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        temp = target.parent / temp_name
        descriptor = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            self._cut("after_temp_create")
            view = memoryview(bytes(data))
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            self._cut("after_write")
            os.fsync(descriptor)
            self._cut("after_file_fsync")
        except Exception:
            os.close(descriptor)
            if not self._cleanup(temp):
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "CLEANUP_RESIDUE")
            return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0, "IO_FAILED")
        else:
            os.close(descriptor)
        published = False
        try:
            os.link(temp, target)  # atomic no-clobber; never replaces a competitor
            published = True
            self._cut("after_replace")
            if not self._cleanup(temp):
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "CLEANUP_RESIDUE")
            self._fsync_dir(target.parent)
            self._cut("after_dir_fsync")
        except FileExistsError:
            if not self._cleanup(temp):
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "CLEANUP_RESIDUE")
            if published:
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "IO_UNCERTAIN")
            return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0,
                                      "TARGET_EXISTS")
        except OSError as error:
            cleanup_ok = self._cleanup(temp)
            if published:
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data),
                                          "CLEANUP_RESIDUE" if not cleanup_ok else "IO_UNCERTAIN")
            if error.errno in {getattr(errno, "EOPNOTSUPP", -1),
                               getattr(errno, "ENOTSUP", -1)}:
                if not cleanup_ok:
                    return DurableWriteResult(relative, "uncertain",
                                              _sha256_hex(bytes(data)), len(data),
                                              "CLEANUP_RESIDUE")
                return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0,
                                          "UNSUPPORTED_NO_CLOBBER")
            if not cleanup_ok:
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "CLEANUP_RESIDUE")
            return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0, "IO_FAILED")
        except Exception:
            if not self._cleanup(temp):
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "CLEANUP_RESIDUE")
            if published:
                return DurableWriteResult(relative, "uncertain", _sha256_hex(bytes(data)),
                                          len(data), "IO_UNCERTAIN")
            return DurableWriteResult(relative, "failed", _sha256_hex(bytes(data)), 0, "IO_FAILED")
        digest = _sha256_hex(bytes(data))
        try:
            readback = self.read_bounded(relative, max_bytes)
        except PrimitiveError:
            return DurableWriteResult(relative, "uncertain", digest, len(data), "READBACK_FAILED")
        if readback != bytes(data):
            return DurableWriteResult(relative, "uncertain", digest, len(data), "READBACK_MISMATCH")
        return DurableWriteResult(relative, "durable", digest, len(data))

    def read_bounded(self, relative: str, max_bytes: int) -> bytes:
        target = self._resolve(relative)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(str(target), flags)
        except OSError as error:
            if error.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                _fail("PATH_SYMLINK")
            _fail("READ_OPEN_FAILED")
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                _require(total <= max_bytes, "READ_TOO_LARGE")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        return b"".join(chunks)


def write_capsule_then_record(writer: DurableWriter, capsule_rel: str, capsule: bytes,
                              record_rel: str, record: bytes) -> tuple[DurableWriteResult, DurableWriteResult | None]:
    capsule_result = writer.write(capsule_rel, capsule, max_bytes=C0_MAX_ENVELOPE)
    if not capsule_result.durable:
        return capsule_result, None
    record_result = writer.write(record_rel, record, max_bytes=MAX_RECORD)
    return capsule_result, record_result


# ---------------------------------------------------------------------- record

@dataclass(frozen=True)
class Record:
    uid: str
    operation_id: str
    deployment_id: str
    actor: str | None
    actor_role: str
    request_sha256: str
    display_name: str
    request: Mapping[str, Any]
    commitments: Mapping[str, str]
    capsule: CapsuleRef
    csr_pem: str
    csr_sha256: str
    spki_sha256: str
    csr_cn: str
    ca_config: Mapping[str, Any]
    phase: str
    backends: Mapping[str, str]
    revision: int
    cancellation: Mapping[str, Any]
    updated_at: int

    def identity(self) -> tuple[str, str, str, str]:
        return (self.uid, self.operation_id, self.request_sha256, self.deployment_id)

    def copy(self, **changes: Any) -> "Record":
        values = {field_name: getattr(self, field_name) for field_name in self.__dataclass_fields__}
        values.update(changes)
        return Record(**values)

    def to_json(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "uid": self.uid,
            "operationId": self.operation_id,
            "deploymentId": self.deployment_id,
            "actor": self.actor,
            "actorRole": self.actor_role,
            "requestSha256": self.request_sha256,
            "displayName": self.display_name,
            "request": dict(self.request),
            "commitments": dict(self.commitments),
            "capsule": {
                "capsuleId": self.capsule.capsule_id,
                "ciphertextSha256": self.capsule.ciphertext_sha256,
                "envelopeSha256": self.capsule.envelope_sha256,
                "size": self.capsule.size,
            },
            "csr": {"pem": self.csr_pem, "sha256": self.csr_sha256,
                    "spkiSha256": self.spki_sha256, "cn": self.csr_cn},
            "caConfig": dict(self.ca_config),
            "phase": self.phase,
            "backends": dict(self.backends),
            "revision": self.revision,
            "cancellation": dict(self.cancellation),
            "updatedAt": self.updated_at,
        }
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_RECORD, "RECORD_TOO_LARGE")
        return encoded


def decode_record(raw: bytes) -> Record:
    value = strict_json(raw, max_bytes=MAX_RECORD)
    fields = exact_object(value, (
        "schema", "uid", "operationId", "deploymentId", "actor", "actorRole",
        "requestSha256", "displayName", "request", "commitments", "capsule", "csr",
        "caConfig", "phase", "backends", "revision", "cancellation", "updatedAt",
    ))
    _require(_require_int(fields["schema"], "RECORD_SCHEMA") == SCHEMA, "RECORD_SCHEMA")
    uid = _require_hex(fields["uid"], 32, "RECORD_UID")
    operation_id = _require_hex(fields["operationId"], 32, "RECORD_OP")
    deployment_id = _require_str(fields["deploymentId"], "RECORD_DEPLOYMENT", 128)
    actor = fields["actor"]
    _require(actor is None or _is_hex(actor, 32), "RECORD_ACTOR")
    actor_role = fields["actorRole"]
    _require(actor_role in ("owner", "delegate"), "RECORD_ROLE")
    request_sha = _require_hex(fields["requestSha256"], 64, "RECORD_REQUEST_HASH")
    display_name = _validate_display_name(fields["displayName"])
    request = _parse_public_request(fields["request"], display_name)
    commitments = fields["commitments"]
    _require(type(commitments) is dict, "RECORD_COMMITMENTS")
    for kind, digest in commitments.items():
        _require(kind in MATERIAL_IDS, "MATERIAL_UNSUPPORTED")
        _require_hex(digest, 64, "COMMITMENT_INVALID")
    for kind, digest in request.commitments.items():
        _require(commitments.get(kind) == digest, "COMMITMENT_OVERLAP_MISMATCH")
    for kind in commitments:
        _require(kind in request.commitments or kind in SERVER_MATERIALS,
                 "COMMITMENT_SCOPE")
    _require(request.sha256() == request_sha, "RECORD_REQUEST_MISMATCH")
    capsule_value = exact_object(fields["capsule"],
                                 ("capsuleId", "ciphertextSha256", "envelopeSha256", "size"))
    capsule = CapsuleRef(
        capsule_id=_require_hex(capsule_value["capsuleId"], 32, "CAPSULE_ID"),
        ciphertext_sha256=_require_hex(capsule_value["ciphertextSha256"], 64, "CAPSULE_DIGEST"),
        envelope_sha256=_require_hex(capsule_value["envelopeSha256"], 64, "CAPSULE_RAW"),
        size=_require_int(capsule_value["size"], "CAPSULE_SIZE", 0, C0_MAX_ENVELOPE),
    )
    csr_value = exact_object(fields["csr"], ("pem", "sha256", "spkiSha256", "cn"))
    csr_pem = csr_value["pem"]
    _require(type(csr_pem) is str and 1 <= len(csr_pem.encode("utf-8")) <= MAX_CSR, "CSR_SIZE")
    _require(csr_value["sha256"] == _sha256_hex(csr_pem.encode("utf-8")), "CSR_HASH")
    csr_sha = _require_hex(csr_value["sha256"], 64, "CSR_HASH")
    spki_sha = _require_hex(csr_value["spkiSha256"], 64, "SPKI_HASH")
    csr_cn = _require_str(csr_value["cn"], "CSR_CN", 128)
    ca_config = fields["caConfig"]
    _validate_ca_config_value(ca_config)
    phase = fields["phase"]
    _require(phase in PHASES, "PHASE")
    backends = fields["backends"]
    _require(type(backends) is dict and set(backends) <= set(BACKEND_NAMES), "BACKENDS")
    for state in backends.values():
        _require(state in BACKEND_STATES, "BACKEND_STATE")
    revision = _require_int(fields["revision"], "REVISION")
    cancellation = exact_object(fields["cancellation"], ("requested", "confirmed", "requestedAt"))
    _require_bool(cancellation["requested"], "CANCEL_REQUESTED")
    _require_bool(cancellation["confirmed"], "CANCEL_CONFIRMED")
    _require_int(cancellation["requestedAt"], "CANCEL_TIME")
    updated_at = _require_int(fields["updatedAt"], "UPDATED_AT")
    return Record(
        uid=uid, operation_id=operation_id, deployment_id=deployment_id,
        actor=actor, actor_role=actor_role, request_sha256=request_sha,
        display_name=display_name, request=json.loads(request.canonical()),
        commitments=commitments, capsule=capsule, csr_pem=csr_pem, csr_sha256=csr_sha,
        spki_sha256=spki_sha, csr_cn=csr_cn, ca_config=ca_config,
        phase=phase, backends=backends, revision=revision,
        cancellation=cancellation, updated_at=updated_at,
    )


# -------------------------------------------------------- authority / state

@dataclass(frozen=True)
class Principal:
    uid: str | None
    role: str  # owner | delegate
    revoked: bool


def _validate_principal(principal: Any) -> bool:
    if not isinstance(principal, Principal):
        return False
    if principal.role not in ("owner", "delegate"):
        return False
    if type(principal.revoked) is not bool:
        return False
    if principal.role == "owner":
        return principal.uid is None
    return type(principal.uid) is str and re.fullmatch(r"[0-9a-f]{32}", principal.uid) is not None


def authorize(record: Record, principal: Principal) -> bool:
    if not _validate_principal(principal):
        return False
    if principal.revoked:
        return False
    if principal.role == "owner":
        return True
    return record.actor is not None and principal.uid == record.actor


@dataclass(frozen=True)
class Transition:
    record: Record | None
    code: str = ""


@dataclass(frozen=True)
class PinResult:
    accepted: bool
    code: str = ""


def pin_capsule(record: Record, capsule: CapsuleRef, expected_revision: int) -> PinResult:
    if record.revision != expected_revision:
        return PinResult(False, "STALE_REVISION")
    if record.capsule == capsule:
        return PinResult(True, "REPLAY")
    return PinResult(False, "CONFLICT_CAPSULE")


def replay_operation(record: Record, operation_id: str, request_sha256: str) -> str:
    if record.operation_id != operation_id:
        return "CONFLICT_OPERATION"
    if record.request_sha256 != request_sha256:
        return "CONFLICT_REQUEST"
    if record.cancellation["confirmed"]:
        return "CANCELLED"
    if record.cancellation["requested"]:
        return "PENDING_CANCEL"
    if record.phase in TERMINAL_PHASES:
        return "REPLAY"
    return "UNRESOLVED"


def _proposal(record: Record, **changes: Any) -> Transition:
    return Transition(record.copy(revision=record.revision + 1, **changes))


def transition(record: Record, expected_revision: int, event: str, *,
               principal: Principal | None = None,
               backends: Mapping[str, str] | None = None,
               complete_absent: bool = False,
               ca_settled: bool = False,
               no_effect_proved: bool = False,
               now: int = 0) -> Transition:
    _require(event in (
        "backend_applied", "complete", "cancel_request", "cancel_confirm",
        "reject", "repair",
    ), "EVENT_UNSUPPORTED")
    _require(type(now) is int and 0 <= now <= MAX_SAFE_INTEGER, "NOW_INVALID")
    if principal is not None and not authorize(record, principal):
        return Transition(None, "UNAUTHORIZED")
    if record.revision != expected_revision:
        return Transition(None, "STALE_REVISION")
    if record.cancellation["confirmed"]:
        return Transition(None, "TOMBSTONE")
    if record.phase in TERMINAL_PHASES:
        return Transition(None, "TERMINAL")
    if record.cancellation["requested"] and event in (
            "backend_applied", "complete", "reject"):
        return Transition(None, "CANCEL_REQUESTED")
    if event == "backend_applied":
        _require(backends is not None, "BACKENDS_REQUIRED")
        merged = dict(record.backends)
        for name, state in backends.items():
            _require(name in BACKEND_NAMES and state in BACKEND_STATES, "BACKEND_STATE")
            current = record.backends.get(name, "notStarted")
            if state == current:
                continue
            allowed = (
                (current == "notStarted" and state in
                 ("staged", "appliedVerified", "applyUnknown", "failed"))
                or (current == "staged" and state == "appliedVerified")
                or (current == "applyUnknown" and state == "appliedVerified")
            )
            if not allowed:
                return Transition(None, "BACKEND_REGRESSION")
            merged[name] = state
        return _proposal(record, backends=merged, updated_at=now)
    if event == "complete":
        required = ("delegation", "awg", "rivet", "stackCA", "stackActivate")
        if not all(record.backends.get(name) == "appliedVerified" for name in required):
            return Transition(None, "BACKENDS_INCOMPLETE")
        return _proposal(record, phase="complete", updated_at=now)
    if event == "cancel_request":
        cancellation = dict(record.cancellation)
        cancellation.update(requested=True, requestedAt=now)
        return _proposal(record, phase="cancelledRequested", cancellation=cancellation,
                       updated_at=now)
    if event == "cancel_confirm":
        if not record.cancellation["requested"]:
            return Transition(None, "CANCEL_NOT_REQUESTED")
        if not complete_absent or not ca_settled:
            return Transition(None, "CANCEL_EVIDENCE_INCOMPLETE")
        cancellation = dict(record.cancellation)
        cancellation.update(confirmed=True)
        return _proposal(record, phase="cancelledConfirmed", cancellation=cancellation,
                       updated_at=now)
    if event == "reject":
        if any(state != "notStarted" for state in record.backends.values()) \
                and not no_effect_proved:
            return Transition(None, "NO_EFFECT_REQUIRED")
        return _proposal(record, phase="rejected", updated_at=now)
    return _proposal(record, phase="repairRequired", updated_at=now)


class RecordStore(Protocol):
    """Injected writer-exclusion/current-read/hash-CAS store (fake is enough)."""

    def exclusive(self) -> Any:
        ...

    def read(self, uid: str) -> tuple[bytes, str, Record]:
        ...

    def compare_and_swap(self, uid: str, expected_raw_sha256: str, data: bytes) -> None:
        ...

    def current_principal(self, uid: str, operation_id: str) -> "Principal":
        ...


def advance_record(store: RecordStore, uid: str, expected_raw_sha256: str,
                   expected_revision: int, event: str, *,
                   principal: Principal | None = None,
                   expected_operation_id: str | None = None,
                   **kwargs: Any) -> Transition:
    """The only safe mutation path: fresh read + hash CAS under one exclusion.

    The caller supplies actor identity only. Current role/revocation are read
    from the injected store under the same exclusion; the raw record is decoded
    here and bound to the requested UID/identity/revision before a proposal is
    made. The generated candidate is validated by the module's own decoder
    before CAS. No readback is claimed as durability proof.
    """
    with store.exclusive():
        raw, raw_sha256, _stored = store.read(uid)
        _require(isinstance(raw, bytes), "STORE_RAW")
        if raw_sha256 != _sha256_hex(raw):
            return Transition(None, "STORE_HASH_MISMATCH")
        if raw_sha256 != expected_raw_sha256:
            return Transition(None, "STALE_RECORD")
        current = decode_record(raw)
        if current.uid != uid:
            return Transition(None, "UID_PLACEMENT")
        if expected_operation_id is not None and current.operation_id != expected_operation_id:
            return Transition(None, "OPERATION_PLACEMENT")
        if current.revision != expected_revision:
            return Transition(None, "STALE_REVISION")
        if principal is None:
            return Transition(None, "AUTHORITY_REQUIRED")
        reader = getattr(store, "current_principal", None)
        if reader is None:
            return Transition(None, "AUTHORITY_REQUIRED")
        current_authority = reader(uid, current.operation_id)
        if not _validate_principal(current_authority):
            return Transition(None, "AUTHORITY_INVALID")
        if current_authority.uid != principal.uid:
            return Transition(None, "ACTOR_MISMATCH")
        if not authorize(current, current_authority):
            return Transition(None, "UNAUTHORIZED")
        if current.revision >= MAX_SAFE_INTEGER:
            return Transition(None, "REVISION_EXHAUSTED")
        result = transition(current, expected_revision, event,
                            principal=current_authority, **kwargs)
        if result.record is None:
            return result
        if result.record.identity() != current.identity():
            return Transition(None, "IDENTITY_CHANGED")
        candidate = result.record.to_json()
        try:
            decode_record(candidate)
        except PrimitiveError:
            return Transition(None, "GENERATED_INVALID")
        store.compare_and_swap(uid, raw_sha256, candidate)
        return result


# ------------------------------------------------------------------ reservations

@dataclass(frozen=True)
class RegistryEntry:
    uid: str
    revoked: bool
    slot: int
    keys: tuple[str, ...]
    role: str
    created_by: str | None


@dataclass(frozen=True)
class Reservation:
    uid: str
    operation_id: str
    slot: int
    keys: tuple[str, ...]
    quota: bool
    created_by: str | None


@dataclass(frozen=True)
class Admission:
    accepted: bool
    code: str = ""
    slot: int | None = None
    reservation: Reservation | None = None


class AdmissionBook:
    def __init__(self, registry: Mapping[str, RegistryEntry],
                 reservations: Iterable[Reservation] = ()):
        self.registry = dict(registry)
        self.reservations = list(reservations)

    def _keys_in_use(self) -> set[str]:
        keys: set[str] = set()
        for entry in self.registry.values():
            keys.update(entry.keys)
        for reservation in self.reservations:
            keys.update(reservation.keys)
        return keys

    def _slots_in_use(self) -> dict[int, str]:
        slots = {entry.slot: uid for uid, entry in self.registry.items()
                 if not entry.revoked}
        for reservation in self.reservations:
            slots.setdefault(reservation.slot, reservation.uid)
        return slots

    def _reservations_for(self, actor: str | None, exclude: str | None = None) -> int:
        return sum(
            1 for reservation in self.reservations
            if reservation.quota and reservation.created_by == actor
            and reservation.operation_id != exclude
        )

    def admit(self, *, uid: str, operation_id: str, keys: Sequence[str],
              quota: bool, actor: str | None, user_limit: int) -> Admission:
        if uid in self.registry:
            return Admission(False, "UID_EXISTS")
        if any(reservation.uid == uid or reservation.operation_id == operation_id
               for reservation in self.reservations):
            return Admission(False, "RESERVATION_EXISTS")
        used_keys = self._keys_in_use()
        if any(key in used_keys for key in keys):
            return Admission(False, "KEY_CONFLICT")
        used_slots = self._slots_in_use()
        slot = next((candidate for candidate in range(2, 255) if candidate not in used_slots), None)
        if slot is None:
            return Admission(False, "SLOT_EXHAUSTED")
        if quota:
            active = sum(1 for entry in self.registry.values()
                         if entry.created_by == actor and not entry.revoked)
            if active + self._reservations_for(actor) >= user_limit:
                return Admission(False, "QUOTA_EXCEEDED")
        reservation = Reservation(uid=uid, operation_id=operation_id, slot=slot,
                                  keys=tuple(keys), quota=quota, created_by=actor)
        self.reservations.append(reservation)
        return Admission(True, slot=slot, reservation=reservation)

    def verify_resume(self, uid: str, operation_id: str) -> Admission:
        for reservation in self.reservations:
            if reservation.uid == uid and reservation.operation_id == operation_id:
                return Admission(True, slot=reservation.slot, reservation=reservation)
        return Admission(False, "RESERVATION_MISSING")

    def release(self, uid: str, operation_id: str, *, terminal: bool = False,
                no_effect_proved: bool = False) -> bool:
        if not (terminal or no_effect_proved):
            return False
        for index, reservation in enumerate(self.reservations):
            if reservation.uid == uid and reservation.operation_id == operation_id:
                del self.reservations[index]
                return True
        return False


# ---------------------------------------------------------------------------- CA

@dataclass(frozen=True)
class CAConfigWitness:
    config_sha256: str
    mapping: Mapping[str, str]
    options: Mapping[str, Any]

    def encode(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "kind": CA_CONFIG_KIND,
            "configSha256": self.config_sha256,
            "mapping": dict(self.mapping),
            "options": dict(self.options),
        }
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_INTENT, "WITNESS_TOO_LARGE")
        return encoded

    def ca_config_sha256(self) -> str:
        return _sha256_hex(self.encode())


def config_witness(ca_cnf_bytes: bytes, mapping: Mapping[str, str],
                   options: Mapping[str, Any]) -> CAConfigWitness:
    _require(type(ca_cnf_bytes) is bytes and len(ca_cnf_bytes) <= MAX_INTENT,
             "CA_CONFIG_SIZE")
    _require(set(mapping) == set(CA_MAPPING_FIELDS), "CA_MAPPING_FIELDS")
    clean_mapping: dict[str, str] = {}
    for key, value in mapping.items():
        clean_mapping[key] = _require_str(value, "CA_MAPPING_VALUE", 512)
    directory = clean_mapping["dir"].rstrip("/")
    _require(clean_mapping["database"] == directory + "/index", "CA_MAPPING_DATABASE")
    _require(clean_mapping["new_certs_dir"] == directory + "/certs", "CA_MAPPING_CERTS")
    _require(clean_mapping["serial"] == directory + "/serial", "CA_MAPPING_SERIAL")
    _require(clean_mapping["crlnumber"] == directory + "/crlnumber", "CA_MAPPING_CRL")
    _require(clean_mapping["certificate"] == directory + "/ca.crt", "CA_MAPPING_CERT")
    _require(clean_mapping["private_key"] == directory + "/ca.key", "CA_MAPPING_KEY")
    _require(set(options) == set(CA_OPTION_FIELDS), "CA_OPTION_FIELDS")
    # The accepted CA uses unique_subject=no; the witness records the boolean,
    # it does not require it to be true.
    _require_bool(options["unique_subject"], "CA_OPTION_UNIQUE")
    _require(1 <= _require_int(options["default_days"], "CA_OPTION_DAYS", 1, 3650) <= 3650,
             "CA_OPTION_DAYS")
    _require(1 <= _require_int(options["default_crl_days"], "CA_OPTION_CRL", 1, 3650) <= 3650,
             "CA_OPTION_CRL")
    _require(options["default_md"] == "sha256", "CA_OPTION_MD")
    _require(options["policy"] == "policy", "CA_OPTION_POLICY")
    return CAConfigWitness(config_sha256=_sha256_hex(ca_cnf_bytes),
                           mapping=clean_mapping, options=dict(options))


def _validate_ca_config_value(value: Any) -> None:
    fields = exact_object(value, ("schema", "kind", "configSha256", "mapping", "options"))
    _require(_require_int(fields["schema"], "CA_CONFIG_SCHEMA") == SCHEMA, "CA_CONFIG_SCHEMA")
    _require(fields["kind"] == CA_CONFIG_KIND, "CA_CONFIG_KIND")
    _require_hex(fields["configSha256"], 64, "CA_CONFIG_HASH")
    mapping = fields["mapping"]
    _require(type(mapping) is dict and set(mapping) == set(CA_MAPPING_FIELDS), "CA_MAPPING_FIELDS")
    clean_mapping: dict[str, str] = {}
    for key, item in mapping.items():
        clean_mapping[key] = _require_str(item, "CA_MAPPING_VALUE", 512)
    directory = clean_mapping["dir"].rstrip("/")
    _require(clean_mapping["database"] == directory + "/index", "CA_MAPPING_DATABASE")
    _require(clean_mapping["new_certs_dir"] == directory + "/certs", "CA_MAPPING_CERTS")
    _require(clean_mapping["serial"] == directory + "/serial", "CA_MAPPING_SERIAL")
    _require(clean_mapping["crlnumber"] == directory + "/crlnumber", "CA_MAPPING_CRL")
    _require(clean_mapping["certificate"] == directory + "/ca.crt", "CA_MAPPING_CERT")
    _require(clean_mapping["private_key"] == directory + "/ca.key", "CA_MAPPING_KEY")
    options = fields["options"]
    _require(type(options) is dict and set(options) == set(CA_OPTION_FIELDS), "CA_OPTION_FIELDS")
    _require_bool(options["unique_subject"], "CA_OPTION_UNIQUE")
    _require(1 <= _require_int(options["default_days"], "CA_OPTION_DAYS", 1, 3650) <= 3650,
             "CA_OPTION_DAYS")
    _require(1 <= _require_int(options["default_crl_days"], "CA_OPTION_CRL", 1, 3650) <= 3650,
             "CA_OPTION_CRL")
    _require(options["default_md"] == "sha256", "CA_OPTION_MD")
    _require(options["policy"] == "policy", "CA_OPTION_POLICY")


@dataclass(frozen=True)
class CAIntent:
    operation_id: str
    uid: str
    csr_sha256: str
    spki_sha256: str
    expected_cn: str
    ca_config_sha256: str
    ca_certificate_sha256: str
    pre_state: Mapping[str, Any]

    def encode(self) -> bytes:
        payload = {
            "schema": SCHEMA,
            "kind": "XIO-CA-INTENT-1",
            "operationId": self.operation_id,
            "uid": self.uid,
            "csrSha256": self.csr_sha256,
            "spkiSha256": self.spki_sha256,
            "expectedCn": self.expected_cn,
            "caConfigSha256": self.ca_config_sha256,
            "caCertificateSha256": self.ca_certificate_sha256,
            "preState": dict(self.pre_state),
        }
        encoded = _canonical_json(payload)
        _require(len(encoded) <= MAX_INTENT, "INTENT_TOO_LARGE")
        return encoded


def make_ca_intent(*, operation_id: str, uid: str, csr_sha256: str, spki_sha256: str,
                   expected_cn: str, witness: CAConfigWitness,
                   ca_certificate_sha256: str, pre_state: Mapping[str, Any]) -> CAIntent:
    _require_hex(operation_id, 32, "INTENT_OP")
    _require_hex(uid, 32, "INTENT_UID")
    _require_hex(csr_sha256, 64, "INTENT_CSR")
    _require_hex(spki_sha256, 64, "INTENT_SPKI")
    _require_hex(ca_certificate_sha256, 64, "INTENT_CA")
    _require_str(expected_cn, "INTENT_CN", 128)
    _require(type(pre_state) is dict, "INTENT_PRE")
    clean_pre = _validate_pre_state(pre_state)
    intent = CAIntent(operation_id, uid, csr_sha256, spki_sha256, expected_cn,
                      witness.ca_config_sha256(), ca_certificate_sha256, clean_pre)
    intent.encode()
    return intent


def _validate_pre_state(pre_state: Mapping[str, Any]) -> dict[str, Any]:
    fields = exact_object(pre_state,
                          ("indexSha256", "serial", "serialSha256", "crlnumber",
                           "crlnumberSha256", "certs", "staged"))
    _require_hex(fields["indexSha256"], 64, "PRE_INDEX")
    _require_int(fields["serial"], "PRE_SERIAL", 0)
    _require_hex(fields["serialSha256"], 64, "PRE_SERIAL_HASH")
    _require_int(fields["crlnumber"], "PRE_CRL", 0)
    _require_hex(fields["crlnumberSha256"], 64, "PRE_CRL_HASH")
    certs = fields["certs"]
    _require(type(certs) is dict and len(certs) <= 128, "PRE_CERTS")
    for serial, digest in certs.items():
        _require(re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", serial) is not None, "PRE_SERIAL")
        _require_hex(digest, 64, "PRE_CERT_HASH")
    staged = fields["staged"]
    _require(type(staged) is dict and len(staged) <= 128, "PRE_STAGED")
    for key, digest in staged.items():
        _require_str(key, "PRE_STAGED_KEY", 256)
        _require_hex(digest, 64, "PRE_STAGED_HASH")
    return dict(fields)


@dataclass(frozen=True)
class IndexRow:
    cn: str
    serial: str
    status: str  # V | R


@dataclass(frozen=True)
class CertificateInfo:
    cn: str
    serial: str
    spki_der: bytes
    issuer_sha256: str
    digest: str


class CAEvidenceAdapter(Protocol):
    def csr_spki_der(self, csr_pem: bytes) -> bytes:
        ...

    def certificate_info(self, cert_pem: bytes) -> CertificateInfo:
        ...


@dataclass(frozen=True)
class CAEvidence:
    index_bytes: bytes
    rows: tuple[IndexRow, ...]
    certs: Mapping[str, bytes]  # serial -> body
    staged: Mapping[str, bytes]  # stage key -> body
    serial: int
    crlnumber: int

    def __post_init__(self) -> None:
        _require(len(self.index_bytes) <= 65536, "EVIDENCE_INDEX_TOO_LARGE")
        _require(len(self.certs) <= 128, "EVIDENCE_CERTS")
        _require(len(self.staged) <= 128, "EVIDENCE_STAGED")
        aggregate = 0
        for body in list(self.certs.values()) + list(self.staged.values()):
            _require(type(body) is bytes and len(body) <= MAX_CERT, "EVIDENCE_BODY")
            aggregate += len(body)
            _require(aggregate <= 1024 * 1024, "EVIDENCE_AGGREGATE")
        _require(_require_int(self.serial, "EVIDENCE_SERIAL", 0) >= 0, "EVIDENCE_SERIAL")
        _require(_require_int(self.crlnumber, "EVIDENCE_CRL", 0) >= 0, "EVIDENCE_CRL")
        for row in self.rows:
            _require(re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", row.serial) is not None, "EVIDENCE_SERIAL")


class LeaseState(Enum):
    FREE = "free"
    HELD = "held"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CAResult:
    decision: str  # issue | adopt | adopt_seed_stage | no_effect_clear | repair | fenced | unsupported
    code: str = ""


def _require_client_issue_kind(kind: str) -> None:
    if kind in OTHER_CA_KINDS:
        _fail("UNSUPPORTED_CA_KIND")
    _require(kind in CA_OPERATION_KINDS, "UNSUPPORTED_CA_KIND")


_INDEX_LINE = re.compile(
    rb"(V|R)\t([0-9]{12}Z)\t((?:[0-9]{12}Z)?)\t([1-9a-f][0-9a-f]{0,39})\t(unknown)\t/CN=(.+)\Z"
)


def _index_lines(raw: bytes) -> list[bytes]:
    _require(isinstance(raw, bytes) and len(raw) <= 65536, "INDEX_RAW")
    if raw == b"":
        return []
    _require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw,
             "INDEX_NEWLINE")
    lines = raw.split(b"\n")[:-1]
    _require(all(lines), "INDEX_EMPTY_LINE")
    _require(all(0 < len(line) <= 1024 for line in lines), "INDEX_ROW_BOUNDS")
    return lines


def _bind_index_rows(raw: bytes, rows: Sequence[IndexRow]) -> list[bytes]:
    lines = _index_lines(raw)
    _require(len(lines) == len(rows), "INDEX_ROW_COUNT")
    for line, row in zip(lines, rows):
        parts = line.split(b"\t")
        _require(len(parts) == 6, "INDEX_ROW_CN")
        match = _INDEX_LINE.fullmatch(line)
        _require(match is not None, "INDEX_ROW_FORM")
        status, expiry, revoked, serial, file_token, subject = match.groups()
        _require(status.decode() == row.status, "INDEX_ROW_STATUS")
        _require(expiry.decode() == "300101000000Z", "INDEX_ROW_EXPIRY")
        _require((revoked == b"") == (row.status == "V"), "INDEX_ROW_REVOCATION")
        if row.status == "R":
            _require(revoked.decode() == "261106000000Z", "INDEX_ROW_REVOCATION")
        _require(serial.decode() == row.serial, "INDEX_ROW_SERIAL")
        _require(file_token == b"unknown", "INDEX_ROW_FILE")
        _require(subject != b"", "INDEX_ROW_CN")
        cn_bytes = subject
        _require(0 < len(cn_bytes) <= 256, "INDEX_ROW_CN")
        _require(all(byte >= 0x20 and byte != 0x7F for byte in cn_bytes), "INDEX_ROW_CN")
        try:
            subject_cn = cn_bytes.decode("utf-8")
        except UnicodeDecodeError:
            _fail("INDEX_ROW_CN")
        _require(not any(char in subject_cn for char in "\t\r\n\x00"), "INDEX_ROW_CN")
        _require(subject_cn == row.cn, "INDEX_ROW_CN")
    return lines


def _prefix_index_bytes(raw: bytes, rows: Sequence[IndexRow]) -> bytes:
    lines = _bind_index_rows(raw, rows)
    if not rows:
        _require(raw == b"", "INDEX_UNEXPECTED_ROWS")
        return b""
    prefix = b"\n".join(lines[:-1])
    if prefix:
        prefix += b"\n"
    return prefix


def _validate_native_evidence(evidence: CAEvidence) -> None:
    _require(isinstance(evidence, CAEvidence), "EVIDENCE_TYPE")
    _require(type(evidence.serial) is int and 0 <= evidence.serial <= MAX_SAFE_INTEGER,
             "EVIDENCE_SERIAL")
    _require(type(evidence.crlnumber) is int and 0 <= evidence.crlnumber <= MAX_SAFE_INTEGER,
             "EVIDENCE_CRL")
    if evidence.index_bytes == b"":
        _require(len(evidence.rows) == 0, "INDEX_ROW_COUNT")
    else:
        _bind_index_rows(evidence.index_bytes, evidence.rows)


def reconcile_client_issue(*, kind: str, intent: CAIntent | None, witness: CAConfigWitness,
                           evidence: CAEvidence, lease: LeaseState,
                           csr_pem: str, adapter: CAEvidenceAdapter,
                           marker_present: bool, staged_key: str,
                           intent_durable: bool,
                           barrier_complete: bool) -> CAResult:
    _require_client_issue_kind(kind)
    _require_bool(marker_present, "MARKER_TYPE")
    _require_bool(intent_durable, "INTENT_DURABLE_TYPE")
    _require_bool(barrier_complete, "BARRIER_TYPE")
    _validate_native_evidence(evidence)
    if not intent_durable:
        return CAResult("repair", "INTENT_NOT_DURABLE")
    if lease is not LeaseState.FREE:
        return CAResult("fenced", "LEASE_NOT_FREE")
    if not barrier_complete:
        return CAResult("fenced", "BARRIER_INCOMPLETE")
    if intent is None:
        # No prepared identity means target effects cannot be classified and no
        # issue may be authorized. Empty state is not a durable baseline proof.
        if marker_present or evidence.rows or evidence.certs or evidence.staged:
            return CAResult("repair", "INTENT_MISSING")
        return CAResult("repair", "INTENT_REQUIRED")
    _require(witness.ca_config_sha256() == intent.ca_config_sha256, "CA_CONFIG_MISMATCH")
    csr_bytes = csr_pem.encode("utf-8")
    _require(_sha256_hex(csr_bytes) == intent.csr_sha256, "CSR_HASH_MISMATCH")
    spki_der = adapter.csr_spki_der(csr_bytes)
    _require(len(spki_der) <= MAX_SPKI, "SPKI_SIZE")
    _require(_sha256_hex(spki_der) == intent.spki_sha256, "SPKI_HASH_MISMATCH")

    def exact_baseline() -> bool:
        current_certs = {serial: _sha256_hex(body) for serial, body in evidence.certs.items()}
        current_staged = {key: _sha256_hex(body) for key, body in evidence.staged.items()}
        return (current_certs == dict(intent.pre_state["certs"])
                and current_staged == dict(intent.pre_state["staged"])
                and evidence.crlnumber == intent.pre_state["crlnumber"])

    def target_only_delta(row: IndexRow, cert_body: bytes,
                          staged_body: bytes | None) -> bool:
        current_certs = {serial: _sha256_hex(body) for serial, body in evidence.certs.items()}
        current_staged = {key: _sha256_hex(body) for key, body in evidence.staged.items()}
        pre_certs = dict(intent.pre_state["certs"])
        pre_staged = dict(intent.pre_state["staged"])
        if row.serial in pre_certs:
            return False
        allowed_certs = dict(pre_certs)
        allowed_certs[row.serial] = _sha256_hex(cert_body)
        if current_certs != allowed_certs:
            return False
        allowed_staged = dict(pre_staged)
        if staged_body is not None:
            if staged_key in pre_staged:
                return False
            allowed_staged[staged_key] = _sha256_hex(staged_body)
        if current_staged != allowed_staged:
            return False
        return evidence.crlnumber == intent.pre_state["crlnumber"]

    rows = [] if intent is None else [row for row in evidence.rows
                                      if row.cn == intent.expected_cn]
    target_bodies = []
    target_staged_keys = []
    if intent is not None:
        for serial, body in evidence.certs.items():
            info = adapter.certificate_info(body)
            _require(info.digest == _sha256_hex(body), "CERT_DIGEST")
            if info.cn == intent.expected_cn or info.spki_der == spki_der:
                target_bodies.append(serial)
        for key, body in evidence.staged.items():
            try:
                info = adapter.certificate_info(body)
            except Exception:
                target_staged_keys.append(key)
                continue
            _require(info.digest == _sha256_hex(body), "CERT_DIGEST")
            if info.cn == intent.expected_cn or info.spki_der == spki_der \
                    or key == staged_key:
                target_staged_keys.append(key)
    if not marker_present:
        # ISSUE authorizes a new native operation only against the exact durable
        # baseline: unchanged raw index, serial, CRL, cert/staged manifests and
        # no target effects. It is not a delta branch.
        if _sha256_hex(evidence.index_bytes) != intent.pre_state["indexSha256"]:
            return CAResult("repair", "INDEX_BASELINE_CHANGED")
        if evidence.serial != intent.pre_state["serial"]:
            return CAResult("repair", "SERIAL_BASELINE_CHANGED")
        if not exact_baseline():
            return CAResult("repair", "PRE_MANIFEST_LOSS")
        if any(row.cn == intent.expected_cn for row in evidence.rows):
            return CAResult("repair", "LEGACY_TARGET_ROW")
        if target_bodies or target_staged_keys:
            return CAResult("repair", "LEGACY_NATIVE_EFFECT")
        return CAResult("issue")
    if len(rows) > 1 or len(target_bodies) > 1 or len(evidence.staged) > 1:
        return CAResult("repair", "AMBIGUOUS")
    if rows:
        row = rows[0]
        if evidence.rows[-1] is not row:
            return CAResult("repair", "INDEX_TARGET_NOT_APPENDED")
        try:
            prefix = _prefix_index_bytes(evidence.index_bytes, evidence.rows)
        except PrimitiveError:
            return CAResult("repair", "INDEX_BINDING")
        if _sha256_hex(prefix) != intent.pre_state["indexSha256"]:
            return CAResult("repair", "INDEX_PRE_ROW_CHANGED")
        _require(row.status in ("V", "R"), "EVIDENCE_SERIAL")
        if row.status != "V":
            return CAResult("repair", "CERT_STATUS")
        if row.serial not in evidence.certs:
            return CAResult("repair", "CERT_BODY_MISSING")
        if int(row.serial, 16) != intent.pre_state["serial"]:
            return CAResult("repair", "SERIAL_ISSUED_MISMATCH")
        if evidence.serial != intent.pre_state["serial"] + 1:
            return CAResult("repair", "SERIAL_DELTA_MISMATCH")
        cert_body = evidence.certs[row.serial]
        cert_info = adapter.certificate_info(cert_body)
        _require(cert_info.digest == _sha256_hex(cert_body), "CERT_DIGEST")
        if cert_info.cn != intent.expected_cn:
            return CAResult("repair", "CN_MISMATCH")
        if cert_info.spki_der != spki_der:
            return CAResult("repair", "SPKI_MISMATCH")
        if cert_info.issuer_sha256 != intent.ca_certificate_sha256:
            return CAResult("repair", "CA_MISMATCH")
        if cert_info.serial != row.serial:
            return CAResult("repair", "SERIAL_MISMATCH")
        if target_staged_keys and target_staged_keys != [staged_key]:
            return CAResult("repair", "STAGED_IDENTITY_OTHER_KEY")
        staged_body = evidence.staged.get(staged_key)
        if staged_body is not None:
            staged_info = adapter.certificate_info(staged_body)
            _require(staged_info.digest == _sha256_hex(staged_body),
                     "CERT_DIGEST")
            if staged_info.digest != cert_info.digest:
                return CAResult("repair", "STAGED_MISMATCH")
        if not target_only_delta(row, cert_body, staged_body):
            return CAResult("repair", "MANIFEST_DELTA")
        return CAResult("adopt" if staged_body is not None else "adopt_seed_stage")
    if any(row.cn == intent.expected_cn for row in evidence.rows) \
            or target_bodies or target_staged_keys:
        return CAResult("repair", "NATIVE_TARGET_EFFECT")
    current_certs = {serial: _sha256_hex(body) for serial, body in evidence.certs.items()}
    current_staged = {key: _sha256_hex(body) for key, body in evidence.staged.items()}
    if current_certs != dict(intent.pre_state["certs"]):
        return CAResult("repair", "PRE_CERTS_MISMATCH")
    if current_staged != dict(intent.pre_state["staged"]):
        return CAResult("repair", "PRE_STAGED_MISMATCH")
    if evidence.serial != intent.pre_state["serial"]:
        return CAResult("repair", "SERIAL_CHANGED")
    if evidence.crlnumber != intent.pre_state["crlnumber"]:
        return CAResult("repair", "CRLNUMBER_CHANGED")
    if _sha256_hex(evidence.index_bytes) != intent.pre_state["indexSha256"]:
        return CAResult("repair", "INDEX_CHANGED")
    return CAResult("no_effect_clear")


# -------------------------------------------------------------------- capability

def internal_capability() -> bytes:
    payload = {
        "schema": SCHEMA,
        "implementation": "c1a",
        "complete": False,
        "atomic": True,
        "mesh": False,
        "actions": {
            "capabilities": True, "put": False, "read": False, "resume": False,
            "needsMaterialReply": False, "cancel": False, "ackDelivery": False,
            "readCapsule": False,
        },
        "requires": ["A-D-journal-v2", "D-caller"],
        "limits": {
            "stdin": MAX_REQUEST_INPUT, "firstPin": MAX_FIRST_PIN,
            "progress": MAX_PROGRESS, "capsuleResponse": MAX_CAPSULE_RESPONSE,
            "record": MAX_RECORD, "intent": MAX_INTENT,
        },
    }
    encoded = _canonical_json(payload)
    _require(len(encoded) <= 4096, "CAPABILITY_TOO_LARGE")
    return encoded


@dataclass(frozen=True)
class AckResult:
    accepted: bool
    code: str
    deleted: bool = False


def ack_delivery(delivery_sha256: str) -> AckResult:
    _require_hex(delivery_sha256, 64, "DELIVERY_DIGEST")
    return AckResult(False, "ACK_TRUST_REQUIRED", False)
