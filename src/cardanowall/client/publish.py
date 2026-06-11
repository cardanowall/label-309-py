"""High-level publish helpers — collapse the new uploads + publish flow into
single calls for the three common shapes:

1. :py:meth:`PoeNamespace.publish_content` — anchor a single content blob by
   its ``sha2-256`` (or ``blake2b-256``) digest. No Arweave, no /uploads —
   the record is constructed entirely client-side and posted directly to
   /publish.

2. :py:meth:`PoeNamespace.publish_sealed` — encrypt the content to the
   recipient X25519 public keys (age-style sealed envelope), upload the
   ciphertext to Arweave via /uploads, build a Label 309 record with the
   resulting ``ar://`` URI, sign, and post to /publish.

3. :py:meth:`PoeNamespace.publish_merkle` — anchor an arbitrary number of
   leaf hashes under a single RFC 9162 §2.1.1 root, with the leaves-list
   CBOR uploaded to Arweave via /uploads. The Merkle root + leaf_count are
   bound into the on-chain record via ``merkle[0]``.

Signer architecture: the SDK does NOT hold identity keys (privacy contract
in ``off_host_sign.py``). The helpers take an optional :class:`Signer` that
owns the Ed25519 private key (in-memory PyNaCl, AWS KMS, GCP HSM, ...). The
SDK never sees the private key — it builds the canonical-CBOR
``Sig_structure`` and hands the bytes to the signer.

Parity twin: the publish helpers in ``@cardanowall/sdk-ts``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, TypedDict, cast, runtime_checkable

import httpx

from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall._crypto.merkle_leaves_list import encode_leaves_list
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall._crypto.sealed_poe import (
    SealedEnvelope as _SealedEnvelopeDataclass,
)
from cardanowall._crypto.sealed_poe import (
    ecies_sealed_poe_wrap,
)
from cardanowall.poe_standard import (
    EncryptionEnvelope,
    MerkleCommit,
    PoeRecord,
    encode_poe_record,
)

from .off_host_sign import assemble_cose_sign1, prepare_sig_structure
from .parse_http_error import parse_http_error
from .partial_upload_error import PartialUploadError
from .types import (
    PoeStatus,
    PublishResponse,
    UploadsResponse,
)

_ED25519_PUBLIC_KEY_LENGTH = 32
_ED25519_SIGNATURE_LENGTH = 64
_X25519_PUBLIC_KEY_LENGTH = 32
# X-Wing hybrid (ML-KEM-768 + X25519) recipient public key length. Mirrors the
# TS MLKEM768X25519_PUBLIC_KEY_LENGTH constant; the per-recipient guard below is
# KEM-aware and validates against this for the hybrid path.
_MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216
_LEAF_DIGEST_LENGTH = 32
_STORAGE_TARGET_ARWEAVE: Literal["arweave"] = "arweave"

SupportedHashAlg = Literal["sha2-256", "blake2b-256"]

# KEM selector for sealed-PoE. Defaults to the post-quantum-safe X-Wing hybrid;
# 'x25519' is the explicit classical opt-out. Mirrors the TS PublishSealedInput.kem.
SupportedKem = Literal["x25519", "mlkem768x25519"]


SignerCallback = Callable[[bytes], Awaitable[bytes]] | Callable[[bytes], bytes]


@runtime_checkable
class Signer(Protocol):
    """Pluggable Ed25519 signer for the high-level publish helpers.

    ``signer_pubkey`` MUST be the 32-byte raw Ed25519 public key.

    ``sign(sig_structure_bytes)`` receives the canonical-CBOR
    ``[ "Signature1", protected_bytes, h'' (empty external_aad), to_sign ]``
    bytes and MUST return a 64-byte raw Ed25519 signature (NOT a DER-encoded
    one). May be a coroutine; the helpers ``await`` if needed. Byte-identical
    to the input accepted by AWS KMS ``Sign`` for Ed25519 keys.
    """

    @property
    def signer_pubkey(self) -> bytes: ...

    def sign(self, sig_structure_bytes: bytes, /) -> bytes | Awaitable[bytes]: ...


class PublishError(Exception):
    """Raised when the publish helpers receive malformed input.

    ``code`` discriminator values:

    - ``"INVALID_SIGNER_PUBKEY"`` — ``signer.signer_pubkey`` is not 32 bytes.
    - ``"INVALID_SIGNER_SIGNATURE"`` — ``signer.sign()`` returned wrong-length bytes.
    - ``"INVALID_LEAVES"`` — leaves array is empty or wrong-shaped.
    - ``"INVALID_DIGEST"`` — supplied hex digest is wrong length / non-hex.
    - ``"INVALID_RECIPIENT"`` — recipient public key is wrong length.
    - ``"UNSUPPORTED_HASH_ALG"`` — hash algorithm not registered.
    """

    INVALID_SIGNER_PUBKEY = "INVALID_SIGNER_PUBKEY"
    INVALID_SIGNER_SIGNATURE = "INVALID_SIGNER_SIGNATURE"
    INVALID_LEAVES = "INVALID_LEAVES"
    INVALID_DIGEST = "INVALID_DIGEST"
    INVALID_RECIPIENT = "INVALID_RECIPIENT"
    UNSUPPORTED_HASH_ALG = "UNSUPPORTED_HASH_ALG"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


@dataclass(frozen=True)
class _ResolvedPublishConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


class PublishContentInput(TypedDict, total=False):
    content: bytes | str  # required
    quote_id: str  # required — UUID from POST /api/v1/poe/quote
    hash_alg: SupportedHashAlg
    signer: Signer
    idempotency_key: str


class PublishPrehashedInput(TypedDict, total=False):
    """Caller-supplied digest map for :py:meth:`PoeNamespace.publish_prehashed`.

    ``hashes`` is keyed by Label 309 algorithm id (``sha2-256``, ``blake2b-256``).
    At least one entry is required; values are hex-encoded digests of the
    expected byte length (32 bytes / 64 hex chars for both registered v1
    algorithms).
    """

    hashes: dict[SupportedHashAlg, str]  # required
    quote_id: str  # required — UUID from POST /api/v1/poe/quote
    signer: Signer
    idempotency_key: str


class PublishSealedInput(TypedDict, total=False):
    content: bytes | str  # required
    # Recipient public keys. Length is KEM-dependent: 32 bytes for kem='x25519',
    # 1216 bytes for kem='mlkem768x25519' (X-Wing hybrid).
    recipients: Sequence[bytes]  # required
    quote_id: str  # required — UUID from POST /api/v1/poe/quote
    hash_alg: SupportedHashAlg
    # KEM the sealed envelope is built under. Defaults to 'mlkem768x25519'
    # (post-quantum-safe X-Wing hybrid). Every recipient MUST be addressed under
    # this single KEM; mixing is not permitted.
    kem: SupportedKem
    signer: Signer
    idempotency_key: str


class PublishMerkleInput(TypedDict, total=False):
    leaves: list[bytes | str]  # required
    quote_id: str  # required — UUID from POST /api/v1/poe/quote
    hash_alg: Literal["sha2-256"]
    signer: Signer
    idempotency_key: str


class PublishMerkleResponse(TypedDict):
    id: str
    tx_hash: str | None
    status: PoeStatus
    root: str
    leaf_count: int
    ar_uri: str
    # Account balance after the debit, USD micro-cents (decimal string).
    balance_after_usd_micros: str


def _to_bytes(content: bytes | str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    return content


def _hex_to_bytes(hex_str: str) -> bytes:
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise PublishError(PublishError.INVALID_DIGEST, f"invalid hex: {e}") from e


def _hash_content(content: bytes, alg: SupportedHashAlg) -> bytes:
    if alg == "sha2-256":
        return sha256(content)
    if alg == "blake2b-256":
        return blake2b_256(content)
    raise PublishError(
        PublishError.UNSUPPORTED_HASH_ALG,
        f"hash_alg must be 'sha2-256' or 'blake2b-256', got {alg!r}",
    )


def _assert_signer(signer: Signer) -> bytes:
    if (
        not isinstance(signer.signer_pubkey, (bytes, bytearray))
        or len(signer.signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH
    ):
        raise PublishError(
            PublishError.INVALID_SIGNER_PUBKEY,
            f"signer.signer_pubkey must be {_ED25519_PUBLIC_KEY_LENGTH} bytes",
        )
    if not callable(signer.sign):
        raise PublishError(
            PublishError.INVALID_SIGNER_PUBKEY,
            "signer.sign must be callable",
        )
    return bytes(signer.signer_pubkey)


async def _invoke_signer(signer: Signer, sig_structure_bytes: bytes) -> bytes:
    result = signer.sign(sig_structure_bytes)
    # Accept both sync and async signers — KMS clients are typically async,
    # in-memory ones are sync.
    if hasattr(result, "__await__"):
        sig = await result
    else:
        sig = result
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != _ED25519_SIGNATURE_LENGTH:
        length_repr = str(len(sig)) if isinstance(sig, (bytes, bytearray)) else "unknown"
        raise PublishError(
            PublishError.INVALID_SIGNER_SIGNATURE,
            f"signer.sign() must return {_ED25519_SIGNATURE_LENGTH} bytes; got "
            f"{type(sig).__name__} of length {length_repr}",
        )
    return bytes(sig)


def _build_json_headers(api_key: str | None, idempotency_key: str | None = None) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    return headers


def _build_multipart_headers(
    api_key: str | None, idempotency_key: str | None = None
) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    return headers


def _parse_retry_after(header: str | None) -> int | None:
    if header is None:
        return None
    try:
        parsed = int(header)
    except ValueError:
        return None
    return parsed


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    request_id = response.headers.get("x-request-id")
    retry_after_seconds = _parse_retry_after(response.headers.get("retry-after"))
    raise parse_http_error(
        http_status=response.status_code,
        body=body,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


async def _sign_record(record: PoeRecord, signer: Signer) -> PoeRecord:
    """Sign a record path-1 (in-memory Ed25519 / KMS / HSM) and return a new
    record with the COSE_Sign1 entry embedded in ``sigs[]``.
    """
    signer_pubkey = _assert_signer(signer)
    sig_structure_bytes, _protected_header_bytes = prepare_sig_structure(
        record=record,
        signer_pubkey=signer_pubkey,
    )
    signature = await _invoke_signer(signer, sig_structure_bytes)
    _cose_sign1_bytes, sig_entry = assemble_cose_sign1(
        record=record,
        signer_pubkey=signer_pubkey,
        signature=signature,
    )
    return {**record, "sigs": [sig_entry]}


async def _encode_record(record: PoeRecord, signer: Signer | None) -> bytes:
    if signer is None:
        return encode_poe_record(record)
    signed = await _sign_record(record, signer)
    return encode_poe_record(signed)


async def _post_publish(
    config: _ResolvedPublishConfig,
    record_bytes_hex: str,
    quote_id: str,
    idempotency_key: str | None,
) -> PublishResponse:
    body = {"record": record_bytes_hex, "quote_id": quote_id}
    response = await config.http_client.post(
        f"{config.base_url}/api/v1/poe/publish",
        content=json.dumps(body, separators=(",", ":")),
        headers=_build_json_headers(config.api_key, idempotency_key),
    )
    _raise_for_status(response)
    parsed: dict[str, object] = response.json()
    parsed["dedup_hit"] = response.status_code == 200
    return cast("PublishResponse", parsed)


async def _post_uploads(
    config: _ResolvedPublishConfig,
    blobs: Sequence[bytes],
    idempotency_key: str | None,
) -> UploadsResponse:
    files: list[tuple[str, tuple[str, bytes, str]]] = []
    for idx, payload in enumerate(blobs):
        files.append(
            (
                f"file_{idx}",
                (f"file_{idx}.bin", payload, "application/octet-stream"),
            )
        )
    response = await config.http_client.post(
        f"{config.base_url}/api/v1/poe/uploads",
        data={"target": _STORAGE_TARGET_ARWEAVE},
        files=files,
        headers=_build_multipart_headers(config.api_key, idempotency_key),
    )
    _raise_for_status(response)
    result: UploadsResponse = response.json()
    if any(u["ok"] is False for u in result["uploads"]):
        raise PartialUploadError(result)
    return result


async def publish_content(
    config: _ResolvedPublishConfig,
    *,
    content: bytes | str,
    quote_id: str,
    signer: Signer | None = None,
    hash_alg: SupportedHashAlg = "sha2-256",
    idempotency_key: str | None = None,
) -> PublishResponse:
    """Hash-only PoE — anchor a single content blob's digest, optionally with
    one path-1 signature. No Arweave, no /uploads.
    """
    if signer is not None:
        _assert_signer(signer)
    content_bytes = _to_bytes(content)
    digest = _hash_content(content_bytes, hash_alg)

    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {hash_alg: digest}}],
    }
    record_bytes = await _encode_record(record, signer)
    return await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)


# Both registered hash algorithms produce 32-byte digests. Kept as a per-alg
# map for forward-compat when wider hash registries land.
_DIGEST_BYTE_LENGTH: dict[SupportedHashAlg, int] = {
    "sha2-256": 32,
    "blake2b-256": 32,
}


async def publish_prehashed(
    config: _ResolvedPublishConfig,
    *,
    hashes: dict[SupportedHashAlg, str],
    quote_id: str,
    signer: Signer | None = None,
    idempotency_key: str | None = None,
) -> PublishResponse:
    """Hash-already-computed PoE — anchor a precomputed content digest
    (hex-encoded), optionally signed.
    """
    if signer is not None:
        _assert_signer(signer)
    present = [(alg, hex_digest) for alg, hex_digest in hashes.items() if hex_digest]
    if not present:
        raise PublishError(
            PublishError.INVALID_DIGEST,
            "publish_prehashed requires at least one digest in `hashes`",
        )
    decoded: dict[SupportedHashAlg, bytes] = {}
    for alg, hex_digest in present:
        if alg not in _DIGEST_BYTE_LENGTH:
            raise PublishError(
                PublishError.UNSUPPORTED_HASH_ALG,
                f"unsupported hash algorithm '{alg}' (expected 'sha2-256' or 'blake2b-256')",
            )
        digest_bytes = _hex_to_bytes(hex_digest)
        expected = _DIGEST_BYTE_LENGTH[alg]
        if len(digest_bytes) != expected:
            raise PublishError(
                PublishError.INVALID_DIGEST,
                f"hashes[{alg}] must be a {expected}-byte digest (got {len(digest_bytes)} bytes)",
            )
        decoded[alg] = digest_bytes

    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": decoded}],
    }
    record_bytes = await _encode_record(record, signer)
    return await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)


async def publish_sealed(
    config: _ResolvedPublishConfig,
    *,
    content: bytes | str,
    recipients: Sequence[bytes],
    quote_id: str,
    signer: Signer | None = None,
    hash_alg: SupportedHashAlg = "sha2-256",
    kem: SupportedKem = "mlkem768x25519",
    idempotency_key: str | None = None,
) -> PublishResponse:
    """Sealed-PoE: encrypt content to N X25519 recipients (age-style
    envelope), upload the ciphertext to Arweave, build a single-item record
    with the resulting ``ar://`` URI and the sealed envelope in
    ``items[0].enc``, sign (optional), and post to /publish.

    The plaintext content-hash is bound into ``items[0].hashes`` so any
    verifier that successfully decrypts the ciphertext can reconstruct the
    plaintext and prove the chain of custody from the on-chain hash to the
    decrypted bytes.
    """
    if signer is not None:
        _assert_signer(signer)
    if len(recipients) < 1:
        raise PublishError(
            PublishError.INVALID_RECIPIENT,
            "publish_sealed requires at least one recipient X25519 public key",
        )
    # KEM-aware recipient-length guard: 32 B for the classical x25519 path,
    # 1216 B for the X-Wing hybrid. Mirrors the TS publishSealed guard.
    expected_recipient_length = (
        _X25519_PUBLIC_KEY_LENGTH if kem == "x25519" else _MLKEM768X25519_PUBLIC_KEY_LENGTH
    )
    for i, pub in enumerate(recipients):
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != expected_recipient_length:
            raise PublishError(
                PublishError.INVALID_RECIPIENT,
                f"recipients[{i}] must be a {expected_recipient_length}-byte "
                f"public key for kem='{kem}'",
            )

    plaintext = _to_bytes(content)
    plaintext_digest = _hash_content(plaintext, hash_alg)

    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[bytes(p) for p in recipients],
        hashes={hash_alg: plaintext_digest},
        kem=kem,
    )

    uploads_resp = await _post_uploads(config, [sealed.ciphertext], idempotency_key)
    first = uploads_resp["uploads"][0]
    # narrowed: _post_uploads raised on any failure, so every entry has ok=True
    uri = cast("str", first.get("uri"))

    envelope_data = sealed.envelope
    envelope: EncryptionEnvelope = _envelope_to_wire(envelope_data)

    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {hash_alg: plaintext_digest},
                "uris": [uri],
                "enc": envelope,
            },
        ],
    }
    record_bytes = await _encode_record(record, signer)
    return await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)


def _envelope_to_wire(envelope: _SealedEnvelopeDataclass) -> EncryptionEnvelope:
    """Convert the dataclass-shaped wrap output to the TypedDict the encoder
    expects. Field names are wire-identical; only the runtime container shape
    differs.
    """
    # The TypedDict declares scheme/aead/kem as narrow Literal types matching
    # the dataclass's runtime values; cast pins the narrower type at the
    # boundary so downstream encoders typecheck.
    # Per-slot wire shape is KEM-driven (the dataclass carries epk XOR kem_ct):
    #   - x25519:         { epk: bstr(32), wrap: bstr(48) }
    #   - mlkem768x25519: { kem_ct: bstr(1120), wrap: bstr(48) } — the X-Wing
    #     ciphertext as a single byte string, NO per-slot epk.
    slots: list[dict[str, object]]
    if envelope.kem == "mlkem768x25519":
        slots = [{"kem_ct": s.kem_ct or b"", "wrap": s.wrap} for s in envelope.slots]
    else:
        slots = [{"epk": s.epk, "wrap": s.wrap} for s in envelope.slots]
    return cast(
        "EncryptionEnvelope",
        {
            "scheme": envelope.scheme,
            "aead": envelope.aead,
            "kem": envelope.kem,
            "nonce": envelope.nonce,
            "slots": slots,
            "slots_mac": envelope.slots_mac,
        },
    )


async def publish_merkle(
    config: _ResolvedPublishConfig,
    *,
    leaves: list[bytes | str],
    quote_id: str,
    signer: Signer | None = None,
    hash_alg: Literal["sha2-256"] = "sha2-256",
    idempotency_key: str | None = None,
) -> PublishMerkleResponse:
    """Batch publish via a Merkle root — N leaves under one transaction.
    The leaves-list CBOR is uploaded to Arweave; the on-chain record carries
    ``merkle[0] = {alg: 'rfc9162-sha256', root, leaf_count, uris: [ar://<tx>]}``.

    Only ``'sha2-256'`` leaves are supported because ``rfc9162-sha256`` is
    the only registered tree algorithm and its underlying hash is SHA-256
    (32-byte leaves).
    """
    if signer is not None:
        _assert_signer(signer)
    if hash_alg != "sha2-256":
        raise PublishError(
            PublishError.UNSUPPORTED_HASH_ALG,
            f"publish_merkle only supports 'sha2-256' leaves; got {hash_alg!r}",
        )
    if len(leaves) < 1:
        raise PublishError(
            PublishError.INVALID_LEAVES,
            "publish_merkle requires at least one leaf hash",
        )

    leaves_bytes: list[bytes] = []
    for idx, leaf in enumerate(leaves):
        b = _hex_to_bytes(leaf) if isinstance(leaf, str) else bytes(leaf)
        if len(b) != _LEAF_DIGEST_LENGTH:
            raise PublishError(
                PublishError.INVALID_LEAVES,
                f"leaves[{idx}] must be a {_LEAF_DIGEST_LENGTH}-byte sha2-256 digest",
            )
        leaves_bytes.append(b)

    root = merkle_sha2_256_root(leaves_bytes)
    leaves_list_cbor = encode_leaves_list(leaves=leaves_bytes, root=root)

    uploads_resp = await _post_uploads(config, [leaves_list_cbor], idempotency_key)
    first = uploads_resp["uploads"][0]
    uri = cast("str", first.get("uri"))

    # MERKLE_ALG_ID is the only registered tree algorithm string.
    merkle_entry: MerkleCommit = {
        "alg": "rfc9162-sha256",
        "root": root,
        "leaf_count": len(leaves_bytes),
        "uris": [uri],
    }
    record: PoeRecord = {"v": 1, "merkle": [merkle_entry]}
    record_bytes = await _encode_record(record, signer)
    published = await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)

    return {
        "id": published["id"],
        "tx_hash": published["tx_hash"],
        "status": published["status"],
        "root": root.hex(),
        "leaf_count": len(leaves_bytes),
        "ar_uri": uri,
        "balance_after_usd_micros": published["balance_after_usd_micros"],
    }


__all__ = [
    "PublishContentInput",
    "PublishError",
    "PublishMerkleInput",
    "PublishMerkleResponse",
    "PublishPrehashedInput",
    "PublishResponse",
    "PublishSealedInput",
    "Signer",
    "SignerCallback",
    "SupportedHashAlg",
    "SupportedKem",
    "publish_content",
    "publish_merkle",
    "publish_prehashed",
    "publish_sealed",
]
