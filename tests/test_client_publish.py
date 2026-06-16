"""Unit tests for the high-level helpers — publish_content() /
publish_prehashed() / publish_sealed() / publish_merkle() — asserting
canonical record shape, signer integration, sealed-envelope construction,
Merkle root binding, partial-upload handling, and input-validation
boundaries.

Round-trip parity through the structural validator is exercised because the
test decodes the submitted bytes with the wire validator.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from typing import Any, cast

import httpx
import pytest

from cardanowall._crypto.kem import x25519_public_key
from cardanowall._crypto.mlkem768x25519 import xwing_keygen
from cardanowall._crypto.sealed_poe import (
    SealedEnvelope as _SealedEnvelopeDataclass,
)
from cardanowall._crypto.sealed_poe import (
    SealedSlot as _SealedSlotDataclass,
)
from cardanowall._crypto.sealed_poe import (
    ecies_sealed_poe_unwrap,
)
from cardanowall._crypto.sig import get_public_key_ed25519, sign_ed25519
from cardanowall.client.label309_client import Label309Client
from cardanowall.client.partial_upload_error import PartialUploadError
from cardanowall.client.publish import PublishError, Signer
from cardanowall.merkle import merkle_sha2_256_root
from cardanowall.poe_standard import validate

# Opaque bearer token — forwarded verbatim, never parsed by the client.
FIXTURE_API_KEY = "opaque-bearer-fixture-token"
QUOTE_ID = "01956b41-7c00-7000-8000-000000000001"


def _client_with_handler(handler: Callable[[httpx.Request], httpx.Response]) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=FIXTURE_API_KEY,
        # Full versioned base: the served path stays /api/v1/poe/… after the
        # resource suffix joins, so the handler path matches keep working.
        base_url="http://test.example/api/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )


class _InMemorySigner:
    """Deterministic Ed25519 signer; mirrors the integrator-side wiring an
    in-memory PyNaCl user would write.
    """

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._pubkey = get_public_key_ed25519(seed)

    @property
    def signer_pubkey(self) -> bytes:
        return self._pubkey

    def sign(self, sig_structure_bytes: bytes, /) -> bytes:
        return sign_ed25519(self._seed, sig_structure_bytes)


def _make_signer() -> _InMemorySigner:
    return _InMemorySigner(seed=b"\x42" * 32)


PUBLISH_BODY: dict[str, Any] = {
    "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
    "tx_hash": None,
    "status": "submitting",
    "items_count": 1,
    "signed": True,
    "sealed": False,
    "items": [],
    "conformance_profile": "signed",
    "balance_after_usd_micros": "4500000",
}


def _uploads_response(uri: str) -> dict[str, Any]:
    return {
        "uploads": [{"idx": 0, "ok": True, "uri": uri, "sha256": "00" * 32, "bytes": 42}],
    }


# ---------------------------------------------------------------------------
# publish_content()
# ---------------------------------------------------------------------------


def test_publish_content_hash_only_happy_path() -> None:
    """publish_content() hashes content (sha2-256 default) and posts a
    signed record directly to /publish (no /uploads).
    """

    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_content(
                content="hello world",
                quote_id=QUOTE_ID,
                signer=signer,
            )
            assert out["id"] == PUBLISH_BODY["id"]
            assert out["status"] == "submitting"
            assert out["balance_after_usd_micros"] == "4500000"
            assert out["dedup_hit"] is False

        assert "/api/v1/poe/publish" in str(captured["url"])
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["quote_id"] == QUOTE_ID
        record_bytes = bytes.fromhex(body["record"])
        result = validate(record_bytes)
        assert result.ok
        record = result.record
        assert record["v"] == 1
        assert len(record["items"]) == 1
        assert len(record["sigs"]) == 1

        expected_digest = hashlib.sha256(b"hello world").digest()
        assert record["items"][0]["hashes"]["sha2-256"] == expected_digest

    asyncio.run(run())


def test_publish_content_unsigned_when_no_signer_supplied() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            await client.poe.publish_content(content="hello", quote_id=QUOTE_ID)
        body = captured["body"]
        assert isinstance(body, dict)
        record_bytes = bytes.fromhex(body["record"])
        result = validate(record_bytes)
        assert result.ok
        assert "sigs" not in result.record

    asyncio.run(run())


def test_publish_content_supports_blake2b_256() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured.update(json.loads(req.content))
            return httpx.Response(202, json=PUBLISH_BODY)

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            await client.poe.publish_content(
                content=b"\xaa\xbb\xcc",
                quote_id=QUOTE_ID,
                hash_alg="blake2b-256",
                signer=signer,
            )

        record_bytes = bytes.fromhex(cast("str", captured["record"]))
        result = validate(record_bytes)
        assert result.ok
        hashes = result.record["items"][0]["hashes"]
        assert "blake2b-256" in hashes
        assert "sha2-256" not in hashes

    asyncio.run(run())


def test_publish_content_threads_idempotency_key_into_header() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["idem"] = req.headers.get("idempotency-key")
            return httpx.Response(202, json=PUBLISH_BODY)

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            await client.poe.publish_content(
                content="x",
                quote_id=QUOTE_ID,
                signer=signer,
                idempotency_key="idem-py-7",
            )
        assert captured["idem"] == "idem-py-7"

    asyncio.run(run())


def test_publish_content_dedup_hit_true_on_200() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=PUBLISH_BODY)

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_content(content="x", quote_id=QUOTE_ID, signer=signer)
            assert out["dedup_hit"] is True

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish_sealed()
# ---------------------------------------------------------------------------


def test_publish_sealed_encrypts_uploads_publishes_with_ar_uri() -> None:
    async def run() -> None:
        recipient_secret = b"\x11" * 32
        recipient_pub = x25519_public_key(recipient_secret)
        ar_uri = "ar://" + ("C" * 43)
        seen: dict[str, Any] = {"ciphertext": None, "publish_body": None}

        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "POST" and req.url.path == "/api/v1/poe/uploads":
                body = req.content
                marker = b'name="file_0"'
                idx = body.find(marker)
                assert idx >= 0
                # Skip past `Content-Disposition` line + blank line to data.
                tail = body[idx:]
                data_start = tail.find(b"\r\n\r\n") + 4
                data_end = tail.find(b"\r\n--")
                seen["ciphertext"] = tail[data_start:data_end]
                return httpx.Response(200, json=_uploads_response(ar_uri))
            if req.method == "POST" and req.url.path == "/api/v1/poe/publish":
                seen["publish_body"] = json.loads(req.content)
                return httpx.Response(202, json=PUBLISH_BODY)
            raise AssertionError(f"unexpected request {req.method} {req.url}")

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_sealed(
                content="top-secret",
                recipients=[recipient_pub],
                quote_id=QUOTE_ID,
                signer=signer,
                kem="x25519",
            )
            assert out["id"] == PUBLISH_BODY["id"]

        # The ciphertext we captured decrypts back to the plaintext.
        assert seen["ciphertext"] is not None
        publish_body = seen["publish_body"]
        assert isinstance(publish_body, dict)
        assert publish_body["quote_id"] == QUOTE_ID
        record_bytes = bytes.fromhex(publish_body["record"])
        result = validate(record_bytes)
        assert result.ok
        item = result.record["items"][0]
        assert "enc" in item
        assert "uris" in item
        # Each URI is one absolute URI in a single text string.
        assert item["uris"] == [ar_uri]
        assert len(result.record["sigs"]) == 1

        # End-to-end decrypt.
        enc = item["enc"]
        envelope = _SealedEnvelopeDataclass(
            scheme=enc["scheme"],
            aead=enc["aead"],
            kem=enc["kem"],
            nonce=enc["nonce"],
            slots=tuple(_SealedSlotDataclass(epk=s["epk"], wrap=s["wrap"]) for s in enc["slots"]),
            slots_mac=enc["slots_mac"],
        )
        unwrap = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=cast("bytes", seen["ciphertext"]),
            hashes=dict(item["hashes"].items()),
            recipient_secret_key=recipient_secret,
        )
        assert unwrap.matched
        assert unwrap.plaintext == b"top-secret"

    asyncio.run(run())


def test_publish_sealed_rejects_empty_recipients() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_sealed(content="x", recipients=[], quote_id=QUOTE_ID)
            assert exc.value.code == "INVALID_RECIPIENT"

    asyncio.run(run())


def test_publish_sealed_rejects_wrong_length_recipient() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_sealed(
                    content="x", recipients=[b"\x00" * 31], quote_id=QUOTE_ID
                )
            assert exc.value.code == "INVALID_RECIPIENT"

    asyncio.run(run())


def test_publish_sealed_raises_partial_upload_error_on_failed_upload() -> None:
    """publish_sealed escalates a per-file /uploads failure into
    PartialUploadError and never reaches /publish.
    """

    async def run() -> None:
        recipient_pub = x25519_public_key(b"\x22" * 32)
        call_count = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            if req.url.path == "/api/v1/poe/uploads":
                return httpx.Response(
                    200,
                    json={
                        "uploads": [
                            {
                                "idx": 0,
                                "ok": False,
                                "error": {
                                    "code": "upload-failed",
                                    "detail": "arweave timeout",
                                },
                            }
                        ],
                    },
                )
            raise AssertionError(f"/publish must not be called; got {req.url.path}")

        async with _client_with_handler(handler) as client:
            with pytest.raises(PartialUploadError) as exc:
                await client.poe.publish_sealed(
                    content="x",
                    recipients=[recipient_pub],
                    quote_id=QUOTE_ID,
                    kem="x25519",
                )
            assert exc.value.failed_indices == (0,)
        assert call_count["n"] == 1

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish_merkle()
# ---------------------------------------------------------------------------


def test_publish_merkle_binds_root_and_leaf_count() -> None:
    async def run() -> None:
        leaves = [hashlib.sha256(bytes([i])).digest() for i in range(4)]
        expected_root = merkle_sha2_256_root(leaves)
        ar_uri = "ar://" + ("X" * 43)
        seen: dict[str, Any] = {"publish_body": None}

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/api/v1/poe/uploads":
                return httpx.Response(200, json=_uploads_response(ar_uri))
            if req.url.path == "/api/v1/poe/publish":
                seen["publish_body"] = json.loads(req.content)
                return httpx.Response(202, json=PUBLISH_BODY)
            raise AssertionError(f"unexpected {req.url.path}")

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_merkle(
                leaves=list(leaves), quote_id=QUOTE_ID, signer=signer
            )

        assert out["leaf_count"] == 4
        assert out["root"] == expected_root.hex()
        assert out["ar_uri"] == ar_uri
        assert out["balance_after_usd_micros"] == "4500000"

        submit_body = seen["publish_body"]
        assert isinstance(submit_body, dict)
        assert submit_body["quote_id"] == QUOTE_ID
        record_bytes = bytes.fromhex(submit_body["record"])
        result = validate(record_bytes)
        assert result.ok
        merkle = result.record["merkle"]
        assert len(merkle) == 1
        assert merkle[0]["leaf_count"] == 4
        assert merkle[0]["root"] == expected_root
        assert len(result.record["sigs"]) == 1

    asyncio.run(run())


def test_publish_merkle_rejects_empty_leaves() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_merkle(leaves=[], quote_id=QUOTE_ID, signer=signer)
            assert exc.value.code == "INVALID_LEAVES"

    asyncio.run(run())


def test_publish_merkle_raises_partial_upload_error() -> None:
    async def run() -> None:
        leaves: list[bytes | str] = [hashlib.sha256(b"\x00").digest()]
        call_count = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            if req.url.path == "/api/v1/poe/uploads":
                return httpx.Response(
                    200,
                    json={
                        "uploads": [
                            {
                                "idx": 0,
                                "ok": False,
                                "error": {
                                    "code": "upload-failed",
                                    "detail": "arweave timeout",
                                },
                            }
                        ],
                    },
                )
            raise AssertionError(f"/publish must not be called; got {req.url.path}")

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            with pytest.raises(PartialUploadError):
                await client.poe.publish_merkle(leaves=leaves, quote_id=QUOTE_ID, signer=signer)
        assert call_count["n"] == 1

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Signer rejection paths
# ---------------------------------------------------------------------------


def test_publish_content_rejects_short_pubkey_signer() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        class _BadSigner:
            @property
            def signer_pubkey(self) -> bytes:
                return b"\x00" * 31

            def sign(self, sig_structure_bytes: bytes, /) -> bytes:
                return b"\x00" * 64

        bad: Signer = _BadSigner()
        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_content(content="x", quote_id=QUOTE_ID, signer=bad)
            assert exc.value.code == "INVALID_SIGNER_PUBKEY"

    asyncio.run(run())


def test_publish_content_rejects_short_signature_from_signer() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        real_pubkey = get_public_key_ed25519(b"\x11" * 32)

        class _ShortSigSigner:
            def __init__(self, pub: bytes) -> None:
                self._pub = pub

            @property
            def signer_pubkey(self) -> bytes:
                return self._pub

            def sign(self, sig_structure_bytes: bytes, /) -> bytes:
                return b"\x00" * 63

        bad: Signer = _ShortSigSigner(real_pubkey)
        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_content(content="x", quote_id=QUOTE_ID, signer=bad)
            assert exc.value.code == "INVALID_SIGNER_SIGNATURE"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish_prehashed()
# ---------------------------------------------------------------------------


def test_publish_prehashed_happy_path() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        supplied_digest = hashlib.sha256(b"hello world").digest()
        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_prehashed(
                hashes={"sha2-256": supplied_digest.hex()},
                quote_id=QUOTE_ID,
                signer=signer,
            )
            assert out["id"] == PUBLISH_BODY["id"]

        assert "/api/v1/poe/publish" in str(captured["url"])
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["quote_id"] == QUOTE_ID
        record_bytes = bytes.fromhex(body["record"])
        result = validate(record_bytes)
        assert result.ok
        assert result.record["items"][0]["hashes"]["sha2-256"] == supplied_digest

    asyncio.run(run())


def test_publish_prehashed_multiple_algs_land_in_same_item() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured.update(json.loads(req.content))
            return httpx.Response(202, json=PUBLISH_BODY)

        sha = hashlib.sha256(b"x").digest()
        b2b = hashlib.blake2b(b"x", digest_size=32).digest()
        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            await client.poe.publish_prehashed(
                hashes={"sha2-256": sha.hex(), "blake2b-256": b2b.hex()},
                quote_id=QUOTE_ID,
                signer=signer,
            )
        record_bytes = bytes.fromhex(cast("str", captured["record"]))
        result = validate(record_bytes)
        assert result.ok
        hashes = result.record["items"][0]["hashes"]
        assert hashes["sha2-256"] == sha
        assert hashes["blake2b-256"] == b2b

    asyncio.run(run())


def test_publish_prehashed_rejects_empty_hashes() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_prehashed(hashes={}, quote_id=QUOTE_ID, signer=signer)
            assert exc.value.code == "INVALID_DIGEST"

    asyncio.run(run())


def test_publish_prehashed_rejects_wrong_length_digest() -> None:
    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        short_hex = "aa" * 31
        signer = _make_signer()
        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_prehashed(
                    hashes={"sha2-256": short_hex},
                    quote_id=QUOTE_ID,
                    signer=signer,
                )
            assert exc.value.code == "INVALID_DIGEST"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish_sealed() — X-Wing hybrid KEM (the post-quantum-safe DEFAULT)
# ---------------------------------------------------------------------------


def test_publish_sealed_defaults_to_hybrid_kem_and_round_trips() -> None:
    """The default (no `kem` arg) MUST build an mlkem768x25519 hybrid envelope:
    per-slot `{ kem_ct, wrap }` (no `epk`), envelope.kem == 'mlkem768x25519',
    structurally valid, and decryptable by the recipient's X-Wing secret seed.
    This is the parity twin of the TS publishSealed default.
    """

    async def run() -> None:
        recipient_pub, recipient_seed = xwing_keygen(b"\x11" * 32)
        assert len(recipient_pub) == 1216
        ar_uri = "ar://" + ("C" * 43)
        seen: dict[str, Any] = {"ciphertext": None, "publish_body": None}

        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "POST" and req.url.path == "/api/v1/poe/uploads":
                body = req.content
                marker = b'name="file_0"'
                idx = body.find(marker)
                assert idx >= 0
                tail = body[idx:]
                data_start = tail.find(b"\r\n\r\n") + 4
                data_end = tail.find(b"\r\n--")
                seen["ciphertext"] = tail[data_start:data_end]
                return httpx.Response(200, json=_uploads_response(ar_uri))
            if req.method == "POST" and req.url.path == "/api/v1/poe/publish":
                seen["publish_body"] = json.loads(req.content)
                return httpx.Response(202, json=PUBLISH_BODY)
            raise AssertionError(f"unexpected request {req.method} {req.url}")

        async with _client_with_handler(handler) as client:
            # No kem= → must default to the hybrid.
            out = await client.poe.publish_sealed(
                content="top-secret-pq",
                recipients=[recipient_pub],
                quote_id=QUOTE_ID,
            )
            assert out["id"] == PUBLISH_BODY["id"]

        assert seen["ciphertext"] is not None
        record_bytes = bytes.fromhex(seen["publish_body"]["record"])
        result = validate(record_bytes)
        assert result.ok

        item = result.record["items"][0]
        enc = item["enc"]
        # The PQC-default correctness assertion: hybrid envelope + hybrid slots.
        assert enc["kem"] == "mlkem768x25519"
        for slot in enc["slots"]:
            assert "epk" not in slot
            # kem_ct is the SINGLE 1120-byte X-Wing encapsulation.
            assert isinstance(slot["kem_ct"], bytes)
            assert len(slot["kem_ct"]) == 1120

        # End-to-end decrypt with the recipient's X-Wing secret seed.
        envelope = _SealedEnvelopeDataclass(
            scheme=enc["scheme"],
            aead=enc["aead"],
            kem=enc["kem"],
            nonce=enc["nonce"],
            slots=tuple(
                _SealedSlotDataclass(kem_ct=s["kem_ct"], wrap=s["wrap"]) for s in enc["slots"]
            ),
            slots_mac=enc["slots_mac"],
        )
        unwrap = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=cast("bytes", seen["ciphertext"]),
            hashes=dict(item["hashes"].items()),
            recipient_secret_key=recipient_seed,
        )
        assert unwrap.matched
        assert unwrap.plaintext == b"top-secret-pq"

    asyncio.run(run())


def test_publish_sealed_hybrid_rejects_x25519_length_recipient() -> None:
    """Under the default hybrid KEM a 32-byte X25519 key is the wrong length
    and is rejected before any network call."""

    async def run() -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be touched on input rejection")

        async with _client_with_handler(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_sealed(
                    content="x",
                    recipients=[x25519_public_key(b"\x11" * 32)],  # 32 B, wrong for hybrid
                    quote_id=QUOTE_ID,
                )
            assert exc.value.code == "INVALID_RECIPIENT"

    asyncio.run(run())


def test_publish_sealed_classical_kem_opt_out_emits_epk_slots() -> None:
    """kem='x25519' is the explicit classical opt-out: 32-byte recipients,
    per-slot `{ epk, wrap }`, envelope.kem == 'x25519'."""

    async def run() -> None:
        recipient_secret = b"\x33" * 32
        recipient_pub = x25519_public_key(recipient_secret)
        ar_uri = "ar://" + ("D" * 43)
        seen: dict[str, Any] = {"ciphertext": None, "publish_body": None}

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/api/v1/poe/uploads":
                body = req.content
                idx = body.find(b'name="file_0"')
                tail = body[idx:]
                data_start = tail.find(b"\r\n\r\n") + 4
                data_end = tail.find(b"\r\n--")
                seen["ciphertext"] = tail[data_start:data_end]
                return httpx.Response(200, json=_uploads_response(ar_uri))
            if req.url.path == "/api/v1/poe/publish":
                seen["publish_body"] = json.loads(req.content)
                return httpx.Response(202, json=PUBLISH_BODY)
            raise AssertionError(f"unexpected request {req.url}")

        async with _client_with_handler(handler) as client:
            await client.poe.publish_sealed(
                content="classical",
                recipients=[recipient_pub],
                quote_id=QUOTE_ID,
                kem="x25519",
            )

        result = validate(bytes.fromhex(seen["publish_body"]["record"]))
        assert result.ok
        enc = result.record["items"][0]["enc"]
        assert enc["kem"] == "x25519"
        for slot in enc["slots"]:
            assert "epk" in slot
            assert "kem_ct" not in slot

        envelope = _SealedEnvelopeDataclass(
            scheme=enc["scheme"],
            aead=enc["aead"],
            kem=enc["kem"],
            nonce=enc["nonce"],
            slots=tuple(_SealedSlotDataclass(epk=s["epk"], wrap=s["wrap"]) for s in enc["slots"]),
            slots_mac=enc["slots_mac"],
        )
        unwrap = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=cast("bytes", seen["ciphertext"]),
            hashes=dict(result.record["items"][0]["hashes"].items()),
            recipient_secret_key=recipient_secret,
        )
        assert unwrap.matched
        assert unwrap.plaintext == b"classical"

    asyncio.run(run())
