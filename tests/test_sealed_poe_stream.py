"""Byte-parity tests for the streaming sealed-PoE seal / unwrap.

The streaming API MUST be byte-identical to the buffered ``ecies_sealed_poe_wrap``
/ ``stream_seal`` path — the same pinned cross-SDK fixtures
(``wrap-*`` / ``stream-layout``) validate it, with ZERO new crypto vectors. The
load-bearing proof (per the EOF-lookahead contract) feeds the streaming seal its
plaintext in odd-sized producer chunks (whose boundaries are NOT STREAM chunk
boundaries) and asserts the concatenated output equals the pinned
``expected_ciphertext_hex``, across the empty / 1-byte / exact-64-KiB /
exact-2x-64-KiB / just-over-64-KiB sizes; the streaming unwrap is fed the pinned
ciphertext in odd chunks and asserts the streamed plaintext and the outcome.
The passphrase streaming pair is validated the same way, against the pinned
``passphrase-n1`` vector and its own buffered twin.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.sealed_poe import (
    Argon2idParams,
    EciesSealedPoeError,
    PassphraseEnvelope,
    RecipientKeyBundle,
    SealedEnvelope,
    SealedSlot,
    StreamUnwrapResult,
    _seal_stream_body,
    ecies_sealed_poe_seal_stream,
    ecies_sealed_poe_unwrap_stream,
    ecies_sealed_poe_wrap,
    passphrase_sealed_poe_open_stream,
    passphrase_sealed_poe_seal,
    passphrase_sealed_poe_seal_stream,
)
from cardanowall._crypto.stream import CHUNK_SIZE, stream_seal

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def _chunked(data: bytes, sizes: list[int]) -> list[bytes]:
    """Split ``data`` into a list of slices cycling through ``sizes``.

    Producer boundaries deliberately do NOT align to CHUNK_SIZE / SEALED_CHUNK_SIZE,
    so the seal/unwrap re-chunking + EOF lookahead is what proves byte-parity.
    """
    out: list[bytes] = []
    pos = 0
    i = 0
    while pos < len(data):
        n = sizes[i % len(sizes)]
        out.append(data[pos : pos + n])
        pos += n
        i += 1
    return out


def _hashes_from_fixture(hashes_hex: dict[str, str]) -> dict[str, bytes]:
    return {alg: bytes.fromhex(h) for alg, h in hashes_hex.items()}


def _envelope_from_fixture(env: dict[str, Any]) -> SealedEnvelope:
    slots: list[SealedSlot] = []
    for s in env["slots"]:
        if "epk_hex" in s:
            slots.append(
                SealedSlot(epk=bytes.fromhex(s["epk_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            )
        else:
            slots.append(
                SealedSlot(kem_ct=bytes.fromhex(s["kem_ct_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            )
    return SealedEnvelope(
        scheme=int(env["scheme"]),
        aead=str(env["aead"]),
        kem=str(env["kem"]),
        nonce=bytes.fromhex(str(env["nonce_hex"])),
        slots=tuple(slots),
        slots_mac=bytes.fromhex(str(env["slots_mac_hex"])),
    )


# Odd producer chunkings whose boundaries straddle the 64 KiB STREAM grid: a tiny
# 1-byte trickle, sizes one short of / one over a full chunk, and a multi-chunk
# stride that never lands on a boundary.
_PLAINTEXT_CHUNKINGS = [
    [1],
    [CHUNK_SIZE - 1],
    [CHUNK_SIZE + 1],
    [7, CHUNK_SIZE, 3],
]
# Sealed-chunkings whose strides straddle the 65552-byte sealed-chunk grid.
_SEALED_CHUNKINGS = [
    [1],
    [65551],
    [65553],
    [7, 65552, 11],
]


# ---------------------------------------------------------------------------
# Item 1 — seal stream byte-parity against the pinned wrap-* envelope vectors.
# ---------------------------------------------------------------------------


def _check_seal_stream_matches_wrap(filename: str) -> None:
    vector = _load(filename)["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    ephemeral_secrets = [bytes.fromhex(h) for h in vector["ephemeral_secrets_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])

    reference = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=ephemeral_secrets,
        skip_shuffle=True,
    )

    for sizes in _PLAINTEXT_CHUNKINGS:
        envelope, body_gen = ecies_sealed_poe_seal_stream(
            plaintext=_chunked(plaintext, sizes),
            recipient_public_keys=recipient_publics,
            hashes=hashes,
            cek=cek,
            nonce=nonce,
            ephemeral_secrets=ephemeral_secrets,
            skip_shuffle=True,
        )
        body = b"".join(body_gen)
        # The envelope is byte-identical to the buffered wrap, and the streamed
        # body equals the pinned cross-SDK ciphertext regardless of producer
        # chunking.
        assert envelope == reference.envelope, (filename, sizes)
        assert body.hex() == vector["expected_ciphertext_hex"], (filename, sizes)
        assert body == reference.ciphertext, (filename, sizes)


def test_seal_stream_matches_wrap_n1_empty() -> None:
    _check_seal_stream_matches_wrap("wrap-n1-empty.json")


def test_seal_stream_matches_wrap_n3() -> None:
    _check_seal_stream_matches_wrap("wrap-n3.json")


def test_seal_stream_matches_wrap_n32() -> None:
    _check_seal_stream_matches_wrap("wrap-n32.json")


def test_seal_stream_matches_wrap_hybrid() -> None:
    # The X-Wing hybrid path uses eseeds, not ephemeral_secrets.
    vector = _load("wrap-hybrid-n3.json")["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    eseeds = [bytes.fromhex(h) for h in vector["eseeds_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])

    reference = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        hashes=hashes,
        kem="mlkem768x25519",
        cek=cek,
        nonce=nonce,
        eseeds=eseeds,
        skip_shuffle=True,
    )
    envelope, body_gen = ecies_sealed_poe_seal_stream(
        plaintext=_chunked(plaintext, [7, 11]),
        recipient_public_keys=recipient_publics,
        hashes=hashes,
        kem="mlkem768x25519",
        cek=cek,
        nonce=nonce,
        eseeds=eseeds,
        skip_shuffle=True,
    )
    assert envelope == reference.envelope
    assert b"".join(body_gen).hex() == vector["expected_ciphertext_hex"]


# ---------------------------------------------------------------------------
# Item 1 — seal stream STREAM-layer parity against stream-layout vectors plus
# the constructed boundary sizes (empty / 1B / 64KiB / 2x64KiB / 65537), all in
# odd producer chunking. This is the load-bearing EOF-lookahead proof.
# ---------------------------------------------------------------------------


def test_seal_stream_body_matches_stream_layout_vectors() -> None:
    corpus = _load("stream-layout.json")
    payload_key = bytes.fromhex(corpus["payload_key_hex"])
    for vector in corpus["positive_vectors"]:
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        for sizes in _PLAINTEXT_CHUNKINGS:
            pieces = _chunked(plaintext, sizes)
            body = b"".join(_seal_stream_body(payload_key, pieces, None))
            assert body.hex() == vector["expected_ciphertext_hex"], (vector["name"], sizes)


def test_seal_stream_body_boundary_sizes_match_stream_seal() -> None:
    # Construct the exact boundary sizes the EOF-lookahead contract pins —
    # including exact-2x-64-KiB, which the pinned fixture does not carry — and
    # assert the streamed body equals the already-vector-validated whole-buffer
    # stream_seal for every odd producer chunking.
    payload_key = bytes(range(32))
    boundary_sizes = [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
        2 * CHUNK_SIZE + 5,
    ]
    for size in boundary_sizes:
        plaintext = bytes((i * 7) & 0xFF for i in range(size))
        reference = stream_seal(payload_key, plaintext)
        for sizes in _PLAINTEXT_CHUNKINGS:
            pieces = _chunked(plaintext, sizes) if size else []
            body = b"".join(_seal_stream_body(payload_key, pieces, None))
            assert body == reference, (size, sizes)


# ---------------------------------------------------------------------------
# Item 1 — unwrap stream byte-parity against the pinned unwrap-* vectors.
# ---------------------------------------------------------------------------


def _check_unwrap_stream(filename: str) -> None:
    vector = _load(filename)["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    expected = bytes.fromhex(str(vector["expected_plaintext_hex"]))
    for priv_hex in vector["recipient_secrets_hex"]:
        priv = bytes.fromhex(priv_hex)
        for sizes in _SEALED_CHUNKINGS:
            pieces = _chunked(ciphertext, sizes) if ciphertext else []
            gen, result = ecies_sealed_poe_unwrap_stream(
                envelope=envelope,
                ciphertext=pieces,
                hashes=hashes,
                recipient_secret_key=priv,
            )
            plaintext = b"".join(gen)
            assert plaintext == expected, (filename, sizes)
            assert result.matched is True, (filename, sizes)
            assert result.reason is None, (filename, sizes)


def test_unwrap_stream_n1_empty() -> None:
    _check_unwrap_stream("unwrap-n1-empty.json")


def test_unwrap_stream_n3() -> None:
    _check_unwrap_stream("unwrap-n3.json")


def test_unwrap_stream_n32() -> None:
    _check_unwrap_stream("unwrap-n32.json")


# ---------------------------------------------------------------------------
# Round-trip seal→unwrap byte-parity across the boundary sizes (envelope path).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size", [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 2 * CHUNK_SIZE + 5]
)
def test_seal_then_unwrap_roundtrip_via_envelope(size: int) -> None:
    from cardanowall._crypto.kem import x25519_public_key

    priv = bytes((100 + i) & 0xFF for i in range(32))
    pub = x25519_public_key(priv)
    cek = bytes(range(32))
    nonce = bytes(range(24))
    eph = [bytes((7 + i) & 0xFF for i in range(32))]
    plaintext = bytes((i * 13) & 0xFF for i in range(size))
    hashes = {"sha2-256": hashlib.sha256(plaintext).digest()}

    reference = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub],
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=eph,
        skip_shuffle=True,
    )
    envelope, body_gen = ecies_sealed_poe_seal_stream(
        plaintext=_chunked(plaintext, [1, CHUNK_SIZE - 1, CHUNK_SIZE + 1]) if size else [],
        recipient_public_keys=[pub],
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=eph,
        skip_shuffle=True,
    )
    body = b"".join(body_gen)
    assert body == reference.ciphertext

    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=envelope,
        ciphertext=_chunked(body, [1, 65551, 65553]) if body else [],
        hashes=hashes,
        recipient_secret_key=priv,
    )
    assert b"".join(gen) == plaintext
    assert result.matched is True


# ---------------------------------------------------------------------------
# Tamper detection — a flipped or truncated sealed chunk yields TAMPERED_CIPHERTEXT.
# ---------------------------------------------------------------------------


def test_unwrap_stream_flipped_tag_is_tampered() -> None:
    vector = _load("unwrap-n3.json")["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytearray(bytes.fromhex(str(vector["ciphertext_hex"])))
    hashes = _hashes_from_fixture(vector["hashes"])
    priv = bytes.fromhex(vector["recipient_secrets_hex"][0])
    # Flip the final tag byte.
    ciphertext[-1] ^= 0x01
    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=envelope,
        ciphertext=[bytes(ciphertext)],
        hashes=hashes,
        recipient_secret_key=priv,
    )
    list(gen)  # drain
    assert result.matched is False
    assert result.reason == "TAMPERED_CIPHERTEXT"


def test_unwrap_stream_truncated_is_tampered() -> None:
    # A multi-chunk ciphertext truncated to drop the final chunk: the remaining
    # full chunk is forced into the final position where its non-final-flag tag
    # cannot verify.
    from cardanowall._crypto.kem import x25519_public_key

    priv = bytes((100 + i) & 0xFF for i in range(32))
    pub = x25519_public_key(priv)
    cek = bytes(range(32))
    nonce = bytes(range(24))
    eph = [bytes((7 + i) & 0xFF for i in range(32))]
    plaintext = bytes((i) & 0xFF for i in range(CHUNK_SIZE + 100))
    hashes = {"sha2-256": hashlib.sha256(plaintext).digest()}
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub],
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=eph,
        skip_shuffle=True,
    )
    truncated = sealed.ciphertext[: CHUNK_SIZE + 16]
    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=sealed.envelope,
        ciphertext=[truncated],
        hashes=hashes,
        recipient_secret_key=priv,
    )
    list(gen)
    assert result.matched is False
    assert result.reason == "TAMPERED_CIPHERTEXT"


# ---------------------------------------------------------------------------
# Bundle form parity (stream + buffered) and empty-bundle clean no-match.
# ---------------------------------------------------------------------------


def test_unwrap_stream_bundle_form_decrypts() -> None:
    vector = _load("unwrap-n3.json")["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    expected = bytes.fromhex(str(vector["expected_plaintext_hex"]))
    priv = bytes.fromhex(vector["recipient_secrets_hex"][0])
    # The x25519 envelope selects x25519_private_keys; the hybrid seed list is
    # empty and irrelevant.
    bundle = RecipientKeyBundle(x25519_private_keys=[priv], mlkem768x25519_secret_seeds=[])
    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=envelope,
        ciphertext=[ciphertext],
        hashes=hashes,
        recipient_key_bundle=bundle,
    )
    assert b"".join(gen) == expected
    assert result.matched is True


def test_unwrap_stream_empty_bundle_list_is_clean_no_match() -> None:
    vector = _load("unwrap-n3.json")["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    # An x25519 envelope with an empty x25519 list: the recipient holds no key for
    # this KEM, so it is a clean no-match (no plaintext yielded), not an error.
    bundle = RecipientKeyBundle(x25519_private_keys=[], mlkem768x25519_secret_seeds=[])
    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=envelope,
        ciphertext=[ciphertext],
        hashes=hashes,
        recipient_key_bundle=bundle,
    )
    assert list(gen) == []
    assert result.matched is False
    assert result.reason == "WRONG_RECIPIENT_KEY"


def test_unwrap_stream_wrong_recipient_yields_nothing() -> None:
    vector = _load("unwrap-n3.json")["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    wrong = bytes((200 + i) & 0xFF for i in range(32))
    gen, result = ecies_sealed_poe_unwrap_stream(
        envelope=envelope,
        ciphertext=[ciphertext],
        hashes=hashes,
        recipient_secret_key=wrong,
    )
    # No plaintext is released to a non-recipient.
    assert list(gen) == []
    assert result.matched is False
    assert result.reason == "WRONG_RECIPIENT_KEY"


# ---------------------------------------------------------------------------
# Cancellation — the seal generator stops and raises on a cooperative cancel.
# ---------------------------------------------------------------------------


def test_seal_stream_cancel_raises() -> None:
    from cardanowall._crypto.kem import x25519_public_key
    from cardanowall._crypto.sealed_poe import EciesSealedPoeError

    priv = bytes((100 + i) & 0xFF for i in range(32))
    pub = x25519_public_key(priv)
    hashes = {"sha2-256": hashlib.sha256(b"x" * 200000).digest()}
    _envelope, gen = ecies_sealed_poe_seal_stream(
        plaintext=[b"a" * CHUNK_SIZE, b"b" * CHUNK_SIZE],
        recipient_public_keys=[pub],
        hashes=hashes,
        cek=bytes(range(32)),
        nonce=bytes(range(24)),
        ephemeral_secrets=[bytes((7 + i) & 0xFF for i in range(32))],
        skip_shuffle=True,
        cancel=lambda: True,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        list(gen)
    assert exc.value.code == "CANCELLED"


def test_streaming_seal_returns_envelope_before_body_consumed() -> None:
    # The envelope is resolved up front: it is available before a single body
    # chunk is iterated (the body generator is lazy).
    from cardanowall._crypto.kem import x25519_public_key

    priv = bytes((100 + i) & 0xFF for i in range(32))
    pub = x25519_public_key(priv)
    hashes = {"sha2-256": hashlib.sha256(b"lazy").digest()}

    def never_iterated() -> Iterator[bytes]:
        raise AssertionError("plaintext iterated before body consumed")
        yield b""  # pragma: no cover

    envelope, _body = ecies_sealed_poe_seal_stream(
        plaintext=never_iterated(),
        recipient_public_keys=[pub],
        hashes=hashes,
        cek=bytes(range(32)),
        nonce=bytes(range(24)),
        ephemeral_secrets=[bytes((7 + i) & 0xFF for i in range(32))],
        skip_shuffle=True,
    )
    # Resolving the envelope did not touch the plaintext iterator.
    assert envelope.scheme == 1
    assert isinstance(envelope.slots_mac, bytes)


def test_stream_unwrap_result_is_distinct_type() -> None:
    # The result holder is a mutable StreamUnwrapResult resolved on generator
    # exhaustion (matched=None until then).
    pending = StreamUnwrapResult(matched=None, reason=None)
    assert pending.matched is None


# ---------------------------------------------------------------------------
# The passphrase path — streaming twin of the buffered pair, validated against
# the same pinned passphrase-n1 vector with ZERO new crypto vectors.
# ---------------------------------------------------------------------------

# Deterministic passphrase inputs for the size-matrix equivalence and the
# outcome tests: registry-floor parameters and a fixed salt / nonce so the
# buffered and streamed seals are directly comparable.
_PW = "correct horse battery staple"
_PW_SALT = b"\x55" * 16
_PW_NONCE = b"\x66" * 24
_PW_PARAMS = Argon2idParams(m=65536, t=3, p=1)
_PW_HASHES = {"sha2-256": b"\x2e" * 32}
_PW_ENVELOPE = PassphraseEnvelope(
    scheme=1,
    aead="chacha20-poly1305-stream64k",
    nonce=_PW_NONCE,
    alg="argon2id",
    salt=_PW_SALT,
    params=_PW_PARAMS,
)


def _pw_stream_seal(plaintext: bytes, sizes: list[int]) -> bytes:
    _envelope, gen = passphrase_sealed_poe_seal_stream(
        plaintext=_chunked(plaintext, sizes),
        passphrase=_PW,
        hashes=_PW_HASHES,
        params=_PW_PARAMS,
        salt=_PW_SALT,
        nonce=_PW_NONCE,
    )
    return b"".join(gen)


def test_passphrase_seal_stream_matches_the_pinned_vector() -> None:
    # Stream-sealing the vector plaintext at odd producer granularities (whose
    # boundaries are NOT STREAM chunk boundaries) must reproduce the pinned
    # blob (commitment || STREAM) byte-for-byte.
    vector = _load("passphrase-n1.json")["vector"]
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    params = Argon2idParams(
        m=int(vector["params"]["m"]), t=int(vector["params"]["t"]), p=int(vector["params"]["p"])
    )
    for sizes in ([1], [7], [31], [max(len(plaintext), 1)]):
        envelope, gen = passphrase_sealed_poe_seal_stream(
            plaintext=_chunked(plaintext, sizes),
            passphrase=str(vector["passphrase"]),
            hashes=hashes,
            params=params,
            salt=bytes.fromhex(str(vector["salt_hex"])),
            nonce=bytes.fromhex(str(vector["nonce_hex"])),
        )
        blob = b"".join(gen)
        assert blob.hex() == vector["expected_ciphertext_hex"], sizes
        assert blob[:32].hex() == vector["expected_commitment_hex"], sizes
        assert envelope.alg == "argon2id"


def test_passphrase_open_stream_recovers_the_pinned_vector() -> None:
    vector = _load("passphrase-n1.json")["vector"]
    blob = bytes.fromhex(str(vector["expected_ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    envelope = PassphraseEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        nonce=bytes.fromhex(str(vector["nonce_hex"])),
        alg="argon2id",
        salt=bytes.fromhex(str(vector["salt_hex"])),
        params=Argon2idParams(
            m=int(vector["params"]["m"]),
            t=int(vector["params"]["t"]),
            p=int(vector["params"]["p"]),
        ),
    )
    # 47 / 48 straddle the lookahead floor; the rest cut across the STREAM grid.
    for sizes in ([1], [7], [47], [48], [len(blob)]):
        gen, result = passphrase_sealed_poe_open_stream(
            envelope=envelope,
            ciphertext=_chunked(blob, sizes),
            passphrase=str(vector["passphrase"]),
            hashes=hashes,
        )
        plaintext = b"".join(gen)
        assert result.opened is True, sizes
        assert plaintext.hex() == vector["expected_plaintext_hex"], sizes


@pytest.mark.parametrize("size", [0, 1, CHUNK_SIZE, 2 * CHUNK_SIZE, 2 * CHUNK_SIZE + 4242])
def test_passphrase_stream_seal_equals_buffered_across_the_chunk_matrix(size: int) -> None:
    # The chunk-boundary size matrix vs the buffered seal: empty (the sole
    # empty-final-chunk case), one byte, an exact 64 KiB chunk (full-size final
    # chunk), an exact multiple (NO trailing empty chunk), and an odd
    # multi-chunk length — each streamed at source granularities that cut
    # across the 64 KiB grid.
    plaintext = bytes((i * 7) & 0xFF for i in range(size))
    buffered = passphrase_sealed_poe_seal(
        plaintext=plaintext,
        passphrase=_PW,
        hashes=_PW_HASHES,
        params=_PW_PARAMS,
        salt=_PW_SALT,
        nonce=_PW_NONCE,
    )
    for sizes in ([1], [65537], [CHUNK_SIZE]):
        envelope, gen = passphrase_sealed_poe_seal_stream(
            plaintext=_chunked(plaintext, sizes),
            passphrase=_PW,
            hashes=_PW_HASHES,
            params=_PW_PARAMS,
            salt=_PW_SALT,
            nonce=_PW_NONCE,
        )
        assert envelope == buffered.envelope, (size, sizes)
        assert b"".join(gen) == buffered.ciphertext, (size, sizes)

    # And the streamed open recovers the plaintext from the buffered blob at a
    # grid-straddling source granularity.
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=buffered.envelope,
        ciphertext=_chunked(buffered.ciphertext, [65537]),
        passphrase=_PW,
        hashes=_PW_HASHES,
    )
    assert b"".join(gen) == plaintext, size
    assert result.opened is True, size


def test_passphrase_open_stream_wrong_passphrase_rejects_with_nothing_yielded() -> None:
    blob = _pw_stream_seal(bytes(100), [100])
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=_PW_ENVELOPE,
        ciphertext=_chunked(blob, [17]),
        passphrase="not the passphrase",
        hashes=_PW_HASHES,
    )
    # A commitment mismatch resolves eagerly and yields nothing.
    assert result.opened is False
    assert list(gen) == []


def test_passphrase_open_stream_flipped_commitment_byte_rejects_with_nothing_yielded() -> None:
    blob = bytearray(_pw_stream_seal(bytes(100), [100]))
    blob[0] ^= 0x01  # inside the 32-byte commitment header
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=_PW_ENVELOPE,
        ciphertext=_chunked(bytes(blob), [17]),
        passphrase=_PW,
        hashes=_PW_HASHES,
    )
    assert result.opened is False
    assert list(gen) == []


def test_passphrase_open_stream_flipped_final_tag_rejects_mid_body() -> None:
    # Flip a byte in the final chunk's tag: the commitment still matches (the
    # header is intact), so the failure surfaces mid-body as the same single
    # generic rejection; the already-yielded first chunk is quarantine the
    # caller discards.
    plaintext = bytes((i * 3) & 0xFF for i in range(CHUNK_SIZE + 33))
    blob = bytearray(_pw_stream_seal(plaintext, [CHUNK_SIZE]))
    blob[-1] ^= 0x01
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=_PW_ENVELOPE,
        ciphertext=_chunked(bytes(blob), [65537]),
        passphrase=_PW,
        hashes=_PW_HASHES,
    )
    yielded = b"".join(gen)
    assert result.opened is False
    # The intact first chunk was released before the tamper was detected.
    assert yielded == plaintext[:CHUNK_SIZE]


def test_passphrase_open_stream_source_below_floor_rejects_without_kdf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 47 bytes is one short of the 48-byte well-formedness floor (32-byte
    # commitment + lone final tag): the lookahead rejects it exactly as the
    # buffered open's length check does, before any Argon2 work.
    import cardanowall._crypto.sealed_poe as sealed_poe_module

    def _kdf_must_not_run(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("argon2id_v13 must not run for a source below the structural floor")

    monkeypatch.setattr(sealed_poe_module, "argon2id_v13", _kdf_must_not_run)
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=_PW_ENVELOPE,
        ciphertext=_chunked(b"\x00" * 47, [5]),
        passphrase=_PW,
        hashes=_PW_HASHES,
    )
    assert result.opened is False
    assert list(gen) == []


def test_passphrase_stream_typed_rejections_mirror_the_buffered_pair() -> None:
    # Seal: a 15-byte salt is the buffered seal's typed rejection, raised
    # eagerly before any plaintext is consumed.
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_seal_stream(
            plaintext=[b"body"],
            passphrase=_PW,
            hashes=_PW_HASHES,
            params=_PW_PARAMS,
            salt=b"\x01" * 15,
            nonce=_PW_NONCE,
        )
    assert exc.value.code == "ENC_PASSPHRASE_SALT_TOO_SHORT"

    # Open: below-floor params are a typed error even when the blob is also
    # below the structural floor — the envelope shape strictly precedes any
    # blob-dependent work.
    below_floor = PassphraseEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        nonce=_PW_NONCE,
        alg="argon2id",
        salt=_PW_SALT,
        params=Argon2idParams(m=8, t=1, p=1),
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_open_stream(
            envelope=below_floor,
            ciphertext=[b"\x00" * 47],
            passphrase=_PW,
            hashes=_PW_HASHES,
        )
    assert exc.value.code == "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"

    # Open: an unsupported aead identifier is a typed error.
    bad_aead = PassphraseEnvelope(
        scheme=1,
        aead="aes-gcm",
        nonce=_PW_NONCE,
        alg="argon2id",
        salt=_PW_SALT,
        params=_PW_PARAMS,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_open_stream(
            envelope=bad_aead,
            ciphertext=[b"\x00" * 47],
            passphrase=_PW,
            hashes=_PW_HASHES,
        )
    assert exc.value.code == "UNSUPPORTED_AEAD_ALG"


def test_passphrase_streaming_seal_returns_envelope_before_body_consumed() -> None:
    # The envelope and the commitment are resolved up front: available before
    # a single body chunk is iterated (the body generator is lazy).
    def never_iterated() -> Iterator[bytes]:
        raise AssertionError("plaintext iterated before body consumed")
        yield b""  # pragma: no cover

    envelope, _body = passphrase_sealed_poe_seal_stream(
        plaintext=never_iterated(),
        passphrase=_PW,
        hashes=_PW_HASHES,
        params=_PW_PARAMS,
        salt=_PW_SALT,
        nonce=_PW_NONCE,
    )
    assert envelope.scheme == 1
    assert envelope.salt == _PW_SALT


def test_passphrase_seal_stream_cancel_raises() -> None:
    _envelope, gen = passphrase_sealed_poe_seal_stream(
        plaintext=[b"a" * CHUNK_SIZE, b"b" * CHUNK_SIZE],
        passphrase=_PW,
        hashes=_PW_HASHES,
        params=_PW_PARAMS,
        salt=_PW_SALT,
        nonce=_PW_NONCE,
        cancel=lambda: True,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        list(gen)
    assert exc.value.code == "CANCELLED"


def test_passphrase_open_stream_cancel_raises() -> None:
    blob = _pw_stream_seal(bytes(2 * CHUNK_SIZE), [CHUNK_SIZE])
    gen, result = passphrase_sealed_poe_open_stream(
        envelope=_PW_ENVELOPE,
        ciphertext=_chunked(blob, [CHUNK_SIZE + 16]),
        passphrase=_PW,
        hashes=_PW_HASHES,
        cancel=lambda: True,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        list(gen)
    assert exc.value.code == "CANCELLED"
    # The outcome stays unresolved on cancellation.
    assert result.opened is None
