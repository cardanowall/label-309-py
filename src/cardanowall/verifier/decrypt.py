"""Sealed-PoE decryption (recipient verifier).

For each ``enc``-bearing item — when the run's decryption keyring is
non-empty — the verifier acquires the ciphertext blob (out-of-band bytes, or
fetched from ``item.uris[]``), dispatches on the item's on-wire key path, and
attempts every applicable keyring credential independently:

  - ``enc.slots``      — the sealed-PoE trial-decrypt loop: per-slot
                         acceptance folds the KEM validity bit, the
                         wrap-open, and the slot-set MAC over ``slots_hash``
                         into one constant-time decision, then the recovered
                         CEK opens the segmented STREAM chunk by chunk.
  - ``enc.passphrase`` — Argon2id over the pinned-normalization passphrase,
                         the leading 32-byte key-commitment header verified
                         in constant time BEFORE any chunk opens, then the
                         same STREAM open.

Failure attribution:

  - WRONG_RECIPIENT_KEY / TAMPERED_HEADER bind to ON-CHAIN data (the slot set
    and its MAC), so they are terminal for the item no matter which blob was
    tried.
  - TAMPERED_CIPHERTEXT is blob-dependent: it holds the blob against the
    record only when the blob is ATTRIBUTABLE (out-of-band, or fetched with a
    verified content-address binding). The same failure over an
    unattributable fetched blob is URI_PROVIDER_INTEGRITY_MISMATCH (warning)
    and the remaining sources are tried; exhaustion without an attributable
    blob ends as CIPHERTEXT_UNAVAILABLE (verdict ``unverifiable``).
  - The post-decryption plaintext-hash recheck needs no attribution
    qualifier: ciphertext that opens under the authenticated envelope is
    attributed by the AEAD itself, so a recheck mismatch is always
    URI_INTEGRITY_MISMATCH and the record's verdict is ``failed`` — no
    "decrypted" surface may outrank it.

Passphrase normalization is owned entirely by the construction layer
(``passphrase_sealed_poe_open`` applies the pinned profile internally); this
module never normalizes a passphrase itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from cardanowall._crypto.sealed_poe import (
    AEAD_CHACHA20_POLY1305_STREAM64K,
    Argon2idParams,
    EciesSealedPoeError,
    PassphraseEnvelope,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_unwrap,
    passphrase_sealed_poe_open,
)
from cardanowall.poe_standard import EncryptionEnvelope, Item

from .fetch import BlobIterationFlags, ContentFetchContext, iterate_blob_sources
from .items import recompute_item_hashes
from .types import ContentCheck, Decryption, DecryptionOutcome, DecryptionRecipient


@dataclass(frozen=True, kw_only=True)
class ItemDecryptionResult:
    content_check: ContentCheck
    decryption: DecryptionOutcome


@dataclass(frozen=True, kw_only=True)
class _AttemptOutcome:
    # "opened"        — plaintext recovered.
    # "header_failure" — bound to on-chain data (WRONG_RECIPIENT_KEY /
    #                    TAMPERED_HEADER); retrying with a different blob
    #                    cannot change it.
    # "blob_failure"   — TAMPERED_CIPHERTEXT; subject to the attribution split.
    # "input_failure"  — a caller-input / KDF problem independent of the blob;
    #                    terminal.
    kind: Literal["opened", "header_failure", "blob_failure", "input_failure"]
    plaintext: bytes | None = None
    code: str = ""
    message: str = ""


# Map a construction-API rejection to the wire error-code vocabulary. Codes
# that exist in the wire registry pass through verbatim; every
# construction-local rejection (recipient-key shape, pre-KDF input bound,
# envelope-field mismatch on an unvalidated record) maps to
# KDF_DERIVATION_FAILED — the credential/derivation input was rejected before
# any blob-dependent work ran.
def _input_failure_from(e: EciesSealedPoeError) -> _AttemptOutcome:
    code = (
        e.code
        if e.code
        in ("ENC_PASSPHRASE_UNNORMALIZABLE", "ENC_PASSPHRASE_EMPTY", "KDF_DERIVATION_FAILED")
        else "KDF_DERIVATION_FAILED"
    )
    return _AttemptOutcome(kind="input_failure", code=code, message=str(e))


def _sealed_envelope_from_parsed(enc: EncryptionEnvelope) -> SealedEnvelope | None:
    """Project the parsed-but-permissive on-wire ``enc`` block into the
    discriminated ``SealedEnvelope`` the unwrap path consumes, or ``None``
    when the block is not a sealed-recipient envelope we can trial-decrypt.
    Unreachable on a structurally validated record (the recipient-role
    validator hard-rejects every envelope it cannot fully validate)."""
    if enc.get("scheme") != 1 or enc.get("aead") != AEAD_CHACHA20_POLY1305_STREAM64K:
        return None
    nonce = enc.get("nonce")
    slots_mac = enc.get("slots_mac")
    raw_slots = enc.get("slots")
    kem = enc.get("kem")
    if nonce is None or slots_mac is None or not raw_slots:
        return None
    slots: list[SealedSlot] = []
    if kem == "x25519":
        for s in raw_slots:
            epk = s.get("epk")
            wrap = s.get("wrap")
            if epk is None or wrap is None:
                return None
            slots.append(SealedSlot(wrap=wrap, epk=epk))
    elif kem == "mlkem768x25519":
        for s in raw_slots:
            kem_ct = s.get("kem_ct")
            wrap = s.get("wrap")
            if kem_ct is None or wrap is None:
                return None
            slots.append(SealedSlot(wrap=wrap, kem_ct=kem_ct))
    else:
        return None
    return SealedEnvelope(
        scheme=1,
        aead=AEAD_CHACHA20_POLY1305_STREAM64K,
        kem=kem,
        nonce=nonce,
        slots=tuple(slots),
        slots_mac=slots_mac,
    )


def _attempt_slots_path(
    *,
    enc: EncryptionEnvelope,
    hashes: Mapping[str, bytes],
    ciphertext: bytes,
    secret_keys: Sequence[bytes],
) -> _AttemptOutcome:
    envelope = _sealed_envelope_from_parsed(enc)
    if envelope is None:
        # Unreachable on a structurally validated record; defensively classed
        # as a header failure.
        return _AttemptOutcome(kind="header_failure", code="TAMPERED_HEADER")
    try:
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            hashes=hashes,
            recipient_secret_keys=list(secret_keys),
        )
    except EciesSealedPoeError as e:
        return _input_failure_from(e)
    if result.matched and result.plaintext is not None:
        return _AttemptOutcome(kind="opened", plaintext=result.plaintext)
    reason = result.reason or "TAMPERED_CIPHERTEXT"
    if reason == "TAMPERED_CIPHERTEXT":
        return _AttemptOutcome(kind="blob_failure", code="TAMPERED_CIPHERTEXT")
    return _AttemptOutcome(kind="header_failure", code=reason)


def _attempt_passphrase_path(
    *,
    enc: EncryptionEnvelope,
    hashes: Mapping[str, bytes],
    blob: bytes,
    passphrases: Sequence[str],
) -> _AttemptOutcome:
    """Attempt every supplied passphrase against one blob: any success wins;
    otherwise the FIRST failure outcome (in keyring order) is the item's
    outcome."""
    passphrase_block = enc.get("passphrase")
    assert passphrase_block is not None  # noqa: S101 — caller dispatched on key path
    envelope = PassphraseEnvelope(
        scheme=enc["scheme"],
        aead=enc["aead"],
        nonce=enc["nonce"],
        alg=passphrase_block["alg"],
        salt=passphrase_block["salt"],
        params=Argon2idParams(
            m=passphrase_block["params"]["m"],
            t=passphrase_block["params"]["t"],
            p=passphrase_block["params"]["p"],
        ),
    )
    first_failure: _AttemptOutcome | None = None
    for passphrase in passphrases:
        try:
            result = passphrase_sealed_poe_open(
                envelope=envelope, ciphertext=blob, passphrase=passphrase, hashes=hashes
            )
        except EciesSealedPoeError as e:
            outcome = _input_failure_from(e)
        else:
            if result.matched and result.plaintext is not None:
                return _AttemptOutcome(kind="opened", plaintext=result.plaintext)
            # Wrong passphrase, tampered salt/params/header fields, a spliced
            # envelope, or a tampered stream — indistinguishable by design.
            outcome = _AttemptOutcome(kind="blob_failure", code="TAMPERED_CIPHERTEXT")
        if first_failure is None:
            first_failure = outcome
    # The keyring is non-empty by construction (the caller filtered applicable
    # credentials before dispatching here).
    assert first_failure is not None  # noqa: S101
    return first_failure


async def decrypt_item(
    *,
    item: Item,
    item_index: int,
    credentials: Sequence[Decryption],
    ctx: ContentFetchContext,
    fetch_content: bool,
    out_of_band_ciphertext: bytes | None = None,
) -> ItemDecryptionResult:
    enc = item.get("enc")
    assert enc is not None  # noqa: S101 — caller dispatches on presence
    # The wire type keys the map by the registry's Literal algorithm ids; the
    # construction layer and digest helpers take the string-keyed reading.
    hashes = cast("Mapping[str, bytes]", item["hashes"])
    base_path: tuple[str | int, ...] = ("items", item_index, "enc")
    is_slots_path = enc.get("slots") is not None

    # Applicable credentials for the item's on-wire key path. The two paths
    # are mutually exclusive on a validated record.
    secret_keys: list[bytes] = []
    passphrases: list[str] = []
    for credential in credentials:
        if isinstance(credential, DecryptionRecipient):
            secret_keys.append(credential.recipient_secret_key)
        else:
            passphrases.append(credential.passphrase)
    applicable = len(secret_keys) if is_slots_path else len(passphrases)
    if applicable == 0:
        ctx.issues.add(
            "WRONG_DECRYPTION_INPUT_SHAPE",
            base_path,
            "the keyring holds no recipient secret key for this slots-path item"
            if is_slots_path
            else "the keyring holds no passphrase for this passphrase-path item",
        )
        return ItemDecryptionResult(
            content_check="not_checked",
            decryption=DecryptionOutcome(decrypted=False, code="WRONG_DECRYPTION_INPUT_SHAPE"),
        )

    flags = BlobIterationFlags()
    async for blob in iterate_blob_sources(
        out_of_band=out_of_band_ciphertext,
        uris=item.get("uris") or [],
        allow_fetch=fetch_content,
        base_path=("items", item_index),
        ctx=ctx,
        flags=flags,
    ):
        if is_slots_path:
            outcome = _attempt_slots_path(
                enc=enc, hashes=hashes, ciphertext=blob.bytes, secret_keys=secret_keys
            )
        else:
            outcome = _attempt_passphrase_path(
                enc=enc, hashes=hashes, blob=blob.bytes, passphrases=passphrases
            )

        if outcome.kind == "opened":
            assert outcome.plaintext is not None  # noqa: S101
            plaintext_hash_ok = recompute_item_hashes(hashes, outcome.plaintext)
            if not plaintext_hash_ok:
                ctx.issues.add(
                    "URI_INTEGRITY_MISMATCH",
                    ("items", item_index),
                    "decryption succeeded but the post-decryption plaintext-hash recheck "
                    "failed; decrypted bytes are attributed by the AEAD itself, so the "
                    "record is condemned",
                )
                return ItemDecryptionResult(
                    content_check="mismatched",
                    decryption=DecryptionOutcome(
                        decrypted=True, plaintext_hash_ok=False, code="URI_INTEGRITY_MISMATCH"
                    ),
                )
            return ItemDecryptionResult(
                content_check="checked",
                decryption=DecryptionOutcome(decrypted=True, plaintext_hash_ok=True),
            )
        if outcome.kind == "header_failure":
            ctx.issues.add(
                outcome.code,
                base_path,
                "no slot accepted any supplied recipient key — the key is not a "
                "recipient of this sealed PoE"
                if outcome.code == "WRONG_RECIPIENT_KEY"
                else "a slot wrap-opened but no candidate content-encryption key "
                "reproduces slots_mac — the authenticated envelope header fails its "
                "integrity check",
            )
            return ItemDecryptionResult(
                content_check="not_checked",
                decryption=DecryptionOutcome(decrypted=False, code=outcome.code),
            )
        if outcome.kind == "blob_failure":
            if blob.attributable():
                ctx.issues.add(
                    "TAMPERED_CIPHERTEXT",
                    base_path,
                    "the ciphertext blob failed the decryption layer and is attributable "
                    "(out-of-band, or content-address-bound to its URI); the record is "
                    "condemned",
                )
                return ItemDecryptionResult(
                    content_check="mismatched",
                    decryption=DecryptionOutcome(decrypted=False, code="TAMPERED_CIPHERTEXT"),
                )
            ctx.issues.add(
                "URI_PROVIDER_INTEGRITY_MISMATCH",
                ("items", item_index, "uris", blob.uri_index)
                if blob.uri_index is not None
                else ("items", item_index),
                f'ciphertext bytes fetched from "{blob.uri or "unknown source"}" fail the '
                "decryption layer and could not be attributed to the URI's content "
                "address; the serving provider is indicted, not the record",
            )
            continue
        # input_failure
        ctx.issues.add(outcome.code, base_path, outcome.message)
        return ItemDecryptionResult(
            content_check="not_checked",
            decryption=DecryptionOutcome(decrypted=False, code=outcome.code),
        )

    end_code = "CONTENT_FETCH_LIMIT_EXCEEDED" if flags.limit_exceeded else "CIPHERTEXT_UNAVAILABLE"
    ctx.issues.add(
        end_code,
        ("items", item_index),
        "a ciphertext fetch for this item was aborted at the maxFetchBytes ceiling; "
        "decryption could not proceed"
        if flags.limit_exceeded
        else "no out-of-band ciphertext was supplied and no URI yielded an attributable "
        "blob; decryption could not proceed",
    )
    return ItemDecryptionResult(
        content_check="not_checked",
        decryption=DecryptionOutcome(decrypted=False, code=end_code),
    )


__all__ = ["ItemDecryptionResult", "decrypt_item"]
