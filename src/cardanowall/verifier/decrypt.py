from __future__ import annotations

import unicodedata
from typing import Final

from cardanowall._crypto.aead import (
    AeadVerificationError,
    xchacha20_poly1305_decrypt,
)
from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.compare_ct import compare_ct
from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall._crypto.kdf import argon2id_v13, hkdf_sha256
from cardanowall._crypto.sealed_poe import (
    CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
    CARDANO_POE_PW_NORM_PROFILE,
    MAX_SEALED_PLAINTEXT,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_unwrap,
)
from cardanowall.poe_standard import (
    EncryptionEnvelope,
    Item,
    PassphraseKdf,
    PoeRecord,
)

from .fetch import (
    ContentUnavailableError,
    UriTargetForbiddenError,
    fetch_item_ciphertext,
)
from .types import (
    DecryptionPassphrase,
    DecryptionRecipient,
    DecryptionVerdict,
    FetchOutbound,
    VerifyItemDecryption,
    VerifyTxInput,
    VerifyUriCheck,
)

# The v1 passphrase KDF registry has a single member.
_PASSPHRASE_KDF_ARGON2ID: Final[str] = "argon2id"  # noqa: S105 — KDF alg id, not a secret

# Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE normalization
# and the Argon2id KDF. An oversized passphrase would otherwise drive unbounded
# NFKC / whitespace-collapse work and a large Argon2id input before any
# cost-bounded primitive runs; capping the raw input closes that pre-KDF DoS.
# The bound is byte length (len(raw.encode('utf-8'))), not code-point count, so a
# short string of wide multi-byte characters is still measured by its encoded
# size. 4096 bytes is far above any human-chosen passphrase. Identical across
# every SDK.
MAX_PASSPHRASE_INPUT_BYTES: Final[int] = 4096

# The Unicode `White_Space` property set under Unicode 16.0 — exactly these 25
# codepoints. The normalization profile collapses every maximal run of these to
# a single U+0020. This is spelled out explicitly rather than via the `\s` regex
# class or `str.isspace`, both of which match a different set (e.g. they exclude
# U+0085 NEL from `\s`, or include codepoints outside `White_Space`), which would
# derive a different CEK from the same passphrase and break cross-implementation
# decryption.
_WHITE_SPACE: Final[frozenset[str]] = frozenset(
    chr(cp)
    for cp in (
        0x0009,
        0x000A,
        0x000B,
        0x000C,
        0x000D,
        0x0020,
        0x0085,
        0x00A0,
        0x1680,
        0x2000,
        0x2001,
        0x2002,
        0x2003,
        0x2004,
        0x2005,
        0x2006,
        0x2007,
        0x2008,
        0x2009,
        0x200A,
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)


async def try_decryptions(
    record: PoeRecord,
    input: VerifyTxInput,
    fetch_fn: FetchOutbound,
    uri_checks_out: list[VerifyUriCheck],
    *,
    allow_uri_fetch: bool,
) -> tuple[VerifyItemDecryption, ...]:
    """Walk `input.decryption[]` and produce one VerifyItemDecryption per entry.

    Mirrors the TypeScript twin's `tryDecryptions`: each entry resolves to a
    discriminated `verdict` (`decrypted` on success, a distinct failure verdict
    otherwise). The verifier MUST NOT throw out of this function — a single
    malformed/unavailable item cannot abort the whole report. Per-attempt URI
    outcomes are appended to `uri_checks_out`.

    When `allow_uri_fetch` is `False`, the on-record `item.uris[]` ciphertext is
    NOT fetched; decryption then succeeds only for items whose ciphertext the
    caller supplied out-of-band, others surface as `ciphertext-unavailable`.
    """
    out: list[VerifyItemDecryption] = []
    reqs = input.decryption or ()
    items = record.get("items") or []

    for req in reqs:
        idx = req.item_index
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0 or idx >= len(items):
            out.append(
                VerifyItemDecryption(
                    item_index=idx, verdict="no-enc-envelope", reason="itemIndex out of range"
                )
            )
            continue
        item = items[idx]
        enc = item.get("enc")
        if enc is None:
            out.append(VerifyItemDecryption(item_index=idx, verdict="no-enc-envelope"))
            continue

        # The two on-wire paths (`slots[]` vs `passphrase`) are mutually
        # exclusive; the validator already rejected envelopes carrying both. A
        # mismatched decryption-entry shape is `wrong-input-shape`.
        has_slots = "slots" in enc and isinstance(enc.get("slots"), list)
        has_passphrase = enc.get("passphrase") is not None
        req_has_secret = isinstance(req, DecryptionRecipient)
        req_has_passphrase = isinstance(req, DecryptionPassphrase)
        if has_slots and not req_has_secret:
            out.append(
                VerifyItemDecryption(
                    item_index=idx,
                    verdict="wrong-input-shape",
                    reason="WRONG_DECRYPTION_INPUT_SHAPE",
                )
            )
            continue
        if has_passphrase and not req_has_passphrase:
            out.append(
                VerifyItemDecryption(
                    item_index=idx,
                    verdict="wrong-input-shape",
                    reason="WRONG_DECRYPTION_INPUT_SHAPE",
                )
            )
            continue

        # Ciphertext acquisition: out-of-band bytes first, then (when fetching is
        # allowed) on-record `item.uris[]`, then `CIPHERTEXT_UNAVAILABLE`.
        oob = input.ciphertext_bytes
        item_uris = item.get("uris") or []
        ciphertext: bytes | None
        if oob is not None and idx in oob:
            ciphertext = oob[idx]
        elif allow_uri_fetch and len(item_uris) > 0:
            try:
                ciphertext = await fetch_item_ciphertext(
                    uris=item_uris,
                    arweave_gateways=input.arweave_gateway_chain,
                    ipfs_gateways=input.ipfs_gateway_chain,
                    fetch_fn=fetch_fn,
                    uri_checks_out=uri_checks_out,
                    item_index=idx,
                )
            except UriTargetForbiddenError:
                out.append(
                    VerifyItemDecryption(
                        item_index=idx,
                        verdict="ciphertext-unavailable",
                        reason="URI_TARGET_FORBIDDEN",
                    )
                )
                continue
            except ContentUnavailableError as e:
                out.append(
                    VerifyItemDecryption(
                        item_index=idx,
                        verdict="content-unavailable",
                        reason=str(e) or "CONTENT_UNAVAILABLE",
                    )
                )
                continue
        else:
            out.append(
                VerifyItemDecryption(
                    item_index=idx,
                    verdict="ciphertext-unavailable",
                    reason="CIPHERTEXT_UNAVAILABLE",
                )
            )
            continue

        plaintext: bytes | None = None
        failure: tuple[DecryptionVerdict, str] | None = None
        if req_has_secret:
            assert isinstance(req, DecryptionRecipient)  # noqa: S101
            envelope = _sealed_envelope_from_parsed(enc)
            if envelope is None:
                out.append(
                    VerifyItemDecryption(
                        item_index=idx,
                        verdict="wrong-input-shape",
                        reason="WRONG_DECRYPTION_INPUT_SHAPE",
                    )
                )
                continue
            try:
                unwrap = ecies_sealed_poe_unwrap(
                    envelope=envelope,
                    ciphertext=ciphertext,
                    recipient_secret_key=req.recipient_secret_key,
                )
            except EciesSealedPoeError:
                failure = ("tampered-ciphertext", "TAMPERED_CIPHERTEXT")
                unwrap = None
            if unwrap is not None:
                if unwrap.matched:
                    plaintext = unwrap.plaintext
                else:
                    failure = _SEALED_FAILURE_MAP.get(
                        unwrap.reason or "", ("tampered-ciphertext", "TAMPERED_CIPHERTEXT")
                    )
        else:
            assert isinstance(req, DecryptionPassphrase)  # noqa: S101
            try:
                plaintext = _decrypt_passphrase(enc, ciphertext, req.passphrase)
            except AeadVerificationError:
                failure = ("tampered-ciphertext", "TAMPERED_CIPHERTEXT")
            except _KdfDerivationError as e:
                failure = ("kdf-failed", str(e))
            except Exception as e:
                failure = ("tampered-ciphertext", str(e) or "TAMPERED_CIPHERTEXT")

        if failure is not None:
            out.append(VerifyItemDecryption(item_index=idx, verdict=failure[0], reason=failure[1]))
            continue
        if plaintext is None:
            # Defensive — failure path should already have returned above.
            out.append(
                VerifyItemDecryption(
                    item_index=idx, verdict="tampered-ciphertext", reason="TAMPERED_CIPHERTEXT"
                )
            )
            continue

        plaintext_hash_ok = _recompute_hashes(item, plaintext)
        out.append(
            VerifyItemDecryption(
                item_index=idx, verdict="decrypted", plaintext_hash_ok=plaintext_hash_ok
            )
        )

    return tuple(out)


# Sealed-unwrap failure reason -> (verdict, reason) projection (TS parity).
_SEALED_FAILURE_MAP: Final[dict[str, tuple[DecryptionVerdict, str]]] = {
    "WRONG_RECIPIENT_KEY": ("wrong-key", "WRONG_RECIPIENT_KEY"),
    "TAMPERED_HEADER": ("tampered-header", "TAMPERED_HEADER"),
    "TAMPERED_CIPHERTEXT": ("tampered-ciphertext", "TAMPERED_CIPHERTEXT"),
}


class _KdfDerivationError(Exception):
    """KDF derivation failed (unsupported alg or Argon2id error)."""


def _sealed_envelope_from_parsed(enc: EncryptionEnvelope) -> SealedEnvelope | None:
    if "slots" not in enc or "slots_mac" not in enc:
        return None
    slots = tuple(SealedSlot(epk=s["epk"], wrap=s["wrap"]) for s in enc["slots"])
    kem = enc.get("kem", "x25519")
    return SealedEnvelope(
        scheme=enc["scheme"],
        aead=enc["aead"],
        kem=kem,
        nonce=enc["nonce"],
        slots=slots,
        slots_mac=enc["slots_mac"],
    )


def _normalize_passphrase(passphrase: str) -> bytes:
    """Apply the `cardano-poe-pw-norm-v1` profile: NFKC, then collapse every
    maximal run of `White_Space` codepoints to a single U+0020, then trim
    leading/trailing space, then encode as UTF-8."""
    nfkc = unicodedata.normalize("NFKC", passphrase)
    out: list[str] = []
    in_run = False
    for ch in nfkc:
        if ch in _WHITE_SPACE:
            if not in_run:
                out.append(" ")
                in_run = True
        else:
            out.append(ch)
            in_run = False
    return "".join(out).strip(" ").encode("utf-8")


# Passphrase-path content AAD: a closed map that binds the KDF parameters and
# the normalization profile id into the content tag. The verifier recomputes it
# from the received `enc` map, so altering `salt` or any `params` value after
# encryption changes the AAD and makes the AEAD open fail. Serialised by the
# shared canonical encoder; the normalization id is a scheme-fixed constant,
# never on the wire.
def _ad_content_passphrase(nonce: bytes, kdf: PassphraseKdf) -> bytes:
    params = kdf["params"]
    ad: dict[str | int, CanonicalCborValue] = {
        "scheme": 1,
        "path": "passphrase",
        "aead": "xchacha20-poly1305",
        "nonce": nonce,
        "passphrase": {
            "alg": "argon2id",
            "salt": kdf["salt"],
            "params": {"m": params["m"], "t": params["t"], "p": params["p"]},
            "normalization": CARDANO_POE_PW_NORM_PROFILE,
        },
    }
    return encode_canonical_cbor(ad)


def _decrypt_passphrase(enc: EncryptionEnvelope, ciphertext: bytes, passphrase: str) -> bytes:
    passphrase_block = enc.get("passphrase")
    if passphrase_block is None:
        raise _KdfDerivationError("KDF_DERIVATION_FAILED: no passphrase block")
    if passphrase_block["alg"] != _PASSPHRASE_KDF_ARGON2ID:
        raise _KdfDerivationError(
            f"KDF_DERIVATION_FAILED: unsupported passphrase alg {passphrase_block['alg']}"
        )
    # Pre-KDF input cap: reject an oversized raw passphrase before normalization
    # or Argon2id, so it cannot drive unbounded pre-KDF work. Byte length of the
    # raw UTF-8 encoding, not code-point count.
    raw_passphrase_bytes = len(passphrase.encode("utf-8"))
    if raw_passphrase_bytes > MAX_PASSPHRASE_INPUT_BYTES:
        raise _KdfDerivationError(
            f"KDF_DERIVATION_FAILED: passphrase length {raw_passphrase_bytes} bytes exceeds "
            f"the maximum {MAX_PASSPHRASE_INPUT_BYTES} bytes"
        )
    password = _normalize_passphrase(passphrase)
    try:
        cek = _derive_kek(password, passphrase_block)
    except (ValueError, KeyError, TypeError) as cause:
        raise _KdfDerivationError(f"KDF_DERIVATION_FAILED: {cause}") from cause
    if enc["aead"] != "xchacha20-poly1305":
        raise _KdfDerivationError(f"KDF_DERIVATION_FAILED: unsupported aead {enc['aead']}")
    nonce = enc["nonce"]
    # Reject a payload at or above the XChaCha20-Poly1305 single-shot bound
    # before invoking the AEAD, matching the slots path.
    if len(ciphertext) >= MAX_SEALED_PLAINTEXT + 16:
        raise _KdfDerivationError(
            f"KDF_DERIVATION_FAILED: ciphertext length={len(ciphertext)} is at or above "
            f"the single-shot payload bound"
        )
    # Content is opened under a payload_key derived from the CEK with the
    # structured passphrase-path AAD; the CEK never keys the content AEAD
    # directly.
    payload_key = hkdf_sha256(
        ikm=cek,
        salt=nonce,
        info=CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
        length=32,
    )
    aad = _ad_content_passphrase(nonce, passphrase_block)
    return xchacha20_poly1305_decrypt(payload_key, nonce, aad, ciphertext)


def _derive_kek(password: bytes, kdf: PassphraseKdf) -> bytes:
    salt = kdf["salt"]
    params = kdf["params"]
    return argon2id_v13(password, salt, params["m"], params["t"], params["p"], 32)


def _recompute_hashes(item: Item, plaintext: bytes) -> bool:
    # The recovered plaintext is "hash-ok" only when there is at least one entry
    # AND every entry names a hash we can recompute AND its digest matches. An
    # empty map, or any entry whose alg we don't recognise, is NOT silently
    # treated as a pass.
    entries = list(item["hashes"].items())
    if len(entries) == 0:
        return False
    for alg, digest in entries:
        if alg == "sha2-256":
            if not compare_ct(sha256(plaintext), digest):
                return False
        elif alg == "blake2b-256":
            if not compare_ct(blake2b_256(plaintext), digest):
                return False
        else:
            return False
    return True


__all__ = ["try_decryptions"]
