from __future__ import annotations

import re
import unicodedata
from typing import Final

from cardanowall._crypto.aead import (
    AeadVerificationError,
    xchacha20_poly1305_decrypt,
)
from cardanowall._crypto.compare_ct import compare_ct
from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall._crypto.kdf import argon2id_v13
from cardanowall._crypto.sealed_poe import (
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

# The passphrase-path content-AEAD AAD is the EMPTY byte string `h''`. (The
# sealed-recipient path uses `nonce || slots_mac`; that binding lives inside
# `ecies_sealed_poe_unwrap`.)
_EMPTY_AAD: Final[bytes] = b""


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
            out.append(
                VerifyItemDecryption(item_index=idx, verdict=failure[0], reason=failure[1])
            )
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


def _decrypt_passphrase(enc: EncryptionEnvelope, ciphertext: bytes, passphrase: str) -> bytes:
    passphrase_block = enc.get("passphrase")
    if passphrase_block is None:
        raise _KdfDerivationError("KDF_DERIVATION_FAILED: no passphrase block")
    if passphrase_block["alg"] != _PASSPHRASE_KDF_ARGON2ID:
        raise _KdfDerivationError(
            f"KDF_DERIVATION_FAILED: unsupported passphrase alg {passphrase_block['alg']}"
        )
    # Passphrase normalisation: NFKC -> collapse whitespace -> trim -> UTF-8.
    normalised = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", passphrase)).strip()
    password = normalised.encode("utf-8")
    try:
        cek = _derive_kek(password, passphrase_block)
    except (ValueError, KeyError, TypeError) as cause:
        raise _KdfDerivationError(f"KDF_DERIVATION_FAILED: {cause}") from cause
    if enc["aead"] != "xchacha20-poly1305":
        raise _KdfDerivationError(f"KDF_DERIVATION_FAILED: unsupported aead {enc['aead']}")
    return xchacha20_poly1305_decrypt(cek, enc["nonce"], _EMPTY_AAD, ciphertext)


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
