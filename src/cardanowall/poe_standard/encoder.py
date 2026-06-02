from __future__ import annotations

from typing import cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor

from .schema import (
    EncryptionEnvelope,
    Item,
    MerkleCommit,
    PoeRecord,
    SigEntry,
    Slot,
)

# Canonical-CBOR producer for CIP-309 v1 records. Output bytes are RFC 8949
# §4.2.1 deterministic (definite-length, sorted bytewise-lex map keys, no
# duplicates) — `encode_canonical_cbor` delegates to `cbor2.dumps(...,
# canonical=True)` which already enforces those rules.
#
# Round-trip property (held by `validate(encode(r)).record == r` for every
# valid `r`): the encoder MUST emit the record fields exactly as the
# validator expects them — no field renames, no synthetic wrapper keys.


def encode_poe_record(record: PoeRecord) -> bytes:
    """Encode a `PoeRecord` to canonical CBOR."""
    return encode_canonical_cbor(_record_to_cbor_value(record, include_sigs=True))


def encode_record_body_for_signing(record: PoeRecord) -> bytes:
    """Encode the record body MINUS `sigs` to canonical CBOR (the signing body).

    Producers (in-process or off-host) prepend the 25-byte UTF-8 domain prefix
    `cardano-poe-record-sig-v1` before invoking Ed25519; the CIP-309 Sig_structure
    builder (`build_cip309_sig_structure`) handles that step internally.
    """
    return encode_canonical_cbor(_record_to_cbor_value(record, include_sigs=False))


# Top-level base keys with bespoke serialization. Every other key in the
# record map is an extension key and is copied through verbatim —
# extension keys are part of the canonical map and of the signed record body,
# so dropping them would break cross-language tx-identity and record-level
# COSE signatures.
_BASE_KEYS = frozenset({"v", "items", "merkle", "supersedes", "sigs", "crit"})


def _record_to_cbor_value(record: PoeRecord, *, include_sigs: bool = True) -> CanonicalCborValue:
    out: dict[str | int, CanonicalCborValue] = {"v": record["v"]}
    if "items" in record:
        out["items"] = [_item_to_cbor_value(it) for it in record["items"]]
    if "merkle" in record:
        out["merkle"] = [_merkle_commit_to_cbor_value(m) for m in record["merkle"]]
    if include_sigs and "sigs" in record:
        out["sigs"] = [_sig_entry_to_cbor_value(s) for s in record["sigs"]]
    if "crit" in record:
        out["crit"] = list(record["crit"])
    if "supersedes" in record:
        out["supersedes"] = record["supersedes"]
    # Preserve extension keys verbatim. Canonical-CBOR key sort handles
    # ordering, so insertion order here is irrelevant to the wire bytes.
    for key, value in record.items():
        if key in _BASE_KEYS:
            continue
        out[key] = cast(CanonicalCborValue, value)
    return out


def _item_to_cbor_value(item: Item) -> CanonicalCborValue:
    out: dict[str | int, CanonicalCborValue] = {
        "hashes": cast(CanonicalCborValue, dict(item["hashes"])),
    }
    if "uris" in item:
        out["uris"] = [list(chunks) for chunks in item["uris"]]
    if "enc" in item:
        out["enc"] = _envelope_to_cbor_value(item["enc"])
    return out


def _envelope_to_cbor_value(enc: EncryptionEnvelope) -> CanonicalCborValue:
    out: dict[str | int, CanonicalCborValue] = {
        "scheme": enc["scheme"],
        "aead": enc["aead"],
        "nonce": enc["nonce"],
    }
    if "kem" in enc:
        out["kem"] = enc["kem"]
    if "slots" in enc:
        out["slots"] = [_slot_to_cbor_value(s) for s in enc["slots"]]
    if "slots_mac" in enc:
        out["slots_mac"] = enc["slots_mac"]
    if "passphrase" in enc:
        pp = enc["passphrase"]
        out["passphrase"] = {
            "alg": pp["alg"],
            "salt": pp["salt"],
            "params": cast(CanonicalCborValue, dict(pp["params"])),
        }
    return out


def _slot_to_cbor_value(slot: Slot) -> CanonicalCborValue:
    # KEM-driven slot serialization. The canonical encoder sorts map keys by
    # length-then-bytewise (RFC 8949 §4.2.1), so it emits `wrap` (4-byte key)
    # before `kem_ct` (6-byte key) and `epk` (3-byte key) before `wrap`
    # automatically — insertion order here is irrelevant to the wire bytes.
    #
    #   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }`
    #   - mlkem768x25519: `{ kem_ct: [ bstr, ... ], wrap: bstr(48) }` — `kem_ct`
    #     is the already-chunked array (NOT re-chunked here), so the bytes match
    #     what crypto-core committed to `slots_mac` byte-for-byte.
    if "kem_ct" in slot:
        return cast(
            CanonicalCborValue,
            {"kem_ct": list(slot["kem_ct"]), "wrap": slot["wrap"]},
        )
    return cast(CanonicalCborValue, {"epk": slot["epk"], "wrap": slot["wrap"]})


def _merkle_commit_to_cbor_value(commit: MerkleCommit) -> CanonicalCborValue:
    out: dict[str | int, CanonicalCborValue] = {
        "alg": commit["alg"],
        "root": commit["root"],
        "leaf_count": commit["leaf_count"],
    }
    if "uris" in commit:
        out["uris"] = [list(chunks) for chunks in commit["uris"]]
    return out


def _sig_entry_to_cbor_value(sig: SigEntry) -> CanonicalCborValue:
    out: dict[str | int, CanonicalCborValue] = {
        "cose_sign1": list(sig["cose_sign1"]),
    }
    if "cose_key" in sig:
        out["cose_key"] = list(sig["cose_key"])
    return out


__all__ = ["encode_poe_record", "encode_record_body_for_signing"]
