"""Label 309 v1 record encoder.

Produces canonical CBOR bytes per RFC 8949 §4.2.1 deterministic encoding —
definite lengths, bytewise-lexicographically sorted map keys, no duplicate
keys, shortest-form integers. The canonical layer
(``cardanowall._crypto.cbor``) owns those rules, so this module's job is only
to project the typed record onto the CBOR value algebra.

That projection is the identity: under the Label 309 wire shapes every record
field already IS its CBOR value — ``hashes`` is a text-keyed map of
byte-string digests, each URI is a single text string, ``kem_ct`` /
``cose_sign1`` / ``cose_key`` are single byte strings, and the canonical
encoder derives map-key order itself. The only transformation performed here
is, for the signing body, removing ``sigs``. Extension keys are part of the
canonical map and of the signed record body, so they pass through verbatim —
dropping them would break cross-language tx-identity and record-level COSE
signatures.

Round-trip property: for every record ``r`` the validator accepts,
``validate(encode_poe_record(r))`` succeeds and the decoded record is ``r``
(modulo CBOR-canonical key order).
"""

from __future__ import annotations

from typing import cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor

from .schema import PoeRecord


def encode_poe_record(record: PoeRecord) -> bytes:
    """Canonical CBOR bytes of the full record body — the bytes the
    chunk-array transport carries on chain."""
    return encode_canonical_cbor(cast("CanonicalCborValue", dict(record)))


def encode_record_body_for_signing(record: PoeRecord) -> bytes:
    """Canonical CBOR bytes of the record body **with ``sigs`` removed** — the
    body a record-level signature covers.

    Producers prepend the 25-byte UTF-8 domain prefix
    ``cardano-poe-record-sig-v1`` before invoking Ed25519 (the
    ``build_label309_sig_structure`` helper handles the prefix and the
    ``Sig_structure`` wrapping).
    """
    body = {key: value for key, value in record.items() if key != "sigs"}
    return encode_canonical_cbor(cast("CanonicalCborValue", body))


__all__ = ["encode_poe_record", "encode_record_body_for_signing"]
