"""Behavioural coverage for the Label 309 inclusion-certificate module.

These tests exercise the round-trip (build -> re-verify), tamper detection, the
single-leaf and absent-target edge cases, structural-misuse rejection, and the
COSE/RFC-9162 CBOR shape — asserting state and bytes, never copy.

The fixed known-vector at the bottom is the parity anchor, loaded from the
shared cross-SDK fixture: the TypeScript and Rust certificate twins reproduce
the same root hex, the same bare IETF inclusion-proof CBOR, and the same COSE
CBOR hex byte-for-byte from the same deterministic leaves/anchor inputs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cardanowall._crypto.cbor import decode_canonical_cbor
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall.certificate import (
    CertificateAnchor,
    CertificateMerkle,
    CertificateTarget,
    build_inclusion_certificate,
    encode_cose_inclusion_proof,
    encode_ietf_inclusion_proof,
    verify_inclusion_certificate,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _leaf_of(i: int) -> bytes:
    # Deterministic leaf: SHA-256 of a single byte. Reused by the parity vector.
    return hashlib.sha256(bytes([i])).digest()


def _make_leaves(n: int) -> list[bytes]:
    return [_leaf_of(i) for i in range(n)]


def _anchor_for(network: str = "mainnet") -> CertificateAnchor:
    return CertificateAnchor(
        network=network,
        tx_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        block_time=1_718_539_200,
        block_height=12_345_678,
        slot=123_456_789,
    )


def _merkle_for(leaves: list[bytes]) -> CertificateMerkle:
    return CertificateMerkle(
        tree_alg="rfc9162-sha256",
        root=merkle_sha2_256_root(leaves),
        tree_size=len(leaves),
    )


# --- build + verify round-trip -------------------------------------------------


def test_builds_and_reverifies_several_targets_to_ok_true() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    targets = [
        CertificateTarget(leaf=leaves[0], label="first"),
        CertificateTarget(leaf=leaves[3], leaf_alg="sha2-256"),
        CertificateTarget(leaf=leaves[7]),
    ]

    cert = build_inclusion_certificate(
        anchor=_anchor_for(), merkle=merkle, leaves=leaves, targets=targets
    )

    assert len(cert["items"]) == 3
    assert all(it["verified"] for it in cert["items"])
    assert [it["index"] for it in cert["items"]] == [0, 3, 7]
    # Hex is lowercase, 64-char values.
    assert all(c in "0123456789abcdef" for c in cert["merkle"]["root"])
    assert len(cert["merkle"]["root"]) == 64
    assert len(cert["items"][0]["leaf"]) == 64

    # anchor snake_case mapping with derived ISO time.
    assert cert["anchor"]["tx_hash"] == _anchor_for().tx_hash
    assert cert["anchor"]["metadata_label"] == 309
    assert cert["anchor"]["block_time_iso"] == "2024-06-16T12:00:00.000Z"
    assert cert["anchor"]["block_height"] == 12_345_678

    # Independent re-verification recomputes every proof against the root.
    result = verify_inclusion_certificate(cert)
    assert result.ok is True
    assert [v.verified for v in result.items] == [True, True, True]
    assert [v.index for v in result.items] == [0, 3, 7]
    assert result.anchor_claim.tx_hash == _anchor_for().tx_hash
    assert result.anchor_claim.block_time == 1_718_539_200


def test_omits_optional_anchor_fields_when_absent() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    anchor = CertificateAnchor(
        network="preprod",
        tx_hash="ff" * 32,
        block_time=1_700_000_000,
    )
    cert = build_inclusion_certificate(
        anchor=anchor, merkle=merkle, leaves=leaves, targets=[CertificateTarget(leaf=leaves[1])]
    )
    assert "block_height" not in cert["anchor"]
    assert "slot" not in cert["anchor"]
    assert "confirmations_at_generation" not in cert["anchor"]
    assert "explorer_urls" not in cert["anchor"]


def test_verification_block_asserts_issuer_independence() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[1], leaf_alg="sha2-256")],
    )

    verification = cert["verification"]
    # Independently verifiable: the proof recomputes from public data, so the
    # issuer is never a trusted party.
    assert verification["requires_issuer_trust"] is False
    # The exact independent-tool list every conforming producer must emit.
    assert verification["independent_tools"] == [
        "cardanowall certificate verify <file>",
        "cardanowall merkle verify (per item)",
        "any RFC 9162 / COSE verifiable-data-structure verifier",
    ]
    # Time is asserted by the chain via public explorers, never by the issuer.
    assert (
        verification["time_asserted_by"] == "Cardano blockchain (block time), via public explorers"
    )
    # The method names the RFC 9162 recompute-and-compare procedure.
    assert "RFC 9162" in verification["method"]
    assert "recompute the Merkle root" in verification["method"]


# --- tamper detection ----------------------------------------------------------


def test_flips_item_to_false_when_sibling_corrupted() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[2])],
    )

    sibling = bytearray(bytes.fromhex(cert["items"][0]["proof"][0]))
    sibling[0] ^= 0xFF
    tampered = dict(cert)
    item = dict(cert["items"][0])
    item["proof"] = [sibling.hex(), *cert["items"][0]["proof"][1:]]
    tampered["items"] = [item]

    result = verify_inclusion_certificate(tampered)  # type: ignore[arg-type]
    assert result.items[0].verified is False
    assert result.ok is False


def test_flips_item_to_false_when_leaf_corrupted() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[5])],
    )

    bad = bytearray(bytes.fromhex(cert["items"][0]["leaf"]))
    bad[31] ^= 0x01
    item = dict(cert["items"][0])
    item["leaf"] = bad.hex()
    tampered = dict(cert)
    tampered["items"] = [item]

    result = verify_inclusion_certificate(tampered)  # type: ignore[arg-type]
    assert result.items[0].verified is False
    assert result.ok is False


def test_flips_every_item_to_false_when_root_corrupted() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0]), CertificateTarget(leaf=leaves[1])],
    )

    bad = bytearray(bytes.fromhex(cert["merkle"]["root"]))
    bad[0] ^= 0xFF
    merkle_block = dict(cert["merkle"])
    merkle_block["root"] = bad.hex()
    tampered = dict(cert)
    tampered["merkle"] = merkle_block

    result = verify_inclusion_certificate(tampered)  # type: ignore[arg-type]
    assert all(v.verified is False for v in result.items)
    assert result.ok is False


# --- edge cases ----------------------------------------------------------------


def test_proves_single_leaf_tree_with_empty_proof() -> None:
    leaves = _make_leaves(1)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0])],
    )
    assert cert["items"][0]["proof"] == []
    assert cert["items"][0]["verified"] is True
    assert verify_inclusion_certificate(cert).ok is True


def test_emits_non_throwing_miss_for_absent_target() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    stranger = hashlib.sha256(bytes([0xAA, 0xBB])).digest()  # not any _leaf_of(i)

    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[
            CertificateTarget(leaf=leaves[1]),
            CertificateTarget(leaf=stranger, label="missing.pdf"),
        ],
    )

    assert len(cert["items"]) == 2
    assert cert["items"][0]["verified"] is True

    miss = cert["items"][1]
    assert miss["verified"] is False
    assert isinstance(miss["error"], str)
    assert len(miss["error"]) > 0
    assert miss["label"] == "missing.pdf"
    # A miss is not encoded to CBOR: its index is -1, no proof.
    assert miss["index"] == -1

    result = verify_inclusion_certificate(cert)
    assert result.ok is False
    assert result.items[1].verified is False
    assert result.items[1].error == miss["error"]


# --- structural misuse raises at build time ------------------------------------


def test_raises_on_root_not_32_bytes() -> None:
    leaves = _make_leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=_anchor_for(),
            merkle=CertificateMerkle(tree_alg="rfc9162-sha256", root=b"\x00" * 31, tree_size=4),
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


def test_raises_when_tree_size_mismatches_leaves() -> None:
    leaves = _make_leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=_anchor_for(),
            merkle=CertificateMerkle(
                tree_alg="rfc9162-sha256", root=merkle_sha2_256_root(leaves), tree_size=5
            ),
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


def test_raises_on_unsupported_tree_alg() -> None:
    leaves = _make_leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=_anchor_for(),
            merkle=CertificateMerkle(
                tree_alg="blake2b-merkle", root=merkle_sha2_256_root(leaves), tree_size=4
            ),
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


def test_raises_when_declared_root_does_not_match_leaves() -> None:
    leaves = _make_leaves(4)
    wrong_root = merkle_sha2_256_root(list(reversed(_make_leaves(4))))
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=_anchor_for(),
            merkle=CertificateMerkle(tree_alg="rfc9162-sha256", root=wrong_root, tree_size=4),
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


# --- verify rejects unsupported certificates without raising -------------------


def _base_cert() -> dict[str, Any]:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    return dict(
        build_inclusion_certificate(
            anchor=_anchor_for(),
            merkle=merkle,
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )
    )


def test_rejects_unknown_format_echoing_anchor() -> None:
    base = _base_cert()
    base["format"] = "something-else"
    result = verify_inclusion_certificate(base)  # type: ignore[arg-type]
    assert result.ok is False
    assert isinstance(result.error, str)
    assert result.items == ()
    assert result.anchor_claim.tx_hash == _anchor_for().tx_hash


def test_rejects_unsupported_tree_alg() -> None:
    base = _base_cert()
    base["merkle"] = {**base["merkle"], "tree_alg": "rfc9162-blake2b"}
    result = verify_inclusion_certificate(base)  # type: ignore[arg-type]
    assert result.ok is False
    assert isinstance(result.error, str)


def test_rejects_forged_oversized_tree_size_without_raising() -> None:
    base = _base_cert()
    base["merkle"] = {**base["merkle"], "tree_size": 0x1_0000_0000}
    result = verify_inclusion_certificate(base)  # type: ignore[arg-type]
    assert result.ok is False
    assert isinstance(result.error, str)


def test_rejects_item_with_out_of_range_index_without_raising() -> None:
    base = _base_cert()
    item = {**base["items"][0], "index": 999}
    base["items"] = [item]
    result = verify_inclusion_certificate(base)  # type: ignore[arg-type]
    assert result.ok is False
    assert result.items[0].verified is False
    assert isinstance(result.items[0].error, str)


def test_rejects_anchor_not_cardano_label_309_echoing_claim() -> None:
    base = _base_cert()
    wrong_chain = dict(base)
    wrong_chain["anchor"] = {**base["anchor"], "chain": "bitcoin"}
    rc = verify_inclusion_certificate(wrong_chain)  # type: ignore[arg-type]
    assert rc.ok is False
    assert isinstance(rc.error, str)
    assert rc.anchor_claim.chain == "bitcoin"

    wrong_label = dict(base)
    wrong_label["anchor"] = {**base["anchor"], "metadata_label": 721}
    rl = verify_inclusion_certificate(wrong_label)  # type: ignore[arg-type]
    assert rl.ok is False
    assert isinstance(rl.error, str)
    assert rl.anchor_claim.metadata_label == 721


# --- COSE / IETF CBOR shape ----------------------------------------------------


def test_encodes_decodable_ietf_inclusion_proof_and_full_cose_map() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    anchor = _anchor_for()
    cert = build_inclusion_certificate(
        anchor=anchor,
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[6], leaf_alg="sha2-256")],
    )
    item = cert["items"][0]

    # The bare IETF inclusion-proof is a `bstr .cbor [...]`: decode it once as a
    # byte string, then decode those bytes as [tree_size, leaf_index, siblings].
    bstr_bytes = encode_ietf_inclusion_proof(item, merkle)
    inner_array_bytes = decode_canonical_cbor(bstr_bytes)
    assert isinstance(inner_array_bytes, bytes)
    inner = decode_canonical_cbor(inner_array_bytes)
    assert isinstance(inner, list)
    assert inner[0] == merkle.tree_size
    assert inner[1] == item["index"]
    siblings = inner[2]
    assert [s.hex() for s in siblings] == item["proof"]

    # Full COSE map.
    cose_bytes = encode_cose_inclusion_proof(item, merkle, anchor)
    cose = decode_canonical_cbor(cose_bytes)
    assert isinstance(cose, dict)
    assert cose["vds"] == 1
    assert cose["root"].hex() == cert["merkle"]["root"]
    assert cose["leaf"].hex() == item["leaf"]
    assert cose["leaf_alg"] == "sha2-256"

    a = cose["anchor"]
    assert a["chain"] == "cardano"
    assert a["network"] == "mainnet"
    assert a["metadata_label"] == 309
    assert a["tx_hash"].hex() == anchor.tx_hash

    # The map's inclusion_proof field is the same bstr the bare IETF helper
    # returns: decoding the map field yields the array bytes; the bare helper's
    # bstr decodes to the identical bytes.
    assert cose["inclusion_proof"].hex() == inner_array_bytes.hex()
    # And the on-wire bstr (header + contents) appears verbatim inside the COSE
    # map bytes — byte-identical to the standalone IETF helper output.
    assert bstr_bytes.hex() in cose_bytes.hex()


def test_refuses_to_encode_non_inclusion_item() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    stranger = hashlib.sha256(bytes([0x99, 0x88])).digest()
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0]), CertificateTarget(leaf=stranger)],
    )
    proven = cert["items"][0]
    miss = cert["items"][1]

    # A miss has an error and verified=False — both encoders refuse it.
    with pytest.raises(TypeError):
        encode_cose_inclusion_proof(miss, merkle, _anchor_for())
    with pytest.raises(TypeError):
        encode_ietf_inclusion_proof(miss, merkle)

    # An otherwise-proven item forced to verified=False is also refused.
    with pytest.raises(TypeError):
        encode_cose_inclusion_proof({**proven, "verified": False}, merkle, _anchor_for())

    # An out-of-range index on a proven-shaped item is refused.
    with pytest.raises(TypeError):
        encode_cose_inclusion_proof({**proven, "index": 4}, merkle, _anchor_for())


def test_omits_leaf_alg_from_cose_map_when_item_has_none() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0])],
    )
    cose = decode_canonical_cbor(
        encode_cose_inclusion_proof(cert["items"][0], merkle, _anchor_for())
    )
    assert isinstance(cose, dict)
    assert "leaf_alg" not in cose


# --- hex case-insensitivity and malformed-hex handling -------------------------


def _uppercase_hex_fields(cert: dict[str, Any]) -> dict[str, Any]:
    out = dict(cert)
    out["merkle"] = {**cert["merkle"], "root": cert["merkle"]["root"].upper()}
    out["items"] = [
        {**it, "leaf": it["leaf"].upper(), "proof": [s.upper() for s in it["proof"]]}
        for it in cert["items"]
    ]
    return out


def test_verifies_uppercase_hex_identically_to_lowercase() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0]), CertificateTarget(leaf=leaves[5])],
    )

    lower = verify_inclusion_certificate(cert)
    upper = verify_inclusion_certificate(_uppercase_hex_fields(dict(cert)))  # type: ignore[arg-type]

    assert upper.ok is True
    assert upper.ok == lower.ok
    assert [v.verified for v in upper.items] == [v.verified for v in lower.items]
    assert [v.verified for v in upper.items] == [True, True]


def test_verify_returns_false_without_raising_on_hex_with_embedded_space() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[1])],
    )
    leaf_hex = cert["items"][0]["leaf"]
    item = {**cert["items"][0], "leaf": f"{leaf_hex[:10]} {leaf_hex[11:]}"}
    spaced = dict(cert)
    spaced["items"] = [item]

    result = verify_inclusion_certificate(spaced)  # type: ignore[arg-type]
    assert result.ok is False
    assert result.items[0].verified is False
    assert isinstance(result.items[0].error, str)


def test_cose_accepts_uppercase_hex_and_emits_same_bytes() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    anchor = _anchor_for()
    cert = build_inclusion_certificate(
        anchor=anchor,
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[2], leaf_alg="sha2-256")],
    )
    lower_cose = encode_cose_inclusion_proof(cert["items"][0], merkle, anchor)
    upper_item = {
        **cert["items"][0],
        "leaf": cert["items"][0]["leaf"].upper(),
        "proof": [s.upper() for s in cert["items"][0]["proof"]],
    }
    upper_anchor = replace(anchor, tx_hash=anchor.tx_hash.upper())
    upper_cose = encode_cose_inclusion_proof(upper_item, merkle, upper_anchor)  # type: ignore[arg-type]
    assert upper_cose == lower_cose


# --- wrong-length hex fields match the canonical TypeScript result shape -------


def test_wrong_length_root_keeps_items_no_cert_error_ok_false() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0]), CertificateTarget(leaf=leaves[3])],
    )
    # 31 bytes of valid hex — decodes fine but is not a 32-byte root.
    short_root = cert["merkle"]["root"][:62]
    forged = dict(cert)
    forged["merkle"] = {**cert["merkle"], "root": short_root}
    result = verify_inclusion_certificate(forged)  # type: ignore[arg-type]
    assert result.ok is False
    assert result.error is None
    assert len(result.items) == 2
    assert all(v.verified is False for v in result.items)
    assert all(v.error is None for v in result.items)


def test_wrong_length_sibling_keeps_item_no_item_error_ok_false() -> None:
    leaves = _make_leaves(8)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[2])],
    )
    sib = cert["items"][0]["proof"][0]
    item = {**cert["items"][0], "proof": [sib[:62], *cert["items"][0]["proof"][1:]]}
    forged = dict(cert)
    forged["items"] = [item]
    result = verify_inclusion_certificate(forged)  # type: ignore[arg-type]
    assert result.ok is False
    assert result.error is None
    assert len(result.items) == 1
    assert result.items[0].verified is False
    assert result.items[0].error is None


# --- block_time range guard in the builder -------------------------------------


def test_builder_renders_fixed_iso_for_in_range_epoch() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_anchor_for(),
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0])],
    )
    assert cert["anchor"]["block_time_iso"] == "2024-06-16T12:00:00.000Z"


def test_builder_raises_on_negative_block_time() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=replace(_anchor_for(), block_time=-1),
            merkle=merkle,
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


def test_builder_raises_on_block_time_beyond_year_9999() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    with pytest.raises(ValueError):
        build_inclusion_certificate(
            anchor=replace(_anchor_for(), block_time=253_402_300_800),
            merkle=merkle,
            leaves=leaves,
            targets=[CertificateTarget(leaf=leaves[0])],
        )


# --- fixed known vector — cross-language parity anchor -------------------------

# The parity vector is loaded from the shared cross-SDK fixture rather than
# inlined: a deterministic 4-leaf tree where leaf_i = SHA-256(<single byte i>),
# a fixed Cardano mainnet anchor, and the item at index 2 carrying leaf_alg
# "sha2-256". The root hex, the bare IETF inclusion-proof CBOR, and the COSE
# CBOR are the byte-parity anchors: the TypeScript and Rust certificate twins
# reproduce these bytes byte-for-byte from the same inputs. If a built value
# diverges from the fixture, the port has drifted — fix the port, not the vector.
_FIXED_GENERATED_AT = "2026-06-16T12:00:00.000Z"

_CERT_KAT = json.loads((FIXTURES / "certificate" / "inclusion-certificate-kat.json").read_text())
_CERT_VECTOR = _CERT_KAT["vectors"][0]
_CERT_INPUT = _CERT_VECTOR["input"]
_CERT_EXPECTED = _CERT_VECTOR["expected"]

_VECTOR_ANCHOR = CertificateAnchor(
    network=_CERT_INPUT["anchor"]["network"],
    tx_hash=_CERT_INPUT["anchor"]["tx_hash"],
    block_time=_CERT_INPUT["anchor"]["block_time"],
)
_VECTOR_LEAVES = [bytes.fromhex(h) for h in _CERT_INPUT["leaves"]]
_VECTOR_TARGET_INDEX = _CERT_INPUT["target"]["index"]
_VECTOR_TARGET_LEAF_ALG = _CERT_INPUT["target"].get("leaf_alg")


def test_reproduces_expected_root_and_cose_cbor_bytes_exactly() -> None:
    leaves = _VECTOR_LEAVES
    merkle = CertificateMerkle(
        tree_alg=_CERT_KAT["tree_alg"],
        root=merkle_sha2_256_root(leaves),
        tree_size=_CERT_INPUT["tree_size"],
    )
    assert merkle.root.hex() == _CERT_EXPECTED["root"]

    cert = build_inclusion_certificate(
        anchor=_VECTOR_ANCHOR,
        merkle=merkle,
        leaves=leaves,
        targets=[
            CertificateTarget(leaf=leaves[_VECTOR_TARGET_INDEX], leaf_alg=_VECTOR_TARGET_LEAF_ALG)
        ],
        generated_at=_FIXED_GENERATED_AT,
    )
    item = cert["items"][0]

    # The bare IETF inclusion proof is the `bstr .cbor` byte string the encoder
    # returns (a CBOR byte string wrapping the `[tree_size, leaf_index,
    # [siblings]]` array). The shared vector pins that byte string directly.
    ietf_hex = encode_ietf_inclusion_proof(item, merkle).hex()
    assert ietf_hex == _CERT_EXPECTED["ietf_inclusion_proof_cbor_hex"]
    assert item["proof"] == _CERT_EXPECTED["inclusion_path"]
    assert item["leaf"] == _CERT_EXPECTED["leaf"]

    cose = encode_cose_inclusion_proof(item, merkle, _VECTOR_ANCHOR)
    assert cose.hex() == _CERT_EXPECTED["cose_inclusion_proof_cbor_hex"]


def test_emits_reproducible_certificate_with_normative_item_key_order() -> None:
    leaves = _make_leaves(4)
    merkle = _merkle_for(leaves)
    cert = build_inclusion_certificate(
        anchor=_VECTOR_ANCHOR,
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[2], leaf_alg="sha2-256", label="contract.pdf")],
        generated_at=_FIXED_GENERATED_AT,
    )

    assert cert["generated_at"] == _FIXED_GENERATED_AT
    # Field-level JSON parity: item keys appear in the normative order.
    assert list(cert["items"][0].keys()) == [
        "leaf",
        "leaf_alg",
        "index",
        "proof",
        "verified",
        "label",
    ]
    # A target without leaf_alg/label omits exactly those keys, order intact.
    cert_plain = build_inclusion_certificate(
        anchor=_VECTOR_ANCHOR,
        merkle=merkle,
        leaves=leaves,
        targets=[CertificateTarget(leaf=leaves[0])],
        generated_at=_FIXED_GENERATED_AT,
    )
    assert list(cert_plain["items"][0].keys()) == ["leaf", "index", "proof", "verified"]
