"""Verifier integration tests.

Covers the full pipeline: verdict three-state, exit-code mapping, profile
boundary, Merkle root recomputation. Tests stub the Cardano gateway chain
via `fetch_outbound` so they run hermetic.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, cast

import cbor2

from cardanowall._crypto.cbor import (
    CanonicalCborValue,
    encode_canonical_cbor,
)
from cardanowall._crypto.cose_sign1 import cose_sign1_build
from cardanowall._crypto.merkle_leaves_list import encode_leaves_list
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall._crypto.sig import get_public_key_ed25519
from cardanowall.poe_standard import (
    PoeRecord,
    chunk_bytes,
    encode_poe_record,
)
from cardanowall.verifier import (
    FetchOutboundOptions,
    FetchOutboundResult,
    VerifyTxInput,
    verify_tx,
)
from cardanowall.verifier.signatures import CARDANO_POE_SIG_DOMAIN_PREFIX

TX_HASH = "a" * 64


def _wrap_metadata_309(record_bytes: bytes) -> bytes:
    """Wrap a label-309 metadata payload in a minimal post-Conway tx CBOR."""
    metadata_map = {309: cbor2.loads(record_bytes)}
    aux_data = {0: metadata_map}
    # Post-Conway tx shape: [body, witness_set, is_valid, auxiliary_data].
    tx_arr: list[Any] = [{}, {}, True, aux_data]
    return cbor2.dumps(tx_arr)


def _mk_koios_routes(tx_cbor: bytes, num_confirmations: int) -> dict[str, Any]:
    return {
        "https://api.koios.rest/api/v1/tx_cbor": FetchOutboundResult(
            status=200,
            bytes=json.dumps([{"tx_hash": TX_HASH, "cbor": tx_cbor.hex()}]).encode("utf-8"),
            duration_ms=5,
        ),
        "https://api.koios.rest/api/v1/tx_info": FetchOutboundResult(
            status=200,
            bytes=json.dumps(
                [
                    {
                        "tx_hash": TX_HASH,
                        "num_confirmations": num_confirmations,
                        "tx_timestamp": 1700000000,
                        "absolute_slot": 12345,
                    }
                ]
            ).encode("utf-8"),
            duration_ms=5,
        ),
    }


def _mk_fetch(routes: dict[str, Any]) -> Any:
    async def stub(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        for prefix, result in routes.items():
            if url.startswith(prefix):
                return cast(FetchOutboundResult, result)
        raise RuntimeError(f"unexpected url: {url}")

    return stub


def _minimal_hash_only_record() -> PoeRecord:
    return cast(
        PoeRecord,
        {"v": 1, "items": [{"hashes": {"sha2-256": b"\x00" * 32}}]},
    )


# ---- Verdict / exit-code transitions ----------------------------------------


def test_happy_path_yields_valid_verdict_exit_code_0() -> None:
    record_bytes = encode_poe_record(_minimal_hash_only_record())
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
            )
        )
    )
    assert result.verdict == "valid"
    assert result.exit_code == 0
    assert result.metadata_present is True
    assert result.validation.valid is True
    assert result.profile == "recipient-sealed"


def test_insufficient_confirmations_yields_pending_verdict_exit_code_3() -> None:
    record_bytes = encode_poe_record(_minimal_hash_only_record())
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=5))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
                confirmation_depth_threshold=15,
            )
        )
    )
    assert result.verdict == "pending"
    assert result.exit_code == 3
    issues = result.validation.issues
    assert any(i.code == "INSUFFICIENT_CONFIRMATIONS" for i in issues)


def test_provider_unavailable_yields_failed_exit_code_2() -> None:
    async def fail_fn(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        raise RuntimeError("simulated_network_error")

    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fail_fn,
            )
        )
    )
    assert result.verdict == "failed"
    assert result.exit_code == 2
    assert any(i.code == "PROVIDER_UNAVAILABLE" for i in result.validation.issues)


def test_metadata_not_found_yields_failed_exit_code_1() -> None:
    # Wrap a tx with NO label-309 metadata (empty aux map).
    tx_arr: list[Any] = [{}, {}, True, {0: {}}]
    tx_cbor = cbor2.dumps(tx_arr)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
            )
        )
    )
    assert result.verdict == "failed"
    assert result.exit_code == 1
    assert any(i.code == "METADATA_NOT_FOUND" for i in result.validation.issues)


# ---- Profile boundary --------------------------------------------------------


def test_core_profile_sees_sigs_emits_out_of_profile_skipped_info() -> None:
    """A `core` verifier reading a record carrying `sigs[]` MUST report the
    field as info-severity OUT_OF_PROFILE_SKIPPED and keep verdict=valid for a
    hash-only structural pass.
    """
    seed = bytes([7]) * 32
    pub = get_public_key_ed25519(seed)
    record_base = _minimal_hash_only_record()
    body_bytes = encode_canonical_cbor(
        cast(CanonicalCborValue, {k: v for k, v in record_base.items() if k != "sigs"})
    )
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + body_bytes
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record_with_sigs: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": chunk_bytes(cose)}]},
    )
    record_bytes = encode_poe_record(record_with_sigs)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                profile="core",
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
            )
        )
    )
    assert result.verdict == "valid", "core profile MUST not fail on out-of-profile sigs"
    assert result.exit_code == 0
    info_codes = [i.code for i in result.validation.info]
    assert "OUT_OF_PROFILE_SKIPPED" in info_codes
    # `record_signatures` MUST NOT be populated — the core verifier did not
    # verify the signatures.
    assert result.record_signatures is None


# ---- Merkle root recompute --------------------------------------------------


def test_merkle_root_mismatch_yields_failed_verdict() -> None:
    # Build a record carrying a Merkle commitment whose on-chain root deliberately
    # does NOT match the recomputed root from the leaves-list.
    leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(4)]
    real_root = merkle_sha2_256_root(leaves)
    wrong_root = bytes(b ^ 0xFF for b in real_root)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "merkle": [
                {
                    "alg": "rfc9162-sha256",
                    "root": wrong_root,
                    "leaf_count": len(leaves),
                }
            ],
        },
    )
    record_bytes = encode_poe_record(record)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    leaves_blob = encode_leaves_list(leaves=leaves, root=real_root)
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
                merkle_leaves={0: leaves_blob},
            )
        )
    )
    assert result.verdict == "failed"
    assert result.exit_code == 1
    assert result.merkle_checks is not None
    assert result.merkle_checks[0].verdict == "mismatch"
    assert result.merkle_checks[0].reason == "MERKLE_ROOT_MISMATCH"


def test_merkle_root_recompute_matches_yields_valid() -> None:
    leaves = [hashlib.sha256(f"x{i}".encode()).digest() for i in range(5)]
    real_root = merkle_sha2_256_root(leaves)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "merkle": [
                {
                    "alg": "rfc9162-sha256",
                    "root": real_root,
                    "leaf_count": len(leaves),
                }
            ],
        },
    )
    record_bytes = encode_poe_record(record)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    leaves_blob = encode_leaves_list(leaves=leaves, root=real_root)
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
                merkle_leaves={0: leaves_blob},
            )
        )
    )
    assert result.verdict == "valid"
    assert result.exit_code == 0
    assert result.merkle_checks is not None
    assert result.merkle_checks[0].verdict == "valid"


def test_merkle_leaves_unavailable_when_no_input_no_uris_warns_only() -> None:
    leaves = [hashlib.sha256(b"a").digest()]
    real_root = merkle_sha2_256_root(leaves)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "merkle": [
                {
                    "alg": "rfc9162-sha256",
                    "root": real_root,
                    "leaf_count": 1,
                }
            ],
        },
    )
    record_bytes = encode_poe_record(record)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
                # No merkle_leaves supplied AND merkle[i] carries no uris[]
                # → MERKLE_LEAVES_UNAVAILABLE (warning), verdict stays valid.
            )
        )
    )
    assert result.verdict == "valid"
    assert result.merkle_checks is not None
    assert result.merkle_checks[0].reason == "MERKLE_LEAVES_UNAVAILABLE"


# ---- Signature verdict policy -----------------------------------------------


def test_signature_unsupported_does_not_fail_hash_only_poe() -> None:
    """SIGNATURE_UNSUPPORTED is info-severity and does NOT fail a public
    hash-only PoE. Verdict stays 'valid' even when every signature carries
    an alg the verifier does not implement.
    """
    seed = bytes([3]) * 32
    pub = get_public_key_ed25519(seed)
    record_base = _minimal_hash_only_record()
    body_bytes = encode_canonical_cbor(
        cast(CanonicalCborValue, {k: v for k, v in record_base.items() if k != "sigs"})
    )
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + body_bytes
    cose = cose_sign1_build(
        protected_header={1: -19, 4: pub},  # unsupported alg
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": chunk_bytes(cose)}]},
    )
    record_bytes = encode_poe_record(record)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
            )
        )
    )
    assert result.verdict == "valid"
    assert result.record_signatures is not None
    assert result.record_signatures[0].reason == "SIGNATURE_UNSUPPORTED"


def test_signature_invalid_fails_verdict() -> None:
    seed = bytes([4]) * 32
    pub = get_public_key_ed25519(seed)
    record_base = _minimal_hash_only_record()
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        payload=b"unrelated-bytes",  # signed wrong payload → SIGNATURE_INVALID
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": chunk_bytes(cose)}]},
    )
    record_bytes = encode_poe_record(record)
    tx_cbor = _wrap_metadata_309(record_bytes)
    fetch_fn = _mk_fetch(_mk_koios_routes(tx_cbor, num_confirmations=100))
    result = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=TX_HASH,
                cardano_gateway_chain=("https://api.koios.rest/api/v1",),
                fetch_outbound=fetch_fn,
            )
        )
    )
    assert result.verdict == "failed"
    assert result.exit_code == 1
    assert result.record_signatures is not None
    assert result.record_signatures[0].reason == "SIGNATURE_INVALID"
