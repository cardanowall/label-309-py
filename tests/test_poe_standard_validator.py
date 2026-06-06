from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import cbor2
import pytest

from cardanowall._crypto.cbor import encode_canonical_cbor
from cardanowall._crypto.cose_sign1 import cose_sign1_build
from cardanowall._crypto.sig import get_public_key_ed25519
from cardanowall.poe_standard import (
    ValidateFail,
    ValidateOk,
    chunk_bytes,
    validate,
)


def _enc(value: object) -> bytes:
    return encode_canonical_cbor(value)  # type: ignore[arg-type]


def _codes(result: object) -> list[str]:
    if isinstance(result, ValidateOk):
        return []
    assert isinstance(result, ValidateFail)
    return [issue.code for issue in result.issues]


def _info_codes(result: object) -> list[str]:
    if not isinstance(result, ValidateOk):
        return []
    return [i.code for i in result.info]


def _ok_record_dict() -> dict[str, Any]:
    return {
        "v": 1,
        "items": [
            {
                "hashes": {
                    "sha2-256": b"\x00" * 32,
                    "blake2b-256": b"\x11" * 32,
                },
            }
        ],
    }


# --- Happy paths -----------------------------------------------------------


def test_validate_happy_path_items_only() -> None:
    res = validate(_enc(_ok_record_dict()))
    assert isinstance(res, ValidateOk)
    assert res.record["v"] == 1


def test_validate_happy_path_merkle_only() -> None:
    rec = {
        "v": 1,
        "merkle": [
            {
                "alg": "rfc9162-sha256",
                "root": b"\x00" * 32,
                "leaf_count": 4,
            }
        ],
    }
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


def test_validate_happy_path_items_plus_merkle() -> None:
    rec: dict[str, Any] = _ok_record_dict()
    rec["merkle"] = [{"alg": "rfc9162-sha256", "root": b"\x00" * 32, "leaf_count": 4}]
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


# --- CBOR / schema basics --------------------------------------------------


def test_malformed_cbor() -> None:
    res = validate(b"\x5b\x00\x00")
    assert "MALFORMED_CBOR" in _codes(res)


def test_duplicate_map_key_is_malformed_cbor() -> None:
    # {"a": 1, "a": 2} — duplicate keys fold into MALFORMED_CBOR (the taxonomy
    # has no separate duplicate-key code).
    dup = bytes.fromhex("a2" + "61" + "61" + "01" + "61" + "61" + "02")
    res = validate(dup)
    assert "MALFORMED_CBOR" in _codes(res)
    assert "MAP_DUPLICATE_KEY" not in _codes(res)


def test_noncanonical_unsorted_keys_is_malformed_cbor() -> None:
    # {"b": 1, "a": 2} — distinct keys in non-canonical order. cbor2 in Python
    # would silently decode this; the pre-scan must reject it as MALFORMED_CBOR
    # to match the TS twin.
    unsorted = bytes.fromhex("a2616201616102")
    res = validate(unsorted)
    assert "MALFORMED_CBOR" in _codes(res)


def test_schema_missing_required_v() -> None:
    rec = _ok_record_dict()
    del rec["v"]
    res = validate(_enc(rec))
    assert "SCHEMA_MISSING_REQUIRED" in _codes(res)


def test_schema_invalid_literal_v() -> None:
    rec = _ok_record_dict()
    rec["v"] = 2
    res = validate(_enc(rec))
    assert "SCHEMA_INVALID_LITERAL" in _codes(res)


def test_schema_unknown_field_top_level() -> None:
    rec = _ok_record_dict()
    rec["bogus"] = 1
    res = validate(_enc(rec))
    assert "SCHEMA_UNKNOWN_FIELD" in _codes(res)


def test_schema_empty_record() -> None:
    rec = {"v": 1}
    res = validate(_enc(rec))
    assert "SCHEMA_EMPTY_RECORD" in _codes(res)


def test_schema_empty_record_both_empty() -> None:
    rec = {"v": 1, "items": [], "merkle": []}
    res = validate(_enc(rec))
    assert "SCHEMA_EMPTY_RECORD" in _codes(res)


# --- Hash entries ----------------------------------------------------------


def test_hash_digest_length_mismatch() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["hashes"]["sha2-256"] = b"\x00" * 31
    res = validate(_enc(rec))
    assert "HASH_DIGEST_LENGTH_MISMATCH" in _codes(res)


def test_unsupported_hash_alg() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["hashes"] = {"md5": b"\x00" * 32}
    res = validate(_enc(rec))
    assert "UNSUPPORTED_HASH_ALG" in _codes(res)


def test_single_hash_is_valid() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["hashes"] = {"sha2-256": b"\x00" * 32}
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


# --- URI checks ------------------------------------------------------------


def test_invalid_uri_unsupported_scheme() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["https://example.com/x"]]
    res = validate(_enc(rec))
    assert "INVALID_URI" in _codes(res)


def test_invalid_uri_data_scheme() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["data:text/plain,abc"]]
    res = validate(_enc(rec))
    assert "INVALID_URI" in _codes(res)


def test_invalid_uri_file_scheme() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["file:///etc/passwd"]]
    res = validate(_enc(rec))
    assert "INVALID_URI" in _codes(res)


def test_invalid_uri_fragment() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#frag"]]
    res = validate(_enc(rec))
    assert "INVALID_URI" in _codes(res)


def test_chunk_too_large_uri_chunk() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["ar://" + "a" * 100]]
    res = validate(_enc(rec))
    assert "CHUNK_TOO_LARGE" in _codes(res)


def test_invalid_utf8_chunk_split_at_decode_layer() -> None:
    # CBOR tstr chunks MUST be valid UTF-8 in isolation AND MUST NOT split a
    # multi-byte codepoint across chunk boundaries. cbor2 enforces the
    # per-chunk UTF-8 invariant at decode time (CBOR major type 3 is strictly
    # UTF-8 per RFC 8949 §3.1), so a producer that splits a multi-byte
    # codepoint emits a tstr chunk that fails CBOR decode. The validator
    # surfaces this as MALFORMED_CBOR.
    # Build a CBOR tstr chunk that contains the leading 2 bytes of a
    # 4-byte UTF-8 codepoint (an incomplete sequence) by hand, wrap it
    # in a minimal record skeleton, and assert MALFORMED_CBOR fires.
    smile_bytes = "\U0001f600".encode("utf-8")
    bad_chunk = smile_bytes[:2]  # incomplete UTF-8
    # CBOR tstr header byte: major-type 3 (0x60) + length
    bad_tstr = bytes([0x60 + len(bad_chunk)]) + bad_chunk
    # Plain top-level CBOR value (not a full record) — cbor2.loads MUST
    # reject the bad tstr at the decode layer.
    res = validate(bad_tstr)
    assert "MALFORMED_CBOR" in _codes(res)


def test_invalid_uri_ipfs_bad_cid() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["ipfs://notacid"]]
    res = validate(_enc(rec))
    assert "INVALID_URI" in _codes(res)


def test_valid_ar_uri_passes() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["uris"] = [["ar://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


# --- Encryption envelope ---------------------------------------------------


@pytest.mark.parametrize(
    "aead",
    [
        "aes-256-cbc",
        "aes-128-cbc",
        "AES-256-CBC",
        "aes-256-ctr",
        "aes-128-ecb",
        "rc4",
        "des-ede3-cbc",
    ],
)
def test_unauthenticated_cipher_forbidden(aead: str) -> None:
    # Realistic OpenSSL/JCA spellings — the prior `"aes-cbc" in aead` substring
    # match missed `aes-256-cbc` etc. The whole unauthenticated-cipher family
    # MUST classify as UNAUTHENTICATED_CIPHER_FORBIDDEN, never UNSUPPORTED_AEAD_ALG.
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": aead,
        "nonce": b"\x00" * 16,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    codes = _codes(validate(_enc(rec)))
    assert "UNAUTHENTICATED_CIPHER_FORBIDDEN" in codes
    assert "UNSUPPORTED_AEAD_ALG" not in codes


@pytest.mark.parametrize("aead", ["aes-256-gcm", "chacha20-poly1305", "rot13"])
def test_unsupported_aead_alg(aead: str) -> None:
    # Unknown-but-authenticated (gcm / chacha20-poly1305) and an arbitrary
    # unknown alg all fall through to UNSUPPORTED_AEAD_ALG — NOT the
    # unauthenticated-cipher code (no false positive on AEADs).
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": aead,
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    codes = _codes(validate(_enc(rec)))
    assert "UNSUPPORTED_AEAD_ALG" in codes
    assert "UNAUTHENTICATED_CIPHER_FORBIDDEN" not in codes


def test_nonce_length_mismatch() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 12,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "NONCE_LENGTH_MISMATCH" in _codes(res)


def test_unsupported_envelope_scheme() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 2,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "UNSUPPORTED_ENVELOPE_SCHEME" in _codes(res)


def test_enc_slots_empty() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [],
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "ENC_SLOTS_EMPTY" in _codes(res)


def test_unsupported_kem_alg() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "rsa",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48}],
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "UNSUPPORTED_KEM_ALG" in _codes(res)


def test_kem_epk_length_mismatch() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 31, "wrap": b"\x00" * 48}],
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "KEM_EPK_LENGTH_MISMATCH" in _codes(res)


def test_wrap_length_mismatch() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 40}],
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "WRAP_LENGTH_MISMATCH" in _codes(res)


def _enc_with_slots(slots: object) -> dict[str, object]:
    return {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": slots,
        "slots_mac": b"\x00" * 32,
    }


def test_enc_slot_invalid_shape_extra_key() -> None:
    # A slot carrying an extra key is "not a 2-key map {epk, wrap}" →
    # ENC_SLOT_INVALID_SHAPE, NOT the generic SCHEMA_UNKNOWN_FIELD.
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = _enc_with_slots(
        [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48, "foo": 1}]
    )
    codes = _codes(validate(_enc(rec)))
    assert "ENC_SLOT_INVALID_SHAPE" in codes
    assert "SCHEMA_UNKNOWN_FIELD" not in codes


def test_enc_slot_invalid_shape_array_slot() -> None:
    # An array where a slot map is expected → ENC_SLOT_INVALID_SHAPE.
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = _enc_with_slots([[1, 2]])
    codes = _codes(validate(_enc(rec)))
    assert "ENC_SLOT_INVALID_SHAPE" in codes


def test_enc_slot_invalid_shape_scalar_slot() -> None:
    # A scalar where a slot map is expected → ENC_SLOT_INVALID_SHAPE.
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = _enc_with_slots([5])
    codes = _codes(validate(_enc(rec)))
    assert "ENC_SLOT_INVALID_SHAPE" in codes


def test_enc_slots_mac_invalid_length() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48}],
        "slots_mac": b"\x00" * 16,
    }
    res = validate(_enc(rec))
    assert "ENC_SLOTS_MAC_INVALID_LENGTH" in _codes(res)


def test_enc_slots_mac_required() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48}],
    }
    res = validate(_enc(rec))
    assert "ENC_SLOTS_MAC_REQUIRED" in _codes(res)


def test_enc_slots_required() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "ENC_SLOTS_REQUIRED" in _codes(res)


def test_enc_kem_required() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48}],
        "slots_mac": b"\x00" * 32,
    }
    res = validate(_enc(rec))
    assert "ENC_KEM_REQUIRED" in _codes(res)


def test_enc_exclusivity_violation() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{"epk": b"\x00" * 32, "wrap": b"\x00" * 48}],
        "slots_mac": b"\x00" * 32,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_EXCLUSIVITY_VIOLATION" in _codes(res)


def test_enc_no_key_path() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
    }
    res = validate(_enc(rec))
    assert "ENC_NO_KEY_PATH" in _codes(res)


def test_enc_passphrase_alg_unsupported() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "scrypt",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_ALG_UNSUPPORTED" in _codes(res)


def test_enc_passphrase_salt_too_short() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 8,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_SALT_TOO_SHORT" in _codes(res)


def test_enc_passphrase_salt_too_long() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 65,
            "params": {"m": 65536, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_SALT_TOO_LONG" in _codes(res)


def test_enc_passphrase_argon2_params_too_low_m() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 1024, "t": 3, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW" in _codes(res)


def test_enc_passphrase_argon2_params_too_low_t() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 1, "p": 1},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW" in _codes(res)


def test_enc_passphrase_argon2_params_too_low_p() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": 65536, "t": 3, "p": 0},
        },
    }
    res = validate(_enc(rec))
    assert "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW" in _codes(res)


def test_enc_requires_content_hash() -> None:
    rec = {
        "v": 1,
        "items": [
            {
                # Empty hashes map can't be encoded canonically by cbor2 as a
                # CBOR map of size 0; we still construct it for negative-path
                # validation. cbor2 accepts an empty dict → encodes as 0xa0.
                "hashes": {},
                "enc": {
                    "scheme": 1,
                    "aead": "xchacha20-poly1305",
                    "nonce": b"\x00" * 24,
                    "passphrase": {
                        "alg": "argon2id",
                        "salt": b"\x00" * 16,
                        "params": {"m": 65536, "t": 3, "p": 1},
                    },
                },
            }
        ],
    }
    res = validate(_enc(rec))
    # `{}`+enc emits BOTH codes (ratified union): the enc-requires-content-hash
    # gate fires whenever `hashes` carries no content-hash entry — independent
    # of empty vs non-empty — AND the empty map separately fails the non-empty
    # `hashes` cardinality with SCHEMA_TYPE_MISMATCH.
    codes = _codes(res)
    assert "ENC_REQUIRES_CONTENT_HASH" in codes
    assert "SCHEMA_TYPE_MISMATCH" in codes


# --- Hybrid (mlkem768x25519) sealed slots ----------------------------------
#
# Mirrors the TS poe-standard `sealed-slots-hybrid-mlkem768x25519` positive
# vector and the hybrid slot-shape negatives. A hybrid slot is
# `{ kem_ct: [ bstr, ... ], wrap: bstr(48) }`: the 1120-byte X-Wing
# (ML-KEM-768 + X25519) `enc` carried as a chunked byte-string array (18 chunks:
# 17 x 64 + 1 x 32); there is NO per-slot `epk`.

MLKEM768X25519_ENC_LENGTH = 1120


def _chunk64(value: bytes) -> list[bytes]:
    """Split a flat byte string into <=64-byte chunks (the on-wire `kem_ct`
    shape). The 1120-byte X-Wing enc chunks into 18 chunks: 17 x 64 + 32."""
    return [value[i : i + 64] for i in range(0, len(value), 64)]


def _sealed_hybrid_base() -> dict[str, object]:
    """A well-formed hybrid sealed envelope (kem='mlkem768x25519'); callers
    mutate individual slots to exercise the cross-KEM shape negatives."""
    return {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "mlkem768x25519",
        "nonce": b"\x00" * 24,
        "slots": [
            {"kem_ct": _chunk64(b"\x11" * MLKEM768X25519_ENC_LENGTH), "wrap": b"\x02" * 48}
        ],
        "slots_mac": b"\x07" * 32,
    }


def test_hybrid_mlkem768x25519_positive_accepts_and_roundtrips() -> None:
    # The TS `sealed-slots-hybrid-mlkem768x25519` positive vector: two hybrid
    # slots, each kem_ct reassembling to 1120 bytes, wrap=48, slots_mac=32.
    from cardanowall.poe_standard import encode_poe_record

    rec: dict[str, Any] = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\xab" * 32, "blake2b-256": b"\x22" * 32},
                "enc": {
                    "scheme": 1,
                    "aead": "xchacha20-poly1305",
                    "kem": "mlkem768x25519",
                    "nonce": b"\x00" * 24,
                    "slots": [
                        {
                            "kem_ct": _chunk64(b"\x11" * MLKEM768X25519_ENC_LENGTH),
                            "wrap": b"\x02" * 48,
                        },
                        {
                            "kem_ct": _chunk64(b"\x33" * MLKEM768X25519_ENC_LENGTH),
                            "wrap": b"\x04" * 48,
                        },
                    ],
                    "slots_mac": b"\x07" * 32,
                },
            }
        ],
    }
    encoded = encode_poe_record(rec)  # type: ignore[arg-type]
    res = validate(encoded)
    assert isinstance(res, ValidateOk), _codes(res)
    # Byte-exact round-trip: validate(encode(R)).record re-encodes identically.
    assert encode_poe_record(res.record) == encoded


def test_hybrid_kem_ct_length_mismatch_short() -> None:
    # A hybrid slot whose kem_ct reassembles to 1119 bytes (one byte short of
    # the 1120-byte X-Wing enc).
    rec = _ok_record_dict()
    enc = _sealed_hybrid_base()
    enc["slots"] = [
        {"kem_ct": _chunk64(b"\x11" * (MLKEM768X25519_ENC_LENGTH - 1)), "wrap": b"\x02" * 48}
    ]
    rec["items"][0]["enc"] = enc
    codes = _codes(validate(_enc(rec)))
    assert "KEM_CT_LENGTH_MISMATCH" in codes
    # Single-defect record: nothing else should fire.
    assert set(codes) == {"KEM_CT_LENGTH_MISMATCH"}


def test_hybrid_slot_carrying_stray_epk_is_invalid_shape() -> None:
    # A hybrid slot carrying a stray `epk` alongside `kem_ct` is cross-KEM
    # contamination → ENC_SLOT_INVALID_SHAPE (sole code).
    rec = _ok_record_dict()
    enc = _sealed_hybrid_base()
    enc["slots"] = [
        {
            "kem_ct": _chunk64(b"\x11" * MLKEM768X25519_ENC_LENGTH),
            "epk": b"\x00" * 32,  # forbidden on the hybrid path
            "wrap": b"\x02" * 48,
        }
    ]
    rec["items"][0]["enc"] = enc
    codes = _codes(validate(_enc(rec)))
    assert "ENC_SLOT_INVALID_SHAPE" in codes
    assert set(codes) == {"ENC_SLOT_INVALID_SHAPE"}


def test_classical_slot_carrying_stray_kem_ct_is_invalid_shape() -> None:
    # A classical x25519 slot carrying a stray `kem_ct` alongside `epk` is
    # cross-KEM contamination → ENC_SLOT_INVALID_SHAPE (sole code).
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [
            {
                "epk": b"\x00" * 32,
                "kem_ct": _chunk64(b"\x11" * MLKEM768X25519_ENC_LENGTH),  # forbidden on x25519
                "wrap": b"\x02" * 48,
            }
        ],
        "slots_mac": b"\x07" * 32,
    }
    codes = _codes(validate(_enc(rec)))
    assert "ENC_SLOT_INVALID_SHAPE" in codes
    assert set(codes) == {"ENC_SLOT_INVALID_SHAPE"}


def test_hybrid_kem_ct_length_mismatch_long() -> None:
    # A hybrid slot whose kem_ct reassembles to 1184 bytes (one extra 64-byte
    # chunk) → KEM_CT_LENGTH_MISMATCH (sole code).
    rec = _ok_record_dict()
    enc = _sealed_hybrid_base()
    enc["slots"] = [
        {"kem_ct": _chunk64(b"\x11" * (MLKEM768X25519_ENC_LENGTH + 64)), "wrap": b"\x02" * 48}
    ]
    rec["items"][0]["enc"] = enc
    codes = _codes(validate(_enc(rec)))
    assert "KEM_CT_LENGTH_MISMATCH" in codes
    assert set(codes) == {"KEM_CT_LENGTH_MISMATCH"}


# --- Enc resource bounds (slot-count cap + decoded-envelope size) ----------
# These build over-bound slot arrays programmatically (too large to freeze in
# the shared corpus). Constants mirror the sealed-PoE unwrap layer
# (MAX_SLOTS = 1024, decoded-envelope bound 65536 bytes).

_MAX_SLOTS = 1024
_MAX_DECODED_ENVELOPE_BYTES = 65536
_NONCE_LEN = 24
_SLOTS_MAC_LEN = 32


def _distinct_epk_slots(n: int) -> list[dict[str, bytes]]:
    # Distinct epk per slot (big-endian counter) so the slot-count / byte cap is
    # what trips, not the duplicate check.
    return [{"epk": i.to_bytes(32, "big"), "wrap": b"\x06" * 48} for i in range(n)]


def test_enc_slots_too_many() -> None:
    # MAX_SLOTS + 1 trips the slot-count cap, which short-circuits the byte
    # backstop, so ENC_SLOTS_TOO_MANY is the sole emitted code even though the
    # x25519 array would also exceed the byte bound at that count.
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = _enc_with_slots(_distinct_epk_slots(_MAX_SLOTS + 1))
    codes = _codes(validate(_enc(rec)))
    assert set(codes) == {"ENC_SLOTS_TOO_MANY"}


def test_enc_envelope_too_large_x25519_byte_backstop() -> None:
    # x25519 per-slot bytes = 32 + 48 = 80. The byte backstop is the tighter
    # guard at this width (it trips below MAX_SLOTS); one slot over the floor
    # emits ENC_ENVELOPE_TOO_LARGE, the floor itself validates.
    per_slot = 32 + 48
    just_under = (_MAX_DECODED_ENVELOPE_BYTES - _NONCE_LEN - _SLOTS_MAC_LEN) // per_slot
    assert just_under < _MAX_SLOTS
    ok = _ok_record_dict()
    ok["items"][0]["enc"] = _enc_with_slots(_distinct_epk_slots(just_under))
    assert isinstance(validate(_enc(ok)), ValidateOk)
    over = _ok_record_dict()
    over["items"][0]["enc"] = _enc_with_slots(_distinct_epk_slots(just_under + 1))
    assert set(_codes(validate(_enc(over)))) == {"ENC_ENVELOPE_TOO_LARGE"}


def test_enc_envelope_too_large_hybrid_byte_backstop() -> None:
    # Hybrid per-slot bytes = 1120 + 48 = 1168; the smallest over-bound slot
    # count is below MAX_SLOTS, so the byte backstop (not the slot cap) fires.
    per_slot = MLKEM768X25519_ENC_LENGTH + 48
    over = (_MAX_DECODED_ENVELOPE_BYTES - _NONCE_LEN - _SLOTS_MAC_LEN) // per_slot + 1
    assert over <= _MAX_SLOTS

    def _hslots(n: int) -> list[dict[str, object]]:
        # Distinct kem_ct per slot so the duplicate check does not fire instead.
        def _ct(i: int) -> bytes:
            return i.to_bytes(2, "big") + b"\x11" * (MLKEM768X25519_ENC_LENGTH - 2)

        return [{"kem_ct": _chunk64(_ct(i)), "wrap": b"\x09" * 48} for i in range(n)]

    rec = _ok_record_dict()
    enc = _sealed_hybrid_base()
    enc["slots"] = _hslots(over)
    rec["items"][0]["enc"] = enc
    assert set(_codes(validate(_enc(rec)))) == {"ENC_ENVELOPE_TOO_LARGE"}


# --- Supersedes ------------------------------------------------------------


def test_supersedes_tx_invalid_length() -> None:
    rec = _ok_record_dict()
    rec["supersedes"] = b"\x00" * 31
    res = validate(_enc(rec))
    assert "SUPERSEDES_TX_INVALID_LENGTH" in _codes(res)


def test_supersedes_valid_32_bytes_passes() -> None:
    rec = _ok_record_dict()
    rec["supersedes"] = b"\x00" * 32
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


# --- Merkle commits --------------------------------------------------------


def test_unsupported_merkle_commit_alg() -> None:
    rec = _ok_record_dict()
    rec["merkle"] = [{"alg": "sha3-256", "root": b"\x00" * 32, "leaf_count": 1}]
    res = validate(_enc(rec))
    assert "UNSUPPORTED_MERKLE_COMMIT_ALG" in _codes(res)


def test_merkle_root_length_mismatch() -> None:
    rec = _ok_record_dict()
    rec["merkle"] = [{"alg": "rfc9162-sha256", "root": b"\x00" * 31, "leaf_count": 1}]
    res = validate(_enc(rec))
    assert "HASH_DIGEST_LENGTH_MISMATCH" in _codes(res)


def test_merkle_missing_leaf_count() -> None:
    rec = _ok_record_dict()
    rec["merkle"] = [{"alg": "rfc9162-sha256", "root": b"\x00" * 32}]
    res = validate(_enc(rec))
    assert "SCHEMA_MISSING_REQUIRED" in _codes(res)


# --- Signatures (structural) ----------------------------------------------


def test_sig_entry_invalid_shape_not_a_map() -> None:
    rec = _ok_record_dict()
    rec["sigs"] = [[b"\x00" * 10]]
    res = validate(_enc(rec))
    assert "SIG_ENTRY_INVALID_SHAPE" in _codes(res)


def test_sig_entry_missing_cose_sign1() -> None:
    rec = _ok_record_dict()
    rec["sigs"] = [{"cose_key": [b"\x00" * 10]}]
    res = validate(_enc(rec))
    assert "SIG_ENTRY_INVALID_SHAPE" in _codes(res)


def test_sig_entry_unknown_field() -> None:
    # The sig-entry schema is closed; an unrecognized key is a malformed
    # sig-entry SHAPE (SIG_ENTRY_INVALID_SHAPE at the offending key's path),
    # not a generic SCHEMA_UNKNOWN_FIELD.
    rec = _ok_record_dict()
    rec["sigs"] = [{"cose_sign1": [b"\x00" * 10], "extra": b"\x00"}]
    res = validate(_enc(rec))
    assert "SIG_ENTRY_INVALID_SHAPE" in _codes(res)
    assert "SCHEMA_UNKNOWN_FIELD" not in _codes(res)
    fail = res
    assert isinstance(fail, ValidateFail)
    assert any(
        issue.code == "SIG_ENTRY_INVALID_SHAPE" and issue.path == ("sigs", 0, "extra")
        for issue in fail.issues
    )


def test_malformed_sig_cose_sign1_attached_payload() -> None:
    rec = _ok_record_dict()
    # COSE_Sign1 with non-null payload field.
    pseudo = cbor2.dumps(
        [
            encode_canonical_cbor({1: -8}),
            {},
            b"attached-bytes",
            b"\x00" * 64,
        ]
    )
    rec["sigs"] = [{"cose_sign1": chunk_bytes(pseudo)}]
    res = validate(_enc(rec))
    assert "MALFORMED_SIG_COSE_SIGN1" in _codes(res)


def test_signature_unsupported_is_info_not_error() -> None:
    pseudo = cbor2.dumps(
        [
            encode_canonical_cbor({1: -7}),
            {},
            None,
            b"\x00" * 64,
        ]
    )
    rec = _ok_record_dict()
    rec["sigs"] = [{"cose_sign1": chunk_bytes(pseudo)}]
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)
    assert "SIGNATURE_UNSUPPORTED" in _info_codes(res)


def test_sig_entry_kid_cose_key_conflict() -> None:
    sk = os.urandom(32)
    pk = get_public_key_ed25519(sk)
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pk},  # 32-byte kid in protected header
        unprotected_header={},
        payload=b"any",
        external_aad=b"",
        signer_secret_key=sk,
    )
    cose_key_blob = encode_canonical_cbor({1: 1, -1: 6, -2: pk})
    rec = _ok_record_dict()
    rec["sigs"] = [{"cose_sign1": chunk_bytes(cose), "cose_key": chunk_bytes(cose_key_blob)}]
    res = validate(_enc(rec))
    assert "SIG_ENTRY_KID_COSE_KEY_CONFLICT" in _codes(res)


def test_sig_private_key_leaked_label_minus_four() -> None:
    # Construct a cbor<COSE_Key> map carrying label -4 (private scalar).
    cose_key_with_private = encode_canonical_cbor({1: 1, -1: 6, -2: b"\xab" * 32, -4: b"\xcd" * 32})
    rec = _ok_record_dict()
    rec["sigs"] = [
        {
            "cose_sign1": [b"\x00" * 10],
            "cose_key": chunk_bytes(cose_key_with_private),
        }
    ]
    res = validate(_enc(rec))
    assert "SIG_PRIVATE_KEY_LEAKED" in _codes(res)


def test_chunk_too_large_sig_chunk() -> None:
    rec = _ok_record_dict()
    rec["sigs"] = [{"cose_sign1": [b"\x00" * 65]}]
    res = validate(_enc(rec))
    assert "CHUNK_TOO_LARGE" in _codes(res)


def test_record_with_valid_ed25519_sig_passes() -> None:
    sk = os.urandom(32)
    pk = get_public_key_ed25519(sk)
    rec = _ok_record_dict()
    payload = encode_canonical_cbor(rec)  # type: ignore[arg-type]
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pk},
        unprotected_header={},
        payload=payload,
        external_aad=b"cardano-poe-record-sig-v1",
        signer_secret_key=sk,
    )
    rec["sigs"] = [{"cose_sign1": chunk_bytes(cose)}]
    res = validate(_enc(rec))
    assert isinstance(res, ValidateOk)


# --- crit[] forward-compat ------------------------------------------------


def test_crit_shape_invalid_base_key() -> None:
    rec = _ok_record_dict()
    rec["crit"] = ["v"]  # base key, not extension-key
    res = validate(_enc(rec))
    assert "CRIT_SHAPE_INVALID" in _codes(res)


def test_crit_shape_invalid_missing_target() -> None:
    rec = _ok_record_dict()
    rec["crit"] = ["x-missing-extension"]
    res = validate(_enc(rec))
    assert "CRIT_SHAPE_INVALID" in _codes(res)


def test_crit_shape_invalid_duplicate_entry() -> None:
    rec = _ok_record_dict()
    rec["x-foo"] = 1
    rec["crit"] = ["x-foo", "x-foo"]
    res = validate(_enc(rec))
    assert "CRIT_SHAPE_INVALID" in _codes(res)


def test_extension_unsupported_critical() -> None:
    rec = _ok_record_dict()
    rec["x-foo"] = 1
    rec["crit"] = ["x-foo"]
    res = validate(_enc(rec))
    assert "EXTENSION_UNSUPPORTED_CRITICAL" in _codes(res)


# --- Round-trip property --------------------------------------------------


def test_roundtrip_encode_validate_property() -> None:
    """validate(encode(r)).record == r for every positive `r` we construct."""
    from cardanowall.poe_standard import encode_poe_record

    rec_minimal: dict[str, Any] = _ok_record_dict()
    rec_merkle: dict[str, Any] = {
        "v": 1,
        "merkle": [{"alg": "rfc9162-sha256", "root": b"\x00" * 32, "leaf_count": 4}],
    }
    rec_both: dict[str, Any] = {**rec_minimal, "merkle": rec_merkle["merkle"]}
    rec_with_supersedes: dict[str, Any] = {**rec_minimal, "supersedes": b"\xaa" * 32}
    for r in (rec_minimal, rec_merkle, rec_both, rec_with_supersedes):
        encoded = encode_poe_record(r)  # type: ignore[arg-type]
        res = validate(encoded)
        assert isinstance(res, ValidateOk), f"failed on {r}: {res}"
        assert res.record == r, f"roundtrip mismatch on {r}"


def test_validator_negative_shared_kat() -> None:
    """Shared cross-SDK KAT: each vector's emitted error-code SET must equal
    `expected_error_codes` exactly (empty ⇒ a valid record).

    Pins the reconciled behaviors: sig-entry extra field → SIG_ENTRY_INVALID_SHAPE,
    `{}`/`{md5}`+enc → ENC_REQUIRES_CONTENT_HASH union, empty `crit` →
    SCHEMA_TYPE_MISMATCH, supersedes type-vs-length split, CIDv0 base58 decode,
    RFC-3986 scheme case-folding (body still validated), and extension-key /
    unauthenticated-cipher newline handling.
    """
    fixture = Path(__file__).parent / "fixtures" / "poe-record" / "validator-negative.json"
    corpus = json.loads(fixture.read_text())
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        cbor_bytes = bytes.fromhex(vector["cbor_hex"])
        res = validate(cbor_bytes)
        emitted = set(_codes(res))
        expected = set(vector["expected_error_codes"])
        assert emitted == expected, (
            f"{vector['name']}: expected {sorted(expected)}, got {sorted(emitted)}"
        )
