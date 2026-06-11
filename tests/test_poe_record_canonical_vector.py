"""Python side of the frozen cross-language canonical-CBOR record vector.

Loads the byte-identical mirror of the canonical fixture (the parity-check
harness asserts the copies share a SHA-256), reconstructs the typed
``PoeRecord`` from its logical ``record``, and asserts the Python encoder
reproduces the frozen ``cbor_hex`` and ``body_cbor_hex`` byte-for-byte.

The load-bearing case is the extension keys (``x-note``, ``x-meta``): they are
part of the canonical map and of the signed record body. An encoder that drops
them emits different bytes and breaks cross-language tx-identity and
record-level COSE signatures. This vector pins every implementation to the
same extension-carrying bytes, so a future third-language SDK has a correct
oracle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cardanowall.poe_standard import (
    PoeRecord,
    ValidateOk,
    encode_poe_record,
    encode_record_body_for_signing,
    validate,
)

_FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "poe-record"
    / "maximal-record-with-extension-keys.json"
)

# Top-level JSON keys the reconstructor consumes itself (base fields + their
# `_hex` reconstruction hints). Every OTHER top-level key is a genuine
# extension key and is copied through verbatim.
_CONSUMED_TOP_KEYS = frozenset({"v", "items", "merkle", "supersedes_hex", "sigs", "crit"})


def _build_record(record_json: dict[str, Any]) -> PoeRecord:
    """Reconstruct the typed record (encoder input) from the JSON fixture.

    Byte-valued fields carry a ``_hex`` suffix; every other field carries its
    wire value verbatim (each URI one string, ``leaf_count`` an integer).
    Extension keys are preserved verbatim.
    """
    record: dict[str, Any] = {"v": record_json["v"]}

    if "items" in record_json:
        items: list[dict[str, Any]] = []
        for item_json in record_json["items"]:
            item: dict[str, Any] = {
                "hashes": {
                    alg: bytes.fromhex(digest_hex)
                    for alg, digest_hex in item_json["hashes_hex"].items()
                }
            }
            if "uris" in item_json:
                item["uris"] = list(item_json["uris"])
            if "enc" in item_json:
                enc_json = item_json["enc"]
                enc: dict[str, Any] = {
                    "scheme": enc_json["scheme"],
                    "aead": enc_json["aead"],
                    "nonce": bytes.fromhex(enc_json["nonce_hex"]),
                }
                if "kem" in enc_json:
                    enc["kem"] = enc_json["kem"]
                if "slots" in enc_json:
                    enc["slots"] = [
                        {
                            "epk": bytes.fromhex(s["epk_hex"]),
                            "wrap": bytes.fromhex(s["wrap_hex"]),
                        }
                        for s in enc_json["slots"]
                    ]
                if "slots_mac_hex" in enc_json:
                    enc["slots_mac"] = bytes.fromhex(enc_json["slots_mac_hex"])
                item["enc"] = enc
            items.append(item)
        record["items"] = items

    if "merkle" in record_json:
        record["merkle"] = [
            {
                "alg": m["alg"],
                "root": bytes.fromhex(m["root_hex"]),
                "leaf_count": m["leaf_count"],
            }
            for m in record_json["merkle"]
        ]

    if "supersedes_hex" in record_json:
        record["supersedes"] = bytes.fromhex(record_json["supersedes_hex"])

    if "sigs" in record_json:
        sigs: list[dict[str, Any]] = []
        for sig_json in record_json["sigs"]:
            sig: dict[str, Any] = {"cose_sign1": bytes.fromhex(sig_json["cose_sign1_hex"])}
            if "cose_key_hex" in sig_json:
                sig["cose_key"] = bytes.fromhex(sig_json["cose_key_hex"])
            sigs.append(sig)
        record["sigs"] = sigs

    if "crit" in record_json:
        record["crit"] = list(record_json["crit"])

    # Extension keys: copy every key the reconstructor did not already consume.
    for key, value in record_json.items():
        if key in _CONSUMED_TOP_KEYS:
            continue
        record[key] = value

    return cast("PoeRecord", record)


def _load_fixture() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(_FIXTURE_PATH.read_text(encoding="utf-8")))


def test_encode_poe_record_matches_frozen_cbor_hex() -> None:
    fixture = _load_fixture()
    record = _build_record(fixture["record"])
    assert encode_poe_record(record).hex() == fixture["cbor_hex"]


def test_encode_record_body_for_signing_matches_frozen_body_cbor_hex() -> None:
    fixture = _load_fixture()
    record = _build_record(fixture["record"])
    assert encode_record_body_for_signing(record).hex() == fixture["body_cbor_hex"]


def test_frozen_bytes_validate_under_the_fixture_validator_options() -> None:
    fixture = _load_fixture()
    supported = frozenset(fixture["validator_options"]["supportedCriticalExtensions"])
    result = validate(
        bytes.fromhex(fixture["cbor_hex"]),
        supported_critical_extensions=supported,
    )
    assert isinstance(result, ValidateOk)


def test_frozen_bytes_fail_under_the_default_empty_crit_set() -> None:
    fixture = _load_fixture()
    result = validate(bytes.fromhex(fixture["cbor_hex"]))
    assert not isinstance(result, ValidateOk)
    assert "EXTENSION_UNSUPPORTED_CRITICAL" in {issue.code for issue in result.issues}


def test_frozen_record_carries_its_extension_keys() -> None:
    # Guards the fixture: if a future edit drops the extension keys, the vector
    # silently stops exercising the encode-extension-key path.
    fixture = _load_fixture()
    record_json = fixture["record"]
    assert "x-note" in record_json
    assert "x-meta" in record_json
    # PoeRecord is a TypedDict; extension keys live on it at runtime but not in
    # its static shape, so read them through a plain-dict view.
    record = cast("dict[str, Any]", _build_record(record_json))
    assert record["x-note"] == record_json["x-note"]
    assert record["x-meta"] == record_json["x-meta"]
