"""Carriage conformance replay.

Replays the frozen carriage fixture corpus (mirrored under
``tests/fixtures/carriage/``) against the transport layer:

  - ``chunk-array-positive.json`` — reassembly positives: the in-order byte
    concatenation of the chunk array is the record body, whatever the split.
  - ``chunk-array-negative.json`` — the carriage-error taxonomy
    (``MALFORMED_CBOR`` for every non-chunk-array shape, ``CHUNK_TOO_LARGE``
    for an oversized element). The empty-concatenation vectors reassemble at
    the transport layer and fail in the canonical decode of the empty record
    body, so the harness runs structural validation on a successful
    reassembly before concluding.
  - ``aux-data-envelope-forms.json`` — the three Conway envelope forms
    unwrap to the same label-309 value with type/tag-only dispatch (never
    key-sniffing); well-formed auxiliary data without a label-309 entry is
    the verifier-layer ``METADATA_NOT_FOUND`` outcome.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall.poe_standard import validate
from cardanowall.verifier import (
    Label309ReassemblyFail,
    Label309ReassemblyOk,
    MalformedTxCborError,
    reassemble_label_309_value,
    unwrap_auxiliary_data,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "carriage"


def _vectors(filename: str) -> list[dict[str, Any]]:
    doc = json.loads((_FIXTURES / filename).read_text(encoding="utf-8"))
    return cast(list[dict[str, Any]], doc["vectors"])


_POSITIVE = _vectors("chunk-array-positive.json")
_NEGATIVE = _vectors("chunk-array-negative.json")
_AUX_FORMS = _vectors("aux-data-envelope-forms.json")


@pytest.mark.parametrize("vector", _POSITIVE, ids=lambda v: cast(str, v["name"]))
def test_chunk_array_positive(vector: dict[str, Any]) -> None:
    result = reassemble_label_309_value(bytes.fromhex(vector["label_309_value_cbor_hex"]))
    assert isinstance(result, Label309ReassemblyOk), vector["name"]
    assert result.body.hex() == vector["expected_record_body_hex"]


@pytest.mark.parametrize("vector", _NEGATIVE, ids=lambda v: cast(str, v["name"]))
def test_chunk_array_negative(vector: dict[str, Any]) -> None:
    result = reassemble_label_309_value(bytes.fromhex(vector["label_309_value_cbor_hex"]))
    if isinstance(result, Label309ReassemblyFail):
        assert result.issue.code == vector["expected_error_code"], vector["name"]
        return
    # Zero-length chunks are tolerated at the transport layer; the pinned
    # code then surfaces from the canonical decode of the reassembled body.
    validation = validate(result.body)
    assert not validation.ok, vector["name"]
    assert any(i.code == vector["expected_error_code"] for i in validation.issues), vector["name"]


@pytest.mark.parametrize("vector", _AUX_FORMS, ids=lambda v: cast(str, v["name"]))
def test_aux_data_envelope_forms(vector: dict[str, Any]) -> None:
    aux_bytes = bytes.fromhex(vector["auxiliary_data_cbor_hex"])
    expected = cast(dict[str, Any], vector["expected"])

    if expected.get("error_code") == "MALFORMED_CBOR":
        with pytest.raises(MalformedTxCborError):
            unwrap_auxiliary_data(aux_bytes)
        return

    unwrapped = unwrap_auxiliary_data(aux_bytes)
    if expected.get("error_code") == "METADATA_NOT_FOUND":
        # Well-formed auxiliary data with no label-309 entry: the pipeline
        # maps the absence to METADATA_NOT_FOUND on the integrity-bound
        # transaction.
        assert unwrapped.label_309 is None, vector["name"]
        return

    assert unwrapped.label_309 is not None, vector["name"]
    assert unwrapped.label_309.hex() == expected["label_309_value_cbor_hex"]
    reassembly = reassemble_label_309_value(unwrapped.label_309)
    assert isinstance(reassembly, Label309ReassemblyOk)
    assert reassembly.body.hex() == expected["record_body_hex"]
