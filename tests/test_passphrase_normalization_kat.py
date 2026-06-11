"""Conformance replay of the cardano-poe-pw-norm-v1 byte-pin corpus.

Every positive case must normalize to the pinned UTF-8 bytes AND derive the
pinned 32-byte CEK through Argon2id v19 under the corpus's fixed salt/params,
proving the embedded Unicode 16.0 tables and the Argon2id engine byte-exact
end-to-end. Error cases must surface the pinned typed rejections.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cardanowall._crypto.kdf import argon2id_v13
from cardanowall._crypto.passphrase import (
    MAX_PASSPHRASE_INPUT_BYTES,
    PassphraseNormalizationError,
    normalize_passphrase,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kdf" / "passphrase-normalization.json"


def _load_corpus() -> dict[str, Any]:
    corpus: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return corpus


def test_corpus_header_and_case_set() -> None:
    corpus = _load_corpus()
    assert corpus["primitive"] == "cardano-poe-pw-norm-v1"
    assert corpus["unicode_version"] == "16.0.0"
    assert corpus["max_passphrase_input_bytes"] == MAX_PASSPHRASE_INPUT_BYTES
    assert corpus["kdf"]["alg"] == "argon2id"
    assert corpus["kdf"]["argon2_version"] == 19
    assert corpus["kdf"]["out_bytes"] == 32
    assert len(corpus["vectors"]) == 17
    assert len(corpus["error_vectors"]) == 8


def test_every_positive_case_normalizes_and_derives_the_pinned_cek() -> None:
    corpus = _load_corpus()
    kdf = corpus["kdf"]
    salt = bytes.fromhex(kdf["salt_hex"])
    params = kdf["params"]
    for vector in corpus["vectors"]:
        name = vector["name"]
        normalized = normalize_passphrase(vector["passphrase"])
        assert normalized.hex() == vector["expected_normalized_utf8_hex"], name
        # The corpus's readable string form and its hex form pin the same bytes.
        assert normalized == vector["expected_normalized"].encode("utf-8"), name
        cek = argon2id_v13(
            normalized, salt, params["m"], params["t"], params["p"], kdf["out_bytes"]
        )
        assert cek.hex() == vector["expected_cek_hex"], name


def test_every_error_case_raises_the_pinned_code() -> None:
    corpus = _load_corpus()
    for vector in corpus["error_vectors"]:
        with pytest.raises(PassphraseNormalizationError) as exc:
            normalize_passphrase(vector["passphrase"])
        assert exc.value.code == vector["expected_error_code"], vector["name"]
