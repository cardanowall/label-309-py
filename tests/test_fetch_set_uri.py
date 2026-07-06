"""The single-source fetch-set URI grammar and its two-tier producer use.

``is_fetch_set_uri`` / ``is_arweave_tx_uri`` in ``poe_standard`` are the one
grammar the canonical record validator and every producer-side pre-check share,
so the early check and the canonical check can never diverge. Two tiers:

- the assembly seam + plain content ``uris`` accept the full fetch set
  ``{ar://, ipfs://}`` (``is_fetch_set_uri``);
- the sealed receipt seam accepts only strict Arweave ``ar://<43-char txid>``
  (``is_arweave_tx_uri``), because a sealed ciphertext always lives on Arweave
  and the fixed 5+43 width keeps the exact-size quote exact.
"""

from __future__ import annotations

from cardanowall.poe_standard import (
    fetch_set_uri_rejection,
    is_arweave_tx_uri,
    is_fetch_set_uri,
    validate,
)

_AR = "ar://" + "A" * 43
_CID = "ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"

_BAD_URIS = [
    "",
    "ar://",
    "ar://tooshort",
    "ar://" + "A" * 44,
    _AR + "#frag",
    "https://example.com/x",
    "ipfs://not-a-cid",
]


def test_fetch_set_accepts_arweave_txid_and_valid_cid() -> None:
    assert is_fetch_set_uri(_AR)
    assert is_fetch_set_uri(_CID)
    assert fetch_set_uri_rejection(_AR) is None
    assert fetch_set_uri_rejection(_CID) is None


def test_fetch_set_and_arweave_predicates_share_the_canonical_grammar() -> None:
    for bad in _BAD_URIS:
        assert not is_fetch_set_uri(bad), f"fetch set accepted {bad!r}"
        # The predicate and the validator's per-URI check are the same function,
        # so a rejection here is a rejection at canonical validation too.
        assert fetch_set_uri_rejection(bad) is not None
        # The Arweave subset never accepts anything the fetch set rejects.
        assert not is_arweave_tx_uri(bad)


def test_arweave_tx_uri_is_the_strict_arweave_subset() -> None:
    # A valid Arweave txid is both a fetch-set member and an Arweave tx uri.
    assert is_arweave_tx_uri(_AR)
    assert is_fetch_set_uri(_AR)
    # A valid CID is a fetch-set member but NOT an Arweave tx uri (the sealed
    # receipt seam rejects it; the assembly seam accepts it).
    assert is_fetch_set_uri(_CID)
    assert not is_arweave_tx_uri(_CID)


def test_a_fetch_set_uri_embedded_in_a_record_passes_canonical_validation() -> None:
    # The producer-side predicate and the record validator agree: a URI the
    # predicate accepts embeds into a record the validator accepts on its URI.
    from cardanowall.poe_standard import ValidateOk, encode_poe_record

    record = encode_poe_record(
        {
            "v": 1,
            "items": [{"hashes": {"sha2-256": b"\x11" * 32}, "uris": [_AR, _CID]}],
        }
    )
    assert isinstance(validate(record), ValidateOk)
