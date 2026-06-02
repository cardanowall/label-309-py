"""Transaction-level decode for the CIP-309 verifier.

This module surfaces the Cardano TRANSACTION that carried a PoE record: which
wallet vkey(s) signed it, the fee, the outputs, and the co-published metadata
labels. It answers "who authorised and paid for this anchoring" — distinct from
the record-level COSE authorship signatures handled in `signatures.py`.

Unlike label-309 extraction, this decode is purely INFORMATIONAL: it is not fed
back into the structural validator, so it is not subject to the canonical-CBOR
byte-faithfulness concern that forces `cbor_walker` to slice rather than decode.
We therefore decode the body + witness-set slices with the permissive CBOR
decoder. The slices themselves are still byte-faithful — `decode_tx_witnesses`
verifies each signature against `blake2b256(tx_body)`, which only equals the
on-chain transaction hash when the body bytes are exactly as produced.
"""

from __future__ import annotations

import hashlib

from cardanowall._crypto.cbor import decode_cbor_permissive
from cardanowall._crypto.hash import blake2b_256
from cardanowall._crypto.sig import verify_ed25519

from .types import VerifyTxOutput, VerifyTxSummary, VerifyTxWitness

_ED25519_PUBLIC_KEY_LENGTH = 32
_ED25519_SIGNATURE_LENGTH = 64

# Conway-era transaction body map keys (RFC-style integer keys).
_BODY_KEY_INPUTS = 0
_BODY_KEY_OUTPUTS = 1
_BODY_KEY_FEE = 2
_BODY_KEY_INVALID_HEREAFTER = 3  # ttl
_BODY_KEY_INVALID_BEFORE = 8  # validity_interval_start
_BODY_KEY_REQUIRED_SIGNERS = 14
_BODY_KEY_NETWORK_ID = 15

# Witness-set map keys. Key 0 is the vkey witness set; every other key
# (native scripts, bootstrap witnesses, Plutus v1/v2/v3) is counted as a
# "script/other" witness without being deep-decoded.
_WITNESS_KEY_VKEY = 0

_BLAKE2B_224_DIGEST_LENGTH = 28


def _blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=_BLAKE2B_224_DIGEST_LENGTH).digest()


def _as_array(v: object) -> list[object]:
    # inputs, vkey_witnesses, and required_signers are CBOR sets (tag 258).
    # The permissive decoder may surface a set as a Python `set`/`frozenset` or
    # a `list`; normalise both to a list. (A CBOR set decoded by cbor2 surfaces
    # as a `set` only when the elements are hashable; otherwise it may stay a
    # list — handle both.)
    if isinstance(v, (set, frozenset)):
        return list(v)
    if isinstance(v, tuple):
        return list(v)
    if isinstance(v, list):
        return v
    return []


def _as_map(v: object) -> dict[object, object] | None:
    return v if isinstance(v, dict) else None


def decode_tx_witnesses(
    witness_set_bytes: bytes, tx_body_bytes: bytes
) -> tuple[VerifyTxWitness, ...]:
    """Decode the vkey witnesses and verify each signature against the tx body.

    Each Cardano vkey witness is `[vkey(32B), signature(64B)]`; the signed
    message is `blake2b256(tx_body)` (the transaction hash). A witness whose
    vkey or signature is malformed, or whose signature does not verify, is
    reported with `signature_valid=False` rather than dropped — the caller
    surfaces it informationally and never fails the record on it.
    """
    witness_set = _as_map(decode_cbor_permissive(witness_set_bytes))
    if witness_set is None:
        return ()
    vkey_witnesses = _as_array(witness_set.get(_WITNESS_KEY_VKEY))
    tx_hash = blake2b_256(tx_body_bytes)

    out: list[VerifyTxWitness] = []
    for entry in vkey_witnesses:
        pair = _as_array(entry)
        vkey = pair[0] if len(pair) > 0 else None
        signature = pair[1] if len(pair) > 1 else None
        if (
            not isinstance(vkey, bytes)
            or len(vkey) != _ED25519_PUBLIC_KEY_LENGTH
            or not isinstance(signature, bytes)
            or len(signature) != _ED25519_SIGNATURE_LENGTH
        ):
            # A structurally malformed witness still describes an attempted
            # authorisation; surface what we can (when the vkey is a valid
            # pubkey) and mark the signature invalid.
            if isinstance(vkey, bytes) and len(vkey) == _ED25519_PUBLIC_KEY_LENGTH:
                out.append(
                    VerifyTxWitness(
                        type="vkey",
                        vkey=vkey.hex(),
                        key_hash=_blake2b_224(vkey).hex(),
                        signature_valid=False,
                    )
                )
            continue
        try:
            signature_valid = verify_ed25519(vkey, tx_hash, signature)
        except Exception:
            signature_valid = False
        out.append(
            VerifyTxWitness(
                type="vkey",
                vkey=vkey.hex(),
                key_hash=_blake2b_224(vkey).hex(),
                signature_valid=signature_valid,
            )
        )
    return tuple(out)


def _count_script_witnesses(witness_set_bytes: bytes) -> int:
    """Count witness-set entries that are NOT vkey witnesses (native scripts,
    bootstrap witnesses, Plutus v1/v2/v3), summed as a single count."""
    witness_set = _as_map(decode_cbor_permissive(witness_set_bytes))
    if witness_set is None:
        return 0
    count = 0
    for key, value in witness_set.items():
        if key == _WITNESS_KEY_VKEY:
            continue
        count += len(_as_array(value))
    return count


def decode_tx_summary(
    tx_body_bytes: bytes,
    witness_set_bytes: bytes,
    network: str,
) -> VerifyTxSummary:
    """Decode a transaction body into a JSON-safe summary.

    All lovelace amounts are serialised as DECIMAL STRINGS so they survive JSON
    round-trips exactly (Cardano coin values can exceed safe-integer range).
    """
    body = _as_map(decode_cbor_permissive(tx_body_bytes))
    if body is None:
        raise ValueError("MALFORMED_CBOR: tx body is not a CBOR map")

    inputs = _as_array(body.get(_BODY_KEY_INPUTS))
    outputs_raw = _as_array(body.get(_BODY_KEY_OUTPUTS))

    outputs: list[VerifyTxOutput] = []
    total_output = 0
    for o in outputs_raw:
        address_bytes, lovelace = _read_output(o)
        total_output += lovelace
        outputs.append(
            VerifyTxOutput(
                address=_encode_cardano_address(address_bytes, network),
                lovelace=str(lovelace),
            )
        )

    required_signers = tuple(
        s.hex() for s in _as_array(body.get(_BODY_KEY_REQUIRED_SIGNERS)) if isinstance(s, bytes)
    )

    invalid_before = body.get(_BODY_KEY_INVALID_BEFORE)
    invalid_hereafter = body.get(_BODY_KEY_INVALID_HEREAFTER)
    network_id = body.get(_BODY_KEY_NETWORK_ID)

    return VerifyTxSummary(
        fee_lovelace=str(_to_int(body.get(_BODY_KEY_FEE))),
        input_count=len(inputs),
        output_count=len(outputs),
        outputs=tuple(outputs),
        total_output_lovelace=str(total_output),
        script_witness_count=_count_script_witnesses(witness_set_bytes),
        invalid_before=invalid_before if isinstance(invalid_before, int) else None,
        invalid_hereafter=invalid_hereafter if isinstance(invalid_hereafter, int) else None,
        required_signer_key_hashes=required_signers if len(required_signers) > 0 else None,
        network_id=network_id if isinstance(network_id, int) else None,
    )


def _read_output(output: object) -> tuple[bytes, int]:
    # A transaction output is EITHER a legacy array `[address, amount]` OR a map
    # `{0: address, 1: amount}` (post-Babbage). `amount` is either a bare coin
    # (uint) or a `[coin, multiasset]` pair — only the coin component matters.
    if isinstance(output, (list, tuple)):
        address = output[0] if len(output) > 0 else None
        amount = output[1] if len(output) > 1 else None
    elif isinstance(output, dict):
        address = output.get(0)
        amount = output.get(1)
    else:
        raise ValueError("MALFORMED_CBOR: tx output is neither a CBOR array nor a CBOR map")
    if not isinstance(address, bytes):
        raise ValueError("MALFORMED_CBOR: tx output address is not a byte string")
    lovelace = _to_int(amount[0]) if isinstance(amount, (list, tuple)) else _to_int(amount)
    return address, lovelace


def _to_int(v: object) -> int:
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    raise ValueError(f"MALFORMED_CBOR: expected an integer coin value, got {type(v).__name__}")


# -----------------------------------------------------------------------------
# Cardano address bech32 encoding (BIP-173, the CIP-19 bech32 form).
# -----------------------------------------------------------------------------
#
# Implemented inline so the published SDK keeps a minimal dependency surface.
# The header byte's high nibble is the address type and its low nibble is the
# network id (0 = testnet, 1 = mainnet). Payment-address types 0-7 use the
# `addr` HRP; stake/reward types 14-15 use the `stake` HRP. The header's
# network nibble is authoritative for the `_test` suffix; the caller's
# `network` argument is the fallback when a header is ambiguous.

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _encode_cardano_address(address_bytes: bytes, network: str) -> str:
    if len(address_bytes) == 0:
        raise ValueError("MALFORMED_CBOR: empty address byte string")
    header = address_bytes[0]
    address_type = header >> 4
    network_nibble = header & 0x0F
    is_stake = address_type in (14, 15)
    # The header's network nibble is authoritative. Fall back to the caller's
    # network only when the nibble is not the canonical 0 / 1.
    if network_nibble == 0:
        is_testnet = True
    elif network_nibble == 1:
        is_testnet = False
    else:
        is_testnet = network == "preprod"
    base = "stake" if is_stake else "addr"
    hrp = f"{base}_test" if is_testnet else base
    return _bech32_encode(hrp, address_bytes)


def _bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    out: list[int] = [ord(c) >> 5 for c in hrp]
    out.append(0)
    out.extend(ord(c) & 31 for c in hrp)
    return out


def _bech32_to_words(data: bytes) -> list[int]:
    # 8-bit -> 5-bit regrouping with zero-padding of the final group.
    acc = 0
    bits = 0
    out: list[int] = []
    maxv = (1 << 5) - 1
    for value in data:
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & maxv)
    if bits > 0:
        out.append((acc << (5 - bits)) & maxv)
    return out


def _bech32_encode(hrp: str, data: bytes) -> str:
    words = _bech32_to_words(data)
    polymod_input = _bech32_hrp_expand(hrp) + words + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(polymod_input) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    result = f"{hrp}1"
    for w in words + checksum:
        result += _BECH32_CHARSET[w]
    return result


__all__ = ["decode_tx_summary", "decode_tx_witnesses"]
