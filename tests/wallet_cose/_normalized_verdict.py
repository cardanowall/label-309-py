"""Python mirror of the cross-language verdict projection.

This is the parity counterpart to the @cardanowall/sdk-ts normalized-verdict
projection. Both languages compute the same `NormalizedSigVerdict` shape from
their native verifier output; the fixture's `expected_normalized_verdict` field
is the single source of truth.

Both implementations emit the same 4-state `verdict: 'valid' | 'invalid' |
'unsupported' | 'unresolved'`. The projection collapses it to a common
`ok: bool` (`verdict == 'valid'`) while preserving `reason`. See the verifier
`types` modules on each side for the underlying types.
"""

from __future__ import annotations

from typing import TypedDict

from cardanowall.verifier import VerifyRecordSignature


class NormalizedSigVerdict(TypedDict):
    index: int
    signer_pub_hex: str | None
    signer_type: str | None
    ok: bool
    reason: str | None


def to_normalized_sig_verdict(check: VerifyRecordSignature) -> NormalizedSigVerdict:
    return {
        "index": check.index,
        "signer_pub_hex": check.signer_pub,
        "signer_type": check.signer_type,
        "ok": check.verdict == "valid",
        "reason": check.reason,
    }
