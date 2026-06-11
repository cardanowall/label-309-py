# Passphrase normalization profile `cardano-poe-pw-norm-v1`.
#
# The normalization applied to a passphrase before the Argon2id KDF is
# normative: two implementations MUST derive a byte-identical content
# encryption key from the same passphrase, so the profile is pinned — NFKC
# under the pinned Unicode 16.0.0 tables, then collapse of every maximal
# `White_Space` run to a single U+0020, then a trim of leading/trailing space,
# then UTF-8. Input the pinned tables cannot normalize stably — a lone
# surrogate, or a codepoint Unicode 16.0 leaves unassigned (a later Unicode
# version may give it a decomposition and silently change the derived key) —
# is rejected. A post-normalization-empty passphrase is rejected too: Argon2id
# would silently accept zero bytes and key the record to a CEK any party can
# derive.

from __future__ import annotations

from typing import Final

from .unicode_nfkc16 import Nfkc16Error, is_white_space16, nfkc16

# Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE any
# normalization or KDF work. An oversized passphrase would otherwise drive
# unbounded NFKC / whitespace-collapse work and a large Argon2id input before
# any cost-bounded primitive runs. The bound is byte length of the raw UTF-8
# encoding, not code-point count, so a short string of wide multi-byte
# characters is still measured by its encoded size. 4096 bytes is far above
# any human-chosen passphrase. Identical across every SDK.
MAX_PASSPHRASE_INPUT_BYTES: Final[int] = 4096

# Normalization profile identifier. A scheme-fixed constant bound into the
# passphrase transcript to pin the exact profile the CEK was derived under;
# never serialised on the wire.
CARDANO_POE_PW_NORM_PROFILE: Final[str] = "cardano-poe-pw-norm-v1"

ENC_PASSPHRASE_EMPTY: Final[str] = "ENC_PASSPHRASE_EMPTY"  # noqa: S105
ENC_PASSPHRASE_UNNORMALIZABLE: Final[str] = "ENC_PASSPHRASE_UNNORMALIZABLE"  # noqa: S105
PASSPHRASE_INPUT_TOO_LONG: Final[str] = "PASSPHRASE_INPUT_TOO_LONG"  # noqa: S105


class PassphraseNormalizationError(Exception):
    """A passphrase was rejected before key derivation.

    Carries a typed ``code``: ``ENC_PASSPHRASE_EMPTY`` for a passphrase that
    normalizes to the empty string, ``ENC_PASSPHRASE_UNNORMALIZABLE`` for one
    the pinned Unicode 16.0 tables cannot normalize stably (a lone surrogate
    or an unassigned codepoint), ``PASSPHRASE_INPUT_TOO_LONG`` for raw input
    over the pre-normalization byte cap.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


def normalize_passphrase(passphrase: str) -> bytes:
    """Apply `cardano-poe-pw-norm-v1` and return the Argon2id password bytes.

    Order: raw UTF-8 byte cap (pre-normalization), pinned-Unicode-16.0 NFKC
    (rejecting unnormalizable input), `White_Space`-run collapse to a single
    U+0020, trim, reject post-normalization empty, UTF-8 encode.
    """
    # The cap measures raw input size even when the text carries lone
    # surrogates (which strict UTF-8 refuses to encode); such input is
    # rejected as unnormalizable immediately after, but the size bound must
    # fire first — and as a typed error, not a UnicodeEncodeError. A lone
    # surrogate measures 3 bytes under surrogatepass, matching what a UTF-16
    # implementation counts for its replacement character.
    raw_bytes = len(passphrase.encode("utf-8", "surrogatepass"))
    if raw_bytes > MAX_PASSPHRASE_INPUT_BYTES:
        raise PassphraseNormalizationError(
            PASSPHRASE_INPUT_TOO_LONG,
            f"raw passphrase is {raw_bytes} UTF-8 bytes; the pre-normalization "
            f"cap is {MAX_PASSPHRASE_INPUT_BYTES}",
        )
    try:
        folded = nfkc16(passphrase)
    except Nfkc16Error as cause:
        raise PassphraseNormalizationError(ENC_PASSPHRASE_UNNORMALIZABLE, str(cause)) from cause
    # Collapse every maximal run of the pinned Unicode 16.0 `White_Space`
    # property to one U+0020. The pinned predicate is used directly — neither
    # the `\s` regex class nor `str.isspace` matches this set exactly, and the
    # CEK derivation must be byte-identical across implementations.
    out: list[str] = []
    in_run = False
    for ch in folded:
        if is_white_space16(ord(ch)):
            if not in_run:
                out.append(" ")
                in_run = True
        else:
            out.append(ch)
            in_run = False
    normalized = "".join(out).strip(" ")
    if not normalized:
        raise PassphraseNormalizationError(
            ENC_PASSPHRASE_EMPTY,
            "passphrase normalizes to the empty string (whitespace-only or vacuous)",
        )
    return normalized.encode("utf-8")
