from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Literal, TypedDict, cast

from .cbor import (
    CanonicalCborError,
    CanonicalCborValue,
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from .compare_ct import compare_ct
from .sig import sign_ed25519, verify_ed25519

# CIP-309 v1 domain separator embedded as a prefix on Sig_structure[3]
# (`to_sign`). Length pinned at 25 UTF-8 bytes by spec.
CARDANO_POE_SIG_DOMAIN_PREFIX: bytes = b"cardano-poe-record-sig-v1"
if len(CARDANO_POE_SIG_DOMAIN_PREFIX) != 25:
    raise AssertionError(
        f"cardano-poe-record-sig-v1 prefix must encode to exactly 25 UTF-8 bytes, "
        f"got {len(CARDANO_POE_SIG_DOMAIN_PREFIX)}"
    )

CoseHeader = dict[int | str, object]


class CoseSign1Decoded(TypedDict):
    protected_header: CoseHeader
    protected_bytes: bytes
    unprotected_header: CoseHeader
    payload: bytes | None
    signature: bytes


class CoseVerifyFailureError(TypedDict):
    code: str
    message: str


class CoseVerifySuccess(TypedDict):
    ok: Literal[True]
    signer_key: bytes
    alg: int


class CoseVerifyFailure(TypedDict):
    ok: Literal[False]
    error: CoseVerifyFailureError


CoseVerifyResult = CoseVerifySuccess | CoseVerifyFailure


class CoseVerifyError(Exception):
    MALFORMED_SIG_COSE = "MALFORMED_SIG_COSE"
    UNSUPPORTED_SIG_ALG = "UNSUPPORTED_SIG_ALG"
    KID_UNRESOLVED = "KID_UNRESOLVED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


def build_sig_structure(
    *,
    context: Literal["Signature1"],
    body_protected_bytes: bytes,
    external_aad: bytes,
    payload: bytes,
) -> bytes:
    value: list[CanonicalCborValue] = [context, body_protected_bytes, external_aad, payload]
    return encode_canonical_cbor(cast(CanonicalCborValue, value))


def encode_cose_sign1(
    *,
    protected_header: CoseHeader,
    unprotected_header: CoseHeader,
    payload: bytes | None,
    signature: bytes,
) -> bytes:
    if len(protected_header) == 0:
        protected_bytes = b""
    else:
        protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    arr: list[CanonicalCborValue] = [
        protected_bytes,
        cast(CanonicalCborValue, unprotected_header),
        payload,
        signature,
    ]
    return encode_canonical_cbor(cast(CanonicalCborValue, arr))


def decode_cose_sign1(data: bytes) -> CoseSign1Decoded:
    try:
        arr = decode_canonical_cbor(data)
    except CanonicalCborError as cause:
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "cose decode failed") from cause
    if not isinstance(arr, list) or len(arr) != 4:
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "expected 4-element array")
    protected_bytes_raw, unprotected_raw, payload_raw, signature_raw = arr
    if not isinstance(protected_bytes_raw, bytes):
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "protected_bytes must be bytes")
    if not isinstance(unprotected_raw, dict):
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "unprotected header must be map")
    if payload_raw is not None and not isinstance(payload_raw, bytes):
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "payload must be bytes or null")
    if not isinstance(signature_raw, bytes) or len(signature_raw) != 64:
        raise CoseVerifyError(CoseVerifyError.MALFORMED_SIG_COSE, "signature must be 64 bytes")
    if len(protected_bytes_raw) == 0:
        protected_header: CoseHeader = {}
    else:
        try:
            decoded_protected = decode_canonical_cbor(protected_bytes_raw)
        except CanonicalCborError as cause:
            raise CoseVerifyError(
                CoseVerifyError.MALFORMED_SIG_COSE, "protected header decode failed"
            ) from cause
        if not isinstance(decoded_protected, dict):
            raise CoseVerifyError(
                CoseVerifyError.MALFORMED_SIG_COSE, "protected header must decode to map"
            )
        # Empty protected header MUST encode as the single byte 0x40 (zero-length bstr),
        # not 0x41 0xA0 (a 1-byte bstr containing an empty CBOR map). RFC 9052 §3 +
        # CIP-309 canonical-CBOR mandate.
        if len(decoded_protected) == 0:
            raise CoseVerifyError(
                CoseVerifyError.MALFORMED_SIG_COSE,
                "empty protected header must encode as 0x40 (zero-length bstr), "
                "not as an empty map",
            )
        # Byte-pin: protected_bytes MUST equal the canonical encoding of the decoded map.
        # Catches non-canonical integer widths (e.g. 0x1801 instead of 0x01 for key=1),
        # non-canonical map key ordering, and other CDE violations that cbor2's permissive
        # decoder accepts. TS parity: cbor2's `cdeDecodeOptions` enforces this at the
        # decoder layer; Python's cbor2 lib does not, so we re-encode and compare here.
        # Empty-map encoded as 0xA0 (1-byte bstr wrapper 0x41A0) is also caught by this
        # check since canonical empty-map protected header MUST be 0x40 (zero-length bstr,
        # handled by the len==0 branch above).
        canonical_bytes = encode_canonical_cbor(cast(CanonicalCborValue, decoded_protected))
        if not compare_ct(canonical_bytes, protected_bytes_raw):
            raise CoseVerifyError(
                CoseVerifyError.MALFORMED_SIG_COSE,
                "protected header bytes are not canonical CBOR",
            )
        protected_header = cast(CoseHeader, decoded_protected)
    return CoseSign1Decoded(
        protected_header=protected_header,
        protected_bytes=protected_bytes_raw,
        unprotected_header=cast(CoseHeader, unprotected_raw),
        payload=payload_raw,
        signature=signature_raw,
    )


def cose_sign1_build(
    *,
    protected_header: CoseHeader,
    unprotected_header: CoseHeader,
    payload: bytes,
    external_aad: bytes,
    signer_secret_key: bytes,
    detached: bool = True,
) -> bytes:
    if len(protected_header) == 0:
        protected_bytes = b""
    else:
        protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    sig_structure_bytes = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_bytes,
        external_aad=external_aad,
        payload=payload,
    )
    signature = sign_ed25519(signer_secret_key, sig_structure_bytes)
    return encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header=unprotected_header,
        payload=None if detached else payload,
        signature=signature,
    )


def cose_sign1_verify(
    *,
    message: bytes,
    external_aad: bytes,
    expected_signer_key: bytes | None = None,
    detached_payload: bytes | None = None,
) -> CoseVerifyResult:
    try:
        decoded = decode_cose_sign1(message)
    except CoseVerifyError as e:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(code=e.code, message="errors.cose.malformed"),
        )
    alg_raw = decoded["protected_header"].get(1)
    if not isinstance(alg_raw, int) or isinstance(alg_raw, bool) or alg_raw != -8:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.UNSUPPORTED_SIG_ALG,
                message="errors.cose.unsupported_alg",
            ),
        )
    kid_raw = decoded["protected_header"].get(4)
    signer_key: bytes | None = None
    if isinstance(kid_raw, bytes) and len(kid_raw) == 32:
        signer_key = kid_raw
    elif expected_signer_key is not None and len(expected_signer_key) == 32:
        signer_key = expected_signer_key
    if signer_key is None:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.KID_UNRESOLVED,
                message="errors.cose.kid_unresolved",
            ),
        )
    if decoded["payload"] is not None:
        payload_bytes = decoded["payload"]
    elif detached_payload is not None:
        payload_bytes = detached_payload
    else:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.MALFORMED_SIG_COSE,
                message="errors.cose.detached_payload_required",
            ),
        )
    sig_structure_bytes = build_sig_structure(
        context="Signature1",
        body_protected_bytes=decoded["protected_bytes"],
        external_aad=external_aad,
        payload=payload_bytes,
    )
    valid = verify_ed25519(signer_key, sig_structure_bytes, decoded["signature"])
    if not valid:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.SIGNATURE_INVALID,
                message="errors.cose.signature_invalid",
            ),
        )
    return CoseVerifySuccess(ok=True, signer_key=signer_key, alg=alg_raw)


# CIP-309 v1 specialisation of Sig_structure:
#   to_sign       = utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_minus_sigs)
#   Sig_structure = [ "Signature1", body_protected, h'' (empty), to_sign ]
def build_cip309_sig_structure(
    *,
    body_protected_bytes: bytes,
    record_body_cbor: bytes,
) -> bytes:
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + record_body_cbor
    return build_sig_structure(
        context="Signature1",
        body_protected_bytes=body_protected_bytes,
        external_aad=b"",
        payload=to_sign,
    )


class CoseSign1BuildError(Exception):
    SIGNER_NOT_PROVIDED = "SIGNER_NOT_PROVIDED"
    SIGNER_AND_SEED_BOTH_PROVIDED = "SIGNER_AND_SEED_BOTH_PROVIDED"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


# CIP-309 v1 record-signature builder. Caller MUST pass exactly one of
# `signer_secret_key` (seed-based test/SDK path) or `signer`
# (injected closure for session-memory zero-leak composer use). The 25-byte
# UTF-8 domain prefix is prepended internally — callers MUST NOT pre-concatenate.
def cose_sign1_cip309_build(
    *,
    protected_header: CoseHeader,
    unprotected_header: CoseHeader,
    record_body_cbor: bytes,
    signer_secret_key: bytes | None = None,
    signer: Callable[[bytes], bytes] | None = None,
) -> bytes:
    if signer_secret_key is None and signer is None:
        raise CoseSign1BuildError(
            CoseSign1BuildError.SIGNER_NOT_PROVIDED,
            "cose_sign1_cip309_build requires either signer_secret_key or signer",
        )
    if signer_secret_key is not None and signer is not None:
        raise CoseSign1BuildError(
            CoseSign1BuildError.SIGNER_AND_SEED_BOTH_PROVIDED,
            "cose_sign1_cip309_build accepts signer_secret_key XOR signer (not both)",
        )
    if len(protected_header) == 0:
        protected_bytes = b""
    else:
        protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    sig_structure_bytes = build_cip309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=record_body_cbor,
    )
    if signer is not None:
        signature = signer(sig_structure_bytes)
        if not isinstance(signature, bytes) or len(signature) != 64:
            got = len(signature) if isinstance(signature, bytes) else type(signature).__name__
            raise CoseSign1BuildError(
                CoseSign1BuildError.SIGNER_NOT_PROVIDED,
                f"injected signer must return 64 bytes; got {got}",
            )
    else:
        assert signer_secret_key is not None  # noqa: S101
        signature = sign_ed25519(signer_secret_key, sig_structure_bytes)
    return encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header=unprotected_header,
        payload=None,
        signature=signature,
    )


# CIP-309 v1 record-signature verifier.
def cose_sign1_cip309_verify(
    *,
    message: bytes,
    detached_record_body_cbor: bytes,
    expected_signer_key: bytes | None = None,
) -> CoseVerifyResult:
    try:
        decoded = decode_cose_sign1(message)
    except CoseVerifyError as e:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(code=e.code, message="errors.cose.malformed"),
        )
    # COSE_Sign1[2] (payload) MUST be CBOR null. Any non-null payload
    # (including h'') is MALFORMED_SIG_COSE_SIGN1.
    if decoded["payload"] is not None:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code="MALFORMED_SIG_COSE_SIGN1",
                message="errors.cose.attached_payload_forbidden",
            ),
        )
    alg_raw = decoded["protected_header"].get(1)
    if not isinstance(alg_raw, int) or isinstance(alg_raw, bool) or alg_raw != -8:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.UNSUPPORTED_SIG_ALG,
                message="errors.cose.unsupported_alg",
            ),
        )
    kid_raw = decoded["protected_header"].get(4)
    signer_key: bytes | None = None
    if isinstance(kid_raw, bytes) and len(kid_raw) == 32:
        signer_key = kid_raw
    elif expected_signer_key is not None and len(expected_signer_key) == 32:
        signer_key = expected_signer_key
    if signer_key is None:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.KID_UNRESOLVED,
                message="errors.cose.kid_unresolved",
            ),
        )
    # When both a protected-header kid AND an expected_signer_key are provided,
    # require they agree (constant-time). Disagreement is a misuse, not a
    # transient mismatch.
    if (
        isinstance(kid_raw, bytes)
        and len(kid_raw) == 32
        and expected_signer_key is not None
        and len(expected_signer_key) == 32
        and not compare_ct(kid_raw, expected_signer_key)
    ):
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.KID_UNRESOLVED,
                message="errors.cose.kid_mismatch",
            ),
        )
    # CIP-8 `hashed = true` mode. When the unprotected header carries
    # `"hashed": True`, both producer and verifier substitute
    # `Sig_structure[3]` with the 28-byte Blake2b-224 digest of the FULL
    # `to_sign` payload (prefix + record body). When absent or False, the
    # standard non-hashed path applies unchanged.
    hashed_flag = decoded["unprotected_header"].get("hashed")
    if hashed_flag is True:
        to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + detached_record_body_cbor
        hashed_payload = hashlib.blake2b(to_sign, digest_size=28).digest()
        sig_structure_bytes = build_sig_structure(
            context="Signature1",
            body_protected_bytes=decoded["protected_bytes"],
            external_aad=b"",
            payload=hashed_payload,
        )
    else:
        sig_structure_bytes = build_cip309_sig_structure(
            body_protected_bytes=decoded["protected_bytes"],
            record_body_cbor=detached_record_body_cbor,
        )
    valid = verify_ed25519(signer_key, sig_structure_bytes, decoded["signature"])
    if not valid:
        return CoseVerifyFailure(
            ok=False,
            error=CoseVerifyFailureError(
                code=CoseVerifyError.SIGNATURE_INVALID,
                message="errors.cose.signature_invalid",
            ),
        )
    return CoseVerifySuccess(ok=True, signer_key=signer_key, alg=alg_raw)
