from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from cardanowall.poe_standard import ErrorCode, PoeRecord

# `VerifyReport.verdict` and `exit_code` are a closed four-state pair.
# `valid` (exit 0) is the only happy path; `pending` (exit 3)
# fires exclusively on `INSUFFICIENT_CONFIRMATIONS`; `failed` splits into
# exit 1 (record-attributable) and exit 2 (network-class — every gateway in a
# chain exhausted). Keeping these as `Literal` types lets mypy --strict catch
# any path that synthesises an off-grid combination.
Verdict = Literal["valid", "pending", "failed"]
ExitCode = Literal[0, 1, 2, 3]
Purpose = Literal["cardano", "arweave", "ipfs"]
Method = Literal["GET", "POST"]

# Four conformance profiles in strict-superset order. `recipient-sealed`
# is the union; lower profiles skip higher-profile fields with the
# info-severity `OUT_OF_PROFILE_SKIPPED` code (NOT `SCHEMA_UNKNOWN_FIELD`,
# which is reserved for fields outside the v1 CDDL).
Profile = Literal["core", "signed", "sealed", "recipient-sealed"]

NetworkId = Literal["cardano:mainnet"]


# Codes the verifier emits in addition to the validator's structural codes.
# Mirror-only: every literal also appears in
# `poe_standard.error_codes.ErrorCode`. The dict survives for callers that
# pre-date the unified literal and want a stable name-lookup table.
VERIFIER_ONLY_ERROR_CODES: Final[dict[str, str]] = {
    "METADATA_NOT_FOUND": "METADATA_NOT_FOUND",
    "INSUFFICIENT_CONFIRMATIONS": "INSUFFICIENT_CONFIRMATIONS",
    "SIGNER_KEY_UNRESOLVED": "SIGNER_KEY_UNRESOLVED",
    "SIGNATURE_INVALID": "SIGNATURE_INVALID",
    "WALLET_ADDRESS_MISMATCH": "WALLET_ADDRESS_MISMATCH",
    "URI_INTEGRITY_MISMATCH": "URI_INTEGRITY_MISMATCH",
    "URI_FETCH_FAILED": "URI_FETCH_FAILED",
    "CONTENT_UNAVAILABLE": "CONTENT_UNAVAILABLE",
    "URI_TARGET_FORBIDDEN": "URI_TARGET_FORBIDDEN",
    "CIPHERTEXT_UNAVAILABLE": "CIPHERTEXT_UNAVAILABLE",
    "WRONG_DECRYPTION_INPUT_SHAPE": "WRONG_DECRYPTION_INPUT_SHAPE",
    "WRONG_RECIPIENT_KEY": "WRONG_RECIPIENT_KEY",
    "TAMPERED_HEADER": "TAMPERED_HEADER",
    "TAMPERED_CIPHERTEXT": "TAMPERED_CIPHERTEXT",
    "PROVIDER_UNAVAILABLE": "PROVIDER_UNAVAILABLE",
    "SERVICE_INDEPENDENCE_VIOLATION": "SERVICE_INDEPENDENCE_VIOLATION",
    "MERKLE_ROOT_MISMATCH": "MERKLE_ROOT_MISMATCH",
    "MERKLE_LEAVES_UNAVAILABLE": "MERKLE_LEAVES_UNAVAILABLE",
    "MERKLE_UNSUPPORTED": "MERKLE_UNSUPPORTED",
    "MERKLE_LEAVES_INFORMATIVE_FORM": "MERKLE_LEAVES_INFORMATIVE_FORM",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH": "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED": "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
    "OUT_OF_PROFILE_SKIPPED": "OUT_OF_PROFILE_SKIPPED",
    "KDF_DERIVATION_FAILED": "KDF_DERIVATION_FAILED",
}

VerifierIssueCode = ErrorCode


@dataclass(frozen=True)
class VerifierIssue:
    code: str
    path: tuple[str | int, ...]
    message: str


# Per-entry signature failure reasons. `SIGNATURE_UNSUPPORTED` is
# info-severity — a hash-only PoE remains `valid` even when every signature
# is unsupported. `WALLET_ADDRESS_MISMATCH` is the path-2-only check; it is
# NOT collapsed into `SIGNATURE_INVALID` because the Ed25519 verify itself
# succeeded — only the address-pubkey binding failed.
SigFailureReason = Literal[
    "MALFORMED_SIG_COSE_SIGN1",
    "SIGNATURE_UNSUPPORTED",
    "SIGNER_KEY_UNRESOLVED",
    "SIGNATURE_INVALID",
    "WALLET_ADDRESS_MISMATCH",
]
SignerType = Literal["in-signature-kid", "wallet-inline-key"]

# Per-entry record-signature verdict. `valid` is the only happy path; the three
# failure verdicts mirror the TypeScript twin so the cross-language goldens stay
# byte-identical. `unsupported` (SIGNATURE_UNSUPPORTED) is info-severity: a
# public hash-only PoE stays `valid` even when every signature is unsupported.
SignatureVerdict = Literal["valid", "invalid", "unsupported", "unresolved"]

# Per-decryption verdict. `decrypted` is the only success state; every other
# value is a distinct failure mode so the UI can render differentiated copy.
DecryptionVerdict = Literal[
    "decrypted",
    "wrong-key",
    "tampered-header",
    "tampered-ciphertext",
    "wrong-input-shape",
    "no-enc-envelope",
    "ciphertext-unavailable",
    "content-unavailable",
    "skipped",
    "kdf-failed",
]

# Per-Merkle-commit verdict. `valid` / `mismatch` are root-bind outcomes;
# `unavailable` (leaves blob unfetchable) is warning-severity — the on-chain
# root commitment alone remains structurally valid — and `format-unsupported`
# / `unsupported` are info/warning-severity, none of which fail the verdict.
MerkleVerdict = Literal[
    "valid",
    "mismatch",
    "unavailable",
    "format-unsupported",
    "unsupported",
]

# Per-decryption failure reasons. Distinct codes per unwrap-stage failure
# mode so UI can render differentiated copy.
DecryptionFailureReason = Literal[
    "no_enc_envelope",
    "URI_FETCH_FAILED",
    "CIPHERTEXT_UNAVAILABLE",
    "URI_TARGET_FORBIDDEN",
    "CONTENT_UNAVAILABLE",
    "WRONG_RECIPIENT_KEY",
    "TAMPERED_HEADER",
    "TAMPERED_CIPHERTEXT",
    "WRONG_DECRYPTION_INPUT_SHAPE",
    "KDF_DERIVATION_FAILED",
    "URI_INTEGRITY_MISMATCH",
]

UriFailureReason = Literal[
    "URI_FETCH_FAILED",
    "URI_INTEGRITY_MISMATCH",
    "URI_TARGET_FORBIDDEN",
    "CONTENT_UNAVAILABLE",
]

# Per-Merkle-commit outcome. `MERKLE_LEAVES_UNAVAILABLE` is warning-severity
# (the on-chain root commitment alone remains structurally valid); every
# other reason here is error-severity.
MerkleCheckReason = Literal[
    "MERKLE_LEAVES_UNAVAILABLE",
    "MERKLE_ROOT_MISMATCH",
    "MERKLE_UNSUPPORTED",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
]


@dataclass(frozen=True, kw_only=True)
class FetchOutboundOptions:
    method: Method
    purpose: Purpose
    headers: Mapping[str, str] | None = None
    body: str | None = None
    # Hard cap on the response body the primitive will buffer. Gateway content
    # (ar:// / ipfs:// / https) is producer-chosen and therefore UNTRUSTED — the
    # verifier never trusts the producer — so a malicious gateway could otherwise
    # stream unbounded bytes into memory. None → DEFAULT_OUTBOUND_MAX_BYTES.
    max_bytes: int | None = None


@dataclass(frozen=True, kw_only=True)
class FetchOutboundResult:
    status: int
    bytes: bytes
    duration_ms: int


class FetchOutbound(Protocol):
    async def __call__(self, url: str, opts: FetchOutboundOptions) -> FetchOutboundResult: ...


# Discriminated decryption union. The `item.enc` shape on the record
# (`enc.slots` vs `enc.passphrase`) selects which Decryption variant the
# verifier expects; a mismatch surfaces as WRONG_DECRYPTION_INPUT_SHAPE.
@dataclass(frozen=True, kw_only=True)
class DecryptionRecipient:
    """Sealed-recipient path entry. `recipient_secret_key` MUST be 32 B X25519."""

    item_index: int
    recipient_secret_key: bytes


@dataclass(frozen=True, kw_only=True)
class DecryptionPassphrase:
    """Passphrase path entry. The passphrase is normalised NFKC → collapse
    whitespace → trim → UTF-8 encode before Argon2id."""

    item_index: int
    passphrase: str


Decryption = DecryptionRecipient | DecryptionPassphrase


# Verifier input. Field names mirror the TS twin with snake_case
# translation.
@dataclass(frozen=True, kw_only=True)
class VerifyTxInput:
    tx_hash: str
    profile: Profile = "recipient-sealed"
    network: NetworkId = "cardano:mainnet"
    cardano_gateway_chain: tuple[str, ...] | None = None
    blockfrost_project_id: str | None = None
    arweave_gateway_chain: tuple[str, ...] | None = None
    ipfs_gateway_chain: tuple[str, ...] | None = None
    confirmation_depth_threshold: int | None = None
    # Deny-host glob is exact-host or `*.<suffix>`. The default list MUST
    # exclude any single-implementer domain so a conformance suite can
    # prove service-independence by running with the default list active
    # and observing no skipped fixtures.
    deny_hosts: tuple[str, ...] | None = None
    # `decryption` carries discriminated-union entries; the verifier dispatches
    # on the on-wire `item.enc.passphrase` vs `item.enc.slots` shape and emits
    # WRONG_DECRYPTION_INPUT_SHAPE on mismatch.
    decryption: tuple[Decryption, ...] | None = None
    # Out-of-band ciphertext. Keyed by item index; local bytes take
    # precedence over `item.uris[]` when both are supplied.
    ciphertext_bytes: Mapping[int, bytes] | None = None
    # Out-of-band Merkle leaves-list (CBOR is the normative wire form).
    # Keyed by `merkle[i]` index. JSON projections trigger
    # MERKLE_LEAVES_INFORMATIVE_FORM info-severity.
    merkle_leaves: Mapping[int, bytes] | None = None
    fetch_outbound: FetchOutbound | None = None


@dataclass(frozen=True, kw_only=True)
class HttpCallRecord:
    url: str
    method: Method
    status: int
    bytes: int
    duration_ms: int
    purpose: Purpose


@dataclass(frozen=True, kw_only=True)
class VerifyRecordSignature:
    index: int
    verdict: SignatureVerdict
    signer_pub: str | None = None
    signer_type: SignerType | None = None
    reason: SigFailureReason | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyItemDecryption:
    item_index: int
    verdict: DecryptionVerdict
    # True iff every content-hash entry in `items[i].hashes` recomputes to the
    # recovered plaintext. Always a concrete boolean on `verdict == 'decrypted'`.
    plaintext_hash_ok: bool | None = None
    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyUriCheck:
    item_index: int
    uri: str
    ok: bool
    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class ItemHashCheck:
    item_index: int
    alg: str
    ok: bool


@dataclass(frozen=True, kw_only=True)
class VerifyMerkleCheck:
    merkle_index: int
    alg: str
    verdict: MerkleVerdict
    root_recomputed: bytes | None = None
    reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class SupersedesResolved:
    tx: str
    exists: bool


# -----------------------------------------------------------------------------
# Transaction-level description — DISTINCT from record-level authorship.
# -----------------------------------------------------------------------------
#
# These surfaces describe the Cardano transaction that carried the PoE: which
# wallet vkey(s) authorised/paid for it, the fee, and the outputs. This is the
# "who submitted and paid for this anchoring" view — orthogonal to
# `record_signatures`, which is the optional CIP-309 record-level authorship
# claim. A failed `signature_valid` here is INFORMATIONAL: it never changes the
# verifier's verdict (the content claim does not depend on who paid the fee).
@dataclass(frozen=True, kw_only=True)
class VerifyTxWitness:
    type: Literal["vkey"]
    vkey: str  # hex 32B Ed25519 pubkey
    key_hash: str  # hex 28B Blake2b-224(vkey)
    signature_valid: bool  # Ed25519.verify(sig, blake2b256(tx_body), vkey)


@dataclass(frozen=True, kw_only=True)
class VerifyTxOutput:
    address: str  # bech32
    lovelace: str  # decimal string


@dataclass(frozen=True, kw_only=True)
class VerifyTxSummary:
    fee_lovelace: str  # decimal string
    input_count: int
    output_count: int
    outputs: tuple[VerifyTxOutput, ...]
    total_output_lovelace: str  # decimal string
    script_witness_count: int
    invalid_before: int | None = None
    invalid_hereafter: int | None = None
    required_signer_key_hashes: tuple[str, ...] | None = None
    network_id: int | None = None


# Three issue sinks per severity, mirroring the validator's `info` /
# `warnings` / `issues` triad. `valid` is a pure structural-pass claim;
# `pending` and `failed` carry their respective code under `issues`.
@dataclass(frozen=True, kw_only=True)
class ValidationSummary:
    valid: bool
    issues: tuple[VerifierIssue, ...] = ()
    warnings: tuple[VerifierIssue, ...] = ()
    info: tuple[VerifierIssue, ...] = ()


@dataclass(frozen=True, kw_only=True)
class VerifyReport:
    tx_hash: str
    verdict: Verdict
    exit_code: ExitCode
    profile: Profile
    network: NetworkId
    confirmation_depth_threshold: int
    validation: ValidationSummary
    http_calls: tuple[HttpCallRecord, ...]
    metadata_present: bool = False
    num_confirmations: int = 0
    block_time: int | None = None
    block_slot: int | None = None
    record: PoeRecord | None = None
    record_signatures: tuple[VerifyRecordSignature, ...] | None = None
    # Transaction-level description (present only when raw tx CBOR is available
    # to the pipeline). `tx_witnesses` is `()` on placeholder-body records and
    # populated when the body carries vkey witnesses; `tx_summary` is present
    # only when the body decodes to a summarisable shape; `metadata_labels` is
    # the ascending-sorted list of every aux metadata label key (`[309]` for a
    # bare PoE tx).
    tx_witnesses: tuple[VerifyTxWitness, ...] | None = None
    tx_summary: VerifyTxSummary | None = None
    metadata_labels: tuple[int, ...] | None = None
    item_hash_checks: tuple[ItemHashCheck, ...] | None = None
    item_decryptions: tuple[VerifyItemDecryption, ...] | None = None
    uri_checks: tuple[VerifyUriCheck, ...] | None = None
    merkle_checks: tuple[VerifyMerkleCheck, ...] | None = None
    supersedes_resolved: SupersedesResolved | None = None


__all__ = [
    "VERIFIER_ONLY_ERROR_CODES",
    "Decryption",
    "DecryptionFailureReason",
    "DecryptionPassphrase",
    "DecryptionRecipient",
    "DecryptionVerdict",
    "ExitCode",
    "FetchOutbound",
    "FetchOutboundOptions",
    "FetchOutboundResult",
    "HttpCallRecord",
    "ItemHashCheck",
    "MerkleCheckReason",
    "MerkleVerdict",
    "Method",
    "NetworkId",
    "Profile",
    "Purpose",
    "SigFailureReason",
    "SignatureVerdict",
    "SignerType",
    "SupersedesResolved",
    "UriFailureReason",
    "ValidationSummary",
    "Verdict",
    "VerifierIssue",
    "VerifierIssueCode",
    "VerifyItemDecryption",
    "VerifyMerkleCheck",
    "VerifyRecordSignature",
    "VerifyReport",
    "VerifyTxInput",
    "VerifyTxOutput",
    "VerifyTxSummary",
    "VerifyTxWitness",
    "VerifyUriCheck",
]
