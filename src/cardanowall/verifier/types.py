from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from cardanowall.poe_standard import ErrorCode, PoeRecord, Severity, severity_of

# The machine verdict and its exit-code projection form a closed four-state
# pair: `valid` → 0, `failed` → 1 (record-attributable outcomes only),
# `unverifiable` → 2 (a required check could not run or could not be
# attributed, for network / policy / provider-integrity reasons), `pending` → 3
# (below the confirmation-depth threshold). Exit codes 4+ are reserved for
# verifier-host runtime failures and never correspond to a verdict.
Verdict = Literal["valid", "pending", "unverifiable", "failed"]
ExitCode = Literal[0, 1, 2, 3]
Purpose = Literal["cardano", "arweave", "ipfs"]
Method = Literal["GET", "POST"]

# Four conformance profiles in strict-superset order. Lower profiles skip
# higher-profile fields with the info-severity `OUT_OF_PROFILE_SKIPPED` code
# (NOT `SCHEMA_UNKNOWN_FIELD`, which is reserved for fields outside the v1
# grammar).
Profile = Literal["core", "signed", "sealed", "recipient-sealed"]

# The report's network identifier names the network of the RESOLVED
# transaction as established by the explorer chain the verifier is configured
# against — never a value read from the record body (records carry none).
NetworkId = Literal["cardano:mainnet", "cardano:preprod", "cardano:preview"]

VerifierIssueCode = ErrorCode

# Three-state per-claim content-check status, so an unchecked claim can never
# masquerade as a verified one: `checked` — bytes were obtained and every
# committed digest matched; `mismatched` — attributable fetched (or decrypted)
# bytes failed a commitment; `not_checked` — the claim was not checked
# (`fetch_content` off, availability failure, unattributable fetched bytes, or
# the per-URI fetch ceiling).
ContentCheck = Literal["checked", "mismatched", "not_checked"]


@dataclass(frozen=True, kw_only=True)
class VerifierIssue:
    """One typed issue, shared by the structural validator and the verifier
    layer. Verifier-layer codes that concern the run rather than a record
    location carry an empty path. `severity` defaults to `error`."""

    code: str
    path: tuple[str | int, ...]
    message: str
    severity: Severity = "error"


# Per-entry record-signature verdict. `valid` is the only happy path;
# `unsupported` (SIGNATURE_UNSUPPORTED, info severity) never fails a public
# hash-only PoE; `invalid` and `unresolved` are error-severity outcomes.
SignatureVerdict = Literal["valid", "invalid", "unsupported", "unresolved"]
SignerType = Literal["in-signature-kid", "wallet-inline-key"]
SigFailureReason = Literal[
    "MALFORMED_SIG_COSE_SIGN1",
    "SIGNATURE_UNSUPPORTED",
    "SIGNER_KEY_UNRESOLVED",
    "SIGNATURE_INVALID",
    "WALLET_ADDRESS_MISMATCH",
]


@dataclass(frozen=True, kw_only=True)
class FetchOutboundOptions:
    method: Method
    purpose: Purpose
    headers: Mapping[str, str] | None = None
    body: str | None = None
    # Hard cap on the response body the primitive will buffer, enforced
    # incrementally during streaming. Gateway content is producer-chosen and
    # therefore untrusted; a hostile gateway must not be able to stream
    # unbounded bytes into memory. None → DEFAULT_OUTBOUND_MAX_BYTES.
    max_bytes: int | None = None
    # Deny-host list forwarded by ``wrap_fetch_outbound`` so the transport can
    # re-apply it to a same-domain redirect target (arweave purpose only). The
    # wrapper validated the ORIGINAL url against this list before dispatch; the
    # transport re-validates each redirect hop it chooses to follow so a 3xx
    # can never pivot the fetch onto a denied host behind the wrapper's back.
    deny_hosts: tuple[str, ...] | None = None


@dataclass(frozen=True, kw_only=True)
class FetchOutboundResult:
    status: int
    bytes: bytes
    duration_ms: int


class FetchOutbound(Protocol):
    async def __call__(self, url: str, opts: FetchOutboundOptions) -> FetchOutboundResult: ...


# -----------------------------------------------------------------------------
# Decryption keyring
# -----------------------------------------------------------------------------
#
# The `decryption[]` array is the verification run's KEYRING: a set of
# decryption credentials global to the run, not positionally paired with
# encrypted items. For each `enc`-bearing item the verifier attempts every
# applicable credential independently — each supplied private key through that
# item's trial-decrypt loop, each supplied passphrase through its passphrase
# path. One credential may open several items; different credentials may
# succeed on different items. An `enc`-bearing item for which the keyring
# holds no credential of the applicable shape is reported
# WRONG_DECRYPTION_INPUT_SHAPE.
@dataclass(frozen=True, kw_only=True, repr=False)
class DecryptionRecipient:
    """Recipient-key credential: a 32-byte X25519 scalar (`x25519`) or a
    32-byte X-Wing decapsulation seed (`mlkem768x25519`). Applies to items on
    the `enc.slots` path."""

    recipient_secret_key: bytes

    def __repr__(self) -> str:
        # The recipient private key is secret: a repr in a log line, error
        # chain, or traceback must never surface it.
        return "DecryptionRecipient(recipient_secret_key=<redacted>)"


@dataclass(frozen=True, kw_only=True, repr=False)
class DecryptionPassphrase:
    """Passphrase credential, normalized under the pinned profile before
    Argon2id. Applies to items on the `enc.passphrase` path."""

    passphrase: str

    def __repr__(self) -> str:
        # The passphrase is secret: never surface it via a repr.
        return "DecryptionPassphrase(passphrase=<redacted>)"


Decryption = DecryptionRecipient | DecryptionPassphrase


# -----------------------------------------------------------------------------
# Inputs
# -----------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class VerifyRecordInput:
    """Option surface shared by the transaction-reference entry point and the
    record-bytes sibling entry point."""

    profile: Profile = "recipient-sealed"
    network: NetworkId = "cardano:mainnet"
    arweave_gateway_chain: tuple[str, ...] | None = None
    ipfs_gateway_chain: tuple[str, ...] | None = None
    confirmation_depth_threshold: int | None = None
    # Deny-host pattern is exact-host or `*.<suffix>`. Every operator domain
    # MUST be deny-able without breaking verification of any conformant
    # record; an outbound call to a listed host hard-fails with
    # SERVICE_INDEPENDENCE_VIOLATION.
    deny_hosts: tuple[str, ...] | None = None
    # The run's decryption keyring (see Decryption above). Non-empty AND the
    # profile admits sealed decryption (>= recipient-sealed) ⇒ the run is a
    # RECIPIENT verifier: the structural validator runs in the
    # `recipient_or_strict` role and sealed decryption is attempted. A lower
    # profile never decrypts, so it keeps the public reading even when
    # credentials were supplied.
    decryption: tuple[Decryption, ...] | None = None
    # Out-of-band ciphertext bytes, keyed by item index. Caller-supplied bytes
    # are attributable by definition and take precedence over `item.uris[]`.
    ciphertext_bytes: Mapping[int, bytes] | None = None
    # Out-of-band Merkle leaves-list bytes (the normative CBOR container),
    # keyed by `merkle[i]` index. Likewise attributable by definition.
    merkle_leaves: Mapping[int, bytes] | None = None
    # Master content-fetch switch. When False, every outbound content fetch —
    # item URIs, Merkle leaves-lists, and ciphertext alike — is suppressed and
    # the record renders offline from indexed CBOR alone, with every content
    # claim reported `not_checked`. Caller-supplied out-of-band bytes are
    # still processed (they require no fetch).
    fetch_content: bool = True
    # Per-URI fetch ceiling, enforced incrementally during streaming. A fetch
    # that reaches it aborts with CONTENT_FETCH_LIMIT_EXCEEDED — a statement
    # about the verifier's policy, never about the record. None → the
    # transport default (DEFAULT_OUTBOUND_MAX_BYTES).
    max_fetch_bytes: int | None = None
    fetch_outbound: FetchOutbound | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyTxInput(VerifyRecordInput):
    tx_hash: str = ""
    cardano_gateway_chain: tuple[str, ...] | None = None
    blockfrost_project_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class BlockInfo:
    """Explorer-asserted chain facts for the record-bytes entry point: the
    caller resolved the transaction itself (e.g. a server-rendered viewer with
    indexed data) and supplies what the chain-resolve step would have
    established. ``confirmation_depth`` is counted in blocks — tip - block + 1,
    so a transaction in a block has depth at least 1 by definition; a smaller
    value contradicts the caller's own tuple and is a caller-input error
    (``ValueError``), never a verification outcome."""

    confirmation_depth: int
    block_time: int
    block_slot: int | None = None

    def __post_init__(self) -> None:
        if self.confirmation_depth < 1:
            raise ValueError(
                "confirmation_depth must be >= 1 (a transaction in the tip "
                f"block has depth exactly 1); got {self.confirmation_depth}"
            )


# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class HttpCallRecord:
    """One recorded outbound network call, captured by the single recording
    egress wrapper for every call — success, failure, and retry. `status` is
    the HTTP status when a response was received and None when none was
    (refused call, transport failure)."""

    url: str
    method: Method
    status: int | None
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
class DecryptionOutcome:
    """The recipient-verifier outcome for one `enc`-bearing item after every
    applicable keyring credential was attempted independently."""

    decrypted: bool
    # The post-decryption recheck: every digest in the item's `hashes` map
    # recomputed over the recovered plaintext. A concrete boolean whenever
    # decryption ran to completion; False raises URI_INTEGRITY_MISMATCH and
    # forces the record's verdict to `failed`.
    plaintext_hash_ok: bool | None = None
    # The typed code describing why decryption did not succeed; the same code
    # also appears in the issue list.
    code: str | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyItemEntry:
    """Per-item report entry, positionally aligned with the record's
    `items[]`."""

    content_check: ContentCheck
    decryption: DecryptionOutcome | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyMerkleEntry:
    """Per-commitment report entry, positionally aligned with the record's
    `merkle[]`."""

    content_check: ContentCheck


# -----------------------------------------------------------------------------
# Transaction-level description — distinct from record-level authorship.
# -----------------------------------------------------------------------------
#
# These surfaces describe the Cardano transaction that carried the PoE: which
# wallet vkey(s) authorised/paid for it, the fee, and the outputs — orthogonal
# to `signatures`, the optional record-level authorship claim. Purely
# informational: a failed `signature_valid` here never changes the verdict.
# Field names are the wire form already (the JSON projection emits them
# verbatim, snake_case).
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


@dataclass(frozen=True, kw_only=True)
class VerifyReport:
    """The structured report of one verification run.

    The JSON projection (`verify_report_to_dict`) emits the schema-pinned key
    names: dataclass field names are camelized except the spec-pinned
    `block_time` / `block_slot` and the transaction-description sub-objects,
    whose fields are wire-form already. Required-by-schema fields: verdict,
    exitCode, issues, items, merkle, auditTrail."""

    verdict: Verdict
    exit_code: ExitCode
    # The structural-validation issue list plus every verifier-layer code
    # raised by the run, sorted segment-wise by path with the error-code
    # registry order as the tie-break.
    issues: tuple[VerifierIssue, ...]
    # One entry per record `items[]` / `merkle[]` element, positionally
    # aligned; empty exactly when the record carries no such array.
    items: tuple[VerifyItemEntry, ...]
    merkle: tuple[VerifyMerkleEntry, ...]
    audit_trail: tuple[HttpCallRecord, ...]
    network: NetworkId
    profile: Profile
    tx_hash: str | None = None
    confirmation_depth: int | None = None
    confirmation_threshold: int | None = None
    block_time: int | None = None
    block_slot: int | None = None
    record: PoeRecord | None = None
    signatures: tuple[VerifyRecordSignature, ...] | None = None
    tx_witnesses: tuple[VerifyTxWitness, ...] | None = None
    tx_summary: VerifyTxSummary | None = None
    metadata_labels: tuple[int, ...] | None = None


# Verdict → exit-code projection (the schema's allOf branches).
_EXIT_CODE_FOR_VERDICT: dict[Verdict, ExitCode] = {
    "valid": 0,
    "failed": 1,
    "unverifiable": 2,
    "pending": 3,
}


def exit_code_for_verdict(verdict: Verdict) -> ExitCode:
    return _EXIT_CODE_FOR_VERDICT[verdict]


# Error-severity codes that are NOT record-attributable: network, policy, and
# provider-integrity outcomes. They block a `valid` verdict but can never
# condemn the record — the verdict they produce is `unverifiable`. Every other
# error-severity code is record-attributable and produces `failed`.
# MERKLE_LEAVES_UNAVAILABLE joins the set only when escalated to error by the
# commitment floor — its warning reading never reaches the verdict
# computation.
NETWORK_CLASS_CODES: frozenset[str] = frozenset(
    {
        "TX_NOT_FOUND",
        "PROVIDER_UNAVAILABLE",
        "TX_INTEGRITY_MISMATCH",
        "CONTENT_UNAVAILABLE",
        "CONTENT_FETCH_LIMIT_EXCEEDED",
        "CIPHERTEXT_UNAVAILABLE",
        "MERKLE_LEAVES_UNAVAILABLE",
        "URI_TARGET_FORBIDDEN",
    }
)


def _registry_severity(code: str) -> Severity:
    try:
        return severity_of(code)  # type: ignore[arg-type]
    except Exception:
        return "error"


@dataclass
class IssueSink:
    """Mutable accumulator the pipeline steps append typed issues to; the
    report assembly sorts it once at emission. ``add`` applies the error-code
    registry's default severity; pass ``severity`` only to apply a
    context-promoted reading (dual-severity codes) — no code may ever be
    softened below its registry severity."""

    issues: list[VerifierIssue] = field(default_factory=list)

    def add(
        self,
        code: str,
        path: tuple[str | int, ...],
        message: str,
        severity: Severity | None = None,
    ) -> None:
        self.issues.append(
            VerifierIssue(
                code=code,
                path=path,
                message=message,
                severity=severity if severity is not None else _registry_severity(code),
            )
        )

    def add_once(
        self,
        code: str,
        path: tuple[str | int, ...],
        message: str,
        severity: Severity | None = None,
    ) -> None:
        """Idempotent ``add``: a no-op when the sink already holds an issue
        with the same code, path, and effective severity. Used where two
        pipeline layers can legitimately conclude the same fact about the same
        location (e.g. the structural validator and the signature pass both
        finding a signature entry unsupported) and the report must carry it
        exactly once."""
        effective = severity if severity is not None else _registry_severity(code)
        for existing in self.issues:
            if existing.code == code and existing.path == path and existing.severity == effective:
                return
        self.issues.append(VerifierIssue(code=code, path=path, message=message, severity=effective))


__all__ = [
    "NETWORK_CLASS_CODES",
    "BlockInfo",
    "ContentCheck",
    "Decryption",
    "DecryptionOutcome",
    "DecryptionPassphrase",
    "DecryptionRecipient",
    "ExitCode",
    "FetchOutbound",
    "FetchOutboundOptions",
    "FetchOutboundResult",
    "HttpCallRecord",
    "IssueSink",
    "Method",
    "NetworkId",
    "Profile",
    "Purpose",
    "SigFailureReason",
    "SignatureVerdict",
    "SignerType",
    "Verdict",
    "VerifierIssue",
    "VerifierIssueCode",
    "VerifyItemEntry",
    "VerifyMerkleEntry",
    "VerifyRecordInput",
    "VerifyRecordSignature",
    "VerifyReport",
    "VerifyTxInput",
    "VerifyTxOutput",
    "VerifyTxSummary",
    "VerifyTxWitness",
    "exit_code_for_verdict",
]
