# cardanowall-sdk — the Python SDK for Label 309 Proof-of-Existence

A byte-identical parity twin of the TypeScript `@cardanowall/sdk-ts`: a
standalone Label 309 verifier, a gateway-agnostic HTTP client, off-host signing,
the structural validator, and the raw-seed identity surface — all in Pythonic,
mypy-strict form.

## What it is

Label 309 is an open standard for anchoring a content hash on the Cardano
blockchain under transaction metadata label 309, so anyone with the transaction
reference can later prove "this content existed on or before block time T" —
without trusting any server, domain, or issuer identity.

`cardanowall-sdk` is the Python member of a five-package family. It bundles the
**standalone verifier** (the three verifier roles), the **gateway-agnostic HTTP
client** for publishing and reading records against any Label 309 service, the
**structural validator** over canonical-CBOR record bytes, the **sealed-PoE**
wrap/unwrap primitives, and **raw-seed identity** helpers. Its cryptographic
core under `cardanowall._crypto` is a byte-for-byte parity twin of the
TypeScript `@cardanowall/crypto-core` and Rust references: every encoder,
digest, signature, and KEM is validated against the same shared known-answer
vectors, so a record produced or verified here is bit-identical to one produced
or verified by any sibling SDK. The whole package is type-checked under
`mypy --strict`.

## Install

```sh
pip install cardanowall-sdk
```

Requires **Python 3.11+**. The SDK is async-canonical (built on
`httpx.AsyncClient`); every client method returns a coroutine. For synchronous
use, wrap calls in `asyncio.run(...)`.

## Quick start

### Verify any Label 309 record — standalone, no service dependency

`verify_tx` is the full public/recipient verifier. Given a Cardano transaction
hash it fetches the metadata from a public explorer, runs structural validation,
verifies record signatures, recomputes Merkle roots, and returns a discriminated
report. No issuer server is contacted.

```python
import asyncio
from cardanowall import verify_tx, VerifyTxInput

report = asyncio.run(verify_tx(VerifyTxInput(tx_hash="<64-char hex tx hash>")))
print(report.verdict)  # "valid" | "pending" | "unverifiable" | "failed"
```

### Validate raw record bytes — pure, no I/O

`validate_poe_record` (re-exported from `poe_standard`) is a pure function over
canonical-CBOR bytes. It returns a discriminated result: `ValidateOk` carries the
typed record, `ValidateFail` carries the structured issue list.

```python
from cardanowall import validate_poe_record
from cardanowall.poe_standard import ValidateOk

result = validate_poe_record(record_bytes)  # bytes
if isinstance(result, ValidateOk):
    print(result.record["v"])               # the parsed record
else:
    for issue in result.issues:
        print(issue.code, issue.path)        # e.g. "SCHEMA_MISSING_REQUIRED"
```

### Publish with the gateway-agnostic client

The client targets **any** Label 309 gateway. `base_url` is **required** and used
verbatim — it is the **full versioned base**, including the API version segment
(e.g. `https://gateway.example.com/api/v1`); each request appends only a resource
suffix (`/records`, `/poe/quote`, …) to it. `api_key` is an **opaque bearer
token** forwarded as `Authorization: Bearer <key>` with no format assumptions.
`gateway.example.com` below is only one example deployment — substitute any
conformant gateway, including a self-hosted one.

```python
import asyncio
from cardanowall import Label309Client, signer_from_seed

async def main() -> None:
    signer = signer_from_seed(seed=b"\x00" * 32)  # 32-byte seed; SDK never sees the private key persisted
    async with Label309Client(
        base_url="https://gateway.example.com/api/v1",
        api_key="<opaque-bearer>",
    ) as client:
        quote = await client.poe.quote(
            record_bytes=200, recipient_count=0, file_bytes_total=0,
        )
        out = await client.poe.publish_content(
            content="hello world",            # also accepts bytes
            quote_id=quote["quote_id"],
            signer=signer,
        )
        print(out["id"], out["status"])

asyncio.run(main())
```

The hash-only flows (`publish_content`, `publish_prehashed`) and the low-level
`publish` / `publish_batch` take a caller-supplied `quote_id`: request a quote
first (it locks the USD price for a 15-minute TTL) and pass the returned
`quote_id` to the call. The quote is consumed atomically with the record insert.
`publish_content` also co-hashes the content under several algorithms
(`hash_algs=["sha2-256", "blake2b-256"]`, bound into one item), and both content
flows accept optional `uris` (already-pinned `ar://` / `ipfs://` content mirrors)
and a `supersedes` link to an earlier record.

The internally-quoting helpers price their exact record shape themselves and
take **no** `quote_id`: `publish_merkle`, and the sealed flow's `submit_sealed`
/ `publish_sealed`. They quote, enforce an optional `max_usd_micros` cap, and
refresh the price lock if a slow upload outlived it. `quote_prepared_seal`
returns a price preview a caller may hand to `submit_sealed` via its `quote`
argument; a stale preview is silently re-quoted.

### Publish a sealed PoE — encrypted to one or more recipients

`publish_sealed` is the one-shot sealed flow: it seals every item to the
recipient public keys (age-style sealed envelope), quotes internally, uploads
each ciphertext to Arweave, and publishes the multi-item record. `items` is a
**list** of `bytes`/`str` (one sealed item each — a bare `str` is rejected, so
wrap a lone value in a list); `recipients` are raw KEM public keys (the
post-quantum X-Wing hybrid by default, 1216 bytes each). It takes **no**
`quote_id` — pass `max_usd_micros` to cap the internally-fetched price. The
result is a `SealedSubmission` (the gateway `response`, the published
`record_bytes`, and the `ar://` `uris`).

```python
import asyncio
from cardanowall import Label309Client, derive_keys_from_seed

async def main() -> None:
    # In practice the recipient shares this key; here we derive it from a seed.
    recipient_pub = derive_keys_from_seed(b"\x11" * 32)["mlkem768x25519"]["public_key"]
    async with Label309Client(
        base_url="https://gateway.example.com/api/v1",
        api_key="<opaque-bearer>",
    ) as client:
        submission = await client.poe.publish_sealed(
            items=[b"secret report", "second attachment"],  # a LIST, one sealed item each
            recipients=[recipient_pub],                      # X-Wing public keys (1216 bytes)
            max_usd_micros=500_000,                          # refuse above $0.50
        )
        print(submission.response["id"], submission.response["status"])
        print(submission.uris)   # the ar:// URI of each item's ciphertext

asyncio.run(main())
```

### Two-phase sealed publish with crash-safe resume

For flows that must survive a crash (CI jobs, multi-GB ciphertexts), split the
sealing from the network round-trips. `seal_prepare` is pure and offline: it
hashes and encrypts every item and returns a `PreparedSeal` that serializes to
the portable `prepared_seal_json_v1` artifact (`to_json()` / `from_json()`, the
latter re-verifying its fingerprint). Persist that artifact, then `submit_sealed`
quotes, uploads, and publishes. If `submit_sealed` fails **after** a paid
upload, the `SubmitSealedError` carries validated `UploadReceipt`s — persist
them and pass them back as `uploaded` on the retry, and the already-uploaded
ciphertexts are never paid for twice.

```python
import asyncio
from cardanowall import Label309Client, derive_keys_from_seed
from cardanowall.client import PreparedSeal, SubmitSealedError, seal_prepare

async def main() -> None:
    recipient_pub = derive_keys_from_seed(b"\x11" * 32)["mlkem768x25519"]["public_key"]

    # Phase 1 — pure and offline: no network, nothing secret leaves the host.
    prepared = seal_prepare(items=[b"page one", b"page two"], recipients=[recipient_pub])

    # Persist the portable artifact; from_json re-verifies its fingerprint on load.
    prepared = PreparedSeal.from_json(prepared.to_json())

    async with Label309Client(
        base_url="https://gateway.example.com/api/v1",
        api_key="<opaque-bearer>",
    ) as client:
        # Phase 2 — online: quote → upload each ciphertext → publish.
        try:
            submission = await client.poe.submit_sealed(prepared=prepared, max_usd_micros=1_000_000)
        except SubmitSealedError as err:
            # Resume: in a real flow you persist err.uploads (and the artifact)
            # across process runs, then replay with the receipts — storage is
            # charged only once.
            submission = await client.poe.submit_sealed(
                prepared=prepared, max_usd_micros=1_000_000, uploaded=err.uploads
            )
        print(submission.response["id"], submission.uris)

asyncio.run(main())
```

### Publish a passphrase-sealed PoE

To deliver to someone who has no Label 309 identity, seal to a **shared
passphrase** instead of recipient keys: anyone who knows it can open the record,
with no delivery address involved. The passphrase surface mirrors the recipient
one — the pure `passphrase_seal_prepare(...)` feeding `submit_passphrase_sealed(...)`
(with `quote_prepared_passphrase_seal(...)` for a preview and `UploadReceipt`
resume), and `publish_passphrase_sealed(...)` as the one-shot wrapper. Read the
passphrase from the environment or a prompt, never a source-embedded literal:

```python
import asyncio
import os
from cardanowall import Label309Client

async def main() -> None:
    passphrase = os.environ["SEAL_PASSPHRASE"]
    async with Label309Client(
        base_url="https://gateway.example.com/api/v1",
        api_key="<opaque-bearer>",
    ) as client:
        submission = await client.poe.publish_passphrase_sealed(
            items=[b"quarterly numbers"],            # a LIST, one sealed item each
            passphrase=passphrase,
            hash_algs=["sha2-256", "blake2b-256"],   # co-hash the item under both
            max_usd_micros=500_000,                  # refuse above $0.50
        )
        print(submission.response["id"], submission.uris)

asyncio.run(main())
```

A recipient opens it by passing the passphrase to `verify_tx` — a
`DecryptionPassphrase` credential joins the same keyring as any recipient key
and is tried against every sealed item.

## API overview

### Verifier (`cardanowall.verifier`, top-level re-exports)

The three verifier roles, all reachable through `verify_tx`:

- **Structural validator** — `validate_poe_record(bytes)`: pure, no I/O, no
  crypto. Returns `ValidateOk | ValidateFail`.
- **Public verifier** — `verify_tx(VerifyTxInput(...))`: fetches metadata, runs
  structural validation, verifies record signatures, recomputes Merkle roots.
- **Recipient verifier** — `verify_tx` with a decryption input (an X25519 / X-Wing
  secret): additionally decrypts a sealed PoE and recomputes plaintext hashes.

Outbound HTTP is funnelled through a single `FetchOutbound` so a caller can
inject a custom transport (`default_fetch_outbound` is the built-in); a
deny-host floor (`DENY_HOSTS_DEFAULT`) blocks single-implementer domains
(including `cardanowall.com`) to prove service-independence. `fetch_item_ciphertext`
fetches sealed-PoE ciphertext bounded by `DEFAULT_OUTBOUND_MAX_BYTES`.
`detect_conformance_profile` reports a record's conformance profile.

### Gateway-agnostic client (`cardanowall.client`)

`Label309Client(base_url=..., api_key=..., http_client=...)` exposes four
namespaces:

- `client.poe` — `quote(...)`, `publish_content(...)` (with `hash_algs`
  co-hashing + optional `uris`), `publish_merkle(...)` (one-call high-level
  flows), the two-phase sealed surface — the pure `seal_prepare(...)` (to
  recipients) / `passphrase_seal_prepare(...)` (to a shared passphrase), both
  from `cardanowall.client`, feeding `quote_prepared_seal(...)` /
  `submit_sealed(...)` and `quote_prepared_passphrase_seal(...)` /
  `submit_passphrase_sealed(...)`, with `publish_sealed(...)` /
  `publish_passphrase_sealed(...)` as the one-shot wrappers — plus the
  low-level `uploads(...)`, `publish(...)`, `publish_batch(...)` wire-shape
  methods. A `PreparedSeal` serializes to the portable `prepared_seal_json_v1`
  artifact (`to_json()` / `from_json()`), so a failed publish retries from
  persisted material and `UploadReceipt`s without ever re-encrypting.
- `client.records` — `get(tx_hash)` to read a record by transaction hash.
- `client.inbox` — sealed-PoE discovery for a recipient.
- `client.account` — `balance()` and account-scoped reads.

All client failures raise typed errors inheriting from `Label309HttpError`:
`RateLimitedError`, `InsufficientFundsError`, `QuoteExpiredError`,
`QuoteAlreadyConsumedError`, `QuoteNotFoundError`, `FxStaleError`,
`IdempotencyConflictError`, `UnauthenticatedError`, `InsufficientScopeError`,
`RecordNotFoundError`, `MalformedCborError`, `InvalidBodyError`,
`PartialUploadError`, and others. `InvalidClientConfigError` is raised eagerly if
`base_url` is missing.

### Wire format (`cardanowall.poe_standard`)

- `encode_poe_record(record)` / `encode_record_body_for_signing(record)` —
  canonical-CBOR encoders.
- `validate(bytes)` (re-exported as `validate_poe_record`) — the structural
  validator; `ValidateOk` / `ValidateFail` / `ValidationIssue` / `ErrorCode` /
  `SEVERITY`.
- `PoeRecord` and the schema TypedDicts (`Item`, `Slot`, `EncryptionEnvelope`,
  `MerkleCommit`, …).

### Primitives, identity, and signing

- `cardanowall.hash` — `sha2_256`, `blake2b_256`, `dual_hash`, `dual_hash_stream`.
- `cardanowall.merkle` — `merkle_sha2_256_root`,
  `merkle_sha2_256_inclusion_proof`, `merkle_sha2_256_verify_inclusion`,
  `encode_leaves_list` / `decode_leaves_list`.
- Sealed PoE — `ecies_sealed_poe_wrap` / `ecies_sealed_poe_unwrap`.
- Recipients — `encode_age_x25519_recipient`, `encode_age_xwing_recipient`,
  `parse_age_recipient`.
- Seed derivation — `derive_ed25519_keypair_from_seed`,
  `derive_x25519_keypair_from_seed`, `derive_mlkem768x25519_keypair_from_seed`.
- Seed identity — `derive_keys_from_seed`, `recipients_from_seed`,
  `signer_from_seed`, `recipient_secret_keys_from_seed`,
  `decrypt_sealed_from_seed`.
- Webhooks — `verify_webhook_signature`, `build_webhook_signature_header`,
  `sign_webhook_payload`.
- Stable identifiers — `encode_prefixed_id` / `decode_prefixed_id`,
  Crockford base32 codecs, and the ID prefix/pattern constants.

See `src/cardanowall/__init__.py` for the exhaustive `__all__`.

### Raw-seed identity, end to end

A developer holding a 32-byte seed can sign, address recipients, and decrypt
without any account envelope. The hybrid post-quantum KEM (X-Wing,
ML-KEM-768 + X25519) is exposed alongside the classical X25519 path.

```python
from cardanowall import (
    derive_keys_from_seed,
    recipients_from_seed,
    signer_from_seed,
)

seed = b"\xff" * 32
keys = derive_keys_from_seed(seed)            # ed25519 / x25519 / mlkem768x25519 keypairs
recipients = recipients_from_seed(seed)       # {"age": "age1...", "age1pqc": "age1pqc..."}
signer = signer_from_seed(seed)               # a path-1 Signer for client.poe.publish_*
```

### Off-host signing

If you build the canonical-CBOR record yourself and sign on a separate host
(KMS, HSM, an air-gapped machine), `build_to_sign(record)` produces the exact
bytes to sign; the SDK never needs the private key.

```python
from cardanowall import build_to_sign
from cardanowall.poe_standard import PoeRecord

record: PoeRecord = {"v": 1, "items": [{"hashes": {"sha2-256": digest}}]}
to_sign = build_to_sign(record)   # hand these bytes to your external signer
```

## Cross-implementation parity

`cardanowall-sdk` is a **byte-identical parity twin** of `@cardanowall/sdk-ts`
and the `cardanowall` Rust crate. The canonical-CBOR encoder, the structural
validator and its error codes, the COSE_Sign1 signing input, the sealed-PoE
envelope, the Merkle leaves-list codec, and the seed-derived recipient strings
are all pinned to the **same shared known-answer vectors** mirrored byte-for-byte
across all three languages. This guarantees that:

- a record encoded in Python produces the exact bytes that go on chain in TS/Rust;
- a record that validates here validates identically everywhere (same verdict,
  same error codes);
- an `age1...` / `age1pqc...` recipient string derived from a seed is identical
  across SDKs, so cross-SDK senders and recipients interoperate.

## Standard and service independence

The verifier proves a PoE from three inputs only: the **transaction metadata**,
optionally the **content bytes**, and a **public blockchain explorer**. No issuer
server is required at any step. The default deny-host list explicitly blocks
single-implementer domains during verification, and the conformance suite runs
with that list active — so a record is provably verifiable without the gateway
that published it.

A bundled conformance runner verifies a transaction from the command line:

```sh
cardanowall-sdk-conformance <tx-hash>
# or:
python -m cardanowall.conformance <tx-hash>
```

Exit codes: `0` valid, `1` failed (integrity), `2` failed (network), `3` pending,
`4` CLI input error.

## Relation to the other packages

- **`@cardanowall/crypto-core`** — closed-catalogue cryptographic primitives
  (hash, KDF, signature, KEM, AEAD, CBOR, COSE, sealed-PoE, discovery, Merkle,
  recipient encoding, seed derivation). The portable building blocks.
- **`@cardanowall/poe-standard`** — the Label 309 wire-format library: record
  schema, canonical-CBOR encoder, pure structural validator, and error-code
  catalogue.
- **`@cardanowall/sdk-ts`** — the browser + Node TypeScript SDK; the reference
  this package mirrors.
- **`cardanowall-sdk` (this package)** — the Python SDK; the byte-parity twin.
- **`cardanowall` (Rust crate)** — the Rust SDK; the byte-parity twin in Rust.
  (The `cardanowall` CLI binary is a separate crate built on it.)

## License

Apache-2.0 — see [LICENSE](./LICENSE).
