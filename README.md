# cardanowall-sdk — the Python SDK for CIP-309 Proof-of-Existence

A byte-identical parity twin of the TypeScript `@cardanowall/sdk-ts`: a
standalone CIP-309 verifier, a gateway-agnostic HTTP client, off-host signing,
the structural validator, and the raw-seed identity surface — all in Pythonic,
mypy-strict form.

## What it is

CIP-309 is an open standard for anchoring a content hash on the Cardano
blockchain under transaction metadata label 309, so anyone with the transaction
reference can later prove "this content existed on or before block time T" —
without trusting any server, domain, or issuer identity.

`cardanowall-sdk` is the Python member of a five-package family. It bundles the
**standalone verifier** (the three verifier roles), the **gateway-agnostic HTTP
client** for publishing and reading records against any CIP-309 service, the
**structural validator** over canonical-CBOR record bytes, the **sealed-PoE**
wrap/unwrap primitives, and **raw-seed identity** helpers. Its cryptographic
core under `cardanowall._crypto` is a byte-for-byte parity twin of the
TypeScript `@cardanowall/crypto-core` and Rust references: every encoder,
digest, signature, and KEM is validated against the same shared known-answer
vectors, so a record produced or verified here is bit-identical to one produced
or verified by any sibling SDK. The whole package is type-checked under
`mypy --strict`.

## Install

The package is not yet published to PyPI (it is pre-1.0, version `0.0.0`).
Build it from the workspace or vendor it from source. Requires **Python 3.11+**.

```sh
# From the package directory, build a wheel:
python -m build        # or: uv build
pip install dist/cardanowall_sdk-*.whl
```

Once published, the intended install form will be:

```sh
pip install cardanowall-sdk   # forthcoming
```

The SDK is async-canonical (built on `httpx.AsyncClient`); every client method
returns a coroutine. For synchronous use, wrap calls in `asyncio.run(...)`.

## Quick start

### Verify any CIP-309 record — standalone, no service dependency

`verify_tx` is the full public/recipient verifier. Given a Cardano transaction
hash it fetches the metadata from a public explorer, runs structural validation,
verifies record signatures, recomputes Merkle roots, and returns a discriminated
report. No issuer server is contacted.

```python
import asyncio
from cardanowall import verify_tx, VerifyTxInput

report = asyncio.run(verify_tx(VerifyTxInput(tx_hash="<64-char hex tx hash>")))
print(report.verdict)  # "valid" | "pending" | "failed"
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

The client targets **any** CIP-309 gateway. `base_url` is **required** and used
verbatim; `api_key` is an **opaque bearer token** forwarded as
`Authorization: Bearer <key>` with no format assumptions. `cardanowall.com` below
is only one example deployment — substitute any conformant gateway, including a
self-hosted one.

```python
import asyncio
from cardanowall import CardanowallClient, signer_from_seed

async def main() -> None:
    signer = signer_from_seed(seed=b"\x00" * 32)  # 32-byte seed; SDK never sees the private key persisted
    async with CardanowallClient(
        base_url="https://gateway.example.com",
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

Every PoE submission requires a `quote_id`. Request a quote first (it locks the
USD price for a 15-minute TTL); pass the returned `quote_id` to the publish call.
The quote is consumed atomically with the record insert.

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

`CardanowallClient(base_url=..., api_key=..., http_client=...)` exposes four
namespaces:

- `client.poe` — `quote(...)`, `publish_content(...)`, `publish_sealed(...)`,
  `publish_merkle(...)` (one-call high-level flows) plus the low-level
  `uploads(...)`, `publish(...)`, `publish_batch(...)` wire-shape methods.
- `client.records` — `get(tx_hash)` to read a record by transaction hash.
- `client.inbox` — sealed-PoE discovery for a recipient.
- `client.account` — `balance()` and account-scoped reads.

All client failures raise typed errors inheriting from `CardanowallHttpError`:
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
- `chunk_bytes` / `chunk_text` / `bytes_chunk_array_concat` /
  `reconstruct_chunked_uri` — the metadata-label-309 chunk codec.

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
- **`@cardanowall/poe-standard`** — the CIP-309 wire-format library: record
  schema, canonical-CBOR encoder, pure structural validator, and error-code
  catalogue.
- **`@cardanowall/sdk-ts`** — the browser + Node TypeScript SDK; the reference
  this package mirrors.
- **`cardanowall-sdk` (this package)** — the Python SDK; the byte-parity twin.
- **`cardanowall` (Rust crate)** — the Rust SDK; the byte-parity twin in Rust.
  (The `cardanowall` CLI binary is a separate crate built on it.)

## License

Apache-2.0 — see [LICENSE](./LICENSE).
