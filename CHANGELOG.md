# Changelog

All notable changes to `cardanowall-sdk` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall-sdk` is a pre-1.0 release. The public API,
> the wire format it implements, and the conformance vectors it tracks may
> change in backward-incompatible ways until a 1.0 release. Pre-1.0 versions do
> not carry the stability guarantees of [Semantic Versioning](https://semver.org/).

## [0.10.0] - 2026-07-05

### Breaking

- The sealed helper is now two-phase and the one-shot loses `quote_id`. `publish_sealed(items=[...], recipients=..., max_usd_micros=...)` seals a multi-item record and quotes the exact size internally under an optional USD cap; there is no separate quote step and no `quote_id`. `publish_merkle(leaves=..., leaf_alg=..., max_usd_micros=...)` likewise quotes internally (no `quote_id`) and returns the published record bytes.
- The inclusion-certificate `verification.requires_trust_in_cardanowall` field is renamed `requires_issuer_trust`.

### Added

- Two-phase sealed publishing. `seal_prepare` encrypts every item offline and returns the portable, fingerprinted `prepared_seal_json_v1` artifact (`PreparedSeal.to_json()` / `from_json()`); `submit_sealed` runs the online half (internal exact-size quote, refresh-if-stale, upload, publish). A publish that fails after a paid upload raises `SubmitSealedError` carrying validated `UploadReceipt`s, so a retry resumes without re-encrypting or re-paying storage. `quote_prepared_seal` previews the price; `sealed_record` / `encode_sealed_record` are the air-gap seams. `quote_prepared_seal`, `submit_sealed`, and `publish_sealed` are exported from the package root.
- `publish_merkle` carries an optional `leaf_alg` through to the leaves list.

### Changed

- `PreparedSeal.from_json` accepts only the exact canonical serialization of `prepared_seal_json_v1`; non-canonical encodings are rejected identically across the three SDKs. `seal_prepare` rejects a bare `str` for `items` (pass a list of items).

## [0.9.0] - 2026-07-03

### Added

- `client.poe.wait(poe_id, target=..., timeout=...)` — follows the gateway's `GET /poe/events/{poe_id}` SSE stream over the injected `httpx` client until the record reaches the requested state. Spec-correct SSE parsing (buffered `id` commits, 64 KiB line / 256 KiB event caps), reconnect backoff with `last-event-id` resume, `Retry-After` on 429, and status normalization; a failed record raises `PoeFailedError`, a deadline raises `PoeWaitTimeoutError` carrying the last snapshot.
- `cardanowall.estimate` — exact upper-bound record-size arithmetic for item, Merkle, and sealed record shapes, for quoting before the final record bytes exist. Strings are charged at UTF-8 byte length; the arithmetic is pinned to the same cross-SDK parity constants as the TypeScript and Rust implementations.
- `chunk_bytes` option on `publish_sealed` / `publish_merkle`, forwarded to the resumable upload session.

### Changed

- Large sealed ciphertexts and Merkle leaves lists now route through the resumable upload above the same size threshold as the TypeScript and Rust clients (previously always single-shot).

## [0.8.0] - 2026-07-02

### Changed

- Version alignment with the coordinated 0.8.0 release; no functional changes.

## [0.7.1] - 2026-06-18

### Fixed

- Arweave content retrieval now fetches through the `turbo-gateway.com` fast-finality gateway and follows the gateway's same-domain sandbox-subdomain redirects. The redirect follow is SSRF-safe: it only targets the same registrable domain, re-checks the deny-host list on every hop, requires `https`, and caps the chain at three hops. The dead default gateways `ar-io.net` and `g8way.io` are removed.

## [0.7.0] - 2026-06-16

### Added

- Label 309 **inclusion certificates**: `build_inclusion_certificate`, `verify_inclusion_certificate`, and the COSE / RFC 9162-aligned CBOR proof encoders (including the bare IETF inclusion-proof byte string), byte-identical with the TypeScript and Rust SDKs. An inclusion certificate is a self-contained, standalone-verifiable proof that a content hash was committed as a leaf of an RFC 9162 SHA-256 Merkle tree whose root was published on Cardano under metadata label 309.
- Streaming sealed-PoE: a streaming seal/open path for the segmented `chacha20-poly1305-stream64k` content layer, plus a resumable upload client with progress, cancel, and abandon.

### Breaking

- Client base URLs now carry the full versioned API root (e.g. `https://gateway.example.com/api/v1`); the client appends only bare resource suffixes. Update your configuration to include the version segment.
- `client.records.verify()` has been removed. A Label 309 verdict must never require trusting a gateway; use this SDK's standalone verifier instead.

### Security

- Require `cryptography>=48.0.1`, which bundles a patched OpenSSL — closing a high-severity advisory present in the OpenSSL shipped with earlier `cryptography` wheels.

## [0.6.0] - 2026-06-13

### Security

- `client.records.verify()` builds the request body field by field and transmits only `fetch_content`. An untyped call site (a raw dict) can no longer pass extra keys — including decryption credentials — through to the gateway.

## [0.5.0] - 2026-06-12

### Breaking

- `client.records.verify()` no longer accepts `decryption` entries. Recipient verification — decrypting sealed items and re-checking plaintext hashes — is a local operation of the verifier; the HTTP client never transmits decryption credentials to any gateway. Hosted verify endpoints act as public verifiers only.

### Fixed

- `verify_uris` was never accepted by conforming gateways; the verify request now carries the correct `fetch_content` flag.

## [0.4.0] - 2026-06-11

### Changed

- **BREAKING (wire format):** The sealed-PoE construction is finalized: nonce-salted key derivation, a content-hash-bound slot transcript, segmented STREAM content encryption (`chacha20-poly1305-stream64k`), an in-ciphertext passphrase commitment, and passphrase normalization pinned to Unicode 16.0 NFKC. Records sealed by earlier releases do not decrypt or verify under 0.4.0, and vice versa.
- **BREAKING (wire format):** Record fields are de-chunked: `kem_ct` is a single byte string, URIs are plain text strings, and COSE fields are single byte strings. The only remaining chunking is the ledger-imposed ≤64-byte segmentation of the whole record body for transport.
- **BREAKING (verifier):** The verifier returns a four-state verdict (`valid` | `pending` | `unverifiable` | `failed`) and a reworked report schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). It enforces transaction-hash and auxiliary-data binding, never fabricates confirmation depth, never follows redirects, and treats a deny-host violation as terminal on the resolve path and per-attempt on the content path. Bytes that fail a URI's own content address are attributed to the provider as `URI_PROVIDER_INTEGRITY_MISMATCH`, distinct from a content-hash failure.
- The structural validator accepts options — supported critical extensions, verifier role, resource bounds, and a passphrase-parameter ceiling — and the error-code registry now holds 76 codes.
- Conformance vectors regenerated under the finalized wire format; transaction vectors are fully bound (transaction hash and auxiliary-data hash).

### Added

- Identity-seed string encoding: `encode_identity_seed` / `parse_identity_seed` for the checksummed `L309-SEED-1…` form (HRP `l309-seed-`, rendered uppercase), with raw-hex input accepted; pinned by a cross-SDK conformance vector.
- New conformance families: carriage, Cardano, KDF, Unicode normalization, seed encoding, and recipient-scan negatives.

## [0.3.0] - 2026-06-06

### Changed

- **BREAKING (wire format):** Implemented the finalized sealed-PoE scheme-1 construction: `slots_mac` now authenticates a header-bound slots transcript hash, content is encrypted under an HKDF-derived `payload_key` (never the CEK directly) with structured AAD on both the recipient-slots and passphrase paths, and the X-Wing per-slot KEK salt binds the reassembled `kem_ct` and the recipient public key. Envelopes sealed under 0.2.0 do not decrypt under 0.3.0.
- Hardened recipient decryption: explicit all-zero X25519 shared-secret rejection folded into a constant-time `kem_ok` bit, CEK-conflict detection across matching slots, per-slot KEK-uniqueness checks, and slot-count / envelope-size bounds enforced before any cryptographic work.
- Passphrase decryption pins the `cardano-poe-pw-norm-v1` normalization profile (NFKC, Unicode 16.0 `White_Space` collapse, trim) and enforces a 4096-byte pre-KDF input cap.

### Added

- Error codes `ENC_SLOTS_DUPLICATE_KEM_MATERIAL`, `ENC_SLOTS_TOO_MANY`, and `ENC_ENVELOPE_TOO_LARGE`, with structural-validator checks that mirror the decrypt-layer bounds.
- Conformance coverage for the finalized construction: transcript, hybrid-KEK-salt, and passphrase-path KATs plus duplicate-KEM-material negatives, byte-identical with the TypeScript and Rust SDKs.

## [0.2.0] - 2026-06-04

### Changed

- **BREAKING:** Public API renamed `Cip309*` → `Label309*` (e.g. `Cip309Client` → `Label309Client`) and `cose_sign1_cip309_*` → `cose_sign1_label309_*`, matching the standard's rename to **Label 309**. No wire-format changes.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 Python SDK (`cardanowall-sdk`).
- A byte-identical parity twin of the TypeScript and Rust SDKs against the shared conformance vectors.
