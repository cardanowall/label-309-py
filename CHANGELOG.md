# Changelog

All notable changes to `cardanowall-sdk` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall-sdk` is a pre-1.0 release. The public API,
> the wire format it implements, and the conformance vectors it tracks may
> change in backward-incompatible ways until a 1.0 release. Pre-1.0 versions do
> not carry the stability guarantees of [Semantic Versioning](https://semver.org/).

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
