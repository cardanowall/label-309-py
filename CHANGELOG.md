# Changelog

All notable changes to `cardanowall-sdk` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall-sdk` is a pre-1.0 release. The public API,
> the wire format it implements, and the conformance vectors it tracks may
> change in backward-incompatible ways until a 1.0 release. Pre-1.0 versions do
> not carry the stability guarantees of [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial public release of the CIP-309 Python SDK: the standalone verifier
  (structural / public / recipient roles), the gateway-agnostic HTTP client,
  the canonical-CBOR structural validator, the sealed-PoE wrap/unwrap
  primitives, off-host signing, and the raw-seed identity surface. A
  byte-identical parity twin of the TypeScript and Rust reference SDKs.
