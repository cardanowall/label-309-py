# Security Policy

`cardanowall-sdk` is the Python implementation of CIP-309, an open standard
for cryptographic Proof of Existence anchored on the Cardano blockchain. Its
verifier, structural validator, and sealed-PoE primitives have real security
properties, so we ask that suspected vulnerabilities be reported responsibly.

## Scope

In scope for a report here:

- A flaw in this SDK that lets a verifier accept an invalid proof, decrypt a
  sealed payload it should not, leak which recipient matched a trial decryption,
  or otherwise diverge from the standard's security guarantees.
- A defect in this package's outbound-HTTP egress controls (the deny-host floor,
  the response size bound) that would weaken service-independence.

Out of scope here (report it in the relevant repository instead):

- An ambiguity or flaw in the **standard itself**, or in the canonical
  conformance vectors — report it in `cip309` (the standard repository).
- A bug in another implementation — `cip309-ts`, `cip309-rs`, or the
  `cip309-cli` tool. Use that repository's security policy.

## Core security goals

A report is **high priority** if it undermines any of the standard's core
guarantees as realised by this SDK:

- **Standalone verifiability** — a proof verifies from the transaction metadata,
  the optional content bytes, and a public blockchain explorer alone.
- **Zero issuer trust** — verifying a proof never requires trusting the
  publisher, their domain, or any server.
- **Confidentiality of sealed PoE** — only an intended recipient can decrypt a
  sealed payload, and trial-decryption does not leak which recipient matched.
- **Byte-parity safety** — the Python SDK produces and accepts the exact bytes
  the shared conformance vectors pin; a divergence that changes a security
  outcome is a vulnerability.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the *Security* tab -> *Report a vulnerability*).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can: a clear description of the issue and the
security property it breaks, a minimal reproduction (a record, a transaction
hash, or steps), and the impact with any suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue, and credit you unless you prefer otherwise.
- Because this SDK is a **pre-1.0 release**, fixes land on the current version;
  there are no long-term-supported released versions yet.

Thank you for helping keep CIP-309 trustworthy.
