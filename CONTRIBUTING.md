# Contributing to cardanowall-sdk (Label 309 Python SDK)

Thank you for your interest in improving `cardanowall-sdk`, the Python SDK for
Label 309 — an open standard for **Proof of Existence (PoE)** anchored on the
Cardano blockchain.

This repository is a **reference implementation** of the standard. It is a
byte-identical parity twin of the TypeScript SDK (`label-309-ts`) and the Rust SDK
(`label-309-rs`). The standard itself — the wire format, the registries, and the
canonical conformance vectors — lives in the separate `label-309` repository.

All contributions are made under the licensing and sign-off terms described in
[Licensing](#licensing) and [Developer Certificate of Origin](#developer-certificate-of-origin-dco).

---

## What belongs in this repository

This repository holds the **Python implementation**: the standalone verifier,
the gateway-agnostic HTTP client, the structural validator, the sealed-PoE
primitives, the raw-seed identity surface, and their tests. Bug fixes,
performance work, new SDK surface, packaging, and Python-specific issues belong
here.

### What does NOT belong here

- **Changes to the wire format, the grammar, the schemas, the registries, or
  the conformance vectors** — those are normative changes to the standard and
  belong in the `label-309` repository. A change here that would alter canonical
  bytes is an implementation bug, not a spec change: the vectors are
  authoritative.
- **Cross-language behaviour changes** — if a change would make this SDK diverge
  from `label-309-ts` or `label-309-rs`, open an issue first. Byte-parity is a hard
  guarantee, not a goal.

If you are unsure which repository a change belongs to, open an issue here and
ask.

---

## Development setup

This project uses [uv](https://docs.astral.sh/uv/) for environment and
dependency management, and targets **Python 3.11+**.

```sh
uv sync          # create the venv and install runtime + dev deps
uv run pytest -q             # the full test suite
uv run ruff check .          # lint
uv run mypy --strict src tests   # type-check (strict)
```

All four must pass before a pull request is ready. The CI workflow runs exactly
these gates.

---

## The byte-parity contract

Cross-implementation **byte-parity** is the core guarantee of Label 309: the
TypeScript, Python, and Rust SDKs produce and accept byte-identical output for
the same inputs, validated against the **same canonical conformance vectors**
(mirrored into this package's `tests/fixtures/`). The vectors — not any one
implementation — are the source of truth.

This imposes one rule:

> **A change that alters the bytes this SDK produces or the verdicts it
> reaches must trace to a vector, and must keep this SDK identical to its
> sibling implementations.**

Concretely:

- If a test fixture and the code disagree, the **fixture is right** unless the
  fixture itself is being corrected to match a ratified change in the standard.
- A behaviour change that has no corresponding change in the standard's
  conformance vectors is almost certainly a bug.
- New behaviour adds tests that pin the new bytes; changed behaviour updates the
  affected tests and explains the change in the pull request description.

---

## Tests

- **Assert behaviour, not strings.** Pin returned values, raised error codes,
  decoded bytes, and end states — not log lines or incidental phrasing.
- **Use the committed fixtures.** Tests load their vectors from
  `tests/fixtures/`; do not hand-inline byte constants that a fixture already
  pins.
- A change to a public function's behaviour ships with a test that would fail
  without it.

---

## Style and house rules

- Code is type-checked under `mypy --strict` and linted with `ruff`; keep both
  green. The lint config bans unvetted crypto and HTTP libraries — use the
  project's closed crypto catalogue and its outbound-HTTP wrapper.
- Cite only stable, public references in comments — RFCs, CIPs at a permanent
  address, NIST/FIPS publications, BIPs. A comment must justify itself on
  engineering merit, not on traceability to any private document.

---

## Pull request checklist

- [ ] The change is in the right repository (this SDK vs. the standard).
- [ ] `uv run pytest -q`, `uv run ruff check .`, and `uv run mypy --strict src tests` all pass.
- [ ] Wire-affecting changes trace to conformance vectors and keep byte-parity
      with the sibling SDKs.
- [ ] New or changed behaviour is covered by a test.
- [ ] Every commit is signed off (see DCO below).

---

## Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin**. There is **no CLA**.

The DCO is a lightweight attestation that you have the right to submit your
contribution under the project's license. You make it by adding a
`Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically with `git commit -s`. The name and email must be real and
must match the commit author. By signing off, you certify the statements in the
Developer Certificate of Origin, version 1.1:

> **Developer Certificate of Origin, Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

---

## Licensing

By contributing, you agree that your contributions are licensed under the
project's license: the **Apache License 2.0** (see [`LICENSE`](LICENSE)).

## Code of Conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before contributing.

## Security

Do not report security-impacting issues through public issues or pull requests.
Follow the private process in our [Security Policy](SECURITY.md).
