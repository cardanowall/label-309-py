from __future__ import annotations

from typing import Final, Literal

from cardanowall.poe_standard import PoeRecord

from .types import Profile, VerifierIssue

# Strict-superset profile order. `core` is the narrowest (hash-only).
# Each higher profile MUST read everything every lower profile reads plus
# its dedicated fields. A lower-profile verifier reading a higher-profile
# field MUST emit `OUT_OF_PROFILE_SKIPPED` (info severity) — NOT
# `SCHEMA_UNKNOWN_FIELD`, which is reserved for fields outside the v1 CDDL.
_PROFILE_ORDER: Final[tuple[Profile, ...]] = (
    "core",
    "signed",
    "sealed",
    "recipient-sealed",
)

_PROFILE_RANK: Final[dict[Profile, int]] = {p: i for i, p in enumerate(_PROFILE_ORDER)}


def profile_at_least(actual: Profile, required: Profile) -> bool:
    """True iff `actual` reads at least the surface of `required`.

    Used by the verifier to gate per-feature checks: the `sigs[]` loop runs
    when `profile_at_least(input.profile, "signed")`, the `enc` decrypt loop
    when `profile_at_least(input.profile, "recipient-sealed")`, etc.
    """
    return _PROFILE_RANK[actual] >= _PROFILE_RANK[required]


def out_of_profile_issues(record: PoeRecord, profile: Profile) -> tuple[VerifierIssue, ...]:
    """Emit one `OUT_OF_PROFILE_SKIPPED` info-severity entry per record field
    the configured profile does not read.

    Profiles form a strict superset ladder; each tier reads everything the
    tier below reads plus its own surface:
      - `core`: reads items.hashes + uris + merkle structurally; skips
        `sigs`, every item's `enc` envelope.
      - `signed`: reads everything `core` reads + `sigs[]`; still skips
        every item's `enc` envelope.
      - `sealed`: reads everything `signed` reads + `enc` structurally;
        skips byte-level decryption.
      - `recipient-sealed`: reads the full surface; no skips.

    `merkle[]` is structurally read in every profile (the `core + merkle`
    add-on is a profile-level capability, not a separate top-level profile),
    so it never produces an OUT_OF_PROFILE_SKIPPED entry here — this verifier
    implements Merkle-fold, so the per-commitment check always runs.
    """
    out: list[VerifierIssue] = []
    if not profile_at_least(profile, "signed") and "sigs" in record:
        out.append(
            VerifierIssue(
                code="OUT_OF_PROFILE_SKIPPED",
                path=("sigs",),
                message=f"sigs[] requires profile >= 'signed'; active profile is '{profile}'",
                severity="info",
            )
        )
    if not profile_at_least(profile, "sealed"):
        for i, item in enumerate(record.get("items") or ()):
            if "enc" in item:
                out.append(
                    VerifierIssue(
                        code="OUT_OF_PROFILE_SKIPPED",
                        path=("items", i, "enc"),
                        message=(
                            f"items[{i}].enc requires profile >= 'sealed'; "
                            f"active profile is '{profile}'"
                        ),
                        severity="info",
                    )
                )
    return tuple(out)


def detect_conformance_profile(record: PoeRecord) -> Literal["core", "signed", "sealed"]:
    """Emit the minimum conformance profile a verifier MUST
    implement to read this record end-to-end. Mirror of TS
    ``detectConformanceProfile``. Classification is content-only:

    - ``'core'``    — no signatures, no sealed items.
    - ``'signed'``  — ``record['sigs']`` non-empty, no sealed items.
    - ``'sealed'``  — any ``record['items'][i]['enc']`` is present (with or
      without sigs — sealed is a strict superset of signed).

    The function does NOT return ``'recipient-sealed'``: that tier is about
    VERIFIER CAPABILITY (whether the verifier decrypts with a recipient X25519
    key), not record content. A recipient-key-aware variant lives outside
    this helper.
    """
    items = record.get("items") or ()
    if any("enc" in it for it in items):
        return "sealed"
    sigs = record.get("sigs") or ()
    if len(sigs) > 0:
        return "signed"
    return "core"


__all__ = ["detect_conformance_profile", "out_of_profile_issues", "profile_at_least"]
