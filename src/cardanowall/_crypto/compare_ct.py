from __future__ import annotations

import hmac


def compare_ct(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)
