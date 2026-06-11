from __future__ import annotations


def test_package_imports() -> None:
    import cardanowall  # noqa: F401

    assert True


def test_sealed_poe_construction_surface_is_public() -> None:
    """The full sealed-PoE construction surface — both key paths — is
    re-exported from the package root, not reachable only via ``_crypto``."""
    import cardanowall
    from cardanowall._crypto import sealed_poe

    assert cardanowall.ecies_sealed_poe_wrap is sealed_poe.ecies_sealed_poe_wrap
    assert cardanowall.ecies_sealed_poe_unwrap is sealed_poe.ecies_sealed_poe_unwrap
    assert cardanowall.passphrase_sealed_poe_seal is sealed_poe.passphrase_sealed_poe_seal
    assert cardanowall.passphrase_sealed_poe_open is sealed_poe.passphrase_sealed_poe_open
    for name in (
        "ecies_sealed_poe_wrap",
        "ecies_sealed_poe_unwrap",
        "passphrase_sealed_poe_seal",
        "passphrase_sealed_poe_open",
    ):
        assert name in cardanowall.__all__
