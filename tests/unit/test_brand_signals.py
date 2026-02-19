"""Unit tests for brand impersonation helpers."""

from app.features.brand_signals import BrandSignalResolver, extract_domain_root


def test_extract_domain_root_normalizes_domain():
    assert extract_domain_root("sub.gogle.com") == "gogle"
    assert extract_domain_root("PAYPA1-security.com") == "paypa1security"


def test_brand_signal_resolver_detects_common_typosquat():
    resolver = BrandSignalResolver(brands={"google", "paypal"})
    is_typosquat, brand, raw, norm = resolver.is_typosquat("gogle")

    assert is_typosquat is True
    assert brand == "google"
    assert raw <= 2
    assert norm < 0.34
