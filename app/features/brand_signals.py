"""Brand-impersonation helpers for cache-free phishing detection."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

from Levenshtein import distance as levenshtein_distance

from app.parsing.email_parser import normalize_domain

DEFAULT_PROTECTED_BRANDS = {
    "apple",
    "amazon",
    "bankofamerica",
    "chase",
    "dhl",
    "dropbox",
    "facebook",
    "github",
    "google",
    "icloud",
    "linkedin",
    "microsoft",
    "netflix",
    "office365",
    "outlook",
    "paypal",
    "wellsfargo",
}

_HOMOGLYPH_SUBS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "2": "z",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "$": "s",
        "@": "a",
        "!": "i",
    }
)


def extract_domain_root(domain: Optional[str]) -> str:
    """Extract a comparable brand root from a domain-like value."""
    normalized = normalize_domain(domain or "")
    if not normalized:
        return ""
    root = normalized.split(".")[0].strip().lower()
    return _normalize_brand_token(root)


def _normalize_brand_token(value: str) -> str:
    value = (value or "").strip().lower()
    return "".join(ch for ch in value if ch.isalnum())


def _homoglyph_fold(value: str) -> str:
    return value.translate(_HOMOGLYPH_SUBS)


class BrandSignalResolver:
    """Resolve brand similarity and typosquatting-like patterns."""

    def __init__(self, brands: Optional[Iterable[str]] = None):
        source = set(DEFAULT_PROTECTED_BRANDS)
        source.update(self._load_brands_from_env())
        if brands:
            source.update(_normalize_brand_token(item) for item in brands if item)
        self.brands = sorted(item for item in source if item)

    def min_distance(self, root: str) -> Tuple[float, str, int]:
        """Return minimum normalized distance, nearest brand, and raw distance."""
        root = _normalize_brand_token(root)
        if not root or not self.brands:
            return 1.0, "", 99

        root_fold = _homoglyph_fold(root)
        best_norm = 1.0
        best_brand = ""
        best_raw = 99

        for brand in self.brands:
            dist = levenshtein_distance(root, brand)
            fold_dist = levenshtein_distance(root_fold, brand)
            raw = min(dist, fold_dist)
            norm = raw / max(len(root), len(brand), 1)
            if norm < best_norm or (norm == best_norm and raw < best_raw):
                best_norm = norm
                best_raw = raw
                best_brand = brand

        return float(best_norm), best_brand, int(best_raw)

    def is_typosquat(
        self,
        root: str,
        max_norm_distance: float = 0.34,
        max_raw_distance: int = 2,
    ) -> Tuple[bool, str, int, float]:
        """Return whether a root likely impersonates a protected brand."""
        root = _normalize_brand_token(root)
        if not root or root in self.brands:
            return False, "", 99, 1.0

        norm, brand, raw = self.min_distance(root)
        if not brand:
            return False, "", raw, norm
        if raw <= max_raw_distance and norm <= max_norm_distance:
            return True, brand, raw, norm
        return False, brand, raw, norm

    @staticmethod
    def _load_brands_from_env() -> Sequence[str]:
        values = set()
        inline = os.getenv("PHISH_PROTECTED_BRANDS", "")
        if inline.strip():
            for item in inline.split(","):
                root = extract_domain_root(item) or _normalize_brand_token(item)
                if root:
                    values.add(root)

        brands_path = os.getenv("PHISH_PROTECTED_BRANDS_PATH", "")
        if brands_path.strip():
            path = Path(brands_path).expanduser()
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    cleaned = line.strip()
                    if not cleaned or cleaned.startswith("#"):
                        continue
                    root = extract_domain_root(cleaned) or _normalize_brand_token(cleaned)
                    if root:
                        values.add(root)
        return sorted(values)
