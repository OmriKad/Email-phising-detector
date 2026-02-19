"""Feature extraction and brand-signal utilities."""

from app.features.brand_signals import BrandSignalResolver
from app.features.email_feature_extractor import EmailFeatureExtractor, FEATURE_ORDER, FeatureExtractionResult

__all__ = [
    "BrandSignalResolver",
    "EmailFeatureExtractor",
    "FEATURE_ORDER",
    "FeatureExtractionResult",
]
