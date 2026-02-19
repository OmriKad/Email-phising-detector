"""ML phishing detector with cache-free feature extraction and explanations."""
from __future__ import annotations

import logging
import os
from typing import Dict, List, Tuple

from app.api.schemas import DetectedIndicator, GmailMessage, PhishingDetectionResponse
from app.features.email_feature_extractor import EmailFeatureExtractor
from app.runtime.model_runtime import ModelRuntime

logger = logging.getLogger(__name__)

INDICATOR_DESCRIPTIONS = {
    "sender_identity_anomaly": "Sender identity or routing metadata appears inconsistent.",
    "url_obfuscation": "URL structure suggests obfuscation or deceptive redirection.",
    "credential_harvest_language": "Language indicates account verification or credential harvesting pressure.",
    "delivery_context_anomaly": "Delivery/authentication headers indicate suspicious mail flow context.",
}


class MLPhishingDetector:
    """Detect phishing risk using local ML features and model contributions."""

    def __init__(self):
        self.extractor = EmailFeatureExtractor()
        self.runtime = ModelRuntime()
        env_threshold = os.getenv("PHISH_ML_THRESHOLD")
        if env_threshold is not None:
            try:
                self.threshold = float(env_threshold)
            except ValueError:
                logger.warning("Invalid PHISH_ML_THRESHOLD='%s'; using model default", env_threshold)
                self.threshold = self.runtime.default_threshold
        else:
            self.threshold = self.runtime.default_threshold

    def detect(self, message: GmailMessage) -> PhishingDetectionResponse:
        """Analyze an email with the local ML model."""
        extraction = self.extractor.extract(message)
        prediction = self.runtime.predict(extraction.features)
        guardrail_caution, guardrail_major, guardrail_reasons = self._compute_guardrails(extraction.features)
        final_probability = self._apply_guardrail_score(prediction.probability, guardrail_caution, guardrail_major)

        indicators = self._build_indicators(
            extraction.features,
            extraction.evidence,
            prediction.contributions,
        )
        classification = self._classify_risk(final_probability)
        message_text = self._generate_message(classification, len(indicators))
        guardrail_applied = final_probability > prediction.probability + 1e-9

        return PhishingDetectionResponse(
            risk_score=round(final_probability, 3),
            raw_probability=round(prediction.raw_probability, 3),
            classification=classification,
            indicators=indicators,
            message=message_text,
            model_version=prediction.model_version,
            decision_threshold=round(self.threshold, 3),
            guardrail_applied=guardrail_applied,
            guardrail_reasons=guardrail_reasons if guardrail_applied else None,
        )

    def _build_indicators(
        self,
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
        contributions: Dict[str, float],
    ) -> List[DetectedIndicator]:
        positive = {
            name: score
            for name, score in contributions.items()
            if score > 0
        }
        if not positive:
            return []

        grouped: Dict[str, Dict[str, object]] = {}
        total_positive = sum(positive.values()) or 1.0

        ranked = sorted(positive.items(), key=lambda item: item[1], reverse=True)
        for feature_name, contribution in ranked:
            feature_value = float(features.get(feature_name, 0.0))
            if feature_value == 0:
                continue
            indicator_type, detail = self._map_feature_to_indicator(feature_name)
            bucket = grouped.setdefault(
                indicator_type,
                {"contribution": 0.0, "features": [], "evidence": [], "details": []},
            )
            bucket["contribution"] = float(bucket["contribution"]) + float(contribution)
            bucket["features"].append(feature_name)
            bucket["details"].append(
                {
                    "feature_name": feature_name,
                    "feature_value": feature_value,
                    "contribution": round(float(contribution), 6),
                }
            )
            feature_evidence = evidence.get(feature_name, [])
            if feature_evidence:
                bucket["evidence"].extend(feature_evidence[:2])
            else:
                bucket["evidence"].append(detail)

        ordered_groups: List[Tuple[str, Dict[str, object]]] = sorted(
            grouped.items(),
            key=lambda item: float(item[1]["contribution"]),
            reverse=True,
        )[:5]

        indicators: List[DetectedIndicator] = []
        for indicator_type, payload in ordered_groups:
            contribution = float(payload["contribution"])
            positive_impact_share = contribution / total_positive
            indicators.append(
                DetectedIndicator(
                    type=indicator_type,
                    description=INDICATOR_DESCRIPTIONS.get(indicator_type, indicator_type.replace("_", " ").title()),
                    severity=self._severity_from_impact(positive_impact_share),
                    contribution=round(contribution, 6),
                    evidence=list(dict.fromkeys(payload["evidence"]))[:3],
                    source="ml_feature",
                    details={
                        # Backward-compatible alias kept temporarily.
                        "impact_share": round(positive_impact_share, 4),
                        "positive_impact_share": round(positive_impact_share, 4),
                        "impact_basis": "share_of_positive_feature_contributions",
                        "top_features": payload["features"][:3],
                        "feature_details": payload["details"][:3],
                    },
                )
            )
        return indicators

    @staticmethod
    def _compute_guardrails(features: Dict[str, float]) -> Tuple[bool, bool, List[str]]:
        reasons: List[str] = []
        brand_typosquat = bool(
            features.get("sender_brand_typosquat_flag", 0.0) > 0
            or features.get("url_brand_typosquat_flag", 0.0) > 0
        )
        credential_language = bool(features.get("language_credential_terms_count", 0.0) > 0)
        link_present = bool(features.get("url_count", 0.0) > 0)
        delivery_or_sender_anomaly = bool(
            features.get("reply_to_mismatch", 0.0) > 0
            or features.get("return_path_mismatch", 0.0) > 0
            or features.get("auth_spf_fail", 0.0) > 0
            or features.get("auth_dkim_fail", 0.0) > 0
            or features.get("auth_dmarc_fail", 0.0) > 0
            or features.get("sender_url_brand_mismatch_flag", 0.0) > 0
        )

        guardrail_caution = brand_typosquat and credential_language and link_present
        guardrail_major = guardrail_caution and delivery_or_sender_anomaly

        if guardrail_caution:
            reasons.append("Brand-impersonation signal with credential request and embedded link")
        if guardrail_major:
            reasons.append("Additional sender/delivery anomaly escalated severity")
        return guardrail_caution, guardrail_major, reasons

    @staticmethod
    def _apply_guardrail_score(model_probability: float, guardrail_caution: bool, guardrail_major: bool) -> float:
        """Apply deterministic escalation without hiding base model output."""
        return max(
            model_probability,
            0.34 if guardrail_caution else 0.0,
            0.51 if guardrail_major else 0.0,
        )

    def _map_feature_to_indicator(self, feature_name: str) -> Tuple[str, str]:
        if feature_name.startswith("url_"):
            return "url_obfuscation", f"Suspicious URL signal from feature '{feature_name}'"
        if feature_name.startswith("sender_") or feature_name in {"reply_to_mismatch", "return_path_mismatch"}:
            return "sender_identity_anomaly", f"Sender identity signal from feature '{feature_name}'"
        if feature_name.startswith("auth_") or feature_name.startswith("delivery_"):
            return "delivery_context_anomaly", f"Delivery context signal from feature '{feature_name}'"
        return "credential_harvest_language", f"Risky phishing language signal from feature '{feature_name}'"

    @staticmethod
    def _severity_from_impact(impact_share: float) -> str:
        if impact_share >= 0.45:
            return "high"
        if impact_share >= 0.2:
            return "medium"
        return "low"

    @staticmethod
    def _classify_risk(score: float) -> str:
        # Risk banding is based on post-policy score (model + optional guardrails).
        if score < 0.33:
            return "Seems safe"
        if score <= 0.5:
            return "Few indicators found, need to be cautious"
        return "Major indicators found!"

    @staticmethod
    def _generate_message(classification: str, indicator_count: int) -> str:
        if indicator_count == 0:
            return "No phishing indicators detected. Email appears safe."
        if classification == "Seems safe":
            return f"Email appears mostly safe, but {indicator_count} minor indicator(s) were detected."
        if classification == "Few indicators found, need to be cautious":
            return f"⚠️ Caution advised: {indicator_count} phishing indicator(s) were detected."
        return f"🚨 Warning: {indicator_count} major phishing indicator(s) were detected. Exercise extreme caution."
