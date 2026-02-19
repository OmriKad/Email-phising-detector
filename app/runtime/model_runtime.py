"""Model loading and prediction runtime for local phishing ML inference."""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import math
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import lightgbm as lgb
except Exception:  # pragma: no cover - optional at runtime
    lgb = None

try:
    import joblib
except Exception:  # pragma: no cover - optional at runtime
    joblib = None


@dataclass
class ModelPrediction:
    """Prediction output including probability and per-feature contributions."""

    probability: float
    raw_probability: float
    contributions: Dict[str, float]
    model_version: str
    feature_names: List[str]


class ModelRuntime:
    """LightGBM-backed runtime with bootstrap fallback."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        calibrator_path: Optional[Path] = None,
        schema_path: Optional[Path] = None,
    ):
        root = Path(__file__).resolve().parents[2]
        env_model = os.getenv("PHISH_ML_MODEL_PATH")
        env_calibrator = os.getenv("PHISH_ML_CALIBRATOR_PATH")
        env_schema = os.getenv("PHISH_ML_SCHEMA_PATH")

        self.model_path = Path(env_model) if env_model else (model_path or root / "models" / "phishing_lgbm_v1.txt")
        self.calibrator_path = (
            Path(env_calibrator) if env_calibrator else (calibrator_path or root / "models" / "calibrator_v1.pkl")
        )
        self.schema_path = Path(env_schema) if env_schema else (schema_path or root / "models" / "feature_schema_v1.json")

        self.booster = None
        self.calibrator = None
        self.schema: Dict[str, object] = {}
        self.default_threshold = 0.5
        self.feature_names: List[str] = []
        self.model_version = "bootstrap-linear-v1"
        self._load_artifacts()

    def predict(self, features: Dict[str, float]) -> ModelPrediction:
        """Predict phishing probability and feature contributions."""
        if self.booster is not None:
            return self._predict_lightgbm(features)
        return self._predict_bootstrap(features)

    def _load_artifacts(self) -> None:
        if self.schema_path.exists():
            try:
                self.schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
                self.feature_names = [str(name) for name in self.schema.get("feature_names", [])]
                self.model_version = str(self.schema.get("model_version", "lightgbm-v1"))
                self.default_threshold = float(self.schema.get("decision_threshold", 0.5))
            except Exception as exc:
                logger.warning("Failed reading ML schema '%s': %s", self.schema_path, exc)

        if lgb is None:
            logger.warning("lightgbm package is unavailable; using bootstrap ML runtime")
            return
        if not self.model_path.exists():
            logger.warning("ML model file not found at '%s'; using bootstrap ML runtime", self.model_path)
            return

        try:
            self.booster = lgb.Booster(model_file=str(self.model_path))
            logger.info("Loaded LightGBM model from %s", self.model_path)
        except Exception as exc:
            logger.warning("Failed loading LightGBM model '%s': %s", self.model_path, exc)
            self.booster = None
            return

        if not self.feature_names:
            try:
                self.feature_names = self.booster.feature_name()
            except Exception:
                self.feature_names = sorted(features for features in self.schema.get("feature_names", []))

        if self.calibrator_path.exists() and joblib is not None:
            try:
                self.calibrator = joblib.load(self.calibrator_path)
                logger.info("Loaded calibrator from %s", self.calibrator_path)
            except Exception as exc:
                logger.warning("Failed loading calibrator '%s': %s", self.calibrator_path, exc)
                self.calibrator = None

    def _predict_lightgbm(self, features: Dict[str, float]) -> ModelPrediction:
        feature_names = self.feature_names or sorted(features.keys())
        row = [[float(features.get(name, 0.0)) for name in feature_names]]

        raw_pred = self.booster.predict(row)  # type: ignore[union-attr]
        raw_probability = float(raw_pred[0]) if raw_pred else 0.0
        probability = self._apply_calibration(raw_probability)

        contributions: Dict[str, float] = {}
        try:
            contrib_pred = self.booster.predict(row, pred_contrib=True)  # type: ignore[union-attr]
            values = contrib_pred[0]
            for idx, name in enumerate(feature_names):
                contributions[name] = float(values[idx])
        except Exception as exc:
            logger.warning("Failed extracting LightGBM contributions: %s", exc)
            contributions = {name: 0.0 for name in feature_names}

        return ModelPrediction(
            probability=self._clamp(probability),
            raw_probability=self._clamp(raw_probability),
            contributions=contributions,
            model_version=self.model_version,
            feature_names=feature_names,
        )

    def _apply_calibration(self, raw_probability: float) -> float:
        if self.calibrator is None:
            return raw_probability
        try:
            if hasattr(self.calibrator, "predict_proba"):
                return float(self.calibrator.predict_proba([[raw_probability]])[0][1])
            if hasattr(self.calibrator, "predict"):
                return float(self.calibrator.predict([[raw_probability]])[0])
        except Exception as exc:
            logger.warning("Calibrator failed; using raw probability: %s", exc)
        return raw_probability

    def _predict_bootstrap(self, features: Dict[str, float]) -> ModelPrediction:
        weights = {
            "reply_to_mismatch": 1.2,
            "return_path_mismatch": 0.9,
            "auth_spf_fail": 0.9,
            "auth_dkim_fail": 0.8,
            "auth_dmarc_fail": 1.0,
            "url_ip_count": 1.3,
            "url_obfuscated_count": 1.0,
            "url_punycode_count": 1.1,
            "url_suspicious_tld_count": 0.8,
            "url_shortener_count": 0.5,
            "url_max_digit_ratio": 1.2,
            "language_urgent_terms_count": 0.25,
            "language_credential_terms_count": 0.2,
            "language_threat_terms_count": 0.3,
            "subject_has_urgent": 0.5,
            "subject_all_caps_ratio": 0.7,
            "content_non_ascii_ratio": 0.7,
            "sender_domain_digit_ratio": 0.8,
            "sender_localpart_suspicious": 0.7,
        }
        bias = -1.8
        logit = bias
        contributions: Dict[str, float] = {}

        for name, weight in weights.items():
            value = float(features.get(name, 0.0))
            contribution = value * weight
            contributions[name] = contribution
            logit += contribution

        raw_probability = 1.0 / (1.0 + math.exp(-logit))
        return ModelPrediction(
            probability=self._clamp(raw_probability),
            raw_probability=self._clamp(raw_probability),
            contributions=contributions,
            model_version="bootstrap-linear-v1",
            feature_names=list(weights.keys()),
        )

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))
