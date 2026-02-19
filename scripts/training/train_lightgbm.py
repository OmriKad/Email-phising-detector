#!/usr/bin/env python3
"""Train a cache-free phishing LightGBM model and export inference artifacts."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import sys
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

try:
    import joblib
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"joblib is required to run training: {exc}") from exc

try:
    import lightgbm as lgb
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"lightgbm is required to run training: {exc}") from exc

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.schemas import GmailMessage, Header, MessagePart, MessagePartBody
from app.features.email_feature_extractor import FEATURE_ORDER, EmailFeatureExtractor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="Input dataset (.csv or .jsonl).")
    parser.add_argument("--out-dir", default=str(ROOT / "models"), help="Artifact output directory.")
    parser.add_argument("--label-col", default="label", help="Binary label column (1 phishing, 0 benign).")
    parser.add_argument("--from-col", default="from", help="Sender column name.")
    parser.add_argument("--subject-col", default="subject", help="Subject column name.")
    parser.add_argument("--body-col", default="body", help="Body column name.")
    parser.add_argument("--reply-to-col", default="reply_to", help="Reply-To column name.")
    parser.add_argument("--auth-results-col", default="auth_results", help="Authentication-Results column name.")
    parser.add_argument("--return-path-col", default="return_path", help="Return-Path column name.")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.2)
    parser.add_argument(
        "--hard-cases",
        default="",
        help="Optional dataset path for scenario regression metrics after training.",
    )
    return parser.parse_args()


def load_dataset(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return pd.read_json(path, lines=True)
    raise ValueError(f"Unsupported dataset format: {path.suffix}")


def make_message(row: pd.Series, args: argparse.Namespace) -> GmailMessage:
    from_value = _as_text(row.get(args.from_col))
    subject_value = _as_text(row.get(args.subject_col))
    body_value = _as_text(row.get(args.body_col))
    reply_to_value = _as_text(row.get(args.reply_to_col))
    auth_results_value = _as_text(row.get(args.auth_results_col))
    return_path_value = _as_text(row.get(args.return_path_col))

    body_b64 = base64.urlsafe_b64encode(body_value.encode("utf-8")).decode("utf-8").rstrip("=")

    headers = [
        Header(name="From", value=from_value),
        Header(name="Subject", value=subject_value),
    ]
    if reply_to_value:
        headers.append(Header(name="Reply-To", value=reply_to_value))
    if auth_results_value:
        headers.append(Header(name="Authentication-Results", value=auth_results_value))
    if return_path_value:
        headers.append(Header(name="Return-Path", value=return_path_value))

    return GmailMessage(
        payload=MessagePart(
            headers=headers,
            body=MessagePartBody(data=body_b64),
            mimeType="text/plain",
        )
    )


def choose_threshold(y_true: np.ndarray, probs: np.ndarray, min_recall: float = 0.9) -> Tuple[float, Dict[str, float]]:
    precisions, recalls, thresholds = precision_recall_curve(y_true, probs)
    best_threshold = 0.5
    best_precision = -1.0
    best_recall = 0.0

    for idx, threshold in enumerate(thresholds):
        precision = float(precisions[idx])
        recall = float(recalls[idx])
        if recall >= min_recall and precision > best_precision:
            best_precision = precision
            best_recall = recall
            best_threshold = float(threshold)

    if best_precision < 0:
        f1_candidates = []
        for idx, threshold in enumerate(thresholds):
            precision = float(precisions[idx])
            recall = float(recalls[idx])
            if precision + recall == 0:
                continue
            f1 = 2 * precision * recall / (precision + recall)
            f1_candidates.append((f1, float(threshold), precision, recall))
        if f1_candidates:
            best_f1, best_threshold, best_precision, best_recall = max(f1_candidates, key=lambda item: item[0])
            _ = best_f1
        else:
            best_precision = 0.0
            best_recall = 0.0

    return best_threshold, {"precision": best_precision, "recall": best_recall}


def evaluate(y_true: np.ndarray, probs: np.ndarray, threshold: float) -> Dict[str, Optional[float]]:
    y_pred = (probs >= threshold).astype(int)
    unique_classes = set(np.asarray(y_true).tolist())
    roc_auc = None
    pr_auc = None
    if len(unique_classes) >= 2:
        roc_auc = float(roc_auc_score(y_true, probs))
        pr_auc = float(average_precision_score(y_true, probs))
    return {
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "threshold": float(threshold),
    }


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and np.isnan(value):
        return ""
    return str(value)


def build_feature_frame(frame: pd.DataFrame, args: argparse.Namespace) -> pd.DataFrame:
    extractor = EmailFeatureExtractor()
    rows = []
    for _, row in frame.iterrows():
        message = make_message(row, args)
        result = extractor.extract(message)
        rows.append([result.features.get(name, 0.0) for name in FEATURE_ORDER])
    return pd.DataFrame(rows, columns=FEATURE_ORDER)


def ensure_feature_frame(data: pd.DataFrame | np.ndarray) -> pd.DataFrame:
    """Ensure LightGBM gets named feature columns during training/eval."""
    if isinstance(data, pd.DataFrame):
        return data.loc[:, FEATURE_ORDER]
    return pd.DataFrame(data, columns=FEATURE_ORDER)


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    frame = load_dataset(dataset_path)
    required_columns = {args.label_col, args.from_col, args.subject_col, args.body_col}
    missing = [name for name in required_columns if name not in frame.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    y = frame[args.label_col].astype(int).to_numpy()
    x = build_feature_frame(frame, args).astype(np.float32)

    x_train_val, x_test, y_train_val, y_test = train_test_split(
        x,
        y,
        test_size=args.test_size,
        random_state=args.random_seed,
        stratify=y,
    )
    x_train, x_val, y_train, y_val = train_test_split(
        x_train_val,
        y_train_val,
        test_size=args.val_size,
        random_state=args.random_seed,
        stratify=y_train_val,
    )

    model = lgb.LGBMClassifier(
        objective="binary",
        learning_rate=0.05,
        n_estimators=400,
        num_leaves=31,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=args.random_seed,
    )
    x_train = ensure_feature_frame(x_train)
    x_val = ensure_feature_frame(x_val)
    x_test = ensure_feature_frame(x_test)

    model.fit(x_train, y_train)

    val_raw = model.predict_proba(x_val)[:, 1]
    calibrator = LogisticRegression(max_iter=400)
    calibrator.fit(val_raw.reshape(-1, 1), y_val)

    val_calibrated = calibrator.predict_proba(val_raw.reshape(-1, 1))[:, 1]
    threshold, threshold_stats = choose_threshold(y_val, val_calibrated)

    test_raw = model.predict_proba(x_test)[:, 1]
    test_calibrated = calibrator.predict_proba(test_raw.reshape(-1, 1))[:, 1]
    metrics = evaluate(y_test, test_calibrated, threshold)
    metrics["val_precision_at_threshold"] = threshold_stats["precision"]
    metrics["val_recall_at_threshold"] = threshold_stats["recall"]
    metrics["feature_count"] = len(FEATURE_ORDER)

    model_path = out_dir / "phishing_lgbm_v1.txt"
    calibrator_path = out_dir / "calibrator_v1.pkl"
    schema_path = out_dir / "feature_schema_v1.json"
    metrics_path = out_dir / "metrics_v1.json"

    model.booster_.save_model(str(model_path))
    joblib.dump(calibrator, calibrator_path)

    schema = {
        "model_version": "phishing-lgbm-v1",
        "feature_names": FEATURE_ORDER,
        "decision_threshold": float(threshold),
        "calibration": "logistic_regression_on_raw_probability",
    }

    if args.hard_cases.strip():
        hard_path = Path(args.hard_cases).expanduser().resolve()
        hard_frame = load_dataset(hard_path)
        hard_missing = [name for name in required_columns if name not in hard_frame.columns]
        if hard_missing:
            raise ValueError(f"Hard-cases dataset is missing required columns: {hard_missing}")
        hard_x = ensure_feature_frame(build_feature_frame(hard_frame, args).astype(np.float32))
        hard_y = hard_frame[args.label_col].astype(int).to_numpy()
        hard_raw = model.predict_proba(hard_x)[:, 1]
        hard_calibrated = calibrator.predict_proba(hard_raw.reshape(-1, 1))[:, 1]
        metrics["hard_cases"] = evaluate(hard_y, hard_calibrated, threshold)
        metrics["hard_cases"]["count"] = int(len(hard_frame))
    schema_path.write_text(json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")

    print("Training complete.")
    print(f"Model: {model_path}")
    print(f"Calibrator: {calibrator_path}")
    print(f"Schema: {schema_path}")
    print(f"Metrics: {metrics_path}")
    print(f"Evaluation: {json.dumps(metrics, indent=2)}")


if __name__ == "__main__":
    main()
