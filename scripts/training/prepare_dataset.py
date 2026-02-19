#!/usr/bin/env python3
"""Normalize raw phishing corpora into the training schema used by this project."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        help="Source dataset. Supports local .csv/.jsonl/.parquet and hf:// parquet URIs.",
    )
    parser.add_argument("--output", required=True, help="Output normalized .csv path.")
    parser.add_argument("--from-col", default="from")
    parser.add_argument("--subject-col", default="subject")
    parser.add_argument("--body-col", default="body")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--text-col", default="", help="Fallback text column when body column is absent.")
    parser.add_argument("--reply-to-col", default="")
    parser.add_argument("--auth-results-col", default="")
    parser.add_argument("--return-path-col", default="")
    parser.add_argument("--default-from", default="unknown@local.invalid")
    parser.add_argument("--drop-empty-body", action="store_true")
    parser.add_argument("--dedupe", action="store_true", help="Drop duplicate body+label rows.")
    parser.add_argument(
        "--drop-body-over-chars",
        type=int,
        default=0,
        help="Drop rows where body length exceeds this limit (0 disables).",
    )
    return parser.parse_args()


def load_frame(source: str) -> pd.DataFrame:
    source = source.strip()
    lowered = source.lower()
    if lowered.startswith("hf://") or lowered.endswith(".parquet"):
        return pd.read_parquet(source)
    if lowered.endswith(".csv"):
        return pd.read_csv(source)
    if lowered.endswith(".jsonl") or lowered.endswith(".ndjson"):
        return pd.read_json(source, lines=True)
    raise ValueError(f"Unsupported input format for '{source}'")


def to_label(value: object) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    truthy = {
        "1",
        "true",
        "yes",
        "phishing",
        "phishing email",
        "malicious",
        "spam",
        "fraud",
        "scam",
        "junk",
    }
    falsy = {
        "0",
        "false",
        "no",
        "benign",
        "legit",
        "ham",
        "safe",
        "safe email",
        "normal",
    }
    if text in truthy:
        return 1
    if text in falsy:
        return 0
    if "phish" in text or "malicious" in text or "fraud" in text or "spam" in text:
        return 1
    if "safe" in text or "legit" in text or "ham" in text or "benign" in text:
        return 0
    try:
        return 1 if float(text) >= 0.5 else 0
    except Exception:
        return 0


def get_col(frame: pd.DataFrame, name: str, default_value: str = "") -> pd.Series:
    if not name:
        return pd.Series([default_value] * len(frame))
    if name not in frame.columns:
        return pd.Series([default_value] * len(frame))
    return frame[name].fillna("").astype(str)


def choose_col(frame: pd.DataFrame, requested: str, candidates: list[str]) -> str:
    if requested and requested in frame.columns:
        return requested
    for name in candidates:
        if name in frame.columns:
            return name
    return ""


def derive_subject_from_body(body_series: pd.Series) -> pd.Series:
    derived = []
    for text in body_series.fillna("").astype(str):
        first_line = text.strip().splitlines()[0] if text.strip() else ""
        derived.append(first_line[:160])
    return pd.Series(derived)


def main() -> None:
    args = parse_args()
    out_path = Path(args.output).expanduser().resolve()

    frame = load_frame(args.input)
    label_col = choose_col(frame, args.label_col, ["label", "Email Type", "type", "class", "target", "is_phishing"])
    body_col = choose_col(frame, args.body_col, ["body", args.text_col, "Email Text", "text", "email", "content", "message"])
    from_col = choose_col(frame, args.from_col, ["from", "sender", "from_email", "From"])
    subject_col = choose_col(frame, args.subject_col, ["subject", "Subject", "title"])

    if not label_col:
        raise ValueError(
            f"Could not find label column. Requested '{args.label_col}'. Available columns: {list(frame.columns)}"
        )
    if not body_col:
        raise ValueError(
            f"Could not find body/text column. Requested '{args.body_col}' or '{args.text_col}'. "
            f"Available columns: {list(frame.columns)}"
        )

    body_series = get_col(frame, body_col)
    subject_series = get_col(frame, subject_col) if subject_col else derive_subject_from_body(body_series)
    from_series = get_col(frame, from_col, default_value=args.default_from)

    normalized = pd.DataFrame(
        {
            "from": from_series,
            "subject": subject_series,
            "body": body_series,
            "reply_to": get_col(frame, args.reply_to_col),
            "auth_results": get_col(frame, args.auth_results_col),
            "return_path": get_col(frame, args.return_path_col),
            "label": frame[label_col].map(to_label),
        }
    )

    if args.drop_empty_body:
        normalized = normalized[normalized["body"].str.strip() != ""]

    if args.drop_body_over_chars > 0:
        normalized = normalized[normalized["body"].str.len() <= args.drop_body_over_chars]

    if args.dedupe:
        normalized = normalized.drop_duplicates(subset=["body", "label"])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    normalized.to_csv(out_path, index=False)

    counts: Dict[int, int] = normalized["label"].value_counts().sort_index().to_dict()
    print(f"Input columns detected: label='{label_col}', body='{body_col}', from='{from_col or '[default]'}', subject='{subject_col or '[derived]'}'")
    print(f"Wrote {len(normalized)} rows to {out_path}")
    print(f"Label distribution: {counts}")


if __name__ == "__main__":
    main()
