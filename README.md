# Email Phishing Detector

Local, CPU-only phishing detection service with:
- FastAPI backend (`/api/v1/detect`)
- Streamlit frontend (`front/app.py`)
- ML-only runtime (LightGBM + calibrator + deterministic guardrails)

## Requirements

- Python `>=3.11`
- [`uv`](https://docs.astral.sh/uv/)

## Install

```bash
uv sync
```

If you plan to run tests too:

```bash
uv sync --all-groups
```

## Run

### 1) Backend (FastAPI)

```bash
uv run python main.py
```

Backend URL: `http://localhost:8000`

### 2) Frontend (Streamlit)

```bash
uv run streamlit run front/app.py
```

Frontend URL: `http://localhost:8501`

## API

### `POST /api/v1/detect`
Analyze one Gmail-format message.

Minimal request example:

```json
{
  "id": "msg-1",
  "payload": {
    "headers": [
      {"name": "From", "value": "security@gogle.com"},
      {"name": "Subject", "value": "Account Verification Required"}
    ],
    "body": {
      "data": "WW91ciBhY2NvdW50IHJlcXVpcmVzIGltbWVkaWF0ZSB2ZXJpZmljYXRpb24uIFBsZWFzZSBjbGljayBodHRwczovL2dvZ2xlLmNvbS92ZXJpZnk"
    },
    "mimeType": "text/plain"
  }
}
```

Response includes:
- `risk_score` (final post-policy score)
- `raw_probability` (model probability before guardrail escalation)
- `classification`
- `indicators[]` with contribution/evidence/details
- `model_version`, `decision_threshold`
- `guardrail_applied`, `guardrail_reasons`

### `GET /`
Basic service status.

### `GET /api/v1/health`
ML runtime health and artifact presence, including:
- runtime (`model_version`, threshold, model/calibrator loaded flags)
- artifact paths and file existence checks

## Runtime Artifacts

Expected in `models/`:
- `phishing_lgbm_v1.txt`
- `calibrator_v1.pkl`
- `feature_schema_v1.json`

Optional env overrides:
- `PHISH_ML_MODEL_PATH`
- `PHISH_ML_CALIBRATOR_PATH`
- `PHISH_ML_SCHEMA_PATH`
- `PHISH_ML_THRESHOLD`

## Training

### Prepare dataset

```bash
uv run python scripts/training/prepare_dataset.py \
  --input /path/to/raw.csv \
  --output /path/to/normalized.csv
```

Supports local `.csv`, `.jsonl/.ndjson`, `.parquet`, and `hf://...` parquet URIs.

### Train model

```bash
uv run python scripts/training/train_lightgbm.py \
  --dataset /path/to/normalized.csv
```

Optional hard-case regression:

```bash
uv run python scripts/training/train_lightgbm.py \
  --dataset /path/to/normalized.csv \
  --hard-cases /path/to/hard_cases.csv
```

## Tests

```bash
uv run pytest
```

or directly with the local venv:

```bash
.venv/bin/python -m pytest
```

## Troubleshooting

### LightGBM `libomp.dylib` missing (macOS)

Install OpenMP runtime (Homebrew):

```bash
brew install libomp
```

Then rerun training.

## Project Structure

```text
.
├── app/
│   ├── api/
│   │   ├── main.py
│   │   └── schemas.py
│   ├── detectors/
│   │   └── ml_detector.py
│   ├── features/
│   │   ├── brand_signals.py
│   │   └── email_feature_extractor.py
│   ├── parsing/
│   │   └── email_parser.py
│   └── runtime/
│       └── model_runtime.py
├── front/
│   └── app.py
├── models/
│   ├── phishing_lgbm_v1.txt
│   ├── calibrator_v1.pkl
│   └── feature_schema_v1.json
├── scripts/
│   └── training/
│       ├── prepare_dataset.py
│       └── train_lightgbm.py
├── tests/
│   ├── integration/
│   └── unit/
└── main.py
```
