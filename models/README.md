# Model Artifacts

Runtime artifacts used by the ML-only serving path:

- `phishing_lgbm_v1.txt` - LightGBM booster model.
- `calibrator_v1.pkl` - Probability calibrator.
- `feature_schema_v1.json` - Feature order + decision threshold metadata.

Generate artifacts with:

```bash
uv run python scripts/training/train_lightgbm.py --dataset /path/to/normalized_dataset.csv
```
