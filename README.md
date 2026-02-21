# Email Phishing Detector (PydanticAI + Streamlit)

Production-minded phishing detection with:
- FastAPI backend
- PydanticAI agent (Ollama-compatible model runner)
- Streamlit frontend
- Frozen API response envelope (`schema_version = v1`)

## API Contract (v1)

`POST /api/v1/detect`

Request:
```json
{
  "source": "gmail_addon",
  "message": {
    "id": "msg-1",
    "payload": {
      "headers": [
        {"name": "From", "value": "security@example.com"},
        {"name": "Subject", "value": "Verify account"}
      ],
      "mimeType": "text/plain",
      "body": {"data": "Q2xpY2sgaGVyZQ"}
    }
  }
}
```

Success response envelope:
```json
{
  "schema_version": "v1",
  "request_id": "uuid",
  "result": {
    "verdict": "likely_phishing",
    "risk_score": 0.88,
    "confidence": 0.79,
    "summary": "Credential harvesting pattern detected.",
    "triggers": [
      {
        "kind": "link",
        "source_field": "body_text",
        "value": "http://example-login-reset.com",
        "reason": "Suspicious login reset domain",
        "severity": "high"
      }
    ]
  },
  "error": null
}
```

Error response envelope:
```json
{
  "schema_version": "v1",
  "request_id": "uuid",
  "result": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request payload.",
    "details": []
  }
}
```

## Normalization strategy

Library-first extraction:
- `mail-parser` for raw MIME (`message.raw`)
- `email-validator` for sender/reply-to normalization
- `BeautifulSoup` + `lxml` for HTML extraction
- `urlextract` for URL extraction
- `tldextract` for host normalization support

Normalized internal object fields:
- `sender_email`
- `reply_to_email`
- `subject_text`
- `body_text`
- `body_html`
- `urls[]`

## Run locally

```bash
uv sync
uv run python main.py
uv run streamlit run front/app.py
```

Backend: `http://localhost:8000`
Frontend: `http://localhost:8501`

## Run with Docker Compose

Prerequisite:
- Docker Desktop running locally.
- Docker model runner (OpenAI-compatible) reachable at `http://host.docker.internal:11434`.

Start the full stack (backend + frontend):
```bash
docker compose up --build
```

Run in detached mode:
```bash
docker compose up --build -d
```

Open:
- Backend health: `http://localhost:8000/api/v1/health`
- Frontend: `http://localhost:8501`

The backend resolves model connectivity in this priority:
1. `PHISHING_DETECT_URL` (injected by Compose `models:` wiring for `phishing-detect`)
2. `OLLAMA_HOST` (fallback)

Model name priority:
1. `PHISHING_DETECT_MODEL`
2. `OLLAMA_MODEL`

View logs:
```bash
docker compose logs -f backend
docker compose logs -f frontend
```

Stop the stack:
```bash
docker compose down
```

Troubleshooting `MODEL_PROVIDER_ERROR` / HTTP 502:
1. Check backend health payload for resolved endpoint:
   `curl http://localhost:8000/api/v1/health`
2. Confirm `model_endpoint` is reachable from the backend container:
   `docker compose exec backend sh -lc 'echo $PHISHING_DETECT_URL $OLLAMA_HOST'`
3. If `PHISHING_DETECT_URL` is empty, verify your Docker Desktop model runner is installed/enabled.

## Tests

```bash
uv run pytest
```

Optional integration/eval runs:
```bash
RUN_MODEL_INTEGRATION=1 uv run pytest tests/integration
RUN_EVALS=1 uv run pytest tests/evals
```
