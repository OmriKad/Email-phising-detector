# Email Phishing Detector

A FastAPI-based backend service with Streamlit web interface that analyzes email content for phishing indicators using Gmail API format.

## Features

- **Streamlit Web Interface**: Interactive email composition form with visual risk analysis
- **Gmail API Compatible**: Accepts email messages in Gmail API MessagePart format
- **Multi-Indicator Detection**:
  - Suspicious links (typosquatting, IP addresses, unknown domains)
  - Spoofed sender domains (typosquatting detection)
  - Urgent/pressure language patterns
- **Weighted Scoring**: Combines indicators with configurable weights (sender 40%, links 40%, language 20%)
- **Risk Classification**: Three-tier classification (safe, caution, major indicators)
- **Domain Validation**: Uses Tranco top-1000 registrable domains with Levenshtein distance for typosquatting detection
- **Domain Age Signal**: Flags domains younger than 30 days using WHOIS/RDAP lookups (cached)
- **HTML Email Support**: Extracts URLs from HTML content (links, images, iframes) using BeautifulSoup

## Requirements

- Python 3.11+
- uv package manager

## Installation

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync
```

## Running the Application

### Option 1: Full Stack (FastAPI Backend + Streamlit Frontend)

**Terminal 1: Start FastAPI Backend**
```bash
uv run python main.py
```
The API will be available at `http://localhost:8000`

**Terminal 2: Start Streamlit UI**
```bash
uv run streamlit run front/app.py
```
The web interface will be available at `http://localhost:8501`

### Option 2: API Only

```bash
# Start the FastAPI development server
uv run python main.py
```

The API will be available at `http://localhost:8000`

## Streamlit Web Interface

Access the web interface at `http://localhost:8501` to:
- Compose emails with From, To, Subject, and Body (Plain Text/HTML)
- Load pre-configured example emails (Safe, Typosquatting, Suspicious Links, Multiple Indicators)
- Analyze emails with visual gauge chart showing risk score (0-100%)
- View detailed phishing indicators with severity levels
- Get color-coded classification alerts

**Example Usage:**
1. Click an example email button in the sidebar
2. Or manually fill in the email composition form
3. Switch between Plain Text and HTML tabs for body content
4. Click "Analyze Email" to detect phishing indicators
5. Review the gauge chart, metrics, and detailed findings

## API Endpoints

### `POST /api/v1/detect`

Analyze an email for phishing indicators.

**Request Body**: Gmail message in Gmail API format

```json
{
  "id": "msg123",
  "payload": {
    "headers": [
      {"name": "From", "value": "sender@example.com"},
      {"name": "Subject", "value": "Email Subject"}
    ],
    "body": {"data": "base64url_encoded_content"},
    "mimeType": "text/plain"
  }
}
```

**Response**:

```json
{
  "risk_score": 0.75,
  "classification": "Major indicators found!",
  "indicators": [
    {
      "type": "spoofed_sender",
      "description": "Sender domain 'gogle' is similar to 'google' (typosquatting)",
      "severity": "high",
      "details": {
        "sender_domain": "gogle",
        "similar_to": "google",
        "levenshtein_distance": 1
      }
    }
  ],
  "message": "🚨 Warning: 1 major phishing indicator(s) detected!"
}
```

### `GET /`

Health check endpoint.

### `GET /api/v1/health`

Detailed health check with domain cache status.

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=app

# Run specific test file
uv run pytest tests/test_phishing_detector.py
```

## Project Structure

```
.
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── models.py            # Pydantic models
│   ├── domain_fetcher.py    # Tranco domain list fetcher
│   ├── email_parser.py      # Email parsing utilities (HTML support)
│   └── phishing_detector.py # Detection logic
├── front/
│   ├── __init__.py
│   └── app.py               # Streamlit web interface
├── tests/
│   ├── test_api.py
│   ├── test_email_parser.py
│   └── test_phishing_detector.py
├── main.py                  # FastAPI entry point
├── pyproject.toml           # Project configuration
└── README.md
```

## Detection Logic

### Risk Scoring

- **Sender Domain** (40% weight):
  - In top-1000 list: 0 points
  - Levenshtein distance ≤ 2: 1.0 (maximum)
  - Newly registered (< 30 days): 0.8
  - Unknown domain: 0.5
  
- **Links** (40% weight):
  - IP address in URL: 1.0
  - Typosquatting domain: 1.0
  - Newly registered (< 30 days): 0.7
  - Unknown domain: 0.3

- **Urgent Language** (20% weight):
  - Patterns: "urgent", "immediately", "action required", "verify account", etc.
  - Score based on number of matches (0.3 per match, capped at 1.0)

### Risk Classification

- **Seems safe** (< 0.33): No major indicators
- **Few indicators found, need to be cautious** (0.33 - 0.5): Minor concerns
- **Major indicators found!** (> 0.5): High risk

## Development

```bash
# Format code
uv run black app/ tests/ front/

# Lint
uv run ruff check app/ tests/ front/

# Type checking
uv run mypy app/
```

## Technology Stack

**Backend:**
- FastAPI - Web framework
- Pydantic - Data validation
- python-Levenshtein - Typosquatting detection
- httpx - Async HTTP client for Tranco API
- python-whois - WHOIS/RDAP domain age lookup
- tldextract - Registrable domain normalization (Public Suffix List)
- BeautifulSoup4 - HTML parsing for URL extraction
- uvicorn - ASGI server

**Frontend:**
- Streamlit - Web UI framework
- Plotly - Interactive gauge charts
- Pandas - Data display
- requests - HTTP client

**Testing:**
- pytest - Testing framework

**Package Management:**
- uv - Fast Python package manager
