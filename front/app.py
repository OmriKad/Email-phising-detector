"""Streamlit frontend for phishing detection API v1."""
from __future__ import annotations

import base64
import os
from typing import Any

import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")


st.set_page_config(page_title="Email Phishing Detector", page_icon="🛡️", layout="wide")
st.title("Email Phishing Detector")
st.caption("LLM-first phishing analysis with strict structured output")


def _encode_b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8").rstrip("=")


def build_gmail_payload(from_addr: str, to_addr: str, subject: str, body_text: str, body_html: str) -> dict[str, Any]:
    headers = [
        {"name": "From", "value": from_addr},
        {"name": "To", "value": to_addr},
        {"name": "Subject", "value": subject},
    ]

    parts = []
    if body_text:
        parts.append({"mimeType": "text/plain", "body": {"data": _encode_b64url(body_text)}})
    if body_html:
        parts.append({"mimeType": "text/html", "body": {"data": _encode_b64url(body_html)}})

    if len(parts) == 1:
        payload = {"headers": headers, "mimeType": parts[0]["mimeType"], "body": parts[0]["body"]}
    else:
        payload = {"headers": headers, "mimeType": "multipart/alternative", "parts": parts}

    return {"id": "streamlit-msg", "payload": payload}


with st.sidebar:
    st.subheader("Backend")
    st.code(BACKEND_URL)

col1, col2 = st.columns(2)
with col1:
    from_addr = st.text_input("From", value="security@example.com")
    to_addr = st.text_input("To", value="user@example.com")
with col2:
    subject = st.text_input("Subject", value="Action required")

body_text = st.text_area("Body (plain text)", height=180)
body_html = st.text_area("Body (HTML optional)", height=180)

json_override = st.text_area(
    "Optional raw request JSON override",
    value="",
    help="If provided, this JSON is sent as-is. Otherwise the form payload is used.",
)

if st.button("Analyze", type="primary"):
    if json_override.strip():
        try:
            import json

            request_payload = json.loads(json_override)
        except Exception as exc:
            st.error(f"Invalid JSON override: {exc}")
            st.stop()
    else:
        request_payload = {
            "source": "streamlit",
            "message": build_gmail_payload(from_addr, to_addr, subject, body_text, body_html),
        }

    with st.spinner("Analyzing..."):
        try:
            response = requests.post(f"{BACKEND_URL}/api/v1/detect", json=request_payload, timeout=60)
            envelope = response.json()
        except Exception as exc:
            st.error(f"Request failed: {exc}")
            st.stop()

    st.subheader("Response")
    st.code(f"HTTP {response.status_code}")

    if envelope.get("error"):
        st.error(envelope["error"]["code"])
        st.write(envelope["error"]["message"])
        if envelope["error"].get("details"):
            st.json(envelope["error"]["details"])
        st.stop()

    result = envelope.get("result") or {}
    st.metric("Verdict", result.get("verdict", "unknown"))
    st.metric("Risk score", f"{result.get('risk_score', 0):.2f}")
    st.metric("Confidence", f"{result.get('confidence', 0):.2f}")
    st.write(result.get("summary", ""))

    triggers = result.get("triggers", [])
    st.subheader("Triggers")
    if triggers:
        st.dataframe(triggers, use_container_width=True)
    else:
        st.info("No triggers returned")

    st.subheader("Envelope")
    st.json(envelope)
