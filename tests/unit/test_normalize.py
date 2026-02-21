"""Unit tests for library-first normalization."""
from __future__ import annotations

import base64

from app.api.schemas.email import GmailMessage, Header, MessagePart, MessagePartBody
from app.domain.email.normalize import normalize_email


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8").rstrip("=")


def test_normalize_from_raw_mime() -> None:
    raw_email = (
        "From: Security Team <security@example.com>\r\n"
        "Reply-To: support@updates.example.com\r\n"
        "Subject: Verify account\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Click https://example.com/verify to continue."
    )

    message = GmailMessage(raw=_b64(raw_email))
    normalized = normalize_email(message)

    assert normalized.sender_email == "security@example.com"
    assert normalized.reply_to_email == "support@updates.example.com"
    assert "verify" in normalized.subject_text.lower()
    assert any("https://example.com/verify" in url for url in normalized.urls)


def test_normalize_from_gmail_payload_html_and_text() -> None:
    payload = MessagePart(
        headers=[
            Header(name="From", value="alerts@example.org"),
            Header(name="Subject", value="Action required"),
        ],
        mimeType="multipart/alternative",
        parts=[
            MessagePart(mimeType="text/plain", body=MessagePartBody(data=_b64("Visit http://phish.example/login"))),
            MessagePart(
                mimeType="text/html",
                body=MessagePartBody(
                    data=_b64('<html><body><a href="https://safe.example/help">Help</a></body></html>')
                ),
            ),
        ],
    )

    message = GmailMessage(payload=payload)
    normalized = normalize_email(message)

    assert normalized.sender_email == "alerts@example.org"
    assert "action required" in normalized.subject_text.lower()
    assert any("phish.example/login" in url for url in normalized.urls)
    assert any("safe.example/help" in url for url in normalized.urls)


def test_invalid_sender_email_graceful_fallback() -> None:
    payload = MessagePart(
        headers=[Header(name="From", value="not-an-email")],
        mimeType="text/plain",
        body=MessagePartBody(data=_b64("hello")),
    )

    normalized = normalize_email(GmailMessage(payload=payload))
    assert normalized.sender_email is None


def test_html_is_compacted_to_text_and_attachment_names_kept() -> None:
    large_html = "<html><body>" + ("<p>Hello world</p>" * 2000) + "</body></html>"
    payload = MessagePart(
        headers=[Header(name="From", value="alerts@example.org")],
        mimeType="multipart/mixed",
        parts=[
            MessagePart(
                mimeType="text/html",
                body=MessagePartBody(data=_b64(large_html)),
            ),
            MessagePart(
                mimeType="application/pdf",
                filename="invoice-2026.pdf",
                body=MessagePartBody(data=_b64("binary")),
            ),
        ],
    )

    normalized = normalize_email(GmailMessage(payload=payload))

    assert "<p>" not in normalized.body_html
    assert "hello world" in normalized.body_html.lower()
    assert len(normalized.body_html) < 5000
    assert "invoice-2026.pdf" in normalized.attachment_names


def test_attachment_binary_is_not_included_in_body_text() -> None:
    payload = MessagePart(
        headers=[Header(name="From", value="alerts@example.org")],
        mimeType="multipart/mixed",
        parts=[
            MessagePart(
                mimeType="text/plain",
                body=MessagePartBody(data=_b64("Hello from body")),
            ),
            MessagePart(
                mimeType="application/pdf",
                filename="invoice.pdf",
                body=MessagePartBody(data=_b64("%PDF-1.7 binary blob contents")),
            ),
        ],
    )

    normalized = normalize_email(GmailMessage(payload=payload))

    assert "Hello from body" in normalized.body_text
    assert "PDF-1.7" not in normalized.body_text
    assert "invoice.pdf" in normalized.attachment_names


def test_non_utf8_charset_decodes_hebrew_text() -> None:
    hebrew = "שלום עולם"
    body_data = base64.urlsafe_b64encode(hebrew.encode("cp1255")).decode("utf-8").rstrip("=")

    payload = MessagePart(
        headers=[Header(name="From", value="alerts@example.org")],
        mimeType="text/plain",
        parts=[
            MessagePart(
                mimeType="text/plain",
                headers=[
                    Header(name="Content-Type", value="text/plain; charset=windows-1255"),
                ],
                body=MessagePartBody(data=body_data),
            )
        ],
    )

    normalized = normalize_email(GmailMessage(payload=payload))
    assert "שלום" in normalized.body_text
