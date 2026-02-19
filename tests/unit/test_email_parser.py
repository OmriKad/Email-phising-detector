"""Unit tests for email parsing utilities."""
import base64

from app.api.schemas import Header, MessagePart, MessagePartBody
from app.parsing.email_parser import (
    decode_body_data,
    extract_domain_from_url,
    extract_email_body,
    extract_header_value,
    extract_sender_domain,
    extract_urls_from_text,
)


def test_extract_header_value():
    headers = [
        Header(name="From", value="test@example.com"),
        Header(name="Subject", value="Test Subject"),
    ]

    assert extract_header_value(headers, "From") == "test@example.com"
    assert extract_header_value(headers, "Subject") == "Test Subject"
    assert extract_header_value(headers, "To") is None
    assert extract_header_value(None, "From") is None


def test_extract_sender_domain():
    assert extract_sender_domain("user@google.com") == "google.com"
    assert extract_sender_domain("Name <user@facebook.com>") == "facebook.com"
    assert extract_sender_domain('"Full Name" <test@example.com>') == "example.com"
    assert extract_sender_domain("invalid-email") is None
    assert extract_sender_domain(None) is None


def test_extract_urls_from_text():
    text = """
    Check out https://example.com for more info.
    Also visit http://test.org/page
    """

    urls = extract_urls_from_text(text)
    assert len(urls) == 2
    assert "https://example.com" in urls
    assert "http://test.org/page" in urls


def test_extract_domain_from_url():
    assert extract_domain_from_url("https://google.com/path") == "google.com"
    assert extract_domain_from_url("http://sub.amazon.com:8080/page") == "amazon.com"
    assert extract_domain_from_url("https://example.com") == "example.com"
    assert extract_domain_from_url("https://192.168.1.1") == "192.168.1.1"
    assert extract_domain_from_url("invalid-url") is None


def test_decode_body_data():
    text = "Hello World"
    encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

    decoded = decode_body_data(encoded)
    assert decoded == text

    assert decode_body_data(None) == ""
    assert decode_body_data("") == ""


def test_extract_email_body():
    body_text = "This is the email body"
    encoded = base64.urlsafe_b64encode(body_text.encode()).decode().rstrip("=")

    message_part = MessagePart(
        body=MessagePartBody(data=encoded),
        mimeType="text/plain",
    )

    extracted = extract_email_body(message_part)
    assert body_text in extracted


def test_extract_email_body_nested():
    part1_text = "Part 1"
    part2_text = "Part 2"

    part1_encoded = base64.urlsafe_b64encode(part1_text.encode()).decode().rstrip("=")
    part2_encoded = base64.urlsafe_b64encode(part2_text.encode()).decode().rstrip("=")

    message_part = MessagePart(
        mimeType="multipart/mixed",
        parts=[
            MessagePart(body=MessagePartBody(data=part1_encoded), mimeType="text/plain"),
            MessagePart(body=MessagePartBody(data=part2_encoded), mimeType="text/html"),
        ],
    )

    extracted = extract_email_body(message_part)
    assert "Part 1" in extracted
    assert "Part 2" in extracted
