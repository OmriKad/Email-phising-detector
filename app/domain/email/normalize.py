"""Library-first email normalization and extraction."""
from __future__ import annotations

import base64
import logging
import quopri
import re
from email.utils import parseaddr
from typing import Iterable
from urllib.parse import urlparse

import mailparser
import tldextract
from bs4 import BeautifulSoup
from email_validator import EmailNotValidError, validate_email
from urlextract import URLExtract

from app.api.schemas.email import GmailMessage, MessagePart
from app.domain.agents.models import NormalizedEmail

logger = logging.getLogger(__name__)
_URL_EXTRACTOR = URLExtract()
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)
_MAX_SUBJECT_CHARS = 300
_MAX_BODY_TEXT_CHARS = 4000
_MAX_BODY_HTML_TEXT_CHARS = 4000
_MAX_TOTAL_CONTENT_CHARS = 12000
_MAX_URLS = 30
_MAX_ATTACHMENT_NAMES = 20
_MAX_ATTACHMENT_NAME_CHARS = 200


def normalize_email(message: GmailMessage) -> NormalizedEmail:
    """Normalize either Gmail MessagePart input or raw MIME payload into one typed shape."""
    if message.raw:
        normalized = _normalize_from_raw(message.raw)
        if normalized:
            return _compact_for_model(normalized)

    return _compact_for_model(_normalize_from_message_part(message))


def _normalize_from_raw(raw_value: str) -> NormalizedEmail | None:
    raw_text = _decode_possible_base64(raw_value)
    parsed = None

    for parser in (mailparser.parse_from_string, mailparser.parse_from_bytes):
        try:
            payload = raw_text if parser is mailparser.parse_from_string else raw_text.encode("utf-8", errors="ignore")
            parsed = parser(payload)
            break
        except Exception:
            continue

    if parsed is None:
        logger.warning("mail-parser failed to parse raw payload; falling back to MessagePart handling")
        return None

    sender_email = _first_parsed_email(getattr(parsed, "from_", None))
    reply_to_email = _first_parsed_email(getattr(parsed, "reply_to", None))
    subject_text = getattr(parsed, "subject", "") or ""
    body_text = "\n".join(getattr(parsed, "text_plain", []) or [])
    body_html = "\n".join(getattr(parsed, "text_html", []) or [])
    attachment_names = _attachment_names_from_raw(parsed)

    urls: set[str] = set(getattr(parsed, "urls", []) or [])
    urls.update(_extract_urls_from_text(body_text))
    urls.update(_extract_urls_from_html(body_html))

    return NormalizedEmail(
        sender_email=sender_email,
        reply_to_email=reply_to_email,
        subject_text=subject_text,
        body_text=body_text,
        body_html=body_html,
        urls=sorted(urls),
        attachment_names=attachment_names,
    )


def _normalize_from_message_part(message: GmailMessage) -> NormalizedEmail:
    payload = message.payload
    headers = payload.headers if payload and payload.headers else []

    sender_email = _normalize_address(_header_value(headers, "From"))
    reply_to_email = _normalize_address(_header_value(headers, "Reply-To"))
    subject_text = _header_value(headers, "Subject") or ""

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachment_names: list[str] = []
    if payload:
        _collect_parts(payload, text_parts, html_parts, attachment_names)

    body_text = "\n".join([p for p in text_parts if p])
    body_html = "\n".join([p for p in html_parts if p])

    urls: set[str] = set()
    urls.update(_extract_urls_from_text(body_text))
    urls.update(_extract_urls_from_html(body_html))

    return NormalizedEmail(
        sender_email=sender_email,
        reply_to_email=reply_to_email,
        subject_text=subject_text,
        body_text=body_text,
        body_html=body_html,
        urls=sorted(urls),
        attachment_names=_dedupe_preserve(attachment_names, _MAX_ATTACHMENT_NAMES),
    )


def _collect_parts(
    part: MessagePart,
    text_parts: list[str],
    html_parts: list[str],
    attachment_names: list[str],
) -> None:
    mime_type = (part.mimeType or "").lower()
    has_filename = bool(part.filename and part.filename.strip())
    if has_filename:
        attachment_names.append(part.filename.strip())

    # Only feed genuine message text into the model; never decode attachment bodies as text.
    if (
        part.body
        and part.body.data
        and not has_filename
        and not mime_type.startswith("multipart/")
        and _should_extract_text(mime_type)
    ):
        decoded = _decode_part_data(part.body.data, part.headers)
        if decoded:
            if "html" in mime_type:
                html_parts.append(decoded)
            else:
                text_parts.append(decoded)

    for nested in part.parts or []:
        _collect_parts(nested, text_parts, html_parts, attachment_names)


def _decode_possible_base64(raw_value: str) -> str:
    decoded = _decode_base64url(raw_value)
    if "From:" in decoded or "Subject:" in decoded:
        return decoded
    return raw_value


def _decode_base64url(data: str) -> str:
    raw = _decode_base64url_to_bytes(data)
    if not raw:
        return ""
    return _decode_text_bytes(raw, None)


def _decode_base64url_to_bytes(data: str) -> bytes:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return b""


def _extract_urls_from_text(text: str) -> set[str]:
    if not text:
        return set()

    library_urls = set(_URL_EXTRACTOR.find_urls(text))
    regex_urls = set(re.findall(r"https?://[^\s<>'\"\)]+", text))
    urls = {_normalize_url(url) for url in library_urls | regex_urls}
    return {url for url in urls if url}


def _extract_urls_from_html(html: str) -> set[str]:
    if not html:
        return set()

    urls: set[str] = set()
    soup = BeautifulSoup(html, "lxml")

    for tag, attr in (("a", "href"), ("img", "src"), ("iframe", "src"), ("form", "action")):
        for element in soup.find_all(tag):
            value = element.attrs.get(attr)
            if isinstance(value, str):
                normalized = _normalize_url(value)
                if normalized:
                    urls.add(normalized)

    urls.update(_extract_urls_from_text(soup.get_text(" ", strip=True)))
    return urls


def _normalize_url(url: str) -> str | None:
    value = (url or "").strip().strip("\"'")
    if not value:
        return None

    parsed = urlparse(value)
    if not parsed.scheme:
        value = f"https://{value}"
        parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        return None

    host = parsed.hostname or ""
    if host:
        _DOMAIN_EXTRACTOR(host)

    return value


def _header_value(headers: Iterable, name: str) -> str | None:
    for header in headers:
        if (header.name or "").lower() == name.lower():
            return header.value
    return None


def _first_parsed_email(values) -> str | None:
    if not values:
        return None

    first = values[0]
    if isinstance(first, (list, tuple)) and len(first) >= 2:
        return _normalize_address(first[1])
    if isinstance(first, str):
        return _normalize_address(first)
    return None


def _normalize_address(value: str | None) -> str | None:
    if not value:
        return None

    _, parsed_email = parseaddr(value)
    if not parsed_email:
        return None

    try:
        validated = validate_email(parsed_email, check_deliverability=False)
        return validated.normalized
    except EmailNotValidError:
        candidate = parsed_email.strip().lower()
        return candidate if "@" in candidate else None


def _should_extract_text(mime_type: str) -> bool:
    if not mime_type:
        return True
    if mime_type.startswith("text/"):
        return True
    if mime_type == "message/rfc822":
        return True
    return False


def _decode_part_data(data: str, headers: Iterable | None) -> str:
    raw = _decode_base64url_to_bytes(data)
    if not raw:
        return ""

    transfer_encoding = (_header_value(headers or [], "Content-Transfer-Encoding") or "").lower()
    if "quoted-printable" in transfer_encoding:
        raw = quopri.decodestring(raw)

    charset = _extract_charset(_header_value(headers or [], "Content-Type"))
    text = _decode_text_bytes(raw, charset)
    if _looks_like_binary_noise(text):
        return ""
    return text


def _extract_charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    match = re.search(r"charset\s*=\s*['\"]?([a-zA-Z0-9._-]+)", content_type)
    return match.group(1).strip().lower() if match else None


def _decode_text_bytes(raw: bytes, preferred_charset: str | None) -> str:
    candidates = [
        preferred_charset,
        "utf-8",
        "windows-1255",
        "iso-8859-8",
        "cp1252",
        "latin-1",
    ]
    for charset in [c for c in candidates if c]:
        try:
            return raw.decode(charset)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


def _looks_like_binary_noise(text: str) -> bool:
    if not text:
        return False
    if len(text) < 20:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    ratio = printable / max(len(text), 1)
    return ratio < 0.7


def _compact_for_model(normalized: NormalizedEmail) -> NormalizedEmail:
    subject = _truncate(_normalize_whitespace(normalized.subject_text), _MAX_SUBJECT_CHARS)
    body_text = _truncate(_normalize_whitespace(normalized.body_text), _MAX_BODY_TEXT_CHARS)

    # Reduce HTML payload to meaningful text only to keep model context small.
    body_html_text = _truncate(_normalize_whitespace(_html_to_text(normalized.body_html)), _MAX_BODY_HTML_TEXT_CHARS)

    urls = _dedupe_preserve([u.strip() for u in normalized.urls if u and u.strip()], _MAX_URLS)
    attachment_names = _dedupe_preserve(
        [_truncate(a.strip(), _MAX_ATTACHMENT_NAME_CHARS) for a in normalized.attachment_names if a and a.strip()],
        _MAX_ATTACHMENT_NAMES,
    )

    subject, body_text, body_html_text, urls, attachment_names = _enforce_total_budget(
        subject,
        body_text,
        body_html_text,
        urls,
        attachment_names,
    )

    return NormalizedEmail(
        sender_email=normalized.sender_email,
        reply_to_email=normalized.reply_to_email,
        subject_text=subject,
        body_text=body_text,
        body_html=body_html_text,
        urls=urls,
        attachment_names=attachment_names,
    )


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text(" ", strip=True)


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + " ...[truncated]"


def _dedupe_preserve(values: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= limit:
            break
    return out


def _enforce_total_budget(
    subject: str,
    body_text: str,
    body_html_text: str,
    urls: list[str],
    attachment_names: list[str],
) -> tuple[str, str, str, list[str], list[str]]:
    def total_chars() -> int:
        return (
            len(subject)
            + len(body_text)
            + len(body_html_text)
            + sum(len(x) for x in urls)
            + sum(len(x) for x in attachment_names)
        )

    while total_chars() > _MAX_TOTAL_CONTENT_CHARS:
        if len(body_html_text) > 1200:
            body_html_text = _truncate(body_html_text[: int(len(body_html_text) * 0.85)], _MAX_BODY_HTML_TEXT_CHARS)
            continue
        if len(body_text) > 1200:
            body_text = _truncate(body_text[: int(len(body_text) * 0.85)], _MAX_BODY_TEXT_CHARS)
            continue
        if len(urls) > 10:
            urls = urls[:-1]
            continue
        if len(attachment_names) > 5:
            attachment_names = attachment_names[:-1]
            continue
        break

    return subject, body_text, body_html_text, urls, attachment_names


def _attachment_names_from_raw(parsed) -> list[str]:
    attachments = getattr(parsed, "attachments", None) or []
    names: list[str] = []

    for item in attachments:
        if isinstance(item, dict):
            candidate = item.get("filename") or item.get("file_name") or item.get("name")
            if isinstance(candidate, str) and candidate.strip():
                names.append(candidate.strip())

    return _dedupe_preserve(names, _MAX_ATTACHMENT_NAMES)
