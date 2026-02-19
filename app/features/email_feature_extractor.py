"""Deterministic email feature extraction for local phishing ML inference."""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.api.schemas import GmailMessage, MessagePart
from app.features.brand_signals import BrandSignalResolver, extract_domain_root
from app.parsing.email_parser import (
    extract_email_body,
    extract_domain_from_url,
    extract_header_value,
    extract_sender_domain,
    extract_urls_from_message,
    is_ip_address,
    normalize_domain,
)

_EMAIL_RE = re.compile(r"([\w.+-]+)@([\w.-]+)")
_TOKEN_RE = re.compile(r"\b[a-z0-9][a-z0-9_-]*\b")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")

URGENT_TERMS = (
    "urgent",
    "immediately",
    "action required",
    "act now",
    "deadline",
    "expired",
    "suspended",
    "alert",
)
CREDS_TERMS = (
    "verify",
    "account",
    "password",
    "credential",
    "login",
    "bank",
    "invoice",
    "payment",
    "security code",
    "ssn",
)
THREAT_TERMS = (
    "suspend",
    "locked",
    "disabled",
    "terminated",
    "unauthorized",
    "compromised",
    "final warning",
)
SUSPICIOUS_TLDS = {"zip", "top", "work", "click", "link", "gq", "tk", "xyz"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
}

FEATURE_ORDER = [
    "sender_has_display_name",
    "sender_domain_length",
    "sender_domain_entropy",
    "sender_domain_digit_ratio",
    "sender_domain_hyphen_count",
    "sender_localpart_digit_ratio",
    "sender_localpart_suspicious",
    "sender_brand_min_distance",
    "sender_brand_typosquat_flag",
    "reply_to_mismatch",
    "return_path_mismatch",
    "auth_spf_fail",
    "auth_dkim_fail",
    "auth_dmarc_fail",
    "delivery_received_chain_count",
    "url_count",
    "url_ip_count",
    "url_punycode_count",
    "url_obfuscated_count",
    "url_suspicious_tld_count",
    "url_shortener_count",
    "url_https_ratio",
    "url_max_length",
    "url_max_subdomain_depth",
    "url_max_entropy",
    "url_max_digit_ratio",
    "url_brand_min_distance",
    "url_brand_typosquat_flag",
    "sender_url_brand_mismatch_flag",
    "language_urgent_terms_count",
    "language_credential_terms_count",
    "language_threat_terms_count",
    "credential_plus_link_flag",
    "subject_has_urgent",
    "subject_all_caps_ratio",
    "subject_exclamation_count",
    "content_exclamation_count",
    "content_non_ascii_ratio",
    "content_form_tag_count",
    "content_text_length",
]


@dataclass
class FeatureExtractionResult:
    """Container for model features and per-feature evidence strings."""

    features: Dict[str, float]
    evidence: Dict[str, List[str]]


class EmailFeatureExtractor:
    """Extract cache-free lexical and structural phishing features."""

    def __init__(self, brand_resolver: Optional[BrandSignalResolver] = None):
        self.brand_resolver = brand_resolver or BrandSignalResolver()

    def extract(self, message: GmailMessage) -> FeatureExtractionResult:
        features = {name: 0.0 for name in FEATURE_ORDER}
        evidence: Dict[str, List[str]] = {}

        payload = message.payload if message.payload is not None else MessagePart()
        headers = payload.headers or []

        from_header = extract_header_value(headers, "From") or ""
        reply_to = extract_header_value(headers, "Reply-To") or ""
        return_path = extract_header_value(headers, "Return-Path") or ""
        auth_results = extract_header_value(headers, "Authentication-Results") or ""
        received_spf = extract_header_value(headers, "Received-SPF") or ""
        subject = extract_header_value(headers, "Subject") or ""
        body = extract_email_body(payload)
        urls = extract_urls_from_message(payload)

        full_text = f"{subject}\n{body}"
        full_text_lower = full_text.lower()

        sender_domain = extract_sender_domain(from_header)
        sender_local_part, sender_raw_domain = self._extract_sender_parts(from_header)
        reply_domain = extract_sender_domain(reply_to)
        return_path_domain = extract_sender_domain(return_path)

        if from_header and "<" in from_header and ">" in from_header:
            self._set_feature(
                features,
                evidence,
                "sender_has_display_name",
                1.0,
                f"From header uses display-name format: {from_header}",
            )

        if sender_domain:
            self._set_feature(features, evidence, "sender_domain_length", float(len(sender_domain)))
            self._set_feature(
                features,
                evidence,
                "sender_domain_entropy",
                self._entropy(sender_domain),
                f"Sender domain entropy for {sender_domain}",
            )
            self._set_feature(
                features,
                evidence,
                "sender_domain_digit_ratio",
                self._digit_ratio(sender_domain),
                f"Sender domain contains digits: {sender_domain}",
            )
            self._set_feature(
                features,
                evidence,
                "sender_domain_hyphen_count",
                float(sender_domain.count("-")),
                f"Sender domain hyphen count: {sender_domain.count('-')}",
            )
        elif sender_raw_domain:
            self._set_feature(features, evidence, "sender_domain_length", float(len(sender_raw_domain)))

        if sender_local_part:
            local_digit_ratio = self._digit_ratio(sender_local_part)
            self._set_feature(
                features,
                evidence,
                "sender_localpart_digit_ratio",
                local_digit_ratio,
                f"Sender local-part contains digits: {sender_local_part}",
            )
            suspicious_local = (
                local_digit_ratio > 0.35
                or len(sender_local_part) > 18
                or bool(re.search(r"\d{4,}", sender_local_part))
            )
            if suspicious_local:
                self._set_feature(
                    features,
                    evidence,
                    "sender_localpart_suspicious",
                    1.0,
                    f"Suspicious sender local-part: {sender_local_part}",
                )

        if sender_domain and reply_domain and sender_domain != reply_domain:
            self._set_feature(
                features,
                evidence,
                "reply_to_mismatch",
                1.0,
                f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})",
            )

        if sender_domain and return_path_domain and sender_domain != return_path_domain:
            self._set_feature(
                features,
                evidence,
                "return_path_mismatch",
                1.0,
                f"Return-Path domain ({return_path_domain}) differs from sender domain ({sender_domain})",
            )

        auth_blob = f"{auth_results} {received_spf}".lower()
        if re.search(r"\bspf=(?:fail|softfail|none|neutral)\b", auth_blob):
            self._set_feature(
                features,
                evidence,
                "auth_spf_fail",
                1.0,
                f"SPF signal indicates failure: {auth_results or received_spf}",
            )
        if re.search(r"\bdkim=(?:fail|none|temperror|permerror)\b", auth_blob):
            self._set_feature(
                features,
                evidence,
                "auth_dkim_fail",
                1.0,
                f"DKIM signal indicates failure: {auth_results}",
            )
        if re.search(r"\bdmarc=(?:fail|none|temperror|permerror)\b", auth_blob):
            self._set_feature(
                features,
                evidence,
                "auth_dmarc_fail",
                1.0,
                f"DMARC signal indicates failure: {auth_results}",
            )

        received_chain = self._count_header_values(headers, "Received")
        self._set_feature(features, evidence, "delivery_received_chain_count", float(received_chain))

        url_domains = self._populate_url_features(urls, features, evidence)
        sender_brand_domain = sender_domain or normalize_domain(sender_raw_domain)
        self._populate_brand_features(sender_brand_domain, url_domains, features, evidence)
        self._populate_language_features(subject, full_text, full_text_lower, features, evidence)
        self._populate_guardrail_support_features(features, evidence)

        return FeatureExtractionResult(features=features, evidence=evidence)

    def _populate_url_features(
        self,
        urls: List[str],
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
    ) -> List[str]:
        if not urls:
            return []

        self._set_feature(features, evidence, "url_count", float(len(urls)), f"Email contains {len(urls)} URL(s)")

        ip_count = 0
        punycode_count = 0
        obfuscated_count = 0
        suspicious_tld_count = 0
        shortener_count = 0
        https_count = 0
        max_len = 0.0
        max_subdomain_depth = 0.0
        max_entropy = 0.0
        max_digit_ratio = 0.0
        normalized_domains: List[str] = []

        for url in urls:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            normalized_domain = extract_domain_from_url(url)
            if normalized_domain:
                normalized_domains.append(normalized_domain)
            if parsed.scheme == "https":
                https_count += 1
            if hostname in SHORTENER_DOMAINS:
                shortener_count += 1
                self._append_evidence(evidence, "url_shortener_count", f"URL shortener used: {hostname}")
            if "xn--" in hostname:
                punycode_count += 1
                self._append_evidence(evidence, "url_punycode_count", f"Punycode hostname used: {hostname}")
            if is_ip_address(hostname):
                ip_count += 1
                self._append_evidence(evidence, "url_ip_count", f"IP-based URL used: {url}")
            tld = hostname.split(".")[-1] if hostname else ""
            if tld in SUSPICIOUS_TLDS:
                suspicious_tld_count += 1
                self._append_evidence(
                    evidence,
                    "url_suspicious_tld_count",
                    f"Potentially risky TLD '.{tld}' in URL: {url}",
                )

            has_obfuscation = (
                "@" in url
                or "%" in url
                or "0x" in url.lower()
                or bool(re.search(r"%[0-9a-fA-F]{2}", url))
            )
            if has_obfuscation:
                obfuscated_count += 1
                self._append_evidence(evidence, "url_obfuscated_count", f"Obfuscated URL detected: {url}")

            if hostname:
                max_subdomain_depth = max(max_subdomain_depth, float(max(0, hostname.count(".") - 1)))
                max_entropy = max(max_entropy, self._entropy(hostname))
                max_digit_ratio = max(max_digit_ratio, self._digit_ratio(hostname))
            max_len = max(max_len, float(len(url)))

        self._set_feature(features, evidence, "url_ip_count", float(ip_count))
        self._set_feature(features, evidence, "url_punycode_count", float(punycode_count))
        self._set_feature(features, evidence, "url_obfuscated_count", float(obfuscated_count))
        self._set_feature(features, evidence, "url_suspicious_tld_count", float(suspicious_tld_count))
        self._set_feature(features, evidence, "url_shortener_count", float(shortener_count))
        self._set_feature(features, evidence, "url_https_ratio", https_count / max(len(urls), 1))
        self._set_feature(features, evidence, "url_max_length", max_len)
        self._set_feature(features, evidence, "url_max_subdomain_depth", max_subdomain_depth)
        self._set_feature(features, evidence, "url_max_entropy", max_entropy)
        self._set_feature(features, evidence, "url_max_digit_ratio", max_digit_ratio)
        return normalized_domains

    def _populate_brand_features(
        self,
        sender_domain: Optional[str],
        url_domains: List[str],
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
    ) -> None:
        sender_root = extract_domain_root(sender_domain)
        sender_norm, sender_brand, _sender_raw = self.brand_resolver.min_distance(sender_root)
        self._set_feature(features, evidence, "sender_brand_min_distance", sender_norm)

        sender_typosquat = False
        if sender_root:
            sender_typosquat, matched_brand, raw_distance, norm_distance = self.brand_resolver.is_typosquat(sender_root)
            if sender_typosquat:
                self._set_feature(
                    features,
                    evidence,
                    "sender_brand_typosquat_flag",
                    1.0,
                    (
                        f"Sender domain root '{sender_root}' is similar to protected brand "
                        f"'{matched_brand}' (distance={raw_distance}, norm={norm_distance:.3f})"
                    ),
                )
                sender_brand = matched_brand
                sender_norm = norm_distance
            elif sender_root in self.brand_resolver.brands:
                sender_brand = sender_root

        url_min_norm = 1.0
        url_typosquat = False
        url_brand_candidates = set()

        for domain in url_domains:
            root = extract_domain_root(domain)
            if not root:
                continue
            norm, nearest_brand, raw_distance = self.brand_resolver.min_distance(root)
            url_min_norm = min(url_min_norm, norm)
            if root in self.brand_resolver.brands:
                url_brand_candidates.add(root)
            elif nearest_brand:
                is_typosquat, matched_brand, match_raw, match_norm = self.brand_resolver.is_typosquat(root)
                if is_typosquat:
                    url_typosquat = True
                    url_brand_candidates.add(matched_brand)
                    self._append_evidence(
                        evidence,
                        "url_brand_typosquat_flag",
                        (
                            f"URL domain root '{root}' is similar to protected brand "
                            f"'{matched_brand}' (distance={match_raw}, norm={match_norm:.3f})"
                        ),
                    )
                else:
                    _ = raw_distance

        self._set_feature(features, evidence, "url_brand_min_distance", url_min_norm)
        if url_typosquat:
            self._set_feature(features, evidence, "url_brand_typosquat_flag", 1.0)

        if sender_brand and url_brand_candidates and sender_brand not in url_brand_candidates:
            self._set_feature(
                features,
                evidence,
                "sender_url_brand_mismatch_flag",
                1.0,
                (
                    f"Sender appears related to '{sender_brand}', but URL brand signals point to "
                    f"{', '.join(sorted(url_brand_candidates))}"
                ),
            )

    def _populate_guardrail_support_features(
        self,
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
    ) -> None:
        credential_plus_link = float(
            features.get("language_credential_terms_count", 0.0) > 0
            and features.get("url_count", 0.0) > 0
        )
        if credential_plus_link:
            self._set_feature(
                features,
                evidence,
                "credential_plus_link_flag",
                1.0,
                "Credential request language appears together with one or more URLs",
            )
        else:
            self._set_feature(features, evidence, "credential_plus_link_flag", 0.0)

    def _populate_language_features(
        self,
        subject: str,
        full_text: str,
        full_text_lower: str,
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
    ) -> None:
        urgent_count = self._count_terms(full_text_lower, URGENT_TERMS)
        creds_count = self._count_terms(full_text_lower, CREDS_TERMS)
        threat_count = self._count_terms(full_text_lower, THREAT_TERMS)

        if urgent_count > 0:
            self._append_evidence(evidence, "language_urgent_terms_count", f"Urgency terms found in message: {urgent_count}")
        if creds_count > 0:
            self._append_evidence(
                evidence,
                "language_credential_terms_count",
                f"Credential/payment terms found in message: {creds_count}",
            )
        if threat_count > 0:
            self._append_evidence(evidence, "language_threat_terms_count", f"Threat terms found in message: {threat_count}")

        self._set_feature(features, evidence, "language_urgent_terms_count", float(urgent_count))
        self._set_feature(features, evidence, "language_credential_terms_count", float(creds_count))
        self._set_feature(features, evidence, "language_threat_terms_count", float(threat_count))

        subject_lower = subject.lower()
        has_urgent_subject = float(any(term in subject_lower for term in URGENT_TERMS))
        if has_urgent_subject:
            self._append_evidence(evidence, "subject_has_urgent", f"Urgency found in subject: {subject}")
        self._set_feature(features, evidence, "subject_has_urgent", has_urgent_subject)

        letters = [ch for ch in subject if ch.isalpha()]
        caps_ratio = (
            sum(1 for ch in letters if ch.isupper()) / len(letters)
            if letters
            else 0.0
        )
        self._set_feature(features, evidence, "subject_all_caps_ratio", caps_ratio)
        self._set_feature(features, evidence, "subject_exclamation_count", float(subject.count("!")))
        self._set_feature(features, evidence, "content_exclamation_count", float(full_text.count("!")))

        text_length = len(full_text)
        non_ascii_ratio = (
            len(_NON_ASCII_RE.findall(full_text)) / text_length
            if text_length > 0
            else 0.0
        )
        self._set_feature(features, evidence, "content_non_ascii_ratio", non_ascii_ratio)
        self._set_feature(features, evidence, "content_form_tag_count", float(len(re.findall(r"<form\b", full_text_lower))))
        self._set_feature(features, evidence, "content_text_length", float(text_length))

    @staticmethod
    def _count_terms(text: str, terms: tuple[str, ...]) -> int:
        count = 0
        for term in terms:
            count += len(re.findall(rf"\b{re.escape(term)}\b", text))
        return count

    @staticmethod
    def _count_header_values(headers: List, name: str) -> int:
        return sum(1 for header in headers if (header.name or "").lower() == name.lower())

    @staticmethod
    def _extract_sender_parts(from_header: str) -> tuple[Optional[str], Optional[str]]:
        match = _EMAIL_RE.search(from_header or "")
        if not match:
            return None, None
        local_part = (match.group(1) or "").lower()
        domain = (match.group(2) or "").lower().strip(".")
        return local_part, domain

    @staticmethod
    def _digit_ratio(value: str) -> float:
        if not value:
            return 0.0
        digits = sum(1 for ch in value if ch.isdigit())
        return digits / len(value)

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        length = len(value)
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def _append_evidence(evidence: Dict[str, List[str]], key: str, text: str) -> None:
        evidence.setdefault(key, []).append(text)

    def _set_feature(
        self,
        features: Dict[str, float],
        evidence: Dict[str, List[str]],
        key: str,
        value: float,
        detail: Optional[str] = None,
    ) -> None:
        features[key] = float(value)
        if detail and value:
            self._append_evidence(evidence, key, detail)
