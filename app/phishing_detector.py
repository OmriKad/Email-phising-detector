"""Phishing detection logic with weighted scoring."""
import re
import logging
from typing import List, Tuple, Optional
from Levenshtein import distance as levenshtein_distance
from .models import GmailMessage, DetectedIndicator, PhishingDetectionResponse
from .email_parser import (
    extract_header_value,
    extract_sender_domain,
    extract_urls_from_message,
    extract_domain_from_url,
    extract_email_body,
    is_ip_address
)
from .domain_fetcher import domain_cache

logger = logging.getLogger(__name__)

# Weights for different indicators
WEIGHT_SENDER = 0.4
WEIGHT_LINKS = 0.4
WEIGHT_LANGUAGE = 0.2

# Levenshtein distance threshold for typosquatting
TYPOSQUATTING_THRESHOLD = 2

# Domain age threshold (days)
YOUNG_DOMAIN_DAYS = 30

# Scores for young domains
YOUNG_SENDER_SCORE = 0.8
YOUNG_LINK_SCORE = 0.7

# Urgent language patterns
URGENT_PATTERNS = [
    r'\burgent\b',
    r'\bimmediately\b',
    r'\baction required\b',
    r'\bact now\b',
    r'\bverify (your )?account\b',
    r'\bsuspended\b',
    r'\bexpire[ds]?\b',
    r'\bconfirm (your )?identity\b',
    r'\bunusual activity\b',
    r'\bsecurity alert\b'
]


class PhishingDetector:
    """Detect phishing indicators in email messages."""
    
    def __init__(self):
        self.domains = domain_cache.get_domains()
    
    def detect(self, message: GmailMessage) -> PhishingDetectionResponse:
        """Analyze email message for phishing indicators."""
        indicators: List[DetectedIndicator] = []
        score = 0.0
        
        # Check sender domain
        sender_score, sender_indicators = self._check_sender(message)
        score += sender_score * WEIGHT_SENDER
        indicators.extend(sender_indicators)
        
        # Check links
        links_score, link_indicators = self._check_links(message)
        score += links_score * WEIGHT_LINKS
        indicators.extend(link_indicators)
        
        # Check urgent language
        language_score, language_indicators = self._check_urgent_language(message)
        score += language_score * WEIGHT_LANGUAGE
        indicators.extend(language_indicators)
        
        # Classify risk
        classification = self._classify_risk(score)
        
        # Generate summary message
        message_text = self._generate_message(classification, len(indicators))
        
        return PhishingDetectionResponse(
            risk_score=round(score, 3),
            classification=classification,
            indicators=indicators,
            message=message_text
        )
    
    def _check_sender(self, message: GmailMessage) -> Tuple[float, List[DetectedIndicator]]:
        """Check sender domain for spoofing attempts."""
        indicators = []
        
        # Extract sender from headers
        from_header = extract_header_value(message.payload.headers, "From")
        if not from_header:
            return 0.0, indicators
        
        sender_domain = extract_sender_domain(from_header)
        if not sender_domain:
            return 0.0, indicators
        
        # Check if domain is in top list (exact match = safe)
        if sender_domain in self.domains:
            return 0.0, indicators
        
        # Check for typosquatting (Levenshtein distance <= 2)
        for known_domain in self.domains:
            dist = levenshtein_distance(sender_domain, known_domain)
            if dist <= TYPOSQUATTING_THRESHOLD:
                indicators.append(DetectedIndicator(
                    type="spoofed_sender",
                    description=f"Sender domain '{sender_domain}' is similar to '{known_domain}' (typosquatting)",
                    severity="high",
                    details={
                        "sender_domain": sender_domain,
                        "similar_to": known_domain,
                        "levenshtein_distance": dist,
                        "from_header": from_header
                    }
                ))
                return 1.0, indicators  # Maximum score for typosquatting

        # Check domain age for unknown domains
        age_days = domain_cache.get_domain_age(sender_domain)
        if age_days is not None and age_days < YOUNG_DOMAIN_DAYS:
            indicators.append(DetectedIndicator(
                type="young_domain",
                description=(
                    f"Sender domain '{sender_domain}' is newly registered ({age_days} days old)"
                ),
                severity="medium",
                details={
                    "sender_domain": sender_domain,
                    "age_days": age_days,
                    "threshold_days": YOUNG_DOMAIN_DAYS,
                    "from_header": from_header
                }
            ))
            return YOUNG_SENDER_SCORE, indicators
        
        # Unknown domain (not in top 100, not typosquatting)
        indicators.append(DetectedIndicator(
            type="spoofed_sender",
            description=f"Sender domain '{sender_domain}' is not a recognized top domain",
            severity="medium",
            details={
                "sender_domain": sender_domain,
                "from_header": from_header
            }
        ))
        return 0.5, indicators  # Moderate score for unknown domain
    
    def _check_links(self, message: GmailMessage) -> Tuple[float, List[DetectedIndicator]]:
        """Check links in email for suspicious domains."""
        indicators = []
        
        # Extract all URLs
        urls = extract_urls_from_message(message.payload)
        if not urls:
            return 0.0, indicators
        
        max_score = 0.0
        
        for url in urls:
            # Check for IP addresses in URL (suspicious)
            if self._is_ip_address_url(url):
                indicators.append(DetectedIndicator(
                    type="suspicious_link",
                    description=f"URL contains IP address instead of domain name",
                    severity="high",
                    details={"url": url}
                ))
                max_score = max(max_score, 1.0)
                continue
            
            # Extract domain from URL
            domain = extract_domain_from_url(url)
            if not domain:
                continue

            if is_ip_address(domain):
                continue
            
            # Check if domain is in top list (exact match = safe)
            if domain in self.domains:
                continue
            
            # Check for typosquatting
            for known_domain in self.domains:
                dist = levenshtein_distance(domain, known_domain)
                if dist <= TYPOSQUATTING_THRESHOLD:
                    indicators.append(DetectedIndicator(
                        type="suspicious_link",
                        description=f"URL domain '{domain}' is similar to '{known_domain}' (typosquatting)",
                        severity="high",
                        details={
                            "url": url,
                            "domain": domain,
                            "similar_to": known_domain,
                            "levenshtein_distance": dist
                        }
                    ))
                    max_score = max(max_score, 1.0)
                    break
            else:
                # Unknown domain
                indicators.append(DetectedIndicator(
                    type="suspicious_link",
                    description=f"URL contains unknown domain '{domain}'",
                    severity="low",
                    details={
                        "url": url,
                        "domain": domain
                    }
                ))
                max_score = max(max_score, 0.3)

                age_days = domain_cache.get_domain_age(domain)
                if age_days is not None and age_days < YOUNG_DOMAIN_DAYS:
                    indicators.append(DetectedIndicator(
                        type="young_domain",
                        description=(
                            f"URL domain '{domain}' is newly registered ({age_days} days old)"
                        ),
                        severity="medium",
                        details={
                            "url": url,
                            "domain": domain,
                            "age_days": age_days,
                            "threshold_days": YOUNG_DOMAIN_DAYS
                        }
                    ))
                    max_score = max(max_score, YOUNG_LINK_SCORE)
        
        return max_score, indicators
    
    def _check_urgent_language(self, message: GmailMessage) -> Tuple[float, List[DetectedIndicator]]:
        """Check for urgent/pressure language patterns."""
        indicators = []
        
        # Extract email body and subject
        body_text = extract_email_body(message.payload)
        subject = extract_header_value(message.payload.headers, "Subject") or ""
        
        full_text = f"{subject}\n{body_text}".lower()
        
        # Check for urgent patterns
        matches = []
        for pattern in URGENT_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                matches.append(pattern)
        
        if matches:
            # Extract pattern names without regex markers
            pattern_names = [p.replace(r'\b', '').replace('\\b', '') for p in matches[:3]]
            indicators.append(DetectedIndicator(
                type="urgent_language",
                description=f"Email contains urgent/pressure language: {', '.join(pattern_names)}",
                severity="low",
                details={
                    "patterns_matched": len(matches),
                    "examples": matches[:3]
                }
            ))
            # Score based on number of matches (more matches = higher score)
            score = min(1.0, len(matches) * 0.3)
            return score, indicators
        
        return 0.0, indicators
    
    def _is_ip_address_url(self, url: str) -> bool:
        """Check if URL contains an IP address instead of domain."""
        # Match IPv4 addresses in URL
        ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
        return bool(re.match(ip_pattern, url))
    
    def _classify_risk(self, score: float) -> str:
        """Classify risk level based on score."""
        if score < 0.33:
            return "Seems safe"
        elif score <= 0.5:
            return "Few indicators found, need to be cautious"
        else:
            return "Major indicators found!"
    
    def _generate_message(self, classification: str, indicator_count: int) -> str:
        """Generate summary message."""
        if indicator_count == 0:
            return "No phishing indicators detected. Email appears safe."
        elif classification == "Seems safe":
            return f"Email appears mostly safe, but {indicator_count} minor indicator(s) detected."
        elif classification == "Few indicators found, need to be cautious":
            return f"⚠️ Caution advised: {indicator_count} phishing indicator(s) detected."
        else:
            return f"🚨 Warning: {indicator_count} major phishing indicator(s) detected! Exercise extreme caution."
