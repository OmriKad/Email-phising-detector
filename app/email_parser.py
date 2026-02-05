"""Utilities for parsing Gmail message structure."""
import re
import base64
import logging
import ipaddress
from typing import List, Optional
from urllib.parse import urlparse
import tldextract
from .models import MessagePart, Header

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

logger = logging.getLogger(__name__)

_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


def is_ip_address(hostname: Optional[str]) -> bool:
    """Return True if the hostname is a valid IP address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def normalize_domain(hostname: Optional[str]) -> Optional[str]:
    """Normalize to registrable domain using PSL (e.g., sub.a.co.uk -> a.co.uk)."""
    if not hostname:
        return None

    cleaned = hostname.strip().lower().rstrip(".")
    if not cleaned:
        return None

    try:
        cleaned = cleaned.encode("idna").decode("ascii")
    except Exception:
        pass

    if is_ip_address(cleaned):
        return cleaned

    extracted = _DOMAIN_EXTRACTOR(cleaned)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return cleaned


def extract_header_value(headers: Optional[List[Header]], header_name: str) -> Optional[str]:
    """Extract value of a specific header by name."""
    if not headers:
        return None
    
    for header in headers:
        if header.name.lower() == header_name.lower():
            return header.value
    
    return None


def extract_sender_domain(from_header: Optional[str]) -> Optional[str]:
    """Extract domain from From header email address."""
    if not from_header:
        return None
    
    # Extract email address from "Name <email@domain.com>" format
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', from_header)
    if email_match:
        full_domain = email_match.group(1)
        return normalize_domain(full_domain)
    
    return None


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from text content."""
    # Match http(s):// URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    return urls


def extract_urls_from_html(html: str) -> List[str]:
    """Extract all URLs from HTML content using BeautifulSoup.
    
    Extracts URLs from:
    - <a href="..."> tags
    - <img src="..."> tags
    - <iframe src="..."> tags
    
    Falls back to regex if BeautifulSoup is unavailable or parsing fails.
    """
    urls = []
    
    if not html:
        return urls
    
    # Try BeautifulSoup parsing first
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract from <a href>
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    urls.append(href)
            
            # Extract from <img src>
            for img in soup.find_all('img', src=True):
                src = img['src']
                if src.startswith(('http://', 'https://')):
                    urls.append(src)
            
            # Extract from <iframe src>
            for iframe in soup.find_all('iframe', src=True):
                src = iframe['src']
                if src.startswith(('http://', 'https://')):
                    urls.append(src)
            
            logger.debug(f"Extracted {len(urls)} URLs from HTML using BeautifulSoup")
            return urls
            
        except Exception as e:
            logger.warning(f"Failed to parse HTML with BeautifulSoup: {e}, falling back to regex")
    
    # Fallback to regex extraction
    urls = extract_urls_from_text(html)
    logger.debug(f"Extracted {len(urls)} URLs from HTML using regex fallback")
    return urls


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract normalized registrable domain from URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Return None if no hostname
        if not hostname:
            return None
        
        return normalize_domain(hostname)
    except Exception:
        return None


def decode_body_data(data: Optional[str]) -> str:
    """Decode base64url encoded body data."""
    if not data:
        return ""
    
    try:
        # Gmail uses base64url encoding (RFC 4648)
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters with standard base64 characters
        data = data.replace('-', '+').replace('_', '/')
        
        decoded_bytes = base64.b64decode(data)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return ""


def extract_email_body(message_part: MessagePart) -> str:
    """Extract email body text from MessagePart structure."""
    body_text = ""
    
    # If this part has body data, decode it
    if message_part.body and message_part.body.data:
        decoded = decode_body_data(message_part.body.data)
        body_text += decoded + "\n"
    
    # Recursively extract from nested parts
    if message_part.parts:
        for part in message_part.parts:
            body_text += extract_email_body(part) + "\n"
    
    return body_text


def extract_urls_from_message(message_part: MessagePart) -> List[str]:
    """Extract all URLs from a Gmail message.
    
    Handles both plain text and HTML content. Uses BeautifulSoup for HTML
    to properly extract URLs from links, images, and iframes.
    """
    urls = []
    
    # Helper function to extract URLs based on MIME type
    def extract_from_part(part: MessagePart):
        nonlocal urls
        
        if part.body and part.body.data:
            decoded = decode_body_data(part.body.data)
            
            # Check MIME type to determine extraction method
            mime_type = part.mimeType or ''
            
            if 'html' in mime_type.lower():
                # Use HTML parser for HTML content
                urls.extend(extract_urls_from_html(decoded))
            else:
                # Use regex for plain text
                urls.extend(extract_urls_from_text(decoded))
        
        # Recursively process nested parts
        if part.parts:
            for nested_part in part.parts:
                extract_from_part(nested_part)
    
    extract_from_part(message_part)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls
