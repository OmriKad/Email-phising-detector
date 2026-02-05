"""Fetch and cache top domains from Tranco API."""
import httpx
import json
import logging
from datetime import datetime, timedelta, timezone, date
from pathlib import Path
from typing import Set, Optional, Dict, Any
import whois
from .email_parser import normalize_domain, is_ip_address

logger = logging.getLogger(__name__)


class DomainCache:
    """Cache for top domains from Tranco list."""
    
    def __init__(self):
        self.domains: Set[str] = set()
        self.domain_ages: Dict[str, Dict[str, Any]] = {}
        self._initialized = False
        self._cache_ttl = timedelta(days=1)
        self._age_cache_ttl = timedelta(days=7)
        self._cache_path = Path(__file__).resolve().parent.parent / "cache" / "domains.json"
        self._max_domains = 1000
    
    async def initialize(self):
        """Fetch top 100 domains from Tranco and cache them."""
        if self._initialized:
            logger.info("Domain cache already initialized")
            return

        if self._load_cache():
            return
        
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # Fetch the Tranco list (top 1M domains)
                url = "https://tranco-list.eu/top-1m.csv.zip"
                logger.info(f"Fetching Tranco domain list from {url}")
                
                response = await client.get(url)
                response.raise_for_status()
                
                # Extract CSV from ZIP and parse top 100
                import zipfile
                import io
                
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    # Get the first (and only) file in the ZIP
                    csv_filename = z.namelist()[0]
                    with z.open(csv_filename) as csv_file:
                        lines = csv_file.read().decode('utf-8').splitlines()
                        
                        # Parse top N domains (format: rank,domain)
                        for line in lines[:self._max_domains]:
                            parts = line.strip().split(',')
                            if len(parts) >= 2:
                                domain = parts[1]
                                normalized = normalize_domain(domain)
                                if normalized:
                                    self.domains.add(normalized.lower())
                
                self._initialized = True
                logger.info(f"Successfully cached {len(self.domains)} domains")
                self._save_cache()
                
        except Exception as e:
            logger.error(f"Failed to fetch Tranco domains: {e}")
            # Add fallback domains for testing
            self.domains = {
                "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
                "amazon.com", "wikipedia.org", "reddit.com", "linkedin.com", "netflix.com",
                "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com"
            }
            self._initialized = True
            logger.warning(f"Using fallback domains: {len(self.domains)} domains")

    def _load_cache(self) -> bool:
        """Load domains from JSON cache if fresh enough."""
        if not self._cache_path.exists():
            return False

        try:
            raw = self._cache_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            timestamp_str = data.get("timestamp")
            domains = data.get("domains")
            ages = data.get("ages", {})

            if not timestamp_str or not isinstance(domains, list):
                logger.warning("Domain cache file is invalid; ignoring")
                return False

            cache_time = datetime.fromisoformat(timestamp_str)
            if cache_time.tzinfo is None:
                cache_time = cache_time.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age = now - cache_time
            if age > self._cache_ttl:
                logger.info("Domain cache is stale; refreshing from API")
                return False

            self.domains = {
                domain.strip().lower()
                for domain in domains
                if isinstance(domain, str) and domain.strip()
            }
            if self.domains:
                with_dot = sum(1 for d in self.domains if "." in d)
                if with_dot / len(self.domains) < 0.8:
                    logger.info("Domain cache appears to be legacy SLD format; refreshing from API")
                    return False
            if isinstance(ages, dict):
                self.domain_ages = {
                    domain: info
                    for domain, info in ages.items()
                    if isinstance(domain, str) and isinstance(info, dict)
                }
            self._initialized = True
            logger.info(
                f"Loaded {len(self.domains)} domains from cache (age: {age})"
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to read domain cache; ignoring: {e}")
            return False

    def _save_cache(self) -> None:
        """Persist domains to JSON cache with timestamp."""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "domains": sorted(self.domains),
                "ages": self.domain_ages,
            }
            self._cache_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            logger.info(f"Saved domain cache to {self._cache_path}")
        except Exception as e:
            logger.warning(f"Failed to write domain cache: {e}")

    def _is_age_fresh(self, fetched_at: Optional[str]) -> bool:
        if not fetched_at:
            return False
        try:
            fetched_time = datetime.fromisoformat(fetched_at)
            if fetched_time.tzinfo is None:
                fetched_time = fetched_time.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) - fetched_time <= self._age_cache_ttl
        except Exception:
            return False

    def _parse_creation_date(self, creation_value: Any) -> Optional[datetime]:
        if creation_value is None:
            return None

        if isinstance(creation_value, list):
            dates = [d for d in creation_value if isinstance(d, (datetime, date))]
            if not dates:
                return None
            creation_value = min(dates)

        if isinstance(creation_value, date) and not isinstance(creation_value, datetime):
            creation_value = datetime.combine(creation_value, datetime.min.time())

        if isinstance(creation_value, datetime):
            if creation_value.tzinfo is None:
                return creation_value.replace(tzinfo=timezone.utc)
            return creation_value

        return None

    def _fetch_domain_age(self, domain: str) -> Optional[int]:
        if not domain or is_ip_address(domain):
            return None

        try:
            result = whois.whois(domain)
            creation_date = None
            if isinstance(result, dict):
                creation_date = result.get("creation_date")
            else:
                creation_date = getattr(result, "creation_date", None)

            created_at = self._parse_creation_date(creation_date)
            if not created_at:
                return None

            now = datetime.now(timezone.utc)
            age_days = (now - created_at).days
            if age_days < 0:
                return None
            return age_days
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def get_domain_age(self, domain: str) -> Optional[int]:
        """Get cached domain age in days, fetching if needed."""
        normalized = normalize_domain(domain)
        if not normalized:
            return None

        info = self.domain_ages.get(normalized)
        if isinstance(info, dict) and self._is_age_fresh(info.get("fetched_at")):
            return info.get("age_days")

        age_days = self._fetch_domain_age(normalized)
        self.domain_ages[normalized] = {
            "age_days": age_days,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_cache()
        return age_days
    
    def get_domains(self) -> Set[str]:
        """Get cached domain names (registrable domains)."""
        return self.domains
    
    def is_initialized(self) -> bool:
        """Check if cache has been initialized."""
        return self._initialized


# Global domain cache instance
domain_cache = DomainCache()
