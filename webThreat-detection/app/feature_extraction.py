"""
Feature extraction module for phishing detection.
Extracts lexical/URL-based features, SSL certificate validity, WHOIS domain age, and redirect count.
Optimized for high-speed sub-second execution with parallel lookups and caching.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import socket
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlparse

try:
    import whois
except ImportError:
    whois = None

try:
    import requests
except ImportError:
    requests = None

# Persistent thread pool for fast parallel network I/O
_EXECUTOR = ThreadPoolExecutor(max_workers=16)


def is_ip_address(hostname: Optional[str]) -> int:
    """
    Check if the hostname is an IPv4 or IPv6 address instead of a domain name.
    Returns 1 if IP address, 0 otherwise.
    """
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


@lru_cache(maxsize=4096)
def check_ssl_validity(hostname: Optional[str], port: int = 443, timeout: float = 0.6) -> int:
    """
    Check if the host has a valid SSL certificate using socket and ssl modules.
    Cached and bounded by a strict 0.6s timeout.
    Returns 1 if valid, 0 if invalid or on any error.
    """
    if not hostname or is_ip_address(hostname):
        return 0

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return 1 if cert else 0
    except Exception:
        return 0


@lru_cache(maxsize=4096)
def _raw_whois_lookup(hostname: str) -> int:
    """Internal helper to perform WHOIS query."""
    if whois is None:
        return -1
    try:
        w = whois.whois(hostname)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, str):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    creation_date = datetime.strptime(creation_date, fmt)
                    break
                except ValueError:
                    pass

        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            age_days = (now - creation_date).days
            return max(0, age_days)
    except Exception:
        return -1
    return -1


@lru_cache(maxsize=4096)
def get_domain_age_days(hostname: Optional[str]) -> int:
    """
    Calculate domain age in days with caching and strict timeout protection.
    Returns domain age in days, or -1 if lookup fails or domain age is unavailable.
    """
    if not hostname or is_ip_address(hostname) or whois is None:
        return -1

    # Run in thread with strict 0.6s timeout so WHOIS never hangs the pipeline
    future = _EXECUTOR.submit(_raw_whois_lookup, hostname)
    try:
        return future.result(timeout=0.6)
    except Exception:
        return -1


def get_num_redirects(url: str, timeout: float = 0.5) -> int:
    """
    Determine number of HTTP redirects using fast HEAD requests.
    Returns redirect count, or 0 if request fails or times out.
    """
    if requests is None:
        return 0

    target_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        # Use HEAD request instead of full GET for 10x faster header-only redirect inspection
        response = requests.head(target_url, timeout=timeout, allow_redirects=True, headers=headers)
        return len(response.history)
    except Exception:
        return 0


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract comprehensive phishing detection features in parallel:
    - URL length
    - Number of dots
    - Presence of '@' symbol
    - Presence of IP address instead of domain
    - Use of HTTPS
    - SSL certificate validity (parallel)
    - Domain age in days (parallel, cached)
    - Number of redirects (parallel, fast HEAD)
    """
    normalized_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()
    except Exception:
        hostname = ""
        scheme = ""

    # 1. Instant lexical features (< 1ms)
    url_length = len(url)
    num_dots = url.count(".")
    has_at_symbol = 1 if "@" in url else 0
    ip_present = is_ip_address(hostname)
    use_https = 1 if (scheme == "https" or url.startswith("https://")) else 0

    # 2. Parallel network lookups for sub-second total response
    future_ssl = _EXECUTOR.submit(check_ssl_validity, hostname, 443, 0.5) if use_https else None
    future_whois = _EXECUTOR.submit(get_domain_age_days, hostname)
    future_red = _EXECUTOR.submit(get_num_redirects, url, 0.5)

    try:
        ssl_valid = future_ssl.result(timeout=0.6) if future_ssl else 0
    except Exception:
        ssl_valid = 1 if use_https else 0

    try:
        domain_age_days = future_whois.result(timeout=0.6)
    except Exception:
        domain_age_days = -1

    try:
        num_redirects = future_red.result(timeout=0.6)
    except Exception:
        num_redirects = 0

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "has_at_symbol": has_at_symbol,
        "is_ip_address": ip_present,
        "use_https": use_https,
        "ssl_valid": ssl_valid,
        "domain_age_days": domain_age_days,
        "num_redirects": num_redirects,
    }


# Backwards compatibility alias
extract_all_features = extract_features
