import re
import socket
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update",
    "bank", "paypal", "signin", "confirm", "ebay",
    "webscr", "support", "billing", "password"
]


def is_ip_address(domain: str) -> bool:
    """Check if domain is a raw IP address (common phishing trick)."""
    try:
        socket.inet_aton(domain)
        return True
    except (socket.error, OSError):
        return False


def has_punycode(domain: str) -> bool:
    """Detect punycode / homograph domains (xn--)."""
    return "xn--" in domain.lower()


def analyze_url(url: str) -> dict:
    """Extract structural and lexical features from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc.lower().split(":")[0]  # strip port if present

    features = {
        "url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "path": parsed.path,
        "length": len(url),
        "contains_at": "@" in url,
        "subdomain_count": domain.count("."),
        "is_ip": is_ip_address(domain),
        "has_hyphen_in_domain": "-" in domain,
        "has_punycode": has_punycode(domain),
        "uses_https": url.lower().startswith("https://"),
        "matched_keywords": [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()],
        "has_port": parsed.port is not None,
    }
    return features
