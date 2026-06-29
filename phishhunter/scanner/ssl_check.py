"""SSL/TLS analyzer — checks certificate validity, TLS protocol version,
cipher strength, and days remaining until expiry."""
import ssl
import socket
from datetime import datetime, timezone

# TLS versions considered weak/deprecated — their presence is a red flag.
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cipher suites considered weak (export-grade, RC4, NULL, DES, etc.)
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "NULL", "EXPORT", "MD5", "anon"]


def _parse_cert_date(date_str: str):
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def check_ssl_sync(domain: str, timeout: float = 5.0) -> dict:
    result = {
        "has_valid_cert": False,
        "issuer": None,
        "expires": None,
        "days_until_expiry": None,
        "is_expiring_soon": False,
        "is_expired": False,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                result["has_valid_cert"] = True
                result["issuer"] = issuer_parts.get("organizationName", "Unknown")
                result["expires"] = cert.get("notAfter")

                expiry_date = _parse_cert_date(cert.get("notAfter", ""))
                if expiry_date:
                    days_left = (expiry_date - datetime.now(timezone.utc)).days
                    result["days_until_expiry"] = days_left
                    result["is_expired"] = days_left < 0
                    result["is_expiring_soon"] = 0 <= days_left <= 14
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_tls_sync(domain: str, timeout: float = 5.0) -> dict:
    """Inspects the negotiated TLS protocol version and cipher suite.

    Note: Python's ssl module negotiates the *best* protocol both sides
    support by default — it doesn't enumerate every protocol the server
    is willing to accept. This reports what was actually negotiated, which
    is a reasonable proxy: if the negotiated protocol is already weak,
    the server is misconfigured at best.
    """
    result = {
        "checked": False,
        "tls_version": None,
        "cipher_name": None,
        "cipher_bits": None,
        "is_weak_protocol": False,
        "is_weak_cipher": False,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                cipher_name, _, cipher_bits = ssock.cipher()

                result["checked"] = True
                result["tls_version"] = version
                result["cipher_name"] = cipher_name
                result["cipher_bits"] = cipher_bits
                result["is_weak_protocol"] = version in WEAK_TLS_VERSIONS
                result["is_weak_cipher"] = any(
                    weak in cipher_name.upper() for weak in WEAK_CIPHER_KEYWORDS
                )
    except Exception as e:
        result["error"] = str(e)

    return result

