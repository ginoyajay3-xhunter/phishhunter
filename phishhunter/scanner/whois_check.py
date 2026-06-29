"""WHOIS lookup module — checks domain registration age and registrar.
Newly registered domains are a strong phishing signal.
"""
import time
from datetime import datetime, timezone

try:
    import whois  # python-whois package
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def _query_whois(domain: str, retries: int = 2, delay: float = 1.5):
    """Single WHOIS query with a couple of retries — WHOIS servers are
    public infrastructure that occasionally rate-limit or respond slowly.
    A single attempt produces visible run-to-run inconsistency (registrar
    showing up on one scan and "Unknown" on the next for the same domain);
    a short retry makes results far more stable without adding much delay.
    """
    if not WHOIS_AVAILABLE:
        return None

    last_error = None
    for attempt in range(retries + 1):
        try:
            return whois.whois(domain)
        except Exception as e:
            last_error = e
            if attempt < retries:
                time.sleep(delay)
    return None


def whois_check_sync(domain: str) -> dict:
    """Single combined WHOIS lookup — previously this module queried WHOIS
    twice (once for age, once for registrar), which doubled the chance of
    hitting a slow/rate-limited response and caused the same domain to
    show different registrar values across consecutive scans.

    This stays synchronous on purpose: python-whois talks raw sockets to
    WHOIS servers (port 43) and has no async variant. The caller is
    expected to run this via asyncio.to_thread() so it doesn't block the
    event loop while still letting it run in parallel with the other
    (genuinely async) checks.
    """
    w = _query_whois(domain)

    age_days = None
    registrar = None
    expiration_date = None

    if w is not None:
        try:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date is not None:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation_date).days
        except Exception:
            pass

        try:
            registrar = w.registrar
        except Exception:
            pass

        try:
            exp = w.expiration_date
            if isinstance(exp, list):
                exp = exp[0]
            if exp:
                expiration_date = str(exp)
        except Exception:
            pass

    return {
        "domain_age_days": age_days,
        "is_newly_registered": age_days is not None and age_days < 90,
        "lookup_succeeded": w is not None,
        "registrar": registrar,
        "expiration_date": expiration_date,
    }
