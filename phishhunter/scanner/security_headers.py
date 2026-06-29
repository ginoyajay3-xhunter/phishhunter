"""Security headers scanner — checks for presence of common HTTP security
headers (CSP, HSTS, X-Frame-Options, etc.) that protect against common
web attacks like clickjacking, XSS, and protocol downgrade.
"""
import httpx

from config import logger

log = logger.getChild("security_headers")

# header_name: (display_name, severity_if_missing)
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS (Strict-Transport-Security)", "high"),
    "content-security-policy": ("Content-Security-Policy (CSP)", "high"),
    "x-frame-options": ("X-Frame-Options", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "medium"),
    "referrer-policy": ("Referrer-Policy", "low"),
    "permissions-policy": ("Permissions-Policy", "low"),
    "x-xss-protection": ("X-XSS-Protection (legacy)", "low"),
}


async def check_security_headers(url: str, timeout: float = 8.0) -> dict:
    result = {
        "checked": False,
        "headers_present": {},
        "headers_missing": [],
        "all_headers": [],  # ordered list: every tracked header with its status, for table display
        "error": None,
    }

    try:
        # Fix: explicitly follow redirects (httpx's equivalent of requests'
        # allow_redirects=True). A site that redirects http->https or to a
        # canonical hostname would otherwise be scanned at the pre-redirect
        # response, which often lacks headers the final page actually sets.
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                url, headers={"User-Agent": "Mozilla/5.0 (compatible; PhishAnalyzer/1.0)"},
            )
        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        present = {}
        missing = []
        all_headers = []
        for header_key, (display_name, severity) in SECURITY_HEADERS.items():
            if header_key in response_headers:
                value = response_headers[header_key]
                present[display_name] = value
                all_headers.append({
                    "name": display_name, "present": True,
                    "value": value, "severity": severity,
                })
            else:
                missing.append({"name": display_name, "severity": severity})
                all_headers.append({
                    "name": display_name, "present": False,
                    "value": None, "severity": severity,
                })

        result["checked"] = True
        result["headers_present"] = present
        result["headers_missing"] = missing
        result["all_headers"] = all_headers

    except httpx.TimeoutException as e:
        result["error"] = f"Request timed out after {timeout}s"
        log.warning("Security headers check for %s timed out: %s", url, e)
    except httpx.RequestError as e:
        result["error"] = f"Request failed: {e}"
        log.warning("Security headers check for %s failed: %s", url, e, exc_info=True)

    return result
