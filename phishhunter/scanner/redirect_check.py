"""Redirect chain analysis — follows HTTP redirects to see where a URL
ultimately lands. Phishing links are often shortened or chained through
multiple hops to obscure the final destination.
"""
import httpx
from urllib.parse import urlparse

from config import logger

log = logger.getChild("redirect_check")


async def analyze_redirect_chain(url: str, timeout: float = 8.0, max_hops: int = 10) -> dict:
    result = {
        "checked": False,
        "hop_count": 0,
        "chain": [],
        "final_url": None,
        "domain_changed": False,
        "error": None,
    }

    try:
        original_domain = urlparse(url).netloc.lower()

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                url, headers={"User-Agent": "Mozilla/5.0 (compatible; PhishAnalyzer/1.0)"},
            )

        chain = [str(r.url) for r in resp.history] + [str(resp.url)]
        final_domain = urlparse(str(resp.url)).netloc.lower()

        result["checked"] = True
        result["hop_count"] = len(resp.history)
        result["chain"] = chain[:max_hops]
        result["final_url"] = str(resp.url)
        result["domain_changed"] = original_domain != final_domain and original_domain != ""

    except httpx.TimeoutException as e:
        result["error"] = f"Request timed out after {timeout}s"
        log.warning("Redirect check for %s timed out: %s", url, e)
    except httpx.RequestError as e:
        result["error"] = f"Request failed: {e}"
        log.warning("Redirect check for %s failed: %s", url, e, exc_info=True)

    return result
