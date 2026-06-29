"""Wayback Machine lookup — checks how long a domain has been archived
on archive.org. Cross-checks WHOIS-reported age with independent evidence;
a domain claiming to be old but with no archive history is worth a second look.
"""
import httpx

from config import logger

log = logger.getChild("wayback")


async def check_wayback_history(domain: str, timeout: float = 8.0) -> dict:
    result = {
        "first_seen": None,
        "total_snapshots": None,
        "checked": False,
        "error": None,
    }

    # Fix: archive.org's CDX API redirects http:// -> https:// on every
    # call, which silently adds a round trip and occasionally drops the
    # request under load. Querying https:// directly avoids the redirect.
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "limit": "1",
        "sort": "ascending",
        "filter": "statuscode:200",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                cdx_url, params=params,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PhishAnalyzer/1.0)"},
            )

        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:  # first row is the header
                timestamp = data[1][1]  # format: YYYYMMDDhhmmss
                result["first_seen"] = (
                    f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
                )
                result["checked"] = True
            else:
                result["checked"] = True  # request succeeded, just no snapshots
        else:
            result["error"] = f"archive.org returned HTTP {resp.status_code}"
            log.warning("Wayback lookup for %s failed: HTTP %s", domain, resp.status_code)

    except httpx.TimeoutException as e:
        result["error"] = f"Request timed out after {timeout}s"
        log.warning("Wayback lookup for %s timed out: %s", domain, e)
    except httpx.RequestError as e:
        # Fix: log the actual underlying exception (connection refused, DNS
        # failure, TLS error, etc.) instead of just swallowing it — this is
        # what "actual error log karo" in the request was asking for.
        result["error"] = f"Request failed: {e}"
        log.warning("Wayback lookup for %s failed: %s", domain, e, exc_info=True)
    except ValueError as e:
        result["error"] = f"Invalid response from archive.org: {e}"
        log.warning("Wayback lookup for %s returned unparseable data: %s", domain, e)

    return result
