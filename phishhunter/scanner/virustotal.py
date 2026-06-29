"""VirusTotal v3 API integration for URL reputation checks.

Requires VT_API_KEY to be set as an environment variable.
"""
import base64
import asyncio
import httpx

from config import VT_API_KEY, VT_BASE_URL, logger

log = logger.getChild("virustotal")


def _url_to_id(url: str) -> str:
    """VirusTotal identifies URLs by a base64 (no padding) of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def submit_and_check_url(url: str, timeout: float = 15.0) -> dict:
    """Submit a URL to VirusTotal and retrieve its analysis report.

    Returns a dict with reputation stats, or an error message if the
    API key is missing/invalid or the request fails.
    """
    if not VT_API_KEY:
        return {
            "error": "No VirusTotal API key configured. Set the VT_API_KEY environment variable.",
            "checked": False,
        }

    headers = {"x-apikey": VT_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            url_id = _url_to_id(url)
            report_resp = await client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

            if report_resp.status_code == 200:
                data = report_resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "checked": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                }

            # If not found, submit it for a fresh scan
            submit_resp = await client.post(
                f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}
            )

            if submit_resp.status_code not in (200, 201):
                log.warning("VirusTotal submission for %s failed: HTTP %s", url, submit_resp.status_code)
                return {
                    "error": f"VirusTotal submission failed: HTTP {submit_resp.status_code}",
                    "checked": False,
                }

            analysis_id = submit_resp.json().get("data", {}).get("id")

            # Poll briefly for results (VT analysis is async on their side)
            for _ in range(3):
                await asyncio.sleep(2)
                poll_resp = await client.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
                if poll_resp.status_code == 200:
                    attrs = poll_resp.json().get("data", {}).get("attributes", {})
                    if attrs.get("status") == "completed":
                        stats = attrs.get("stats", {})
                        return {
                            "checked": True,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                        }

        return {
            "checked": False,
            "error": "Analysis still pending — try checking again in a moment.",
        }

    except httpx.TimeoutException as e:
        log.warning("VirusTotal check for %s timed out: %s", url, e)
        return {"error": f"Request timed out after {timeout}s", "checked": False}
    except httpx.RequestError as e:
        log.warning("VirusTotal check for %s failed: %s", url, e, exc_info=True)
        return {"error": f"Request to VirusTotal failed: {e}", "checked": False}
