"""IOC (Indicator of Compromise) checker — looks up reputation for an IP
address, domain, or file hash using VirusTotal. This is a standalone
lookup separate from the main URL scan, for when you already have an
indicator (from a SIEM alert, email header, etc.) and want a quick check.
"""
import re
import httpx

from config import VT_API_KEY, VT_BASE_URL, logger

log = logger.getChild("ioc_checker")


def _classify_ioc(value: str) -> str:
    value = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "hash_md5"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "hash_sha256"
    if "." in value and " " not in value:
        return "domain"
    return "unknown"


async def check_ioc(value: str, timeout: float = 15.0) -> dict:
    value = value.strip()
    ioc_type = _classify_ioc(value)

    result = {
        "indicator": value,
        "type": ioc_type,
        "checked": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "error": None,
    }

    if ioc_type == "unknown":
        result["error"] = "Could not classify indicator as IP, domain, or file hash"
        return result

    if not VT_API_KEY:
        result["error"] = "No VirusTotal API key configured. Set the VT_API_KEY environment variable."
        return result

    headers = {"x-apikey": VT_API_KEY}

    endpoint_map = {
        "ip": f"{VT_BASE_URL}/ip_addresses/{value}",
        "domain": f"{VT_BASE_URL}/domains/{value}",
        "hash_md5": f"{VT_BASE_URL}/files/{value}",
        "hash_sha1": f"{VT_BASE_URL}/files/{value}",
        "hash_sha256": f"{VT_BASE_URL}/files/{value}",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(endpoint_map[ioc_type], headers=headers)

        if resp.status_code == 404:
            result["checked"] = True
            result["error"] = "Not found in VirusTotal's database"
            return result

        if resp.status_code != 200:
            result["error"] = f"VirusTotal returned HTTP {resp.status_code}"
            return result

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        result["checked"] = True
        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)

    except httpx.TimeoutException as e:
        result["error"] = f"Request timed out after {timeout}s"
        log.warning("IOC check for %s timed out: %s", value, e)
    except httpx.RequestError as e:
        result["error"] = f"Request failed: {e}"
        log.warning("IOC check for %s failed: %s", value, e, exc_info=True)

    return result
