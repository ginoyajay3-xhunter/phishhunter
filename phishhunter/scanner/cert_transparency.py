"""Certificate Transparency monitor — queries crt.sh for all certificates
ever issued for a domain. Surfaces subdomains that may not be publicly
linked (useful for spotting shadow/staging infrastructure) and recent
certificate issuance activity.
"""
import asyncio
import httpx
from datetime import datetime, timezone

from config import logger

log = logger.getChild("cert_transparency")


async def check_certificate_transparency(domain: str, timeout: float = 12.0, retries: int = 2) -> dict:
    """crt.sh is a free public service that occasionally rate-limits or
    times out under load. A single failed attempt previously showed up as
    "N/A" for the whole section even when the domain itself is fine — that
    looks like missing/inconsistent data rather than a transient hiccup.
    A couple of retries with a short backoff makes results far more
    consistent across repeated scans of the same domain.
    """
    result = {
        "checked": False,
        "total_certificates": 0,
        "unique_subdomains": [],
        "recent_certificates": [],
        "error": None,
    }

    last_error = None
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries + 1):
            try:
                resp = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; PhishAnalyzer/1.0)"},
                )

                if resp.status_code != 200:
                    last_error = f"crt.sh returned HTTP {resp.status_code}"
                    log.warning("crt.sh lookup for %s failed (attempt %d): %s", domain, attempt + 1, last_error)
                    if attempt < retries:
                        await asyncio.sleep(2)
                        continue
                    result["error"] = last_error
                    return result

                entries = resp.json()
                result["total_certificates"] = len(entries)

                subdomains = set()
                recent = []
                now = datetime.now(timezone.utc)

                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and domain in name:
                            subdomains.add(name)

                    entry_date_str = entry.get("entry_timestamp", "")
                    if entry_date_str:
                        try:
                            entry_date = datetime.strptime(
                                entry_date_str.split(".")[0], "%Y-%m-%dT%H:%M:%S"
                            ).replace(tzinfo=timezone.utc)
                            days_ago = (now - entry_date).days
                            if days_ago <= 7:
                                recent.append({
                                    "name": name_value.split("\n")[0],
                                    "issued": entry_date_str.split("T")[0],
                                })
                        except Exception:
                            pass

                result["checked"] = True
                result["unique_subdomains"] = sorted(subdomains)[:50]
                result["recent_certificates"] = recent[:20]
                return result

            except httpx.TimeoutException as e:
                last_error = f"Request timed out after {timeout}s"
                log.warning("crt.sh lookup for %s timed out (attempt %d): %s", domain, attempt + 1, e)
                if attempt < retries:
                    await asyncio.sleep(2)
                    continue
            except httpx.RequestError as e:
                last_error = str(e)
                log.warning("crt.sh lookup for %s failed (attempt %d): %s", domain, attempt + 1, e, exc_info=True)
                if attempt < retries:
                    await asyncio.sleep(2)
                    continue
            except ValueError:
                last_error = "crt.sh returned invalid JSON (rate-limited)"
                log.warning("crt.sh lookup for %s returned invalid JSON (attempt %d)", domain, attempt + 1)
                if attempt < retries:
                    await asyncio.sleep(2)
                    continue

    result["error"] = last_error
    return result
