"""Lightweight technology fingerprinting — identifies common CMS, frameworks,
servers, and CDNs from HTTP response headers and page content. This is a
simplified signature-based approach, not a full Wappalyzer-style database.
"""
import re
import httpx

from config import logger

log = logger.getChild("tech_detector")

# Each signature: (technology_name, category, check_function)
def _detect_from_headers(headers: dict, html: str) -> list:
    detections = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # --- Servers / infrastructure ---
    server = headers_lower.get("server", "")
    if "nginx" in server.lower():
        detections.append({"name": "Nginx", "category": "Web Server"})
    if "apache" in server.lower():
        detections.append({"name": "Apache", "category": "Web Server"})
    if "cloudflare" in server.lower() or "cf-ray" in headers_lower:
        detections.append({"name": "Cloudflare", "category": "CDN / Security"})
    if "litespeed" in server.lower():
        detections.append({"name": "LiteSpeed", "category": "Web Server"})

    powered_by = headers_lower.get("x-powered-by", "")
    if "php" in powered_by.lower():
        detections.append({"name": "PHP", "category": "Language"})
    if "asp.net" in powered_by.lower():
        detections.append({"name": "ASP.NET", "category": "Framework"})
    if "express" in powered_by.lower():
        detections.append({"name": "Express.js", "category": "Framework"})

    if "x-vercel-id" in headers_lower:
        detections.append({"name": "Vercel", "category": "Hosting"})
    if "x-amz-cf-id" in headers_lower or "x-amz-id-2" in headers_lower:
        detections.append({"name": "Amazon CloudFront/AWS", "category": "CDN / Hosting"})
    if "x-github-request-id" in headers_lower:
        detections.append({"name": "GitHub Pages", "category": "Hosting"})
    if "x-fastly-request-id" in headers_lower or "fastly" in server.lower():
        detections.append({"name": "Fastly", "category": "CDN"})

    # --- CMS / frameworks from page content ---
    html_lower = html.lower()

    if "wp-content" in html_lower or "wp-includes" in html_lower or "wordpress" in html_lower:
        detections.append({"name": "WordPress", "category": "CMS"})
    if "wp-json" in html_lower:
        detections.append({"name": "WordPress (REST API)", "category": "CMS"})

    if re.search(r"data-reactroot|react-dom|_next/static", html_lower):
        detections.append({"name": "React", "category": "JS Framework"})
    if "__next_data__" in html_lower or "_next/" in html_lower:
        detections.append({"name": "Next.js", "category": "JS Framework"})

    if re.search(r"ng-version|ng-app|angular", html_lower):
        detections.append({"name": "Angular", "category": "JS Framework"})

    if "v-cloak" in html_lower or "__vue__" in html_lower or "data-v-" in html_lower:
        detections.append({"name": "Vue.js", "category": "JS Framework"})

    if "shopify" in html_lower or "cdn.shopify.com" in html_lower:
        detections.append({"name": "Shopify", "category": "E-commerce"})
    if "woocommerce" in html_lower:
        detections.append({"name": "WooCommerce", "category": "E-commerce"})
    if "magento" in html_lower:
        detections.append({"name": "Magento", "category": "E-commerce"})

    if "drupal" in html_lower:
        detections.append({"name": "Drupal", "category": "CMS"})
    if "joomla" in html_lower:
        detections.append({"name": "Joomla", "category": "CMS"})

    if "jquery" in html_lower:
        detections.append({"name": "jQuery", "category": "JS Library"})
    if "bootstrap" in html_lower:
        detections.append({"name": "Bootstrap", "category": "CSS Framework"})
    if "tailwind" in html_lower:
        detections.append({"name": "Tailwind CSS", "category": "CSS Framework"})

    if "google-analytics.com" in html_lower or "gtag(" in html_lower:
        detections.append({"name": "Google Analytics", "category": "Analytics"})
    if "recaptcha" in html_lower:
        detections.append({"name": "reCAPTCHA", "category": "Security"})

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for d in detections:
        key = d["name"]
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


async def detect_technologies(url: str, timeout: float = 8.0) -> dict:
    result = {"checked": False, "technologies": [], "error": None}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                url, headers={"User-Agent": "Mozilla/5.0 (compatible; PhishAnalyzer/1.0)"},
            )
        technologies = _detect_from_headers(resp.headers, resp.text[:200_000])
        result["checked"] = True
        result["technologies"] = technologies
    except httpx.TimeoutException as e:
        result["error"] = f"Request timed out after {timeout}s"
        log.warning("Tech detection for %s timed out: %s", url, e)
    except httpx.RequestError as e:
        result["error"] = f"Request failed: {e}"
        log.warning("Tech detection for %s failed: %s", url, e, exc_info=True)

    # Fix: "None detected" reads like a confident claim that the site uses
    # no recognizable technology, when really our signature set is just
    # small and heuristic. This label makes the limitation explicit.
    result["status_label"] = (
        "No technology fingerprint identified" if not result["technologies"] else None
    )

    return result
