"""PhishHunter — FastAPI Dashboard.

Run with:
    export VT_API_KEY="your_virustotal_key"
    pip install -r requirements.txt
    uvicorn app:app --reload

Then open http://127.0.0.1:8000 in your browser.
"""
import os
import uuid
import asyncio

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()  # loads VT_API_KEY from a .env file if present

from scanner.url_features import analyze_url
from scanner.whois_check import whois_check_sync
from scanner.ssl_check import check_ssl_sync, analyze_tls_sync
from scanner.dns_check import dns_check, dns_health_check
from scanner.virustotal import submit_and_check_url
from scanner.email_security import email_security_check
from scanner.wayback_check import check_wayback_history
from scanner.brand_similarity import check_brand_similarity
from scanner.redirect_check import analyze_redirect_chain
from scanner.security_headers import check_security_headers
from scanner.tech_detector import detect_technologies
from scanner.cert_transparency import check_certificate_transparency
from scanner.security_posture import compute_security_posture
from scanner.scoring import compute_risk_score
from scanner.pdf_report import generate_pdf_report
from scanner.ioc_checker import check_ioc
from scanner.scan_store import save_scan_result, load_scan_result
from config import logger

log = logger.getChild("app")

app = FastAPI(title="PhishHunter")
templates = Jinja2Templates(directory="templates")

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


async def run_full_analysis(url: str) -> dict:
    """Runs every check module and returns a single combined result dict.
    Shared by the HTML form route, JSON API route, and PDF export route.

    Fix (#9): every external check below is independent of the others —
    none needs another's result before it can start — so they all run
    concurrently via asyncio.gather instead of one after another. Checks
    built on sync-only libraries (WHOIS, raw-socket SSL/TLS) are wrapped
    in asyncio.to_thread so they don't block the event loop while still
    running in parallel with everything else. This cuts wall-clock scan
    time roughly to whatever the single slowest check takes, rather than
    the sum of all of them.
    """
    features = analyze_url(url)
    domain = features["domain"]
    uses_https = features["uses_https"]

    dns_data = dns_check(domain)  # cheap, synchronous, needed before dns_health_check

    async def ssl_task():
        if not uses_https:
            return {"has_valid_cert": False, "error": "Not HTTPS"}
        return await asyncio.to_thread(check_ssl_sync, domain)

    async def tls_task():
        if not uses_https:
            return {"checked": False, "error": "Not HTTPS"}
        return await asyncio.to_thread(analyze_tls_sync, domain)

    async def whois_task():
        return await asyncio.to_thread(whois_check_sync, domain)

    (
        whois_data, ssl_data, tls_data, dns_health, vt_data, email_sec,
        wayback_data, brand_data, redirect_data, headers_data, tech_data,
        cert_transparency,
    ) = await asyncio.gather(
        whois_task(),
        ssl_task(),
        tls_task(),
        dns_health_check(domain, dns_basic_result=dns_data),
        submit_and_check_url(url),
        email_security_check(domain),
        check_wayback_history(domain),
        asyncio.to_thread(check_brand_similarity, domain),
        analyze_redirect_chain(url),
        check_security_headers(url),
        detect_technologies(url),
        check_certificate_transparency(domain),
    )

    risk = compute_risk_score(
        features, whois_data, ssl_data, dns_data, vt_data,
        email_sec=email_sec, wayback_data=wayback_data,
        brand_data=brand_data, redirect_data=redirect_data,
    )

    posture = compute_security_posture(
        headers_data, tls_data, dns_health, cert_transparency,
    )

    return {
        "url": url,
        "features": features,
        "whois": whois_data,
        "ssl": ssl_data,
        "tls": tls_data,
        "dns": dns_data,
        "dns_health": dns_health,
        "vt": vt_data,
        "email_security": email_sec,
        "wayback": wayback_data,
        "brand": brand_data,
        "redirects": redirect_data,
        "security_headers": headers_data,
        "technologies": tech_data,
        "cert_transparency": cert_transparency,
        "risk": risk,
        "posture": posture,
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"result": None})


@app.post("/scan", response_class=HTMLResponse)
async def scan_url(request: Request, url: str = Form(...)):
    result = await run_full_analysis(url.strip())

    scan_id = str(uuid.uuid4())
    # Fix (#10): persisted to disk as JSON instead of an in-memory dict —
    # survives server restarts, so a "Download PDF" link generated before
    # a restart (e.g. during development with --reload, or a redeploy)
    # still works afterward instead of 404ing.
    save_scan_result(scan_id, result)

    return templates.TemplateResponse(request, "index.html", {"result": result, "scan_id": scan_id})


@app.get("/api/scan")
async def api_scan(url: str):
    """JSON API endpoint — same analysis, machine-readable response."""
    return await run_full_analysis(url.strip())


@app.get("/export-pdf/{scan_id}")
async def export_pdf(scan_id: str):
    result = load_scan_result(scan_id)
    if not result:
        return JSONResponse(status_code=404, content={"error": "Scan result not found or expired. Please re-run the scan."})

    safe_domain = result["features"]["domain"].replace(":", "_")
    filename = f"phishhunter_report_{safe_domain}_{scan_id[:8]}.pdf"
    output_path = os.path.join(REPORTS_DIR, filename)

    await asyncio.to_thread(generate_pdf_report, result, output_path)

    return FileResponse(output_path, media_type="application/pdf", filename=filename)


@app.get("/api/ioc")
async def api_ioc(value: str):
    """Standalone IOC lookup — IP, domain, or file hash reputation via VirusTotal."""
    return await check_ioc(value.strip())


@app.get("/health")
async def health():
    return {"status": "running"}
