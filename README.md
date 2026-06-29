# 🛡️ PhishHunter

A defensive, self-hosted URL and domain security analysis dashboard. Paste in a URL and get a full risk report — WHOIS, SSL/TLS, DNS health (including DNSSEC/CAA), security headers, technology fingerprinting, certificate transparency, email security (SPF/DKIM/DMARC), brand-impersonation detection, redirect-chain analysis, and VirusTotal reputation — all combined into a transparent, point-by-point risk score and a downloadable PDF report.

This tool is for **defensive analysis only**: checking whether a URL someone sent you (or a site you're auditing) looks legitimate. It does not include any offensive/phishing-creation features.

## Prerequisites

Most Kali installs already have these, but if `setup.sh` complains about a missing module:

```bash
sudo apt update && sudo apt install python3 python3-venv python3-pip git
```

## Features

- **Phishing risk score** — transparent point-by-point breakdown, with discounts applied when multiple independent trust signals (domain age, valid SSL, clean VirusTotal record) line up
- **Security posture grade** — separate "how well-hardened is this site" score (headers, TLS, DNS redundancy, DNSSEC, CAA)
- **WHOIS** — domain age, registrar, with automatic retry for flaky WHOIS servers
- **SSL/TLS analysis** — certificate validity, expiry countdown, negotiated protocol/cipher strength
- **DNS health** — A/AAAA/NS/MX/TXT records, DNSSEC, CAA, with lookup-failure vs. genuinely-missing clearly distinguished
- **Security headers** — CSP, HSTS, X-Frame-Options, and more
- **Technology fingerprinting** — WordPress, React, Nginx, Cloudflare, and other common stacks
- **Certificate Transparency** — crt.sh lookup for subdomains and recent cert issuance
- **Email security** — SPF, DMARC, DKIM (common selectors), correctly treated as informational-only for domains that don't send email
- **Brand impersonation detection** — homograph/punycode and Levenshtein-distance typosquat detection against common brands
- **Redirect chain analysis** — follows redirects, flags destination-domain changes
- **VirusTotal reputation** — URL and standalone IOC (IP/domain/hash) lookups
- **PDF export** — cover page, executive summary with score gauges, full evidence tables, recommendations
- All external checks run **in parallel** (asyncio.gather) for fast scans
- Scan results persist to disk (JSON), so PDF download links survive a server restart

## Quick Start (Kali Linux)

```bash
git clone https://github.com/ginoyajay3-xhunter/phishhunter.git
cd phishhunter/phishhunter
chmod +x setup.sh
./setup.sh
source venv/bin/activate
uvicorn app:app --reload --port 8001
```

Then open **http://127.0.0.1:8001** in your browser.

`setup.sh` automatically creates a `.env` file with placeholder values on first run.

## Manual Setup

If you'd rather not use the setup script:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root with:

```

nano .env
VT_API_KEY=your_virustotal_api_key_here
LOG_LEVEL=INFO
```

Get a free VirusTotal API key from https://www.virustotal.com/gui/my-apikey (optional — the app works without it, just skips reputation checks).

```bash
uvicorn app:app --reload --port 8001
```

## Usage

- **Web dashboard**: open `http://127.0.0.1:8001`, paste a URL, click Analyze
- **JSON API**: `GET /api/scan?url=https://example.com`
- **IOC lookup**: `GET /api/ioc?value=8.8.8.8` (accepts IP, domain, or MD5/SHA1/SHA256 hash)
- **PDF report**: click "Download PDF Report" after a scan, or `GET /export-pdf/{scan_id}`

## Project Structure

```
.
├── app.py                    # FastAPI routes, async orchestration
├── config.py                 # API keys, thresholds, logging setup
├── requirements.txt
├── setup.sh
├── scanner/                  # one module per check
│   ├── url_features.py       # URL structure (IP usage, @ symbol, length, keywords)
│   ├── whois_check.py        # domain age, registrar
│   ├── ssl_check.py          # certificate validity, TLS version/cipher
│   ├── dns_check.py          # A/AAAA/NS/MX/TXT, DNSSEC, CAA
│   ├── email_security.py     # SPF/DMARC/DKIM
│   ├── security_headers.py   # CSP/HSTS/X-Frame-Options/etc.
│   ├── tech_detector.py      # technology fingerprinting
│   ├── cert_transparency.py  # crt.sh integration
│   ├── wayback_check.py      # archive.org history
│   ├── brand_similarity.py   # homograph + typosquat detection
│   ├── redirect_check.py     # redirect chain analysis
│   ├── virustotal.py         # URL reputation
│   ├── ioc_checker.py        # standalone IP/domain/hash lookup
│   ├── scoring.py            # phishing risk score
│   ├── security_posture.py   # security hygiene score
│   ├── pdf_report.py         # PDF generation
│   └── scan_store.py         # persistent scan-result cache
└── templates/
    └── index.html            # dashboard UI
```

## Notes

- This is a personal/educational security tool, not a production-hardened service. Don't expose it directly to the internet without adding authentication.
- External lookups (WHOIS, crt.sh, archive.org) depend on third-party services that can be slow or rate-limited; the tool retries automatically but occasional "lookup failed — try again" messages are normal.
- No data is sent anywhere except to the services each check inherently needs (e.g. VirusTotal's own API, crt.sh, archive.org). Nothing is collected by this project itself.

## License

MIT — see [LICENSE](LICENSE).
