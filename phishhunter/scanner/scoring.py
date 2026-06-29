"""Combines URL features, WHOIS, SSL, DNS, and VirusTotal data into one risk score.

Each finding is tracked as (reason_text, points_added) so the UI/PDF can
show a transparent breakdown of exactly how the final score was reached.
"""

from config import RISK_THRESHOLD_HIGH, RISK_THRESHOLD_SUSPICIOUS


def compute_risk_score(features: dict, whois_data: dict, ssl_data: dict,
                        dns_data: dict, vt_data: dict, email_sec: dict = None,
                        wayback_data: dict = None, brand_data: dict = None,
                        redirect_data: dict = None) -> dict:
    findings = []  # list of {"reason": str, "points": int}
    email_sec = email_sec or {}
    wayback_data = wayback_data or {}
    brand_data = brand_data or {}
    redirect_data = redirect_data or {}

    def add(points, reason):
        findings.append({"reason": reason, "points": points})

    # --- URL structural features ---
    if features.get("is_ip"):
        add(20, "Domain is a raw IP address instead of a name")

    if features.get("contains_at"):
        add(15, "URL contains '@' symbol (redirect trick)")

    if features.get("length", 0) > 100:
        add(8, "Unusually long URL")

    if features.get("subdomain_count", 0) > 3:
        add(10, "Excessive number of subdomains")

    if features.get("has_hyphen_in_domain"):
        add(5, "Hyphen in domain name (common impersonation tactic)")

    if features.get("has_punycode"):
        add(20, "Punycode domain detected (possible homograph attack)")

    if not features.get("uses_https"):
        add(8, "Connection is not using HTTPS")

    keywords = features.get("matched_keywords", [])
    if keywords:
        pts = min(len(keywords) * 4, 16)
        add(pts, f"Contains suspicious keywords: {', '.join(keywords)}")

    # --- WHOIS ---
    if whois_data.get("lookup_succeeded") and whois_data.get("is_newly_registered"):
        add(15, f"Domain registered recently ({whois_data.get('domain_age_days')} days ago)")

    # --- SSL ---
    if not ssl_data.get("has_valid_cert"):
        add(10, "No valid SSL certificate found")

    # --- DNS --- (uses the reconciled `resolves` flag — see dns_check.py)
    if not dns_data.get("resolves"):
        add(10, "Domain does not resolve via DNS")

    # --- VirusTotal ---
    if vt_data.get("checked"):
        malicious = vt_data.get("malicious", 0)
        suspicious = vt_data.get("suspicious", 0)
        if malicious > 0:
            pts = min(malicious * 8, 40)
            add(pts, f"VirusTotal: {malicious} engines flagged this URL as malicious")
        if suspicious > 0:
            pts = min(suspicious * 4, 20)
            add(pts, f"VirusTotal: {suspicious} engines flagged this URL as suspicious")

    # --- Email security posture (mild signals only, and only when the
    # underlying lookup actually succeeded — a DNS timeout should not be
    # reported as "no MX records/SPF/DMARC") ---
    mx = email_sec.get("mx", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})

    # Fix: a domain with no MX records doesn't send/receive email at all,
    # so it has no mail flow to spoof — missing SPF/DMARC there is normal,
    # not a risk signal. email_security_check() marks spf/dmarc as
    # informational_only in that case; we skip the score penalty (but the
    # PDF/dashboard can still mention it as an FYI) rather than treating
    # a non-mail-sending domain as if it forgot to protect mail it never sends.
    if mx and not mx.get("has_mx") and not mx.get("error"):
        add(3, "No MX records found for this domain")
    if spf and not spf.get("has_spf") and not spf.get("error") and not spf.get("informational_only"):
        add(2, "No SPF record configured")
    if dmarc and not dmarc.get("has_dmarc") and not dmarc.get("error") and not dmarc.get("informational_only"):
        add(2, "No DMARC record configured")

    # --- Wayback Machine ---
    if wayback_data.get("checked") and not wayback_data.get("first_seen"):
        add(8, "No Wayback Machine archive history found for this domain")

    # --- Brand similarity / homograph ---
    if brand_data.get("has_homograph"):
        add(20, "Homograph/punycode domain detected (possible lookalike attack)")

    matches = brand_data.get("potential_brand_matches", [])
    if matches:
        top = matches[0]
        if top["edit_distance"] <= 1:
            add(25, f"Domain very closely resembles brand '{top['brand']}' (possible typosquat)")
        elif top["edit_distance"] == 2 or top.get("appears_as_substring"):
            add(15, f"Domain resembles brand '{top['brand']}' (possible impersonation)")

    # --- Redirect chain ---
    if redirect_data.get("checked"):
        hop_count = redirect_data.get("hop_count", 0)
        if hop_count >= 3:
            add(10, f"URL redirects through {hop_count} hops before landing")
        if redirect_data.get("domain_changed"):
            add(8, "URL redirects to a different domain than the one entered")

    # --- Trust discount ---
    # Fix: low-severity DNS/email hygiene findings (missing MX, SPF,
    # DMARC, no Wayback history) were carrying full weight even for
    # domains with strong independent trust signals — an old domain with
    # a valid SSL cert and a clean VirusTotal record is very unlikely to
    # be a phishing site regardless of whether it happens to have SPF
    # configured. We don't remove these findings (they're still genuinely
    # true and worth a mention), but we discount their point contribution
    # once several trust signals line up, so they nudge the score rather
    # than dominate it.
    is_old_domain = (
        whois_data.get("lookup_succeeded")
        and whois_data.get("domain_age_days") is not None
        and whois_data.get("domain_age_days", 0) >= 365
    )
    has_valid_ssl = bool(ssl_data.get("has_valid_cert"))
    vt_clean = (
        vt_data.get("checked")
        and vt_data.get("malicious", 0) == 0
        and vt_data.get("suspicious", 0) == 0
    )
    trust_signal_count = sum([is_old_domain, has_valid_ssl, vt_clean])

    DISCOUNTABLE_REASON_PREFIXES = (
        "No MX records found",
        "No SPF record configured",
        "No DMARC record configured",
        "No Wayback Machine archive history",
        "Domain does not resolve via DNS",
    )

    if trust_signal_count >= 2:
        # 2 of 3 strong trust signals -> halve discountable findings.
        # All 3 -> drop them to a quarter of their original weight.
        discount_factor = 0.25 if trust_signal_count == 3 else 0.5
        for f in findings:
            if any(f["reason"].startswith(p) for p in DISCOUNTABLE_REASON_PREFIXES):
                original = f["points"]
                f["points"] = round(original * discount_factor)
                f["discounted_from"] = original

    raw_total = sum(f["points"] for f in findings)
    score = min(raw_total, 100)

    if score >= RISK_THRESHOLD_HIGH:
        verdict = "HIGH RISK — Likely Phishing"
    elif score >= RISK_THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS — Manual Review Recommended"
    else:
        verdict = "LIKELY SAFE"

    # `reasons` kept as a flat list of strings for backward compatibility
    # with any code that only wants the text; `findings` carries the
    # full reason+points breakdown for transparent display.
    reasons = [f["reason"] for f in findings]

    return {
        "score": score,
        "raw_total": raw_total,
        "verdict": verdict,
        "reasons": reasons,
        "findings": findings,
    }
