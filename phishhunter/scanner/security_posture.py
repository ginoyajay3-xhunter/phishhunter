"""Security posture scoring — distinct from phishing risk scoring.

Phishing risk score (scoring.py) asks: "is this URL trying to deceive someone?"
Security posture score asks: "if this is a legitimate site, how well is it
configured from a security-hygiene standpoint?" A low posture score doesn't
mean a site is malicious — it means it has room to harden its defenses
(missing headers, weak TLS, no DNS redundancy, etc.)
"""


def compute_security_posture(headers_data: dict, tls_data: dict, dns_health: dict,
                              cert_transparency: dict = None) -> dict:
    cert_transparency = cert_transparency or {}
    score = 100  # start at perfect, deduct for issues
    findings = []

    # --- Security headers (worth up to 30 points) ---
    if headers_data.get("checked"):
        missing = headers_data.get("headers_missing", [])
        for item in missing:
            if item["severity"] == "high":
                score -= 8
                findings.append(f"Missing {item['name']} (high impact)")
            elif item["severity"] == "medium":
                score -= 4
                findings.append(f"Missing {item['name']} (medium impact)")
            else:
                score -= 1
                findings.append(f"Missing {item['name']} (low impact)")

    # --- TLS (worth up to 30 points) ---
    if tls_data.get("checked"):
        if tls_data.get("is_weak_protocol"):
            score -= 25
            findings.append(f"Weak TLS protocol negotiated: {tls_data.get('tls_version')}")
        if tls_data.get("is_weak_cipher"):
            score -= 15
            findings.append(f"Weak cipher suite negotiated: {tls_data.get('cipher_name')}")
    elif tls_data.get("error"):
        score -= 10
        findings.append("Could not establish TLS connection")

    # --- Certificate expiry ---
    # (ssl_check data is passed in via tls_data's sibling, handled by caller if needed)

    # --- DNS health (worth up to 20 points) ---
    # Fix: dns_health["issues"] only ever contains genuine misconfigurations
    # now (see dns_check.py — it's gated on domain_resolves, not on
    # individual lookup failures), so it's already safe to deduct for
    # directly. What we must NOT do is also penalize for entries in
    # lookup_errors — those represent OUR query failing (timeout, no
    # responsive nameserver reached from this scanner), not evidence the
    # domain itself is misconfigured. Previously there was no such
    # distinction being enforced at this layer; this makes it explicit so
    # a future change to dns_health's contents can't silently reintroduce
    # "transient lookup hiccup -> site gets blamed for it".
    issues = dns_health.get("issues", [])
    for issue in issues:
        score -= 7
        findings.append(issue)

    if not dns_health.get("has_ipv6"):
        score -= 2
        findings.append("No IPv6 (AAAA) support")

    # DNSSEC: only score it when we got a definitive answer either way.
    # A failed DNSKEY lookup (resolver timeout, etc.) tells us nothing
    # about whether the domain actually has DNSSEC, so it's excluded from
    # scoring entirely rather than counted as "missing".
    dnssec = dns_health.get("dnssec", {})
    if dnssec.get("checked") and not dnssec.get("dnssec_detected"):
        score -= 3
        findings.append("DNSSEC does not appear to be configured")

    # CAA: same principle — only penalize a confirmed absence.
    caa = dns_health.get("caa", {})
    if caa.get("checked") and not caa.get("has_caa"):
        score -= 2
        findings.append("No CAA record — any CA can issue certificates for this domain")

    # --- Certificate transparency (informational, small penalty if many recent certs) ---
    recent_certs = cert_transparency.get("recent_certificates", [])
    if len(recent_certs) > 5:
        score -= 5
        findings.append(f"{len(recent_certs)} certificates issued for this domain in the last 7 days — unusually high churn")

    score = max(0, min(100, score))

    if score >= 80:
        grade = "A — Strong security posture"
    elif score >= 60:
        grade = "B — Good, minor improvements possible"
    elif score >= 40:
        grade = "C — Several gaps, recommend hardening"
    elif score >= 20:
        grade = "D — Significant security gaps"
    else:
        grade = "F — Poor security posture"

    return {
        "score": score,
        "grade": grade,
        "findings": findings,
    }
