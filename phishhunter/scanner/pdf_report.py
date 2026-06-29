"""PDF report generator — produces a professional security report with a
cover page, executive summary (with a visual score gauge), domain info,
raw DNS evidence, SSL/TLS analysis, security headers detail, technology
stack, certificate transparency, email security, reputation, a full risk
score breakdown, and recommendations.
"""
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie


def _verdict_color(verdict: str):
    if "HIGH RISK" in verdict:
        return colors.HexColor("#c0392b")
    if "SUSPICIOUS" in verdict:
        return colors.HexColor("#d68910")
    return colors.HexColor("#1e8449")


def _build_recommendations(result: dict) -> list:
    """Derive plain-language recommendations from the scan result.
    Every recommendation here is gated on an actual detected condition —
    no generic warnings are shown for records that were never checked
    or that resolved fine."""
    recs = []

    if not result["features"].get("uses_https"):
        recs.append("Enable HTTPS with a valid SSL/TLS certificate for this domain.")

    headers_data = result.get("security_headers", {})
    if headers_data.get("checked"):
        for item in headers_data.get("headers_missing", []):
            if item["severity"] in ("high", "medium"):
                recs.append(f"Add the {item['name']} HTTP header to improve browser-level protections.")

    tls_data = result.get("tls", {})
    if tls_data.get("checked"):
        if tls_data.get("is_weak_protocol"):
            recs.append(f"Disable support for outdated TLS protocol ({tls_data.get('tls_version')}); upgrade to TLS 1.2 or 1.3.")
        if tls_data.get("is_weak_cipher"):
            recs.append("Disable weak cipher suites on the web server configuration.")

    ssl_data = result.get("ssl", {})
    if ssl_data.get("is_expiring_soon"):
        recs.append(f"SSL certificate expires in {ssl_data.get('days_until_expiry')} days — renew soon.")
    if ssl_data.get("is_expired"):
        recs.append("SSL certificate has expired — renew immediately.")

    email_sec = result.get("email_security", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})
    # Fix (#2/#12): gate on informational_only (set by email_security_check
    # when the domain has no MX records) rather than re-deriving the same
    # condition here — a domain that doesn't send email has nothing to
    # spoof, so recommending SPF/DMARC for it is misleading noise.
    if not spf.get("error") and not spf.get("has_spf") and not spf.get("informational_only"):
        recs.append("Configure an SPF record to prevent email spoofing from this domain.")
    if not dmarc.get("error") and not dmarc.get("has_dmarc") and not dmarc.get("informational_only"):
        recs.append("Configure a DMARC record to strengthen email authentication.")

    dns_health = result.get("dns_health", {})
    for issue in dns_health.get("issues", []):
        recs.append(f"DNS: {issue}")

    if not recs:
        recs.append("No major issues detected. Continue periodic monitoring.")

    return recs


def _kv_table(rows, col_widths=(160, 320)):
    """Key-value table. String values longer than ~45 chars are wrapped in
    a Paragraph so they don't overflow the page width."""
    wrap_style = ParagraphStyle("KVWrap", fontName="Helvetica", fontSize=9, leading=11)
    safe_rows = []
    for key, value in rows:
        if isinstance(value, str) and len(value) > 45:
            value = Paragraph(value, wrap_style)
        safe_rows.append([key, value])

    table = Table(safe_rows, colWidths=list(col_widths))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _score_gauge_drawing(score: int, verdict_color) -> Drawing:
    """A simple horizontal bar gauge showing the risk score out of 100."""
    width, height = 460, 36
    d = Drawing(width, height)
    d.add(Rect(0, 10, width, 14, fillColor=colors.HexColor("#e8e8e8"), strokeColor=None))
    fill_width = max(4, (score / 100.0) * width)
    d.add(Rect(0, 10, fill_width, 14, fillColor=verdict_color, strokeColor=None))
    d.add(String(0, 0, "0", fontSize=8, fillColor=colors.HexColor("#777777")))
    d.add(String(width - 22, 0, "100", fontSize=8, fillColor=colors.HexColor("#777777")))
    d.add(String(width / 2 - 14, 30, f"{score}/100", fontSize=10, fillColor=colors.black))
    return d


def _posture_pie_drawing(posture_score: int) -> Drawing:
    """Small donut-style pie showing posture score vs. remaining gap."""
    d = Drawing(160, 140)
    pie = Pie()
    pie.x = 30
    pie.y = 10
    pie.width = 100
    pie.height = 100
    remaining = max(0, 100 - posture_score)
    pie.data = [posture_score, remaining] if remaining > 0 else [posture_score, 0.0001]
    pie.labels = None
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.HexColor("#1e8449") if posture_score >= 60 else colors.HexColor("#d68910")
    pie.slices[1].fillColor = colors.HexColor("#e8e8e8")
    d.add(pie)
    d.add(String(55, 0, f"{posture_score}/100", fontSize=10, fillColor=colors.black))
    return d


def generate_pdf_report(result: dict, output_path: str) -> str:
    """Builds a PDF report from a full scan result dict and writes it to
    output_path. Returns the path on success."""
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )
    styles = getSampleStyleSheet()

    cover_title_style = ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=28, leading=34,
        alignment=TA_CENTER, spaceAfter=10, textColor=colors.HexColor("#1a1d26"),
    )
    cover_subtitle_style = ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"], fontSize=13,
        alignment=TA_CENTER, textColor=colors.HexColor("#4f7cff"), spaceAfter=6,
    )
    cover_meta_style = ParagraphStyle(
        "CoverMeta", parent=styles["Normal"], fontSize=10,
        alignment=TA_CENTER, textColor=colors.HexColor("#777777"),
    )
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor("#555555"), spaceAfter=16,
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontSize=13,
        spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#1a1d26"),
    )
    body_style = styles["Normal"]
    small_grey = ParagraphStyle(
        "SmallGrey", parent=styles["Normal"], fontSize=8.5,
        textColor=colors.HexColor("#888888"),
    )

    risk = result["risk"]
    verdict_color = _verdict_color(risk["verdict"])

    story = []

    # ============ COVER PAGE ============
    story.append(Spacer(1, 150))
    story.append(Paragraph("PhishHunter — Security Risk Report", cover_title_style))
    story.append(Paragraph(result["url"], cover_subtitle_style))
    story.append(Spacer(1, 30))

    cover_verdict_style = ParagraphStyle(
        "CoverVerdict", parent=styles["Heading2"], alignment=TA_CENTER,
        textColor=verdict_color, fontSize=16,
    )
    story.append(Paragraph(risk["verdict"], cover_verdict_style))
    story.append(Paragraph(f"Risk Score: {risk['score']} / 100", cover_meta_style))
    story.append(Spacer(1, 60))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", cover_meta_style,
    ))
    story.append(Paragraph(
        "Defensive analysis report — for security review purposes only.", cover_meta_style,
    ))
    story.append(PageBreak())

    # ============ EXECUTIVE SUMMARY ============
    story.append(Paragraph("Executive Summary", title_style))
    story.append(Paragraph(
        f"Target: {result['url']} &middot; Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        subtitle_style,
    ))

    story.append(Paragraph("Phishing Risk Score", section_style))
    story.append(_score_gauge_drawing(risk["score"], verdict_color))
    story.append(Spacer(1, 4))
    verdict_style = ParagraphStyle("Verdict", parent=styles["Heading3"], textColor=verdict_color)
    story.append(Paragraph(risk["verdict"], verdict_style))

    posture = result.get("posture")
    if posture:
        story.append(Paragraph("Security Posture", section_style))
        posture_row = Table(
            [[_posture_pie_drawing(posture["score"]),
              Paragraph(f"<b>{posture['grade']}</b><br/>Reflects security hygiene (headers, TLS, DNS redundancy) — "
                        f"separate from the phishing-risk score above.", body_style)]],
            colWidths=[170, 310],
        )
        posture_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(posture_row)

    story.append(Spacer(1, 8))
    summary_points = []
    if not result["features"].get("uses_https"):
        summary_points.append("Site does not use HTTPS.")
    if result.get("vt", {}).get("malicious", 0) > 0:
        summary_points.append(f"Flagged malicious by {result['vt']['malicious']} VirusTotal engines.")
    if result.get("brand", {}).get("potential_brand_matches"):
        top = result["brand"]["potential_brand_matches"][0]
        summary_points.append(f"Domain resembles known brand '{top['brand']}'.")
    if not summary_points:
        summary_points.append("No major red flags identified in this scan.")
    for p in summary_points:
        story.append(Paragraph(f"&bull; {p}", body_style))

    story.append(Spacer(1, 14))

    # ============ DOMAIN INFORMATION ============
    story.append(Paragraph("Domain Information", section_style))
    whois = result.get("whois", {})
    # "Domain Resolves" reads from the basic socket-based check (result["dns"])
    # — the single source of truth for this flag — same field the dashboard
    # uses. dns_health no longer computes or exposes its own resolves value,
    # so there is nothing left for this to disagree with.
    dns_data = result.get("dns", {})
    story.append(_kv_table([
        ["Domain", result["features"]["domain"]],
        ["Domain Age", f"{whois.get('domain_age_days', 'Unknown')} days" if whois.get("lookup_succeeded") else "Unknown"],
        ["Registrar", whois.get("registrar") or "Unknown"],
        ["Domain Resolves", "Yes" if dns_data.get("resolves") else "No"],
    ]))

    # ============ RAW DNS EVIDENCE ============
    story.append(Paragraph("Raw DNS Records", section_style))
    dns_health = result.get("dns_health", {})
    record_status = dns_health.get("record_status", {})

    wrap_style = ParagraphStyle("WrapCell", parent=body_style, fontSize=8.5, leading=11)

    def _fmt_list_wrapped(records, status_key, limit=8):
        if records:
            shown = records[:limit]
            text = ", ".join(shown)
            if len(records) > limit:
                text += f", … (+{len(records) - limit} more)"
            return Paragraph(text, wrap_style)
        # Fix (#4): distinguish "we confirmed there's no record" from
        # "our query to check couldn't complete" — these mean very
        # different things and were previously both shown as "None found".
        if record_status.get(status_key) == "lookup_failed":
            return Paragraph("<font color='#c0392b'>DNS lookup failed</font>", wrap_style)
        return Paragraph("Record not found", wrap_style)

    dnssec = dns_health.get("dnssec", {})
    caa = dns_health.get("caa", {})

    if not dnssec.get("checked"):
        dnssec_text = "<font color='#c0392b'>Lookup failed</font>"
    elif dnssec.get("dnssec_detected"):
        dnssec_text = "Configured"
    else:
        dnssec_text = "Not configured"

    if not caa.get("checked"):
        caa_text = "<font color='#c0392b'>Lookup failed</font>"
    elif caa.get("has_caa"):
        caa_text = ", ".join(caa.get("caa_records", [])[:5])
    else:
        caa_text = "None found"

    dns_rows = [
        ["A Records", _fmt_list_wrapped(dns_health.get("a_records", []), "a")],
        ["AAAA Records", _fmt_list_wrapped(dns_health.get("aaaa_records", []), "aaaa")],
        ["NS Records", _fmt_list_wrapped(dns_health.get("ns_records", []), "ns")],
        ["MX Records", _fmt_list_wrapped(dns_health.get("mx_records", []), "mx")],
        ["DNSSEC", Paragraph(dnssec_text, wrap_style)],
        ["CAA Record", Paragraph(caa_text, wrap_style)],
    ]
    dns_table = Table(dns_rows, colWidths=[110, 370])
    dns_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(dns_table)
    if dns_health.get("issues"):
        story.append(Spacer(1, 6))
        for issue in dns_health["issues"]:
            story.append(Paragraph(f"&bull; <font color='#d68910'>{issue}</font>", body_style))

    # ============ SSL / TLS ANALYSIS ============
    story.append(Paragraph("SSL / TLS Analysis", section_style))
    ssl_data = result.get("ssl", {})
    tls_data = result.get("tls", {})
    story.append(_kv_table([
        ["Valid Certificate", "Yes" if ssl_data.get("has_valid_cert") else "No"],
        ["Issuer", ssl_data.get("issuer") or "N/A"],
        ["Expires", ssl_data.get("expires") or "N/A"],
        ["Days Until Expiry", str(ssl_data.get("days_until_expiry")) if ssl_data.get("days_until_expiry") is not None else "N/A"],
        ["TLS Version", tls_data.get("tls_version") or "N/A"],
        ["Cipher", tls_data.get("cipher_name") or "N/A"],
        ["Weak Protocol/Cipher", "Yes" if (tls_data.get("is_weak_protocol") or tls_data.get("is_weak_cipher")) else "No"],
    ]))

    story.append(Spacer(1, 14))

    # ============ SECURITY HEADERS DETAIL ============
    story.append(Paragraph("Security Headers", section_style))
    headers_data = result.get("security_headers", {})
    if headers_data.get("checked"):
        header_rows = [["Header", "Status", "Value"]]
        for h in headers_data.get("all_headers", []):
            status = "Present" if h["present"] else "Missing"
            value = (h["value"][:60] + "…") if h["value"] and len(h["value"]) > 60 else (h["value"] or "—")
            header_rows.append([h["name"], status, value])

        header_table = Table(header_rows, colWidths=[170, 70, 240])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a2d36")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(header_table)
    else:
        story.append(Paragraph(headers_data.get("error") or "Not checked", body_style))

    # ============ TECHNOLOGY STACK ============
    story.append(Paragraph("Technology Stack", section_style))
    tech_data = result.get("technologies", {})
    techs = tech_data.get("technologies", [])
    if techs:
        story.append(Paragraph(
            ", ".join(f"{t['name']} ({t['category']})" for t in techs), body_style,
        ))
    elif tech_data.get("error"):
        story.append(Paragraph(f"Lookup failed — {tech_data['error']}", body_style))
    else:
        story.append(Paragraph(tech_data.get("status_label") or "No technology fingerprint identified.", body_style))

    # ============ CERTIFICATE TRANSPARENCY ============
    story.append(Paragraph("Certificate Transparency", section_style))
    ct = result.get("cert_transparency", {})
    if ct.get("checked"):
        story.append(_kv_table([
            ["Total Certificates Issued", str(ct.get("total_certificates", 0))],
            ["Unique Subdomains Found", str(len(ct.get("unique_subdomains", [])))],
            ["Certificates in Last 7 Days", str(len(ct.get("recent_certificates", [])))],
        ]))
        subdomains = ct.get("unique_subdomains", [])
        if subdomains:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Subdomains observed:</b>", small_grey))
            story.append(Paragraph(", ".join(subdomains[:30]), small_grey))
    else:
        story.append(Paragraph(ct.get("error") or "Not checked", body_style))

    story.append(Spacer(1, 14))

    # ============ EMAIL SECURITY ============
    story.append(Paragraph("Email Security", section_style))
    email_sec = result.get("email_security", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})
    dkim = email_sec.get("dkim", {})
    mx = email_sec.get("mx", {})

    if not email_sec.get("uses_email"):
        story.append(Paragraph(
            "This domain has no MX records, so it doesn't send or receive email — "
            "the SPF/DMARC/DKIM fields below are informational only and are not "
            "counted against the risk score.", small_grey,
        ))
        story.append(Spacer(1, 4))

    def _info_suffix(field):
        return " (info only)" if field.get("informational_only") else ""

    story.append(_kv_table([
        ["MX Records", "Found" if mx.get("has_mx") else ("Lookup failed (transient — try again)" if mx.get("error") else "None")],
        ["SPF" + _info_suffix(spf), "Configured" if spf.get("has_spf") else ("Lookup failed (transient — try again)" if spf.get("error") else "Not found")],
        ["DMARC" + _info_suffix(dmarc), "Configured" if dmarc.get("has_dmarc") else ("Lookup failed (transient — try again)" if dmarc.get("error") else "Not found")],
        ["DKIM (common selectors)" + _info_suffix(dkim), dkim.get("status_label", "Could not verify common selectors")],
    ]))

    # ============ REPUTATION ============
    story.append(Paragraph("Reputation (VirusTotal)", section_style))
    vt = result.get("vt", {})
    if vt.get("checked"):
        story.append(Paragraph(
            f"Malicious: {vt.get('malicious', 0)} &nbsp;|&nbsp; Suspicious: {vt.get('suspicious', 0)} "
            f"&nbsp;|&nbsp; Harmless: {vt.get('harmless', 0)}", body_style,
        ))
    else:
        story.append(Paragraph(vt.get("error") or "Not checked", body_style))

    # ============ RISK SCORE BREAKDOWN ============
    story.append(Paragraph("Risk Score Breakdown", section_style))
    findings = risk.get("findings", [])
    if findings:
        reason_wrap = ParagraphStyle("ReasonWrap", parent=body_style, fontSize=8.5, leading=11)
        rows = [["Finding", "Points"]]
        for f in sorted(findings, key=lambda x: -x["points"]):
            reason_text = f["reason"]
            if f.get("discounted_from"):
                reason_text += f" <font color='#888888'>(reduced from +{f['discounted_from']} — strong trust signals)</font>"
            rows.append([Paragraph(reason_text, reason_wrap), f"+{f['points']}"])
        rows.append(["Total", f"{risk['score']} / 100"])

        breakdown_table = Table(rows, colWidths=[400, 80])
        breakdown_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a2d36")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0f0f0")),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(breakdown_table)
    else:
        story.append(Paragraph("No risk signals detected.", body_style))

    story.append(Spacer(1, 14))

    # ============ RECOMMENDATIONS ============
    story.append(Paragraph("Recommendations", section_style))
    for rec in _build_recommendations(result):
        story.append(Paragraph(f"&bull; {rec}", body_style))

    doc.build(story)
    return output_path
