"""Email security posture checks — MX records, SPF, DKIM, DMARC.

A domain with no MX records doesn't send/receive email at all, so missing
SPF/DMARC/DKIM on it is expected and not a finding worth penalizing —
there's no mail flow to spoof. These checks are only meaningful (and only
worth a risk-score penalty) for domains that actually use email.
"""
import asyncio

try:
    import dns.asyncresolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from config import logger

log = logger.getChild("email_security")

PUBLIC_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def _get_resolver(timeout: float = 5.0):
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


async def _resolve_txt(domain: str, timeout: float = 5.0):
    """Return (list of TXT record strings, error) for a domain.

    error is None when the lookup succeeded (even if it found zero
    records — that's a legitimate "no record" result, not a failure).
    error is set when the lookup itself couldn't complete, so callers
    can avoid treating a timeout as proof a record is absent.
    """
    if not DNS_AVAILABLE:
        return [], "dnspython not installed"
    try:
        resolver = _get_resolver(timeout)
        answers = await resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode(errors="ignore") for r in answers], None
    except dns.resolver.NoAnswer:
        return [], None  # domain exists, just has no TXT records — not an error
    except dns.resolver.NXDOMAIN:
        return [], "Domain does not exist"
    except Exception as e:
        log.debug("TXT lookup for %s failed: %s", domain, e)
        return [], str(e)


async def check_mx_records(domain: str, timeout: float = 5.0) -> dict:
    result = {"has_mx": False, "mx_hosts": [], "error": None}
    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    try:
        resolver = _get_resolver(timeout)
        answers = await resolver.resolve(domain, "MX")
        hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
        result["has_mx"] = len(hosts) > 0
        result["mx_hosts"] = hosts
    except dns.resolver.NoAnswer:
        pass  # domain has no MX records — a legitimate, common state
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
    except Exception as e:
        log.debug("MX lookup for %s failed: %s", domain, e)
        result["error"] = str(e)

    return result


async def check_spf(domain: str) -> dict:
    txt_records, error = await _resolve_txt(domain)
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    return {
        "has_spf": len(spf_records) > 0,
        "record": spf_records[0] if spf_records else None,
        "error": error,
    }


async def check_dmarc(domain: str) -> dict:
    txt_records, error = await _resolve_txt(f"_dmarc.{domain}")
    dmarc_records = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    return {
        "has_dmarc": len(dmarc_records) > 0,
        "record": dmarc_records[0] if dmarc_records else None,
        "error": error,
    }


async def check_dkim(domain: str, selectors=None) -> dict:
    """DKIM has no fixed discovery location — it's published per-selector
    (e.g. 'google._domainkey.domain.com'). We probe a handful of common
    selectors in parallel; absence of all of them is inconclusive, not
    proof DKIM is unused — most real-world selectors are unguessable.
    """
    if selectors is None:
        selectors = ["default", "google", "selector1", "selector2", "k1", "dkim"]

    async def _check_selector(selector):
        txt_records, _ = await _resolve_txt(f"{selector}._domainkey.{domain}")
        dkim_records = [t for t in txt_records if "v=dkim1" in t.lower() or "p=" in t.lower()]
        return selector if dkim_records else None

    results = await asyncio.gather(*(_check_selector(s) for s in selectors))
    found = [s for s in results if s]

    return {
        "has_dkim_detected": len(found) > 0,
        "selectors_checked": selectors,
        "selectors_found": found,
        # Fix: "Not detected" reads like a definitive negative finding.
        # DKIM selectors are arbitrary strings chosen by whoever configured
        # the domain's mail — checking 6 common guesses and finding nothing
        # says nothing about whether DKIM is actually configured under a
        # different selector. This phrasing makes that limitation explicit.
        "status_label": (
            "Detected" if found else "Could not verify common selectors"
        ),
    }


async def email_security_check(domain: str) -> dict:
    mx, spf, dmarc, dkim = await asyncio.gather(
        check_mx_records(domain),
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain),
    )

    # Fix: a domain with no MX records sends/receives no email, so SPF/
    # DMARC/DKIM absence there is expected, not a red flag. Mark these as
    # informational-only in that case so callers (risk scoring, PDF
    # recommendations) don't penalize a domain for not protecting mail
    # flow it doesn't have. When MX lookup itself failed (error set), we
    # don't know either way — also treat as informational rather than
    # guessing.
    uses_email = bool(mx.get("has_mx")) and not mx.get("error")

    spf["informational_only"] = not uses_email
    dmarc["informational_only"] = not uses_email
    dkim["informational_only"] = not uses_email

    return {
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "uses_email": uses_email,
    }
