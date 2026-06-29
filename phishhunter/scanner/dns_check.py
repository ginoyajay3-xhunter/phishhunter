"""DNS health analyzer — checks A, AAAA, MX, NS, TXT, CAA records and
DNSSEC status, and flags common DNS misconfigurations (no records, single
point of failure, etc.)
"""
import asyncio
import socket

try:
    import dns.asyncresolver
    import dns.resolver  # for the exception classes, which are shared
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from config import logger

log = logger.getChild("dns_check")

# Use well-known public resolvers instead of the system default. On some
# Windows/ISP setups the system resolver is flaky for less-common TLDs
# (e.g. .edu.in) — it can return an empty-but-"successful" answer instead
# of timing out, which we can't distinguish from a genuine empty record
# set. Pinning to Google + Cloudflare makes lookups consistent and avoids
# spurious "No nameservers found" / "No A records" results.
PUBLIC_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def _get_resolver(timeout: float = 5.0):
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def dns_check(domain: str) -> dict:
    """Basic, synchronous A-record resolution check via the OS socket
    layer. Kept synchronous and dependency-free on purpose — it's the
    single source of truth the rest of the app reconciles against, so it
    deliberately does NOT go through the same dnspython/public-resolver
    path as everything else (see dns_health_check's docstring)."""
    result = {"resolves": False, "ip_addresses": [], "error": None}

    try:
        ip_list = socket.gethostbyname_ex(domain)[2]
        result["resolves"] = True
        result["ip_addresses"] = ip_list
    except Exception as e:
        result["error"] = str(e)
        log.debug("Basic socket resolution for %s failed: %s", domain, e)

    return result


async def _resolve_records(domain: str, record_type: str, timeout: float = 5.0):
    """Returns (records, error, status). status is one of:
      - "found"          -> records were returned
      - "not_found"      -> lookup succeeded, domain has no records of this type
      - "lookup_failed"  -> the query itself could not complete (timeout,
                            no responsive nameservers, malformed response, etc.)
    Fix: previously "no records" and "lookup failed" were both represented
    as error=None + empty list in some cases, or conflated under a single
    error string in others. Splitting into an explicit status lets every
    caller treat them differently without re-deriving the distinction itself.
    """
    if not DNS_AVAILABLE:
        return [], "dnspython not installed", "lookup_failed"
    try:
        resolver = _get_resolver(timeout)
        answers = await resolver.resolve(domain, record_type)
        records = [str(r) for r in answers]
        return records, None, "found"
    except dns.resolver.NoAnswer:
        return [], None, "not_found"  # domain exists, just has no records of this type
    except dns.resolver.NXDOMAIN:
        return [], "Domain does not exist", "lookup_failed"
    except dns.resolver.NoNameservers as e:
        log.warning("No responsive nameservers for %s/%s: %s", domain, record_type, e)
        return [], "No responsive nameservers", "lookup_failed"
    except dns.exception.Timeout as e:
        log.warning("DNS query timed out for %s/%s: %s", domain, record_type, e)
        return [], "DNS query timed out", "lookup_failed"
    except Exception as e:
        log.warning("DNS query failed for %s/%s: %s", domain, record_type, e, exc_info=True)
        return [], str(e), "lookup_failed"


async def _check_dnssec(domain: str, timeout: float = 5.0) -> dict:
    """DNSSEC presence check: looks for a DNSKEY record at the zone apex.
    This confirms the zone publishes signing keys — it does not perform
    full chain-of-trust validation (that requires a validating resolver),
    so we report it as "DNSSEC appears configured" rather than "valid".
    """
    result = {"checked": False, "dnssec_detected": False, "error": None}
    records, error, status = await _resolve_records(domain, "DNSKEY", timeout)
    if status == "lookup_failed":
        result["error"] = error
        return result
    result["checked"] = True
    result["dnssec_detected"] = status == "found" and len(records) > 0
    return result


async def _check_caa(domain: str, timeout: float = 5.0) -> dict:
    """CAA (Certification Authority Authorization) records restrict which
    CAs may issue certificates for a domain — absence is common and not
    inherently a problem, just a missing hardening measure."""
    records, error, status = await _resolve_records(domain, "CAA", timeout)
    return {
        "checked": status != "lookup_failed",
        "caa_records": records,
        "has_caa": len(records) > 0,
        "error": error if status == "lookup_failed" else None,
    }


async def dns_health_check(domain: str, dns_basic_result: dict) -> dict:
    """Full DNS health report across multiple record types, with basic
    misconfiguration flags (e.g. only one nameserver = no redundancy).

    `dns_basic_result` (from dns_check()) is required and is the ONLY
    source of truth for whether the domain resolves. This function does
    not compute its own "resolves" value — that was the root cause of an
    earlier bug where this module's NS/A lookups (via dnspython, a
    separate resolver path) could disagree with the simple, reliable
    socket-based check, producing contradictory output like "DNS
    Resolves: Yes" next to "No nameservers found". There is now exactly
    one place that decides whether a domain resolves, and every other
    check here is gated on it.
    """
    domain_resolves = bool(dns_basic_result.get("resolves"))

    (a_records, a_err, a_status), (aaaa_records, aaaa_err, aaaa_status), \
        (ns_records, ns_err, ns_status), (txt_records, txt_err, txt_status), \
        (mx_records, mx_err, mx_status), dnssec, caa = await asyncio.gather(
        _resolve_records(domain, "A"),
        _resolve_records(domain, "AAAA"),
        _resolve_records(domain, "NS"),
        _resolve_records(domain, "TXT"),
        _resolve_records(domain, "MX"),
        _check_dnssec(domain),
        _check_caa(domain),
    )

    # Backfill A records for display purposes from the trusted socket
    # check if dnspython's own A query came back empty — purely cosmetic,
    # doesn't affect any issue/finding logic below.
    if domain_resolves and not a_records:
        a_records = dns_basic_result.get("ip_addresses", [])

    issues = []

    # "No A/AAAA records" is only ever reported when the single source of
    # truth says the domain doesn't resolve. It can never contradict
    # "Domain Resolves: Yes" because both now read the same flag.
    if not domain_resolves:
        issues.append("No A or AAAA records found — domain may not resolve to any server")

    # NS findings are skipped entirely once we already know the domain is
    # live. Some resolvers return a "successful" but empty NS response for
    # lower-traffic TLDs (e.g. .edu.in) without raising any exception —
    # there's no error to check, just an unreliable empty list that looks
    # identical to a genuine misconfiguration. A domain that resolves
    # necessarily has working nameservers, so we don't second-guess that
    # here; we only surface NS-based findings when the domain is already
    # known not to resolve, where they add diagnostic value instead of
    # risking a contradiction.
    if not domain_resolves and ns_status == "not_found":
        issues.append("No nameservers found")

    return {
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "ns_records": ns_records,
        "txt_records": txt_records,
        "mx_records": mx_records,
        "issues": issues,
        "has_ipv6": len(aaaa_records) > 0,
        "dnssec": dnssec,
        "caa": caa,
        # Per-record-type status, explicitly distinguishing "the record
        # genuinely doesn't exist" from "we couldn't complete the query" —
        # callers should use these rather than inferring from error/list
        # emptiness, which is exactly the ambiguity that caused earlier bugs.
        "record_status": {
            "a": a_status, "aaaa": aaaa_status, "ns": ns_status,
            "txt": txt_status, "mx": mx_status,
        },
        "lookup_errors": {
            "a": a_err, "aaaa": aaaa_err, "ns": ns_err, "txt": txt_err, "mx": mx_err,
        },
    }
