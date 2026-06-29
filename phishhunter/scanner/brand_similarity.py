"""Brand impersonation detection.

Two complementary techniques:
1. Homograph detection — catches lookalike Unicode/punycode tricks (e.g. Cyrillic 'а' instead of Latin 'a').
2. Levenshtein distance — catches simple character-substitution typosquats (e.g. 'paypaI.com', 'g00gle.com').

Neither proves malicious intent on its own — many legitimate small businesses
have names that happen to be similar to bigger brands. Treat this as a signal
to review, not an automatic verdict.
"""

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple", "facebook",
    "instagram", "netflix", "ebay", "linkedin", "twitter", "whatsapp",
    "icicibank", "hdfcbank", "sbi", "axisbank", "irctc",
    "outlook", "yahoo", "dropbox", "adobe",
]


def levenshtein_distance(a: str, b: str) -> int:
    """Standard edit-distance computation, no external dependency needed."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def has_homograph_chars(domain: str) -> bool:
    """Detect punycode (xn--) prefixes, which indicate non-ASCII characters
    were used in the original domain — a common homograph attack vector."""
    return "xn--" in domain.lower()


def check_brand_similarity(domain: str, brands=None, max_distance: int = 2) -> dict:
    """Compare the domain's main label against a list of known brand names.

    Returns the closest match, if any, within max_distance edits — flags
    domains that are suspiciously close to a known brand without being
    an exact (legitimate) match.
    """
    if brands is None:
        brands = KNOWN_BRANDS

    # Strip TLD and common subdomains to get the core label, e.g.
    # "secure-paypal-login.com" -> "secure-paypal-login"
    core = domain.lower().split(".")[0] if "." in domain else domain.lower()
    core_no_hyphen = core.replace("-", "")
    # also check each hyphen/dot-separated segment individually, since brand
    # names are often combined with other words (e.g. "paypal-secure-login")
    segments = [s for s in core.replace("-", " ").split() if s]

    matches = []
    for brand in brands:
        if brand == core or brand == core_no_hyphen:
            continue  # exact match is the real brand itself, not impersonation

        candidates = [core, core_no_hyphen] + segments
        best_dist = min(levenshtein_distance(c, brand) for c in candidates)
        substring_hit = brand in core

        if best_dist <= max_distance or substring_hit:
            matches.append({
                "brand": brand,
                "edit_distance": best_dist,
                "appears_as_substring": substring_hit,
            })

    matches.sort(key=lambda m: m["edit_distance"])

    return {
        "domain_core": core,
        "has_homograph": has_homograph_chars(domain),
        "potential_brand_matches": matches,
    }
