"""Rule-based URL safety checks: sensitive words, brand names, misspellings, and phishing heuristics."""
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import os
import json

from url_features import extract_url_features
from download_phishtank_data import auto_update_database

# High-risk credential / urgency words: increase phishing suspicion when combined with structural risks
HIGH_RISK_CREDENTIAL_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "reset", "password",
    "billing", "confirm", "authenticate", "account-update", "verify-account",
    "secure-login", "account-recovery", "credentials", "passwd", "verification",
    # urgency / support words added for broader phishing coverage
    "update", "secure", "alert", "support", "invoice", "suspended", "unlock",
]

# Neutral security-related words: alone should NOT cause UNSAFE
NEUTRAL_SECURITY_WORDS = [
    "security", "support", "help", "account", "service", "center",
]

# Well-known legitimate platforms; do NOT classify UNSAFE based only on keywords
TRUSTED_DOMAINS = {
    "github.com",
    "google.com",
    "microsoft.com",
    "microsoftonline.com",
    "paypal.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "apple.com",
    "linkedin.com",
    "netflix.com",
    "stripe.com",
    "aws.amazon.com",
    "dropbox.com",
    "twitter.com",
    "x.com",
    "chatgpt.com",
}

# All sensitive/phishing-related words (for detection display)
SENSITIVE_WORDS = [
    "login", "log-in", "signin", "sign-in", "account", "verify", "verification",
    "password", "passwd", "credentials", "secure", "security", "update",
    "suspended", "locked", "confirm", "validation", "authenticate",
    "bank", "banking", "wire", "transfer", "payment", "paypal", "refund",
    "support", "helpdesk", "alert", "urgent", "immediate", "action-required",
    "click", "verify-account", "secure-login", "account-recovery",
    "admin", "administrator", "reset", "unlock", "restore", "billing",
]

# Commonly spoofed brands (phishers impersonate these)
BRAND_NAMES = [
    "google", "gmail", "yahoo", "microsoft", "outlook", "live", "office365",
    "amazon", "apple", "paypal", "netflix", "facebook", "instagram", "twitter",
    "linkedin", "dropbox", "adobe", "dhl", "fedex", "ups", "usps",
    "chase", "bankofamerica", "wellsfargo", "citibank", "capitalone",
    "ebay", "aliexpress", "walmart", "target", "bestbuy", "costco","chatgpt",
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".link", ".pw", ".cc", ".ws", ".buzz", ".rest", ".ru", ".info",".ch",".cfd"
}

# Known URL shortening services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at"
}

# Free hosting / site builders often abused in phishing
FREE_HOSTING_DOMAINS = {
    "000webhostapp.com", "weebly.com", "wixsite.com",
    "blogspot.com", "wordpress.com", "github.io",
    "firebaseapp.com", "netlify.app","framer.app",
}


def _normalize_for_matching(text: str) -> str:
    """Lowercase and keep only alphanumeric for matching."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


# Leetspeak -> plain-letter normalization table
_LEET_TABLE = str.maketrans("01345@", "oieasa")


def _leet_normalize(text: str) -> str:
    """Normalize common leetspeak substitutions (0→o, 1→i, 3→e, 4→a, 5→s, @→a)."""
    return text.lower().translate(_LEET_TABLE)


def _generate_misspell_patterns(brand: str) -> list[re.Pattern]:
    """
    Generate regex patterns for common brand misspellings.
    Handles: 0->o, 1->i/l, 5->s, 4->a, 3->e, @->a
    """
    patterns = []
    # Character substitution map
    subs = {
        "o": "[o0]",
        "0": "[o0]",
        "i": "[i1l]",
        "l": "[i1l]",
        "1": "[i1l]",
        "s": "[s5]",
        "5": "[s5]",
        "a": "[a4@]",
        "4": "[a4]",
        "e": "[e3]",
        "3": "[e3]",
    }
    pattern_chars = []
    for c in brand.lower():
        pattern_chars.append(subs.get(c, re.escape(c)))
    pattern = "".join(pattern_chars)
    patterns.append(re.compile(pattern, re.IGNORECASE))
    return patterns


def detect_sensitive_words(url: str) -> list[str]:
    """
    Detect sensitive/phishing-related words in the URL.
    Returns list of matched words.
    """
    if not url:
        return []
    url_lower = url.lower()
    found = []
    for word in SENSITIVE_WORDS:
        # Match whole word or as part of path segment (between / or . or start/end)
        pattern = r"(?:^|[/.\-_])" + re.escape(word) + r"(?:[/.\-_]|$|[?&#])"
        if re.search(pattern, url_lower):
            found.append(word)
    return found


def detect_high_risk_credential_words(url: str) -> list[str]:
    """Detect high-risk credential words that increase phishing suspicion."""
    if not url:
        return []
    url_lower = url.lower()
    found = []
    for word in HIGH_RISK_CREDENTIAL_WORDS:
        pattern = r"(?:^|[/.\-_])" + re.escape(word) + r"(?:[/.\-_]|$|[?&#])"
        if re.search(pattern, url_lower):
            found.append(word)
    return found


def detect_neutral_words(url: str) -> list[str]:
    """Detect neutral security-related words (alone should NOT cause UNSAFE)."""
    if not url:
        return []
    url_lower = url.lower()
    found = []
    for word in NEUTRAL_SECURITY_WORDS:
        pattern = r"(?:^|[/.\-_])" + re.escape(word) + r"(?:[/.\-_]|$|[?&#])"
        if re.search(pattern, url_lower):
            found.append(word)
    return found


def detect_brand_names(url: str) -> list[str]:
    """
    Detect known brand names in hostname or path.
    Returns list of matched brand names.
    """
    if not url or not isinstance(url, str):
        return []
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()
        combined = hostname + "/" + path
    except Exception:
        combined = url.lower()
    found = []
    for brand in BRAND_NAMES:
        # Brand must appear as a distinct segment (surrounded by . / - or boundary)
        pattern = r"(?:^|[/.\-_])" + re.escape(brand) + r"(?:[/.\-_]|$|[?&#])"
        if re.search(pattern, combined):
            found.append(brand)
    return found


def detect_misspelled_brands(url: str) -> list[tuple[str, str]]:
    """
    Detect misspelled brand names (typosquatting).
    Uses character substitution patterns (0/o, 1/l, etc.) and similarity matching.
    Returns list of (matched_fragment, intended_brand).
    """
    if not url:
        return []
    url_lower = url.lower()
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # Extract hostname and path segments
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()
        segments = re.split(r"[/.\-_]", hostname + path)
    except Exception:
        segments = re.split(r"[/.\-_]", url_lower)

    for segment in segments:
        if len(segment) < 4:  # Skip very short segments
            continue
        for brand in BRAND_NAMES:
            if brand in segment:
                continue  # Exact match handled by detect_brand_names
            # Character-substitution pattern
            patterns = _generate_misspell_patterns(brand)
            for pat in patterns:
                m = pat.search(segment)
                if m:
                    match_str = m.group(0)
                    if len(match_str) >= len(brand) * 0.7:  # Require reasonable length
                        key = (match_str, brand)
                        if key not in seen:
                            seen.add(key)
                            found.append((match_str, brand))
                    break

    # Similarity-based for longer segments (catches typos like "gogle", "amazom")
    for segment in segments:
        if len(segment) < 4:
            continue
        for brand in BRAND_NAMES:
            if len(brand) < 4:
                continue
            # Compare segment to brand (or brand-sized sliding window)
            if len(segment) >= len(brand) * 0.8:
                ratio = SequenceMatcher(None, segment, brand).ratio()
                if 0.75 <= ratio < 0.99:  # Similar but not exact
                    key = (segment, brand)
                    if key not in seen:
                        seen.add(key)
                        found.append((segment, brand))

    # Leetspeak-normalization pass: catch "micr0soft", "payp4l", "g00gle" etc.
    for segment in segments:
        if len(segment) < 4:
            continue
        normalized_seg = _leet_normalize(segment)
        for brand in BRAND_NAMES:
            if brand in segment:  # exact match already handled
                continue
            if brand == normalized_seg or (
                len(normalized_seg) >= len(brand) * 0.8
                and SequenceMatcher(None, normalized_seg, brand).ratio() >= 0.85
            ):
                key = (segment, brand)
                if key not in seen:
                    seen.add(key)
                    found.append((segment, brand))
    return found


def _get_registered_domain(hostname: str) -> str:
    """Extract the registered domain (e.g. example.com from sub.example.com)."""
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def _is_trusted_domain(url: str) -> bool:
    """Check if registrable domain is a well-known legitimate platform."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return False
    reg_domain = _get_registered_domain(hostname)
    return reg_domain in TRUSTED_DOMAINS


def _shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy indicates more randomness/complexity.
    """
    import math
    if not text:
        return 0.0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def is_shortened_url(url: str) -> bool:
    """
    Detect if the URL belongs to a known URL shortening service.
    Returns True if the registrable domain matches a known shortener.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return False
    reg_domain = _get_registered_domain(hostname)
    return reg_domain in SHORTENER_DOMAINS


def is_free_hosting_domain(url: str) -> bool:
    """
    Detect domains from free hosting / site builders often abused in phishing.
    Returns True if the registrable domain matches a known free hosting service.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return False
    reg_domain = _get_registered_domain(hostname)
    return reg_domain in FREE_HOSTING_DOMAINS


def contains_ipfs(url: str) -> bool:
    """
    Return True if URL contains IPFS-related indicators.
    Checks for: "ipfs", "/ipfs/", ".ipfs.", "gateway.ipfs"
    """
    if not url or not isinstance(url, str):
        return False
    url_lower = url.lower()
    return (
        "ipfs" in url_lower or
        "/ipfs/" in url_lower or
        ".ipfs." in url_lower or
        "gateway.ipfs" in url_lower
    )


def hostname_entropy(url: str) -> tuple[bool, float]:
    """
    Compute Shannon entropy of the hostname (excluding TLD).
    Returns (is_high_entropy, entropy_value).
    High entropy threshold: > 4.0
    """
    if not url or not isinstance(url, str):
        return False, 0.0
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return False, 0.0
    
    # Remove TLD for entropy calculation
    parts = hostname.split(".")
    if len(parts) > 1:
        hostname_no_tld = ".".join(parts[:-1])
    else:
        hostname_no_tld = hostname
    
    entropy = _shannon_entropy(hostname_no_tld)
    is_high = entropy > 4.0
    return is_high, entropy


def path_entropy(url: str) -> tuple[bool, float]:
    """
    Compute Shannon entropy of the path portion.
    Returns (is_high_entropy, entropy_value).
    High entropy threshold: > 4.3
    """
    if not url or not isinstance(url, str):
        return False, 0.0
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
    except Exception:
        return False, 0.0
    
    if not path or path == "/":
        return False, 0.0
    
    entropy = _shannon_entropy(path)
    is_high = entropy > 4.3
    return is_high, entropy


def detect_subdomain_tricks(url: str) -> list[str]:
    """
    Detect brand names in subdomains but NOT in the actual registered domain.
    e.g. google-security.com vs security.google.com (legit)
    Returns list of brands found only in subdomains.
    """
    if not url or not isinstance(url, str):
        return []
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return []
    # Skip IP addresses
    feat = extract_url_features(url)
    if feat.get("has_ip"):
        return []
    reg_domain = _get_registered_domain(hostname)
    subdomain_part = hostname[: -len(reg_domain) - 1] if hostname.endswith("." + reg_domain) else ""
    found = []
    for brand in BRAND_NAMES:
        in_subdomain = brand in subdomain_part
        in_reg_domain = brand in reg_domain
        if in_subdomain and not in_reg_domain:
            found.append(brand)
    return found


# Finance / account lure words that flag suspicious subdomains
_FINANCE_LURE_WORDS = [
    "bank", "paypal", "account", "update", "verify", "secure", "login",
    "billing", "invoice", "support", "alert", "signin", "password",
]


def detect_suspicious_tld_plus_keywords(url: str) -> bool:
    """Suspicious TLD combined with any credential/urgency keyword → UNSAFE."""
    if not url:
        return False
    feat = extract_url_features(url)
    if not feat.get("suspicious_tld"):
        return False
    url_lower = url.lower()
    # Check both high-risk credential words AND wider urgency/finance lure words
    all_trigger_words = set(HIGH_RISK_CREDENTIAL_WORDS) | set(_FINANCE_LURE_WORDS)
    for word in all_trigger_words:
        if word in url_lower:
            return True
    return False


def detect_brand_credential_combo(url: str) -> list[str]:
    """
    Detect brand name present in URL tokens (exact OR leet-normalized) AND
    at least one credential/urgency keyword anywhere in the URL.
    Skips trusted domains to avoid false positives on legitimate brand sites.
    Returns list of (brand, keyword) tuples represented as "brand|keyword" strings.
    """
    if not url or not isinstance(url, str):
        return []
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    # Avoid flagging legitimate brand-owned domains (e.g. google.com/signin)
    if _is_trusted_domain(url):
        return []
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        hostname = ""

    # Split hostname into tokens
    host_tokens = re.split(r"[.\-_]", hostname)

    # Detect credential/urgency keywords in the full URL
    url_lower = url.lower()
    present_creds = [
        w for w in (set(HIGH_RISK_CREDENTIAL_WORDS) | set(_FINANCE_LURE_WORDS))
        if w in url_lower
    ]
    if not present_creds:
        return []

    # Check for brand in tokens (exact or leet-normalized)
    found: list[str] = []
    seen: set[str] = set()
    for token in host_tokens:
        if len(token) < 4:
            continue
        normalized = _leet_normalize(token)
        for brand in BRAND_NAMES:
            # Skip if this is actually the registered domain and brand owns it
            in_token = brand == token or brand == normalized
            if not in_token:
                # Fuzzy: normalized token close to brand
                if len(normalized) >= len(brand) * 0.8:
                    in_token = SequenceMatcher(None, normalized, brand).ratio() >= 0.85
            if in_token:
                for cred in present_creds:
                    key = f"{brand}|{cred}"
                    if key not in seen:
                        seen.add(key)
                        found.append(key)
    return found


def detect_finance_lure_in_subdomain(url: str) -> list[str]:
    """
    Detect finance/account lure keywords in subdomain of a non-trusted domain.
    e.g. secure-login.randomdomain.xyz  →  ["secure", "login"]
    Returns list of matched lure words.
    """
    if not url or not isinstance(url, str):
        return []
    url = url.strip()
    if url and "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or "").lower()
    except Exception:
        return []

    # Only fire on non-trusted domains
    if _is_trusted_domain(url):
        return []

    reg_domain = _get_registered_domain(hostname)
    subdomain_part = hostname[: -len(reg_domain) - 1] if hostname.endswith("." + reg_domain) else ""
    if not subdomain_part:
        return []

    found = []
    for word in _FINANCE_LURE_WORDS:
        if word in subdomain_part:
            found.append(word)
    return found


def detect_ip_address(url: str) -> bool:
    """Use of IP address instead of proper domain → UNSAFE."""
    feat = extract_url_features(url)
    return bool(feat.get("has_ip"))


def detect_excessive_hyphens_credentials(url: str) -> bool:
    """Excessive hyphens combined with high-risk credential words → UNSAFE."""
    if not url:
        return False
    feat = extract_url_features(url)
    num_hyphens = feat.get("num_hyphens", 0)
    if num_hyphens < 3:
        return False
    url_lower = url.lower()
    for word in HIGH_RISK_CREDENTIAL_WORDS:
        if word in url_lower:
            return True
    return False


def detect_punycode_encoded(url: str) -> bool:
    """Encoded, obfuscated, or punycode domains (xn--) → UNSAFE."""
    if not url:
        return False
    url_lower = url.lower()
    return "xn--" in url_lower


def detect_urgency_credential_words(url: str) -> list[str]:
    """High-risk credential words (login, verify, reset, etc.). Kept for backward compat."""
    return detect_high_risk_credential_words(url)


def is_unsafe_by_rules(url: str) -> tuple[bool, list[str]]:
    """
    Returns (is_unsafe, reasons).
    Structured reasoning: UNSAFE only when strong phishing indicators or
    suspicious combinations are present. Neutral words alone on trusted
    domains do NOT trigger UNSAFE.
    """
    reasons = []
    findings = run_rule_checks(url)

    # Structural indicators (always UNSAFE when present, except on trusted+no-others)
    has_typosquatting = bool(findings.get("misspelled_brands"))
    has_subdomain_trick = bool(findings.get("subdomain_tricks"))
    has_ip = bool(findings.get("has_ip"))
    has_punycode = bool(findings.get("punycode_encoded"))
    has_suspicious_tld_keywords = bool(findings.get("suspicious_tld_keywords"))
    has_excessive_hyphens_creds = bool(findings.get("excessive_hyphens_credentials"))
    
    # New structural indicators (always UNSAFE)
    has_shortened_url = bool(findings.get("is_shortened_url"))
    has_ipfs = bool(findings.get("contains_ipfs"))
    
    # Conditional indicators (UNSAFE only when combined with phishing signals)
    has_free_hosting = bool(findings.get("is_free_hosting_domain"))
    has_hostname_entropy = bool(findings.get("hostname_entropy_high"))
    has_path_entropy = bool(findings.get("path_entropy_high"))
    
    # Phishing signals that can trigger conditional indicators
    has_high_risk_creds = bool(findings.get("high_risk_credential_words"))
    has_brand_cred_combo = bool(findings.get("brand_credential_combo"))
    
    # Check if conditional indicators should trigger UNSAFE
    phishing_signals_present = (
        has_high_risk_creds
        or has_brand_cred_combo
        or has_typosquatting
        or has_suspicious_tld_keywords
    )

    structural_indicators = (
        has_typosquatting
        or has_subdomain_trick
        or has_ip
        or has_punycode
        or has_suspicious_tld_keywords
        or has_excessive_hyphens_creds
        or has_shortened_url
        or has_ipfs
    )
    
    # Conditional risk: free hosting or high entropy + phishing signals
    conditional_risk = (
        (has_free_hosting or has_hostname_entropy or has_path_entropy)
        and phishing_signals_present
    )

    trusted = _is_trusted_domain(url)

    if trusted:
        # On trusted domains: only UNSAFE if structural indicators present
        # Structural abuse (IPFS, shortened URLs, typosquatting, IP, punycode) still override
        # Keywords alone (high-risk or neutral) do NOT trigger UNSAFE
        # Entropy/free hosting alone do NOT trigger UNSAFE even with keywords on trusted domains
        if structural_indicators:
            if has_typosquatting:
                reasons.append("Typosquatting or misspelled brand names")
            if has_subdomain_trick:
                reasons.append("Subdomain tricks (brand in subdomain, not actual domain)")
            if has_suspicious_tld_keywords:
                reasons.append("Suspicious TLD combined with credential keywords")
            if has_ip:
                reasons.append("IP address used instead of proper domain")
            if has_excessive_hyphens_creds:
                reasons.append("Excessive hyphens with credential-related words")
            if has_punycode:
                reasons.append("Encoded, obfuscated, or punycode domain (xn--)")
            if has_shortened_url:
                reasons.append("Known URL shortening service (structural risk)")
            if has_ipfs:
                reasons.append("IPFS-based URL (structural risk)")
            return True, reasons
        return False, []

    # Untrusted domain: strong indicators or suspicious combos → UNSAFE
    
    # Always-UNSAFE structural indicators
    if has_typosquatting:
        reasons.append("Typosquatting or misspelled brand names")
    if has_subdomain_trick:
        reasons.append("Subdomain tricks (brand in subdomain, not actual domain)")
    if has_ip:
        reasons.append("IP address used instead of proper domain")
    if has_punycode:
        reasons.append("Encoded, obfuscated, or punycode domain (xn--)")
    if has_suspicious_tld_keywords:
        reasons.append("Suspicious TLD combined with credential keywords")
    if has_excessive_hyphens_creds:
        reasons.append("Excessive hyphens with credential-related words")
    if has_shortened_url:
        reasons.append("Known URL shortening service (structural risk)")
    if has_ipfs:
        reasons.append("IPFS-based URL (structural risk)")
    
    # Conditional indicators: only trigger when combined with phishing signals
    if conditional_risk:
        if has_free_hosting and phishing_signals_present:
            reasons.append("Free hosting domain combined with credential/brand phishing indicators")
        if has_hostname_entropy and phishing_signals_present:
            reasons.append("High hostname entropy combined with credential/brand phishing indicators")
        if has_path_entropy and phishing_signals_present:
            reasons.append("High path entropy combined with credential/brand phishing indicators")

    if reasons:
        return True, reasons
    return False, []


def _normalize_url_for_comparison(url: str) -> tuple[str, str, str]:
    """
    Normalize a URL for accurate comparison.
    Returns tuple: (normalized_netloc, path, full_normalized_url)
    - normalized_netloc: domain without www. prefix, lowercased
    - path: the path component (including query and fragment)
    - full_normalized_url: complete normalized URL for fallback matching
    """
    try:
        url_stripped = url.strip()
        
        # Add scheme if missing (required for urlparse to work correctly)
        if '://' not in url_stripped:
            url_stripped = 'http://' + url_stripped
        
        # Parse the URL
        parsed = urlparse(url_stripped)
        
        # Get netloc (domain) and normalize
        netloc = parsed.netloc.lower()
        
        # Remove www. prefix for consistent comparison
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        # Get path (including query and fragment)
        path = parsed.path or ""
        if parsed.query:
            path += "?" + parsed.query
        if parsed.fragment:
            path += "#" + parsed.fragment
        
        # Create full normalized URL (without scheme and www)
        full_url = netloc + path
        
        return netloc, path, full_url
    except Exception:
        # Fallback: simple normalization
        url_lower = url.strip().lower()
        for prefix in ["https://", "http://"]:
            if url_lower.startswith(prefix):
                url_lower = url_lower[len(prefix):]
                break
        if url_lower.startswith("www."):
            url_lower = url_lower[4:]
        return url_lower, "", url_lower


def check_phishtank_database(url: str) -> dict:
    """
    Check if the URL exists in the PhishTank database of known phishing URLs.
    Returns dict with 'flagged' (bool), 'message' (str), and optional details.
    Uses accurate domain and path matching to avoid false positives/negatives.
    Automatically updates database if it's older than 24 hours.
    """
    PHISHTANK_FILE = "online-valid.json"
    
    # Auto-update database if outdated (this will download if missing or >24h old)
    try:
        auto_update_database()
    except Exception as e:
        print(f"Warning: Could not auto-update PhishTank database: {e}")
    
    # Check if PhishTank database file exists
    if not os.path.exists(PHISHTANK_FILE):
        return {
            "flagged": False,
            "message": "PhishTank database not available",
            "error": True
        }
    
    try:
        # Load PhishTank data
        with open(PHISHTANK_FILE, 'r', encoding='utf-8') as f:
            phishtank_data = json.load(f)
        
        # Normalize the input URL
        user_netloc, user_path, user_full = _normalize_url_for_comparison(url)
        
        # Check against PhishTank database
        for entry in phishtank_data:
            phish_url = entry.get('url', '')
            if not phish_url:
                continue
            
            # Normalize the PhishTank URL
            phish_netloc, phish_path, phish_full = _normalize_url_for_comparison(phish_url)
            
            # MATCH CRITERIA (multiple levels for accuracy):
            
            # 1. Exact full match (domain + path)
            if user_full == phish_full:
                return {
                    "flagged": True,
                    "message": "⚠️ URL flagged by PhishTank (exact match)",
                    "phish_id": entry.get('phish_id', 'N/A'),
                    "verified": entry.get('verified', 'N/A'),
                    "submission_time": entry.get('submission_time', 'N/A'),
                    "error": False
                }
            
            # 2. Domain match + path prefix match (for URLs with query params or longer paths)
            # This handles cases where user enters base URL but PhishTank has full path
            if user_netloc == phish_netloc:
                # Both have same domain
                # If paths match or one is prefix of the other (for query string variations)
                if user_path == phish_path:
                    return {
                        "flagged": True,
                        "message": "⚠️ URL flagged by PhishTank (domain and path match)",
                        "phish_id": entry.get('phish_id', 'N/A'),
                        "verified": entry.get('verified', 'N/A'),
                        "submission_time": entry.get('submission_time', 'N/A'),
                        "error": False
                    }
                
                # Allow fuzzy path matching: if user path is a significant prefix of phish path
                # or if normalized paths (removing trailing /) match
                user_path_norm = user_path.rstrip('/')
                phish_path_norm = phish_path.rstrip('/')
                
                if user_path_norm and phish_path_norm:
                    # Check if one path starts with the other (for partial URL entries)
                    if (phish_path_norm.startswith(user_path_norm) or 
                        user_path_norm.startswith(phish_path_norm)):
                        # Only match if the prefix is substantial (not just "/")
                        if len(user_path_norm) > 1 or len(phish_path_norm) > 1:
                            return {
                                "flagged": True,
                                "message": "⚠️ URL flagged by PhishTank (domain match, similar path)",
                                "phish_id": entry.get('phish_id', 'N/A'),
                                "verified": entry.get('verified', 'N/A'),
                                "submission_time": entry.get('submission_time', 'N/A'),
                                "error": False
                            }
                
                # If domain matches but path differs significantly, still flag with lower confidence
                # This catches cases where the domain is the phishing site but path is different
                if phish_path_norm and user_path_norm:
                    # Both have non-trivial paths that don't match
                    # Don't flag - likely different pages on same domain
                    continue
                elif not user_path_norm and not phish_path_norm:
                    # Both have minimal paths (just domain or domain/)
                    # Flag as domain-level match
                    return {
                        "flagged": True,
                        "message": "⚠️ URL flagged by PhishTank (domain match)",
                        "phish_id": entry.get('phish_id', 'N/A'),
                        "verified": entry.get('verified', 'N/A'),
                        "submission_time": entry.get('submission_time', 'N/A'),
                        "error": False
                    }
                else:
                    # One has a path, the other doesn't
                    # Don't flag - the phishing may be on a specific page/path
                    # and user is checking just the domain (likely legitimate)
                    continue
        
        # URL not found in database
        return {
            "flagged": False,
            "message": "Not found in PhishTank database",
            "error": False
        }
    
    except json.JSONDecodeError:
        return {
            "flagged": False,
            "message": "Error reading PhishTank database",
            "error": True
        }
    except Exception as e:
        return {
            "flagged": False,
            "message": f"Error checking PhishTank: {str(e)}",
            "error": True
        }


def run_rule_checks(url: str) -> dict:
    """
    Run all rule-based checks and return findings.
    Returns dict with keys for display and is_unsafe_by_rules evaluation.
    """
    subdomain_tricks = detect_subdomain_tricks(url)
    high_risk = detect_high_risk_credential_words(url)
    brand_cred_combo = detect_brand_credential_combo(url)
    finance_lure = detect_finance_lure_in_subdomain(url)
    
    # New entropy checks
    hostname_entropy_high, hostname_entropy_val = hostname_entropy(url)
    path_entropy_high, path_entropy_val = path_entropy(url)
    
    # PhishTank database check
    phishtank_result = check_phishtank_database(url)
    
    return {
        "sensitive_words": detect_sensitive_words(url),
        "brand_names": detect_brand_names(url),
        "misspelled_brands": detect_misspelled_brands(url),
        "subdomain_tricks": subdomain_tricks,
        "suspicious_tld_keywords": detect_suspicious_tld_plus_keywords(url),
        "has_ip": detect_ip_address(url),
        "excessive_hyphens_credentials": detect_excessive_hyphens_credentials(url),
        "punycode_encoded": detect_punycode_encoded(url),
        "urgency_credential_words": high_risk,
        "high_risk_credential_words": high_risk,
        "neutral_words": detect_neutral_words(url),
        # new findings
        "brand_credential_combo": brand_cred_combo,
        "finance_lure_subdomain": finance_lure,
        # new structural and entropy indicators
        "is_shortened_url": is_shortened_url(url),
        "is_free_hosting_domain": is_free_hosting_domain(url),
        "contains_ipfs": contains_ipfs(url),
        "hostname_entropy_high": hostname_entropy_high,
        "hostname_entropy_value": hostname_entropy_val,
        "path_entropy_high": path_entropy_high,
        "path_entropy_value": path_entropy_val,
        # PhishTank check result
        "phishtank_flagged": phishtank_result.get("flagged", False),
        "phishtank_message": phishtank_result.get("message", ""),
        "phishtank_details": phishtank_result,
    }
