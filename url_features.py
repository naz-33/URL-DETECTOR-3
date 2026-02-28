import re
import numpy as np
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".link", ".pw", ".cc", ".ws", ".buzz", ".rest", ".ru", ".info",
}

SHORTENER_DOMAINS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password"
]

BRAND_WORDS = [
    "google", "gmail", "yahoo", "microsoft", "outlook", "amazon", "apple", "paypal",
    "netflix", "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "dhl", "fedex", "ups", "usps", "chase", "bankofamerica", "wellsfargo", "citibank",
]


def _normalize_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    value = url.strip()
    if value and "://" not in value:
        value = "http://" + value
    return value


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return float(-sum(p * np.log2(p) for p in prob if p > 0))


def extract_url_features(url: str) -> dict:
    """Extract URL features in snake_case keys used by model/rules pipelines."""
    raw_url = url if isinstance(url, str) else ""
    normalized = _normalize_url(raw_url)

    try:
        parsed = urlparse(normalized)
    except Exception:
        parsed = urlparse("http://")

    domain = (parsed.netloc or parsed.path.split('/')[0] if parsed.path else "").lower()
    domain_only = domain.split(':')[0]
    path = parsed.path or ""
    query = parsed.query or ""
    tld = "." + domain_only.split(".")[-1] if "." in domain_only else ""
    subdomain_part = ""
    parts = domain_only.split(".") if domain_only else []
    if len(parts) > 2:
        subdomain_part = ".".join(parts[:-2])

    num_digits = sum(c.isdigit() for c in raw_url)

    features = {
        "url_length": len(raw_url),
        "domain_length": len(domain),
        "path_length": len(path),
        "num_dots": raw_url.count('.'),
        "num_hyphens": raw_url.count('-'),
        "num_underscores": raw_url.count('_'),
        "num_slashes": raw_url.count('/'),
        "num_digits": num_digits,
        "num_special_chars": len(re.findall(r'[!@#$%^&*()+=\[\]{}|;:,<>?]', raw_url)),
        "has_ip": 1 if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain_only) else 0,
        "has_https": 1 if normalized.startswith('https://') else 0,
        "has_http": 1 if normalized.startswith('http://') else 0,
        "num_subdomains": max(domain_only.count('.') - 1, 0),
        "has_at_symbol": 1 if '@' in raw_url else 0,
        "has_double_slash": 1 if '//' in normalized[8:] else 0,
        "digit_ratio": (num_digits / len(raw_url)) if len(raw_url) > 0 else 0,
        "letter_ratio": (sum(c.isalpha() for c in raw_url) / len(raw_url)) if len(raw_url) > 0 else 0,
        "num_params": raw_url.count('='),
        "num_fragments": raw_url.count('#'),
        "num_percent": raw_url.count('%'),
        "entropy": calculate_entropy(raw_url),
        "has_port": 1 if ':' in domain and any(c.isdigit() for c in domain.split(':')[-1]) else 0,
        "is_shortened": 1 if any(short in domain_only for short in SHORTENER_DOMAINS) else 0,
        "suspicious_words": sum(1 for word in SUSPICIOUS_WORDS if word in raw_url.lower()),
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
    }

    # Compatibility keys for model feature_names.pkl (CamelCase -> snake_case)
    path_segments = [seg for seg in path.split("/") if seg]
    contains_brand_in_path = any(brand in (path + query).lower() for brand in BRAND_WORDS)
    contains_brand_in_subdomain = any(brand in subdomain_part for brand in BRAND_WORDS)
    has_embedded_brand = 1 if (contains_brand_in_subdomain or contains_brand_in_path) else 0

    longest_token_len = 0
    for token in re.split(r"[^a-zA-Z0-9]", raw_url):
        if len(token) > longest_token_len:
            longest_token_len = len(token)
    random_string = 1 if (features["entropy"] >= 4.0 and longest_token_len >= 12) else 0

    features.update({
        "subdomain_level": features["num_subdomains"],
        "path_level": len(path_segments),
        "num_dash": features["num_hyphens"],
        "num_dash_in_hostname": domain_only.count("-"),
        "at_symbol": features["has_at_symbol"],
        "tilde_symbol": 1 if "~" in raw_url else 0,
        "num_underscore": features["num_underscores"],
        "num_query_components": len([q for q in query.split("&") if q]) if query else 0,
        "num_ampersand": raw_url.count("&"),
        "num_hash": features["num_fragments"],
        "num_numeric_chars": features["num_digits"],
        "no_https": 0 if features["has_https"] == 1 else 1,
        "ip_address": features["has_ip"],
        "domain_in_subdomains": 1 if contains_brand_in_subdomain else 0,
        "domain_in_paths": 1 if contains_brand_in_path else 0,
        "https_in_hostname": 1 if "https" in domain_only else 0,
        "hostname_length": len(domain_only),
        "query_length": len(query),
        "double_slash_in_path": 1 if "//" in path else 0,
        "num_sensitive_words": features["suspicious_words"],
        "embedded_brand_name": has_embedded_brand,
        "random_string": random_string,
    })

    return features
