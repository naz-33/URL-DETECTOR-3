import streamlit as st
import pickle
import joblib
import numpy as np
import re
import os
import warnings
from urllib.parse import urlparse
from url_features import extract_url_features

# Common legitimate TLDs for domain validation
COMMON_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil',
    'io', 'co', 'ai', 'app', 'dev', 'tech',
    'uk', 'de', 'fr', 'jp', 'au', 'ca', 'br', 'in',
    'info', 'biz', 'me', 'tv', 'cc', 'ws',
    'xyz', 'online', 'site', 'website', 'store'
}


def has_valid_tld(domain: str) -> bool:
    """Check if a domain has a valid/legitimate TLD.
    
    Args:
        domain: Domain name (e.g., 'example.com' or 'example.com:8080')
        
    Returns:
        True if the TLD is in the list of common legitimate TLDs, False otherwise
    """
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Extract TLD (last part after final dot)
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1].lower()
    
    # Check if TLD is in our whitelist
    return tld in COMMON_TLDS


def looks_like_domain(text: str) -> bool:
    """Return True if text looks like a domain name (not an IP check).
    
    A domain-like string:
    - Contains at least one dot
    - Has no spaces
    - Only contains valid domain characters (letters, numbers, dots, hyphens, underscores, slashes, colons for ports)
    """
    if not text or ' ' in text:
        return False
    
    # Must contain at least one dot
    if '.' not in text:
        return False
    
    # Check for valid domain characters (allowing path and port)
    # Valid: letters, numbers, dots, hyphens, underscores, slashes, colons, question marks, equals, ampersands
    import string
    valid_chars = string.ascii_letters + string.digits + '.-_/:?=&%#'
    if not all(c in valid_chars for c in text):
        return False
    
    return True


def normalize_url(raw_input: str) -> str:
    """Normalize user input by adding https:// scheme if missing.
    
    Args:
        raw_input: Raw user input string
        
    Returns:
        Normalized URL with scheme, or original input if it doesn't look like a domain
    """
    stripped = raw_input.strip()
    
    if not stripped:
        return stripped
    
    # Check if scheme is already present
    if '://' in stripped:
        return stripped
    
    # If it looks like a domain, prepend https://
    if looks_like_domain(stripped):
        return f"https://{stripped}"
    
    # Otherwise, return as-is and let validation handle it
    return stripped


def is_valid_url(url: str) -> bool:
    """Return True if url is a well-formed http/https URL with a real domain."""
    try:
        parsed = urlparse(url.strip())
        
        # Basic checks
        if not (parsed.scheme in ("http", "https") and bool(parsed.netloc)):
            return False
        
        # Must contain at least one dot
        if "." not in parsed.netloc:
            return False
        
        # Must be longer than 3 characters
        if len(parsed.netloc) <= 3:
            return False
        
        return True
    except Exception:
        return False

# ── Load and inject external CSS ──────────────────────────────────────────────
def load_css():
    css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Get the directory of the current script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Load the model and feature names
@st.cache_resource
def load_model():
    model_path = os.path.join(SCRIPT_DIR, "hybrid_model.pkl")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = joblib.load(model_path)
    return model

@st.cache_resource
def load_feature_names():
    feature_path = os.path.join(SCRIPT_DIR, "feature_names.pkl")
    with open(feature_path, "rb") as f:
        feature_names = pickle.load(f)
    return feature_names

def camel_to_snake(name):
    """Convert CamelCase to snake_case. """
    # Insert underscore before uppercase letters that follow lowercase letters or digits
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    # Insert underscore before uppercase letters that follow lowercase letters, digits, or uppercase letters
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1)
    # Convert to lowercase
    return s2.lower()

def extract_features(url, feature_names):
    """Extract features from a URL based on feature_names."""
    features = extract_url_features(url)

    aliases = {
        "num_dash_in_hostname": "num_hyphens",
        "num_dash": "num_hyphens",
        "qty_dot": "num_dots",
        "qty_hyphen": "num_hyphens",
        "qty_underline": "num_underscores",
        "qty_slash": "num_slashes",
        "qty_digit": "num_digits",
        "qty_special_char": "num_special_chars",
        "qty_params": "num_params",
        "qty_fragment": "num_fragments",
        "qty_percent": "num_percent",
    }
    
    # Build feature vector in the correct order
    feature_vector = []
    for name in feature_names:
        # Convert CamelCase feature name to snake_case
        normalized_name = camel_to_snake(name)

        if normalized_name in features:
            feature_vector.append(features[normalized_name])
            continue

        alias_key = aliases.get(normalized_name)
        if alias_key and alias_key in features:
            feature_vector.append(features[alias_key])
            continue

        compact = normalized_name.replace("_", "")
        compact_match = next((k for k in features.keys() if k.replace("_", "") == compact), None)
        if compact_match:
            feature_vector.append(features[compact_match])
            continue

        feature_vector.append(0)  # Default value if feature not found
    
    return np.array(feature_vector).reshape(1, -1), features

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in prob if p > 0)

def rule_based_checks(url):
    """Compute rule score and triggered rule descriptions for a URL.
    Returns (rule_score, rule_hits, engine_error) where engine_error is None on success.
    """
    rule_score = 0
    rule_hits = []
    engine_error = None

    try:
        from rules import run_rule_checks
        findings = run_rule_checks(url)
    except Exception as exc:
        engine_error = str(exc)
        print(f"[PhisIchno] Rule engine error for {url!r}: {exc}")
        findings = {}

    def add_hit(points, description, condition):
        nonlocal rule_score
        if condition:
            rule_score += points
            rule_hits.append(f"{description} (+{points})")

    # PhishTank check - highest priority as it's a known phishing database
    add_hit(10, "URL flagged by PhishTank", bool(findings.get("phishtank_flagged")))
    
    add_hit(5, "IP address used instead of domain", bool(findings.get("has_ip")))
    add_hit(4, "Punycode/obfuscated domain detected", bool(findings.get("punycode_encoded")))
    add_hit(4, "Misspelled brand/typosquatting detected", bool(findings.get("misspelled_brands")))
    add_hit(4, "Brand found in suspicious subdomain", bool(findings.get("subdomain_tricks")))
    add_hit(3, "Suspicious TLD with credential keywords", bool(findings.get("suspicious_tld_keywords")))
    add_hit(2, "Excessive hyphens with credential words", bool(findings.get("excessive_hyphens_credentials")))

    # New combo rules
    brand_cred_hits = findings.get("brand_credential_combo", [])
    if brand_cred_hits:
        # +3 if brand appears specifically in subdomain, else +2
        subdomain_tricks = findings.get("subdomain_tricks", [])
        # Determine whether any triggering brand is also a subdomain-trick brand
        triggering_brands = {entry.split("|")[0] for entry in brand_cred_hits}
        subdomain_brand_overlap = triggering_brands & set(subdomain_tricks)
        points = 3 if subdomain_brand_overlap else 2
        sample = ", ".join(sorted(triggering_brands)[:3])
        add_hit(points, f"Brand + credential keyword combo ({sample})", True)

    finance_lure_hits = findings.get("finance_lure_subdomain", [])
    if finance_lure_hits:
        sample = ", ".join(finance_lure_hits[:3])
        add_hit(2, f"Finance/account lure keyword in subdomain ({sample})", True)

    high_risk_words = findings.get("high_risk_credential_words", [])
    if len(high_risk_words) >= 2:
        rule_score += 2
        rule_hits.append(f"Multiple high-risk credential words: {', '.join(high_risk_words[:4])} (+2)")
    elif len(high_risk_words) == 1:
        rule_score += 1
        rule_hits.append(f"High-risk credential word: {high_risk_words[0]} (+1)")

    return int(rule_score), rule_hits, engine_error


# ─────────────────────────────────────────────────────────────────────────────
# Friendly copywriting map  (technical key → user-friendly sentence)
# ─────────────────────────────────────────────────────────────────────────────
_FRIENDLY_RULE_MESSAGES: dict[str, str] = {
    "URL flagged by PhishTank":
        "This URL is listed in PhishTank's database of verified phishing sites.",
    "IP address used instead of domain":
        "Raw IP address used instead of a proper domain name.",
    "Punycode/obfuscated domain detected":
        "Domain uses encoding tricks (possible obfuscation).",
    "Misspelled brand/typosquatting detected":
        "Domain resembles a trusted brand name (possible impersonation).",
    "Brand found in suspicious subdomain":
        "Brand-like wording appears in a subdomain (may be misleading).",
    "Suspicious TLD with credential keywords":
        "High-risk domain ending used with login-related keywords.",
    "Excessive hyphens with credential words":
        "Unusual number of hyphens combined with sensitive keywords.",
}


def _friendly_rule(raw: str) -> str:
    """Convert a technical rule hit string to a short, user-friendly reason."""
    for key, friendly in _FRIENDLY_RULE_MESSAGES.items():
        if key.lower() in raw.lower():
            return friendly
    raw_lower = raw.lower()
    if "brand" in raw_lower and "credential" in raw_lower:
        return "Known brand name combined with sensitive keywords (possible phishing lure)."
    if "finance" in raw_lower or "lure" in raw_lower:
        return "Finance or account-related keyword found in a suspicious subdomain."
    if "multiple high-risk" in raw_lower or "high-risk credential word" in raw_lower:
        return "Multiple sensitive keywords detected in the URL."
    # Strip the point annotation (+N) from raw and return cleaned text
    return re.sub(r"\s*\(\+\d+\)\s*$", "", raw).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Summary-first results renderer
# ─────────────────────────────────────────────────────────────────────────────
def render_results_ui(result: dict) -> None:
    """Render a clean, summary-first UI for a URL analysis result."""
    prediction    = result["prediction"]
    phishing_prob = result.get("phishing_prob", 0.0)
    rule_score    = result.get("rule_score", 0)
    rule_hits     = result.get("rule_hits", [])
    engine_error  = result.get("engine_error", None)
    features_dict = result.get("features_dict", {})
    prob_pct      = phishing_prob * 100

    # ── Normalise status ──────────────────────────────────────────────
    if prediction in ("Malicious (Rules)", "Malicious (Model)"):
        status       = "phishing"
        status_label = "Phishing"
        status_icon  = "🚫"
    elif prediction == "Suspicious":
        status       = "suspicious"
        status_label = "Suspicious"
        status_icon  = "⚠️"
    else:
        status       = "safe"
        status_label = "Safe"
        status_icon  = "🛡️"

    bar_colors = {"safe": "#15803d", "suspicious": "#b45309", "phishing": "#b91c1c"}
    bar_color  = bar_colors[status]

    # ── Main Result Card ──────────────────────────────────────────────
    st.markdown(
        f'<div class="result-card result-card-{status}">'
        f'  <div class="result-card-header">'
        f'    <span class="result-card-icon">{status_icon}</span>'
        f'    <span class="result-card-title">Result: {status_label}</span>'
        f'  </div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Phishing Probability Bar ──────────────────────────────────────
    bar_pct_clamped = min(prob_pct, 100)
    st.markdown(
        f'<div class="prob-bar-wrapper">'
        f'  <div class="prob-bar-label-row">'
        f'    <span class="prob-bar-label">Model Confidence</span>'
        f'    <span class="prob-bar-value" style="color:{bar_color};">{prob_pct:.1f}%</span>'
        f'  </div>'
        f'  <div class="prob-bar-track">'
        f'    <div class="prob-bar-fill" style="width:{bar_pct_clamped:.1f}%; background:{bar_color};"></div>'
        f'  </div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Mismatch notice ───────────────────────────────────────────────
    mismatch_html = ""
    if phishing_prob < 0.30 and status in ("suspicious", "phishing"):
        mismatch_html = (
            '<div class="mismatch-notice mismatch-rules">'
            'Heuristic rules detected suspicious patterns despite a low model probability.'
            '</div>'
        )
    elif phishing_prob >= 0.50 and rule_score < 2:
        mismatch_html = (
            '<div class="mismatch-notice mismatch-model">'
            '🔍 Model probability is high even though no major heuristic rules triggered.'
            '</div>'
        )

    # ── Detection Reasons ─────────────────────────────────────────────
    friendly_reasons = [_friendly_rule(h) for h in rule_hits]
    if friendly_reasons:
        bullets = "".join(
            f'<li class="reason-item">{r}</li>' for r in friendly_reasons
        )
        reasons_body = (
            f'<ul class="reasons-list">{bullets}</ul>'
        )
    else:
        reasons_body = '<p class="reasons-none">No major red flags detected.</p>'

    st.markdown(
        f'{mismatch_html}'
        f'<div class="detection-reasons">'
        f'  <div class="reasons-title">Detection reasons:</div>'
        f'  {reasons_body}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Detailed Analysis Expander ────────────────────────────────────
    with st.expander("Detailed analysis"):

        # Risk category helper (local)
        def _risk_info(p: float):
            if p < 0.30:   return "Low Risk",      "badge-low",      "color-low"
            elif p < 0.60: return "Moderate Risk",  "badge-moderate", "color-moderate"
            elif p < 0.80: return "High Risk",      "badge-high",     "color-high"
            else:          return "Critical Risk",  "badge-critical", "color-critical"

        risk_label, badge_cls, color_cls = _risk_info(phishing_prob)

        # — Model details section —
        st.markdown(
            '<div class="detail-section">'
            '<div class="detail-section-title">Model details</div>'
            f'<div class="section-row"><span>Phishing Probability</span>'
            f'<span class="value {color_cls}">{prob_pct:.1f}%</span></div>'
            f'<div class="section-row"><span>Risk Category</span>'
            f'<span class="risk-category-badge {badge_cls}">{risk_label}</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )

        # — Rule details section —
        if engine_error:
            hits_html = (
                f'<div class="rule-hit" style="color:#b91c1c;">'
                f'<span class="dot" style="background:#b91c1c;"></span>'
                f'<span>Rule engine error: {engine_error}</span>'
                f'</div>'
            )
        elif rule_hits:
            hits_html = "".join(
                f'<div class="rule-hit"><span class="dot"></span><span>{h}</span></div>'
                for h in rule_hits
            )
        else:
            hits_html = '<div class="rule-no-hit">✔ No heuristic red flags detected.</div>'

        st.markdown(
            '<div class="detail-section">'
            '<div class="detail-section-title">Rule details</div>'
            f'<div class="section-row"><span>Rule Score</span>'
            f'<span class="value">{rule_score}</span></div>'
            '<div class="detail-subsection-label">Triggered rules</div>'
            f'{hits_html}'
            '</div>',
            unsafe_allow_html=True,
        )

        # — Technical details section —
        parsed_url  = urlparse(result["url"])
        hostname    = parsed_url.netloc or "—"
        path_str    = parsed_url.path   or "/"
        scheme_str  = parsed_url.scheme or "—"
        url_len     = features_dict.get("url_length", len(result["url"]))
        num_dots    = features_dict.get("num_dots",    "—")
        num_hyphens = features_dict.get("num_hyphens", "—")
        num_digits  = features_dict.get("num_digits",  features_dict.get("qty_digit", "—"))
        has_https   = features_dict.get("has_https",   int(scheme_str == "https"))
        entropy_val = features_dict.get("url_entropy", "—")
        entropy_str = entropy_val if isinstance(entropy_val, str) else f"{entropy_val:.3f}"

        st.markdown(
            '<div class="detail-section">'
            '<div class="detail-section-title">Technical details</div>'
            f'<div class="tech-row"><span>Host</span><span class="tval">{hostname}</span></div>'
            f'<div class="tech-row"><span>Scheme</span><span class="tval">{scheme_str}</span></div>'
            f'<div class="tech-row"><span>Path</span><span class="tval">{path_str}</span></div>'
            f'<div class="tech-row"><span>URL Length</span><span class="tval">{url_len}</span></div>'
            f'<div class="tech-row"><span>HTTPS</span><span class="tval">{"Yes" if has_https else "No"}</span></div>'
            f'<div class="tech-row"><span>Dots in URL</span><span class="tval">{num_dots}</span></div>'
            f'<div class="tech-row"><span>Hyphens in URL</span><span class="tval">{num_hyphens}</span></div>'
            f'<div class="tech-row"><span>Digits in URL</span><span class="tval">{num_digits}</span></div>'
            f'<div class="tech-row"><span>Entropy</span><span class="tval">{entropy_str}</span></div>'
            f'<div class="tech-row"><span>Raw Phishing Probability</span><span class="tval">{phishing_prob:.6f}</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )


# Load model and features
try:
    model = load_model()
    feature_names = load_feature_names()
    model_loaded = True
except Exception as e:
    model_loaded = False
    model_error = str(e)

# Page configuration
st.set_page_config(
    page_title="PhisIchno",
    page_icon="🐟",
    layout="centered"
)
load_css()

# Title
st.title("PhisIchno URL Phishing Detector")

if not model_loaded:
    st.error(f"Failed to load model: {model_error}")

# Initialize session state
if "result" not in st.session_state:
    st.session_state.result = None
if "url_input" not in st.session_state:
    st.session_state.url_input = ""

# Callback for clear button (runs before widget renders)
def clear_inputs():
    st.session_state.url_input = ""
    st.session_state.result = None

# URL input
url = st.text_input("Enter URL:", key="url_input", placeholder="https://phisichno.com")

# Real-time validation with normalization
url_stripped = url.strip()
url_normalized = normalize_url(url_stripped)
url_valid = is_valid_url(url_normalized)

if url_stripped and not url_valid:
    st.markdown(
        '<p style="color:#f38ba8; font-size:0.85rem; margin-top:-0.5rem; margin-bottom:0.5rem;">'
        "Please enter a valid URL (e.g.https://phisichno.com).</p>",
        unsafe_allow_html=True,
    )

# Buttons in columns
col1, col2 = st.columns(2)

with col1:
    predict_clicked = st.button(
        "Predict",
        type="primary",
        use_container_width=True,
        disabled=(not model_loaded) or (not url_valid),
    )

with col2:
    st.button("Clear", use_container_width=True, on_click=clear_inputs)

# Handle Predict button
if predict_clicked and model_loaded:
    if url.strip():
        try:
            # Normalize the URL (add https:// if needed)
            url_to_analyze = normalize_url(url.strip())
            
            # Extract features from normalized URL
            features, features_dict = extract_features(url_to_analyze, feature_names)
            
            prediction = model.predict(features)[0]

            phishing_prob = 0.0
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(features)[0]
                phishing_idx = None
                if hasattr(model, 'classes_'):
                    for idx, cls in enumerate(model.classes_):
                        if cls == 1 or str(cls).strip().lower() in {"1", "malicious", "phishing", "bad", "suspicious"}:
                            phishing_idx = idx
                            break
                if phishing_idx is not None:
                    phishing_prob = float(proba[phishing_idx])
            else:
                if isinstance(prediction, (int, np.integer)):
                    phishing_prob = 1.0 if prediction == 1 else 0.0
                else:
                    phishing_prob = 1.0 if str(prediction).strip().lower() in {"1", "malicious", "phishing", "bad", "suspicious"} else 0.0

            rule_score, rule_hits, engine_error = rule_based_checks(url_to_analyze)

            if rule_score >= 5:
                final_label = "Malicious (Rules)"
            elif phishing_prob >= 0.5:
                final_label = "Malicious (Model)"
            elif rule_score >= 2:
                final_label = "Suspicious"
            else:
                final_label = "Safe"
            
            st.session_state.result = {
                "url": url_to_analyze,
                "prediction": final_label,
                "phishing_prob": phishing_prob,
                "rule_score": rule_score,
                "rule_hits": rule_hits,
                "engine_error": engine_error,
                "features_dict": features_dict,
            }
        except Exception as e:
            st.error(f"Prediction failed: {str(e)}")
    else:
        st.warning("Please enter a URL to analyze.")

# ─────────────────────────────────────────────────────────────────────────────
# Display results
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.result:
    st.markdown("---")
    render_results_ui(st.session_state.result)
