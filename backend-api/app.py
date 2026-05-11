from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import whois
from datetime import datetime
from urllib.parse import urlparse

try:
    import shap
    SHAP_AVAILABLE = True
except Exception:
    shap = None
    SHAP_AVAILABLE = False

app = Flask(__name__)
CORS(app)

model = joblib.load("phishing_model.pkl")

explainer = None
if SHAP_AVAILABLE:
    try:
        explainer = shap.TreeExplainer(model)
        print("SHAP explainer loaded successfully")
    except Exception as e:
        print("SHAP explainer failed to load:", e)
        explainer = None

FEATURE_LABELS = {
    "urlLength": "URL length",
    "hasIP": "IP address usage",
    "hasHTTPS": "HTTPS security",
    "subdomainCount": "number of subdomains",
    "hasAtSymbol": "@ symbol in URL",
    "keywordCount": "suspicious keyword count",
    "externalLinks": "external links",
    "internalLinks": "internal links",
    "scriptCount": "script count",
    "iframeCount": "iframe count",
    "hasLoginForm": "login form presence"
}

# This is intentionally a small trust-adjustment list, not a bypass whitelist.
# Trusted domains are still scanned. The list only reduces weak/contextual penalties
# that commonly appear on legitimate large websites.
TRUSTED_ROOT_DOMAINS = {
    "amazon.com", "amazon.co.uk",
    "google.com", "google.com.ng",
    "microsoft.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "paypal.com",
    "facebook.com", "instagram.com", "linkedin.com",
    "github.com", "wikipedia.org",
    "openai.com", "chatgpt.com"
}

PROTECTED_BRANDS = {
    "amazon": ["amazon.com", "amazon.co.uk"],
    "google": ["google.com", "google.com.ng"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "chatgpt": ["chatgpt.com"],
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".work", ".click"}


def extract_hostname(url):
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def is_domain_or_subdomain(hostname, root_domain):
    return hostname == root_domain or hostname.endswith("." + root_domain)


def is_trusted_domain(hostname):
    return any(is_domain_or_subdomain(hostname, root) for root in TRUSTED_ROOT_DOMAINS)


def detect_brand_impersonation(hostname):
    hits = []
    clean_host = hostname.replace("-", "").replace(".", "")
    for brand, official_roots in PROTECTED_BRANDS.items():
        official = any(is_domain_or_subdomain(hostname, root) for root in official_roots)
        if not official and (brand in hostname or brand in clean_host):
            hits.append(brand)
    return hits


def get_domain_age(url):
    try:
        hostname = extract_hostname(url)
        if not hostname or hostname in {"localhost", "127.0.0.1"}:
            return None
        w = whois.whois(hostname)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        return (datetime.now() - creation).days
    except Exception:
        return None


def build_feature_frame(data):
    # The ML model was trained on this feature family. Runtime-only features such as
    # crossOriginIframeCount are used by the rule layer, not forced into the model.
    mapped = {
        "urlLength": data.get("urlLength", 0),
        "hasIP": 1 if data.get("hasIP") else 0,
        "hasHTTPS": 1 if data.get("hasHTTPS") else 0,
        "subdomainCount": data.get("subdomainCount", 0),
        "hasAtSymbol": 1 if data.get("hasAtSymbol") else 0,
        "keywordCount": data.get("keywordCount", 0),
        "externalLinks": data.get("externalLinks", 0),
        "internalLinks": data.get("internalLinks", 0),
        "scriptCount": data.get("scriptCount", 0),
        "iframeCount": data.get("iframeCount", 0),
        "hasLoginForm": 1 if data.get("hasLoginForm") else 0,
    }
    df = pd.DataFrame([mapped])
    return df.reindex(columns=model.feature_names_in_, fill_value=0)


def get_xai_explanations(df, max_items=4):
    if explainer is None:
        return ["SHAP explanations are unavailable on this deployment."]
    try:
        shap_values = explainer.shap_values(df)
        if isinstance(shap_values, list):
            values = shap_values[1][0]
        else:
            arr = shap_values
            values = arr[0, :, 1] if len(arr.shape) == 3 else arr[0]

        rows = []
        for feature, value, raw in zip(df.columns, values, df.iloc[0].values):
            rows.append({
                "feature": feature,
                "label": FEATURE_LABELS.get(feature, feature),
                "impact": float(value),
                "value": raw
            })

        rows.sort(key=lambda x: abs(x["impact"]), reverse=True)
        explanations = []
        for item in rows[:max_items]:
            direction = "increased" if item["impact"] > 0 else "reduced"
            explanations.append(f"{item['label']} {direction} the model's phishing risk estimate.")
        return explanations
    except Exception as e:
        print("SHAP explanation error:", e)
        return ["SHAP explanation could not be generated for this scan."]


def label_risk(score):
    if score < 30:
        return "Safe"
    if score < 60:
        return "Suspicious"
    return "High Risk"


def safe_reasons(trusted_domain=False):
    if trusted_domain:
        return [
            "Verified trusted domain with no strong phishing indicators detected",
            "Overall risk score is below the warning threshold",
            "Weak page signals were balanced against the trusted domain context"
        ]
    return [
        "No strong phishing indicators detected",
        "Overall risk score is below the warning threshold",
        "The URL and page signals appear acceptable based on the current model"
    ]


@app.route("/")
def home():
    return "Phishing Detection API is running"


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        print("Incoming features:", data)

        url = str(data.get("url", "")).lower()
        hostname = extract_hostname(url)
        trusted_domain = is_trusted_domain(hostname)
        impersonated_brands = detect_brand_impersonation(hostname)

        rule_risk = 0
        suspicious_reasons = []
        strong_red_flags = []
        weak_signals = []

        # -----------------------------
        # STRONG RULE SIGNALS
        # -----------------------------
        if data.get("hasIP"):
            rule_risk += 50
            strong_red_flags.append("IP address used instead of a normal domain name")

        if not data.get("hasHTTPS"):
            # Local file and localhost testing should still show as a warning, but real
            # external websites without HTTPS remain a serious issue.
            is_local = hostname in {"", "localhost", "127.0.0.1"} or url.startswith("file:")
            rule_risk += 15 if is_local else 25
            strong_red_flags.append("Connection is not using HTTPS")

        # @ is dangerous mainly in the authority section, e.g. https://trusted.com@evil.com
        at_location = data.get("atSymbolLocation", "none")
        if data.get("hasAtSymbol") and at_location in {"authority", "unknown"}:
            rule_risk += 35
            strong_red_flags.append("@ symbol appears in a sensitive part of the URL")
        elif at_location == "path_or_query":
            rule_risk += 3
            weak_signals.append("@ symbol appears only in the path or query string")

        for brand in impersonated_brands:
            rule_risk += 40
            strong_red_flags.append(f"Possible impersonation of {brand}")

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                rule_risk += 18
                strong_red_flags.append("Suspicious domain extension detected")
                break

        # -----------------------------
        # WEAK/CONTEXTUAL RULE SIGNALS
        # -----------------------------
        subdomain_limit = 4 if trusted_domain else 2
        if data.get("subdomainCount", 0) > subdomain_limit:
            rule_risk += 6 if trusted_domain else 18
            weak_signals.append("URL contains an unusually high number of subdomains")

        url_length_limit = 160 if trusted_domain else 90
        if data.get("urlLength", 0) > url_length_limit:
            rule_risk += 4 if trusted_domain else 10
            weak_signals.append("URL length is unusually long")

        keyword_count = int(data.get("keywordCount", 0) or 0)
        has_login = bool(data.get("hasLoginForm"))
        if keyword_count >= 5 and (has_login or not trusted_domain):
            rule_risk += 4 if trusted_domain else 14
            weak_signals.append("Several sensitive account or payment-related keywords were detected")
        elif keyword_count >= 3 and has_login and not trusted_domain:
            rule_risk += 10
            weak_signals.append("Login page contains sensitive account-related language")

        if has_login and not trusted_domain:
            rule_risk += 28
            strong_red_flags.append("Login form detected on an untrusted or unknown domain")

        # Better iframe handling: iframe count alone is weak. Cross-origin or hidden iframes are more meaningful.
        cross_iframes = int(data.get("crossOriginIframeCount", 0) or 0)
        hidden_iframes = int(data.get("hiddenIframeCount", 0) or 0)
        iframe_count = int(data.get("iframeCount", 0) or 0)

        if hidden_iframes > 0 and not trusted_domain:
            rule_risk += 22
            strong_red_flags.append("Hidden iframe detected on the page")
        elif cross_iframes >= (5 if trusted_domain else 2):
            rule_risk += 5 if trusted_domain else 16
            weak_signals.append("Multiple cross-domain iframes detected")
        elif iframe_count >= (10 if trusted_domain else 5):
            rule_risk += 3 if trusted_domain else 8
            weak_signals.append("Several embedded frames were detected")

        external_links = int(data.get("externalLinks", 0) or 0)
        internal_links = int(data.get("internalLinks", 0) or 0)
        if not trusted_domain and external_links > max(5, internal_links * 2):
            rule_risk += 10
            weak_signals.append("Page contains unusually many external links")

        if "bank" in hostname and has_login and not trusted_domain:
            rule_risk += 18
            strong_red_flags.append("Banking-related domain pattern with login form detected")

        if not trusted_domain:
            age = get_domain_age(url)
            if age is not None and age < 90:
                rule_risk += 18
                weak_signals.append("Domain appears to have been registered recently")

        suspicious_reasons = strong_red_flags + weak_signals

        # -----------------------------
        # ML MODEL LAYER
        # -----------------------------
        df = build_feature_frame(data)
        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]
        ml_score = probability * 100

        # Rule layer carries more weight because it includes runtime DOM/host signals.
        final_score = (rule_risk * 0.65) + (ml_score * 0.35)
        final_score = max(0, min(final_score, 100))

        # Trusted-domain balancing: reduce only weak false positives, never strong red flags.
        has_strong = len(strong_red_flags) > 0
        if trusted_domain and not has_strong:
            if final_score < 60:
                final_score = min(final_score, 24)
            else:
                final_score = min(final_score, 45)

        level = label_risk(final_score)

        if level == "Safe":
            reasons = safe_reasons(trusted_domain)
        elif level == "Suspicious":
            reasons = suspicious_reasons[:3] or ["The model detected a moderate phishing risk pattern"]
        else:
            reasons = suspicious_reasons[:5] or ["The model detected a high phishing risk pattern"]

        xai_explanations = get_xai_explanations(df)

        return jsonify({
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "risk_score": round(final_score, 2),
            "risk_level": level,
            "confidence": round(float(probability), 4),
            "reasons": reasons,
            "xai_explanations": xai_explanations,
            "raw_rule_reasons": suspicious_reasons,
            "debug": {
                "hostname": hostname,
                "trusted_domain": trusted_domain,
                "rule_risk": round(rule_risk, 2),
                "ml_score": round(ml_score, 2),
                "strong_red_flags": strong_red_flags,
                "weak_signals": weak_signals
            }
        })

    except Exception as e:
        print("Prediction error:", e)
        return jsonify({
            "risk_score": 0,
            "risk_level": "Server Error",
            "reasons": ["Backend error occurred during analysis"],
            "xai_explanations": [],
            "error": str(e)
        }), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
