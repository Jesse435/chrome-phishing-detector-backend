from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import whois
from datetime import datetime

# Optional XAI import. If SHAP fails on Render, the API will still run.
try:
    import shap
    SHAP_AVAILABLE = True
except Exception:
    shap = None
    SHAP_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Load trained ML model
model = joblib.load("phishing_model.pkl")

# Create SHAP explainer once at startup, not on every request.
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


# Small trusted-root list to reduce false positives on major legitimate sites.
# This is NOT a full whitelist. These sites are still analyzed, but weak signals
# like login forms and long tracking URLs are weighted less heavily.
TRUSTED_ROOT_DOMAINS = {
    "amazon.com",
    "amazon.co.uk",
    "google.com",
    "google.com.ng",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com"
}

PROTECTED_BRANDS = {
    "amazon": ["amazon.com", "amazon.co.uk"],
    "google": ["google.com", "google.com.ng"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com"],
}


def extract_hostname(url):
    try:
        return url.split("//")[-1].split("/")[0].split(":")[0].lower()
    except Exception:
        return ""


def is_domain_or_subdomain(hostname, root_domain):
    return hostname == root_domain or hostname.endswith("." + root_domain)


def is_trusted_domain(hostname):
    return any(is_domain_or_subdomain(hostname, root) for root in TRUSTED_ROOT_DOMAINS)


def detect_brand_impersonation(hostname):
    """Flag domains that contain a protected brand name but are not official roots/subdomains."""
    hits = []
    for brand, official_roots in PROTECTED_BRANDS.items():
        if brand in hostname and not any(is_domain_or_subdomain(hostname, root) for root in official_roots):
            hits.append(brand)
    return hits


def get_domain_age(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return None

        age_days = (datetime.now() - creation).days
        return age_days

    except Exception:
        return None


def build_feature_frame(data):
    """Build dataframe using the EXACT feature names used during training."""
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
    df = df.reindex(columns=model.feature_names_in_, fill_value=0)
    return df


def get_xai_explanations(df, max_items=4):
    """Return SHAP explanations for the phishing class where possible."""
    if explainer is None:
        return ["SHAP explanations are unavailable on this deployment."]

    try:
        shap_values = explainer.shap_values(df)

        # RandomForest binary classification commonly returns a list: [class_0, class_1]
        if isinstance(shap_values, list):
            values = shap_values[1][0]
        else:
            # Newer SHAP versions may return ndarray with class dimension
            arr = shap_values
            if len(arr.shape) == 3:
                values = arr[0, :, 1]
            else:
                values = arr[0]

        rows = []
        for feature, value, raw in zip(df.columns, values, df.iloc[0].values):
            rows.append({
                "feature": feature,
                "label": FEATURE_LABELS.get(feature, feature),
                "impact": float(value),
                "value": raw
            })

        rows.sort(key=lambda x: abs(x["impact"]), reverse=True)
        top = rows[:max_items]

        explanations = []
        for item in top:
            direction = "increased" if item["impact"] > 0 else "reduced"
            explanations.append(
                f"{item['label']} {direction} the model's phishing risk estimate."
            )

        return explanations

    except Exception as e:
        print("SHAP explanation error:", e)
        return ["SHAP explanation could not be generated for this scan."]


@app.route("/")
def home():
    return "Phishing Detection API is running"


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        print("Incoming features:", data)

        rule_risk = 0
        suspicious_reasons = []

        url = data.get("url", "").lower()
        hostname = extract_hostname(url)
        trusted_domain = is_trusted_domain(hostname)
        impersonated_brands = detect_brand_impersonation(hostname)

        # -----------------------------
        # RULE-BASED DETECTION
        # -----------------------------
        # Strong red flags: these remain serious even on familiar-looking sites.
        if data.get("hasIP"):
            rule_risk += 50
            suspicious_reasons.append("IP address used instead of a normal domain name")

        if not data.get("hasHTTPS"):
            rule_risk += 20
            suspicious_reasons.append("Connection is not using HTTPS")

        if data.get("hasAtSymbol"):
            rule_risk += 30
            suspicious_reasons.append("@ symbol found in the URL")

        # Brand impersonation is a strong phishing indicator.
        for brand in impersonated_brands:
            rule_risk += 35
            suspicious_reasons.append(f"Possible impersonation of {brand}")

        # Weak/contextual signals: reduce false positives on known legitimate domains.
        subdomain_limit = 4 if trusted_domain else 2
        if data.get("subdomainCount", 0) > subdomain_limit:
            rule_risk += 8 if trusted_domain else 20
            suspicious_reasons.append("URL contains an unusually high number of subdomains")

        url_length_limit = 140 if trusted_domain else 75
        if data.get("urlLength", 0) > url_length_limit:
            rule_risk += 5 if trusted_domain else 10
            suspicious_reasons.append("URL length is unusually long")

        # Keywords alone are weak. They become more meaningful when combined with login/payment context.
        if data.get("keywordCount", 0) > 3 and (data.get("hasLoginForm") or not trusted_domain):
            rule_risk += 5 if trusted_domain else 15
            suspicious_reasons.append("Several sensitive account or payment-related keywords were detected")

        # A login form is normal on trusted platforms, but suspicious elsewhere.
        if data.get("hasLoginForm") and not trusted_domain:
            rule_risk += 30
            suspicious_reasons.append("Login form detected on an untrusted or unknown domain")

        iframe_limit = 6 if trusted_domain else 2
        if data.get("iframeCount", 0) >= iframe_limit:
            rule_risk += 8 if trusted_domain else 20
            suspicious_reasons.append("Multiple iframes detected on the page")

        # Large legitimate websites often use CDNs and external assets.
        if not trusted_domain and data.get("externalLinks", 0) > data.get("internalLinks", 0):
            rule_risk += 12
            suspicious_reasons.append("Page contains more external links than internal links")

        # Generic banking keyword is weaker than brand impersonation.
        if "bank" in hostname and data.get("hasLoginForm") and data.get("subdomainCount", 0) > 1 and not trusted_domain:
            rule_risk += 15
            suspicious_reasons.append("Banking-related domain pattern with login form detected")

        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site"]
        for tld in suspicious_tlds:
            if hostname.endswith(tld):
                rule_risk += 15
                suspicious_reasons.append("Suspicious domain extension detected")
                break

        # Domain age checks can be slow and unreliable on major trusted domains.
        if not trusted_domain:
            age = get_domain_age(url)
            if age is not None and age < 90:
                rule_risk += 20
                suspicious_reasons.append("Domain appears to have been registered recently")

        # -----------------------------
        # ML MODEL LAYER
        # -----------------------------
        df = build_feature_frame(data)
        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]
        ml_score = probability * 100

        final_score = (rule_risk * 0.65) + (ml_score * 0.35)
        final_score = max(0, min(final_score, 100))

        # False-positive control: for verified trusted roots with no strong red flags,
        # cap the final score below Suspicious. This is not a bypass because fake-brand
        # domains, IP URLs, @ symbols, and missing HTTPS still keep their risk.
        strong_red_flags = bool(data.get("hasIP") or data.get("hasAtSymbol") or not data.get("hasHTTPS") or impersonated_brands)
        if trusted_domain and not strong_red_flags and final_score < 60:
            final_score = min(final_score, 24)

        if final_score < 30:
            level = "Safe"
        elif final_score < 60:
            level = "Suspicious"
        else:
            level = "High Risk"

        # -----------------------------
        # USER-FACING REASONS
        # -----------------------------
        if level == "Safe":
            reasons = [
                "No strong phishing indicators detected",
                "Overall risk score is below the warning threshold",
                "The URL and page signals appear acceptable based on the current model"
            ]
        elif level == "Suspicious":
            reasons = suspicious_reasons[:3] or [
                "The model detected a moderate phishing risk pattern"
            ]
        else:
            reasons = suspicious_reasons[:5] or [
                "The model detected a high phishing risk pattern"
            ]

        xai_explanations = get_xai_explanations(df)

        return jsonify({
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "risk_score": round(final_score, 2),
            "risk_level": level,
            "confidence": round(probability, 4),
            "reasons": reasons,
            "xai_explanations": xai_explanations,
            "raw_rule_reasons": suspicious_reasons
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
