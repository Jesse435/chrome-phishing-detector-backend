from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import whois
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Load trained ML model
model = joblib.load("phishing_model.pkl")


# -----------------------------
# DOMAIN AGE CHECK
# -----------------------------
def get_domain_age(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age_days = (datetime.now() - creation).days
        return age_days

    except:
        return None


# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.route("/")
def home():
    return "Phishing Detection API is running"


# -----------------------------
# PREDICTION ROUTE
# -----------------------------
@app.route("/predict", methods=["POST"])
def predict():

    try:
        data = request.get_json()
        print("Incoming features:", data)

        risk = 0
        reasons = []

        url = data.get("url", "").lower()

        # -----------------------------
        # RULE BASED DETECTION
        # -----------------------------

        # IP address in URL
        if data.get("hasIP"):
            risk += 50
            reasons.append("IP address used in URL")

        # No HTTPS
        if not data.get("hasHTTPS"):
            risk += 15
            reasons.append("Connection not using HTTPS")

        # @ symbol
        if data.get("hasAtSymbol"):
            risk += 25
            reasons.append("@ symbol found in URL")

        # Too many subdomains
        if data.get("subdomainCount", 0) > 2:
            risk += 20
            reasons.append("Too many subdomains")

        # Long URL
        if data.get("urlLength", 0) > 75:
            risk += 10
            reasons.append("URL length unusually long")

        # Suspicious keywords
        if data.get("keywordCount", 0) > 1:
            risk += 20
            reasons.append("Suspicious keywords detected")

        # Login form detection
        if data.get("hasLoginForm"):
            risk += 35
            reasons.append("Login form detected")

        # Iframes
        if data.get("iframeCount", 0) >= 2:
            risk += 25
            reasons.append("Multiple iframes detected")

        # External links
        if data.get("externalLinks", 0) > data.get("internalLinks", 0):
            risk += 15
            reasons.append("High number of external links")

        # -----------------------------
        # BRAND IMPERSONATION CHECK
        # -----------------------------
        brands = ["paypal", "apple", "amazon", "bank", "google", "microsoft"]

        for brand in brands:
            if brand in url:
                risk += 25
                reasons.append(f"Possible impersonation of {brand}")

        # -----------------------------
        # SUSPICIOUS DOMAIN EXTENSIONS
        # -----------------------------
        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site"]

        for tld in suspicious_tlds:
            if tld in url:
                risk += 15
                reasons.append("Suspicious domain extension")

        # -----------------------------
        # DOMAIN AGE SIGNAL
        # -----------------------------
        age = get_domain_age(url)

        if age and age < 90:
            risk += 20
            reasons.append("Domain registered recently")

        # -----------------------------
        # ML MODEL LAYER
        # -----------------------------
        mapped = {
            "length_url": data.get("urlLength", 0),
            "nb_dots": data.get("subdomainCount", 0),
            "nb_at": 1 if data.get("hasAtSymbol") else 0,
            "ratio_extHyperlinks": data.get("externalLinks", 0),
            "safe_anchor": data.get("keywordCount", 0),
            "web_traffic": 0,
            "google_index": 1,
            "page_rank": 2
        }

        df = pd.DataFrame([mapped])
        df = df.reindex(columns=model.feature_names_in_, fill_value=0)

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]

        ml_score = probability * 100

        # -----------------------------
        # COMBINED SCORE
        # -----------------------------
        final_score = (risk * 0.65) + (ml_score * 0.35)

        if final_score < 30:
            level = "Safe"
        elif final_score < 60:
            level = "Suspicious"
        else:
            level = "High Risk"

        return jsonify({
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "risk_score": round(final_score, 2),
            "risk_level": level,
            "confidence": round(probability, 4),
            "reasons": reasons
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# -----------------------------
# RUN SERVER
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)