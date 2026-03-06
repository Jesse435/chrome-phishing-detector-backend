from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load trained model
model = joblib.load("phishing_model.pkl")

# Home route (health check)
@app.route("/")
def home():
    return "Phishing Detection API is running"

# Prediction route
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        # -----------------------------
        # SECURITY RULE LAYER
        # -----------------------------
        risk = 0
        reasons = []

        if data.get("hasIP"):
            risk += 40
            reasons.append("URL contains an IP address")

        if data.get("hasAtSymbol"):
            risk += 25
            reasons.append("URL contains '@' symbol")

        if data.get("subdomainCount", 0) > 3:
            risk += 15
            reasons.append("Too many subdomains")

        if data.get("urlLength", 0) > 75:
            risk += 10
            reasons.append("URL is unusually long")

        if data.get("keywordCount", 0) > 2:
            risk += 15
            reasons.append("Suspicious keywords detected")

        if data.get("hasLoginForm"):
            risk += 20
            reasons.append("Login form detected")

        if data.get("iframeCount", 0) > 3:
            risk += 10
            reasons.append("Multiple iframes detected")

        if data.get("externalLinks", 0) > data.get("internalLinks", 0):
            risk += 10
            reasons.append("High number of external links")

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
        # COMBINE RULES + ML
        # -----------------------------
        final_score = (risk + ml_score) / 2

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

        df = pd.DataFrame([mapped])

        # Align remaining model columns
        df = df.reindex(columns=model.feature_names_in_, fill_value=0)

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df).max()

        return jsonify({
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(probability), 4)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

