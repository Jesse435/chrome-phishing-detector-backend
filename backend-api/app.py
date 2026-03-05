from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load trained model
model = joblib.load("phishing_rf_model.pkl")

# Home route (health check)
@app.route("/")
def home():
    return "Phishing Detection API is running"

# Prediction route
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        # Map extension features to model features
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

