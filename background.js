chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (request.action === "process_features") {

    const features = request.data;

    fetch("https://chrome-phishing-detector-backend.onrender.com/predict", {

      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify(features)

    })

    .then((response) => {

      if (!response.ok) {
        throw new Error("Server error");
      }

      return response.json();

    })

    .then((data) => {

      const riskScore = Math.round(data.risk_score);
      const level = data.risk_level;

      // -----------------------------
      // ICON COLOR SYSTEM
      // -----------------------------

      if (level === "Safe") {

        chrome.action.setBadgeText({ text: "✓" });
        chrome.action.setBadgeBackgroundColor({ color: "green" });

      }

      else if (level === "Suspicious") {

        chrome.action.setBadgeText({ text: "!" });
        chrome.action.setBadgeBackgroundColor({ color: "orange" });

      }

      else {

        chrome.action.setBadgeText({ text: "⚠" });
        chrome.action.setBadgeBackgroundColor({ color: "red" });

      }

      sendResponse({

        classification: level,
        riskScore: riskScore,
        reasons: data.reasons

      });

    })

    .catch((error) => {

      console.error("API error:", error);

      sendResponse({
        classification: "Server Error",
        riskScore: 0,
        reasons: ["Unable to contact security server"]
      });

    });

    return true;

  }

});