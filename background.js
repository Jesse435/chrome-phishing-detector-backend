chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (request.action === "process_features") {

    const features = request.data;

    const hostname = new URL(features.url).hostname;

    // 🔹 CHECK CACHE FIRST
    chrome.storage.local.get([hostname], (cached) => {

      if (cached[hostname]) {

        console.log("✅ Using cached result for:", hostname);

        const data = cached[hostname];

        applyBadge(data.risk_level);

        sendResponse({
          classification: data.risk_level,
          riskScore: data.risk_score,
          reasons: data.reasons
        });

      } else {

        console.log("🌐 Fetching from API:", hostname);

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

          // 🔹 SAVE TO CACHE
          chrome.storage.local.set({
            [hostname]: data
          });

          applyBadge(data.risk_level);

          sendResponse({
            classification: data.risk_level,
            riskScore: Math.round(data.risk_score),
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

      }

    });

    return true;
  }
});

function applyBadge(level) {

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

}