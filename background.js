const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action !== "process_features") return;

  const features = request.data;

  if (!features || !features.url) {
    sendResponse({
      classification: "Error",
      riskScore: 0,
      reasons: ["Invalid URL"]
    });
    return true;
  }

  let hostname;
  try {
    hostname = new URL(features.url).hostname;
  } catch (_) {
    sendResponse({
      classification: "Error",
      riskScore: 0,
      reasons: ["Invalid URL format"]
    });
    return true;
  }

  const cacheKey = `scan:${hostname}`;

  chrome.storage.local.get([cacheKey], (cached) => {
    const cachedData = cached[cacheKey];

    if (isValidCache(cachedData)) {
      console.log("✅ Using cached result for:", hostname);
      applyBadge(cachedData.classification, cachedData.riskScore, cachedData.reasons);
      sendResponse(cachedData);
      return;
    }

    console.log("🌐 Fetching from API:", hostname);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    fetch("https://chrome-phishing-detector-backend.onrender.com/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(features),
      signal: controller.signal
    })
      .then((response) => {
        clearTimeout(timeout);
        if (!response.ok) throw new Error("Server error");
        return response.json();
      })
      .then((data) => {
        const result = normalizeApiResult(data);

        chrome.storage.local.set({ [cacheKey]: result });

        applyBadge(result.classification, result.riskScore, result.reasons);
        sendResponse(result);
      })
      .catch((error) => {
        clearTimeout(timeout);
        console.error("API error:", error);

        const errorResult = {
          classification: "Server Error",
          riskScore: 0,
          reasons: ["Unable to contact security server"],
          timestamp: Date.now()
        };

        applyBadge("Server Error", 0, errorResult.reasons);
        sendResponse(errorResult);
      });
  });

  return true;
});

function normalizeApiResult(data) {
  return {
    classification: data.risk_level || data.classification || "Unknown",
    riskScore: Math.round(Number(data.risk_score ?? data.riskScore ?? 0)),
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    timestamp: Date.now()
  };
}

function isValidCache(data) {
  return (
    data &&
    typeof data.classification === "string" &&
    typeof data.riskScore === "number" &&
    Array.isArray(data.reasons) &&
    typeof data.timestamp === "number" &&
    Date.now() - data.timestamp < CACHE_TTL
  );
}

function applyBadge(level, score = 0, reasons = []) {
  let text = "";
  let color = "gray";

  if (level === "Safe") {
    text = "✓";
    color = "green";
  } else if (level === "Suspicious") {
    text = "!";
    color = "orange";
  } else if (level === "High Risk") {
    text = "⚠";
    color = "red";
  } else if (level === "Server Error" || level === "Error") {
    text = "?";
    color = "gray";
  }

  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });

  const reasonPreview = reasons && reasons.length ? `\n${reasons.slice(0, 3).join("\n")}` : "";
  chrome.action.setTitle({
    title: `SafeNest\nStatus: ${level}\nRisk: ${score}/100${reasonPreview}`
  });

  setTimeout(() => {
    chrome.action.setBadgeText({ text: "" });
  }, 5000);
}
