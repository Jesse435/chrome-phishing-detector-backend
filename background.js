chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "process_features") {
    const raw = request.data;

    const normalizedFeatures = {
      urlLength: raw.urlLength / 200,
      subdomainCount: raw.subdomainCount / 10,
      keywordCount: raw.keywordCount / 10,
      externalLinkRatio:
        raw.externalLinks / (raw.internalLinks + 1),
      scriptDensity: raw.scriptCount / 50,
      iframeDensity: raw.iframeCount / 10,
      hasIP: raw.hasIP ? 1 : 0,
      hasHTTPS: raw.hasHTTPS ? 0 : 1,
      hasAtSymbol: raw.hasAtSymbol ? 1 : 0,
      hasLoginForm: raw.hasLoginForm ? 1 : 0
    };

    const riskScore = calculateRiskScore(normalizedFeatures);

    let classification = "Safe";
    if (riskScore >= 70) classification = "Phishing";
    else if (riskScore >= 40) classification = "Suspicious";

    sendResponse({
      riskScore,
      classification,
      features: normalizedFeatures
    });
  }
});

function calculateRiskScore(features) {
  let score = 0;

  score += features.hasIP * 25;
  score += features.hasAtSymbol * 10;
  score += features.hasLoginForm * 20;
  score += features.hasHTTPS * 20; // HTTPS absence
  score += features.externalLinkRatio * 15;
  score += features.scriptDensity * 10;
  score += features.iframeDensity * 10;

  return Math.min(Math.round(score), 100);
}
