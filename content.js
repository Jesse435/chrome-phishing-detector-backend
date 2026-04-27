function extractFeatures() {
  const url = window.location.href;
  const hostname = window.location.hostname;

  const urlLength = url.length;
  const hasIP = /(\d{1,3}\.){3}\d{1,3}/.test(hostname);
  const hasHTTPS = url.startsWith("https://");
  const subdomainCount = Math.max(hostname.split(".").length - 2, 0);
  const hasAtSymbol = url.includes("@");

  const title = document.title || "";
  const bodyText = document.body ? document.body.innerText || "" : "";
  const combinedText = (title + " " + bodyText).toLowerCase();

  const suspiciousKeywords = [
    "login", "verify", "secure", "account", "update", "confirm",
    "password", "signin", "wallet", "payment"
  ];

  let keywordCount = 0;
  suspiciousKeywords.forEach((word) => {
    if (combinedText.includes(word)) keywordCount++;
  });

  const passwordFields = document.querySelectorAll('input[type="password"]');
  const hasLoginForm = passwordFields.length > 0;

  const links = document.querySelectorAll("a");
  let externalLinks = 0;
  let internalLinks = 0;

  links.forEach((link) => {
    const href = link.getAttribute("href");
    if (!href) return;

    try {
      const linkUrl = new URL(href, window.location.href);
      if (linkUrl.hostname && linkUrl.hostname !== hostname) {
        externalLinks++;
      } else {
        internalLinks++;
      }
    } catch (_) {
      internalLinks++;
    }
  });

  const scriptCount = document.querySelectorAll("script").length;
  const iframeCount = document.querySelectorAll("iframe").length;

  return {
    url,
    hostname,
    urlLength,
    hasIP,
    hasHTTPS,
    subdomainCount,
    hasAtSymbol,
    title,
    keywordCount,
    hasLoginForm,
    externalLinks,
    internalLinks,
    scriptCount,
    iframeCount
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_features") {
    sendResponse(extractFeatures());
  }
  return true;
});

// Auto-scan when page loads. This is safe because features is now defined here.
try {
  chrome.runtime.sendMessage({
    action: "process_features",
    data: extractFeatures()
  });
} catch (error) {
  console.error("SafeNest auto-scan failed:", error);
}
