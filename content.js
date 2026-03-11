function extractFeatures() {

  const url = window.location.href;
  const hostname = window.location.hostname;

  // -----------------------------
  // URL FEATURES
  // -----------------------------
  const urlLength = url.length;

  const hasIP = /(\d{1,3}\.){3}\d{1,3}/.test(hostname);

  const hasHTTPS = url.startsWith("https://");

  const subdomainCount = hostname.split(".").length - 2;

  const hasAtSymbol = url.includes("@");

  // -----------------------------
  // TEXT CONTENT
  // -----------------------------
  const title = document.title || "";

  const bodyText = document.body.innerText || "";

  const combinedText = (title + " " + bodyText).toLowerCase();

  const suspiciousKeywords = [
    "login",
    "verify",
    "bank",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
    "wallet",
    "payment"
  ];

  let keywordCount = 0;

  suspiciousKeywords.forEach(word => {
    if (combinedText.includes(word)) {
      keywordCount++;
    }
  });

  // -----------------------------
  // LOGIN FORM DETECTION
  // -----------------------------
  const passwordFields = document.querySelectorAll('input[type="password"]');

  const hasLoginForm = passwordFields.length > 0;

  // -----------------------------
  // LINK ANALYSIS
  // -----------------------------
  const links = document.querySelectorAll("a");

  let externalLinks = 0;
  let internalLinks = 0;

  links.forEach(link => {

    const href = link.getAttribute("href");

    if (!href) return;

    if (href.startsWith("http")) {

      if (!href.includes(hostname)) {
        externalLinks++;
      } else {
        internalLinks++;
      }

    } else {

      internalLinks++;

    }

  });

  // -----------------------------
  // SCRIPT & IFRAME COUNT
  // -----------------------------
  const scriptCount = document.querySelectorAll("script").length;

  const iframeCount = document.querySelectorAll("iframe").length;

  return {
    url,
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


// -----------------------------
// MESSAGE LISTENER
// -----------------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (request.action === "extract_features") {

    const features = extractFeatures();

    sendResponse(features);

  }

  return true;

});