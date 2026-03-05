function extractFeatures() {
  const url = window.location.href;

  // URL features
  const urlLength = url.length;
  const hasIP = /(\d{1,3}\.){3}\d{1,3}/.test(url);
  const hasHTTPS = url.startsWith("https://");
  const subdomainCount = url.split(".").length - 2;
  const hasAtSymbol = url.includes("@");

  // Page content features
  const title = document.title || "";
  const bodyText = document.body.innerText || "";

  const suspiciousKeywords = [
    "login", "verify", "bank", "secure",
    "account", "update", "confirm", "password"
  ];

  let keywordCount = 0;
  suspiciousKeywords.forEach(word => {
    if (bodyText.toLowerCase().includes(word)) {
      keywordCount++;
    }
  });

  // Forms
  const forms = document.getElementsByTagName("form");
  const hasLoginForm = Array.from(forms).some(form =>
    form.innerHTML.toLowerCase().includes("password")
  );

  // Links
  const links = document.getElementsByTagName("a");
  let externalLinks = 0;
  let internalLinks = 0;

  Array.from(links).forEach(link => {
    if (link.href.startsWith("http")) {
      if (link.hostname !== window.location.hostname) {
        externalLinks++;
      } else {
        internalLinks++;
      }
    }
  });

  // Scripts & iframes
  const scriptCount = document.getElementsByTagName("script").length;
  const iframeCount = document.getElementsByTagName("iframe").length;

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

// Message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_features") {
    const features = extractFeatures();
    sendResponse(features);
  }

  return true;
});