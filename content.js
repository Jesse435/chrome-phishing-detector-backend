function extractFeatures() {
  const url = window.location.href;
  const hostname = window.location.hostname;

  const urlLength = url.length;
  const hasIP = /(\d{1,3}\.){3}\d{1,3}/.test(hostname);
  const hasHTTPS = url.startsWith("https://");
  const subdomainCount = Math.max(hostname.split(".").length - 2, 0);

  // Safer @ handling: only treat @ as risky when it appears in the URL authority
  // area before the hostname/path. Encoded email text in query strings should not
  // automatically create a serious signal.
  let hasAtSymbol = false;
  let atSymbolLocation = "none";
  try {
    const parsedUrl = new URL(url);
    const authority = parsedUrl.href.split("//")[1]?.split("/")[0] || "";
    hasAtSymbol = authority.includes("@");
    atSymbolLocation = hasAtSymbol ? "authority" : (parsedUrl.pathname.includes("@") || parsedUrl.search.includes("@") ? "path_or_query" : "none");
  } catch (_) {
    hasAtSymbol = url.includes("@");
    atSymbolLocation = hasAtSymbol ? "unknown" : "none";
  }

  const title = document.title || "";
  const bodyText = document.body ? document.body.innerText || "" : "";
  const combinedText = (title + " " + bodyText).toLowerCase();

  const suspiciousKeywords = [
    "login", "verify", "secure", "account", "update", "confirm",
    "password", "signin", "wallet", "payment", "restricted", "urgent"
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

  const iframes = document.querySelectorAll("iframe");
  const iframeCount = iframes.length;
  let crossOriginIframeCount = 0;
  let hiddenIframeCount = 0;
  let suspiciousIframeCount = 0;

  iframes.forEach((iframe) => {
    const src = iframe.getAttribute("src") || "";
    let crossOrigin = false;

    try {
      if (src) {
        const iframeUrl = new URL(src, window.location.href);
        crossOrigin = iframeUrl.hostname && iframeUrl.hostname !== hostname;
        if (crossOrigin) crossOriginIframeCount++;
      }
    } catch (_) {}

    const rect = iframe.getBoundingClientRect();
    const style = window.getComputedStyle(iframe);
    const hidden = rect.width < 5 || rect.height < 5 || style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0;
    if (hidden) hiddenIframeCount++;

    if (crossOrigin || hidden) suspiciousIframeCount++;
  });

  return {
    url,
    hostname,
    urlLength,
    hasIP,
    hasHTTPS,
    subdomainCount,
    hasAtSymbol,
    atSymbolLocation,
    title,
    keywordCount,
    hasLoginForm,
    externalLinks,
    internalLinks,
    scriptCount,
    iframeCount,
    crossOriginIframeCount,
    hiddenIframeCount,
    suspiciousIframeCount
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_features") {
    sendResponse(extractFeatures());
  }
  return true;
});

try {
  chrome.runtime.sendMessage({
    action: "process_features",
    data: extractFeatures()
  });
} catch (error) {
  console.error("SafeNest auto-scan failed:", error);
}
