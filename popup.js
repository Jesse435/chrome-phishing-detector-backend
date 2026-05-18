const statusCard = document.getElementById("statusCard");
const statusLabel = document.getElementById("statusLabel");
const statusDot = document.getElementById("statusDot");
const scoreNum = document.getElementById("scoreNum");
const ringFill = document.getElementById("ringFill");
const riskFill = document.getElementById("riskFill");
const reasonsWrap = document.getElementById("reasonsWrap");
const reasonsList = document.getElementById("reasonsList");
const xaiWrap = document.getElementById("xaiWrap");
const xaiList = document.getElementById("xaiList");
const idleMsg = document.getElementById("idleMsg");
const spinner = document.getElementById("spinner");
const btnIcon = document.getElementById("btnIcon");
const btnText = document.getElementById("btnText");
const analyzeBtn = document.getElementById("analyzeBtn");
const learnMoreBtn = document.getElementById("learnMoreBtn");
const learnMorePanel = document.getElementById("learnMorePanel");
const CIRC = 138.2;


function renderSignalList(container, wrapper, items, itemClass, iconClass) {
  container.innerHTML = "";

  if (!Array.isArray(items) || !items.length) {
    wrapper.style.display = "none";
    return;
  }

  items.forEach((textValue) => {
    const item = document.createElement("div");
    item.className = itemClass;

    const icon = document.createElement("div");
    icon.className = iconClass;

    const text = document.createElement("span");
    text.textContent = String(textValue);

    item.appendChild(icon);
    item.appendChild(text);
    container.appendChild(item);
  });

  wrapper.style.display = "block";
}

function setLoading(on) {
  analyzeBtn.classList.toggle("loading", on);
  spinner.style.display = on ? "block" : "none";
  btnIcon.style.display = on ? "none" : "block";
  btnText.textContent = on ? "Scanning…" : "Rescan Site";

  if (on) {
    statusLabel.textContent = "Scanning…";
    statusDot.className = "status-dot";
  }
}

function applyResult(score, level, reasons, xaiExplanations = []) {
  setLoading(false);

  const cleanScore = Math.max(0, Math.min(100, Number(score) || 0));
  const cls = level === "Safe" ? "safe" : (level === "Low Risk" || level === "Suspicious") ? "warn" : "danger";

  statusCard.className = "status-card " + cls;
  statusLabel.className = "status-label " + cls;
  riskFill.className = "risk-bar-fill " + cls;
  ringFill.style.stroke = cls === "safe" ? "var(--safe)" : cls === "warn" ? "var(--warn)" : "var(--danger)";

  statusLabel.textContent =
    level === "Safe" ? "✓ Safe" :
    (level === "Low Risk" || level === "Suspicious") ? "⚠ Low Risk" :
    level === "High Risk" ? "✗ High Risk" : level;

  scoreNum.textContent = cleanScore;
  ringFill.style.strokeDashoffset = CIRC - (cleanScore / 100) * CIRC;
  riskFill.style.width = cleanScore + "%";
  idleMsg.style.display = "none";
  statusDot.className = "status-dot live";

  renderSignalList(reasonsList, reasonsWrap, reasons, "reason-item", "reason-icon");
  renderSignalList(xaiList, xaiWrap, xaiExplanations, "xai-item", "xai-icon");
}

function setError(msg) {
  setLoading(false);
  statusCard.className = "status-card";
  statusLabel.className = "status-label";
  statusLabel.textContent = msg || "Scan failed";
  scoreNum.textContent = "—";
  riskFill.style.width = "0%";
  ringFill.style.strokeDashoffset = CIRC;
  reasonsWrap.style.display = "none";
  xaiWrap.style.display = "none";
}

function getCurrentHostname(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      setError("Cannot read current tab.");
      return;
    }

    try {
      const url = new URL(tabs[0].url);
      callback(tabs[0], url.hostname);
    } catch (_) {
      setError("Cannot analyze this page.");
    }
  });
}

function analyzePage() {
  setLoading(true);

  const timeout = setTimeout(() => {
    setError("Scan timeout. Try again.");
  }, 15000);

  getCurrentHostname((tab) => {
    chrome.tabs.sendMessage(tab.id, { action: "extract_features" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        clearTimeout(timeout);
        setError("Cannot analyze this page.");
        return;
      }

      chrome.runtime.sendMessage({ action: "process_features", data: response }, (result) => {
        clearTimeout(timeout);

        if (chrome.runtime.lastError || !result || result.classification === "Server Error") {
          setError("No response from security engine.");
          return;
        }

        applyResult(result.riskScore, result.classification, result.reasons, result.xai_explanations);
      });
    });
  });
}

function buildCacheKey(rawUrl) {
  try {
    const url = new URL(rawUrl);
    url.hash = "";
    return `scan:v3:${url.origin}${url.pathname}${url.search}`;
  } catch (_) {
    return `scan:v3:${rawUrl}`;
  }
}

function loadCachedResult() {
  getCurrentHostname((tab, hostname) => {
    const cacheKey = buildCacheKey(tab.url);

    chrome.storage.local.get([cacheKey], (result) => {
      const data = result[cacheKey];

      if (data && typeof data.classification === "string" && typeof data.riskScore === "number") {
        applyResult(data.riskScore, data.classification, data.reasons, data.xai_explanations);
      } else {
        analyzePage();
      }
    });
  });
}


learnMoreBtn.addEventListener("click", () => {
  learnMorePanel.classList.toggle("open");
  learnMoreBtn.textContent = learnMorePanel.classList.contains("open") ? "Hide Details" : "Learn More";
});

analyzeBtn.addEventListener("click", analyzePage);

loadCachedResult();
