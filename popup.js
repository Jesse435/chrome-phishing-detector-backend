const statusCard = document.getElementById("statusCard");
const statusLabel = document.getElementById("statusLabel");
const statusDot = document.getElementById("statusDot");
const scoreNum = document.getElementById("scoreNum");
const ringFill = document.getElementById("ringFill");
const riskFill = document.getElementById("riskFill");
const reasonsWrap = document.getElementById("reasonsWrap");
const reasonsList = document.getElementById("reasonsList");
const idleMsg = document.getElementById("idleMsg");
const spinner = document.getElementById("spinner");
const btnIcon = document.getElementById("btnIcon");
const btnText = document.getElementById("btnText");
const analyzeBtn = document.getElementById("analyzeBtn");
const autoToggle = document.getElementById("autoToggle");
const learnMoreBtn = document.getElementById("learnMoreBtn");
const learnMorePanel = document.getElementById("learnMorePanel");
const xaiWrap = document.getElementById("xaiWrap");
const xaiList = document.getElementById("xaiList");

const CIRC = 138.2;
const CACHE_VERSION = "v2";

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

function clearList(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function addReasonItem(parent, reason) {
  const item = document.createElement("div");
  item.className = "reason-item";

  const icon = document.createElement("div");
  icon.className = "reason-icon";

  const text = document.createElement("span");
  text.textContent = reason;

  item.appendChild(icon);
  item.appendChild(text);
  parent.appendChild(item);
}

function applyResult(score, level, reasons, xaiExplanations = []) {
  setLoading(false);

  const cleanScore = Math.max(0, Math.min(100, Number(score) || 0));
  const cls = level === "Safe" ? "safe" : level === "Suspicious" ? "warn" : "danger";

  statusCard.className = "status-card " + cls;
  statusLabel.className = "status-label " + cls;
  riskFill.className = "risk-bar-fill " + cls;
  ringFill.style.stroke = cls === "safe" ? "var(--safe)" : cls === "warn" ? "var(--warn)" : "var(--danger)";

  statusLabel.textContent =
    level === "Safe" ? "✓ Safe" :
    level === "Suspicious" ? "⚠ Suspicious" :
    level === "High Risk" ? "✗ High Risk" : level;

  scoreNum.textContent = cleanScore;
  ringFill.style.strokeDashoffset = CIRC - (cleanScore / 100) * CIRC;
  riskFill.style.width = cleanScore + "%";
  idleMsg.style.display = "none";
  statusDot.className = "status-dot live";

  clearList(reasonsList);
  if (Array.isArray(reasons) && reasons.length) {
    reasons.forEach((reason) => addReasonItem(reasonsList, reason));
    reasonsWrap.style.display = "block";
  } else {
    reasonsWrap.style.display = "none";
  }

  clearList(xaiList);
  if (Array.isArray(xaiExplanations) && xaiExplanations.length) {
    xaiExplanations.forEach((reason) => addReasonItem(xaiList, reason));
    xaiWrap.style.display = "block";
  } else {
    xaiWrap.style.display = "none";
  }
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

      if (!url.protocol.startsWith("http")) {
        setError("Cannot analyze this page.");
        return;
      }

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
  }, 18000);

  getCurrentHostname((tab) => {
    chrome.tabs.sendMessage(tab.id, { action: "extract_features" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        clearTimeout(timeout);
        setError("Cannot analyze this page. Refresh the tab and try again.");
        return;
      }

      chrome.runtime.sendMessage({ action: "process_features", data: response }, (result) => {
        clearTimeout(timeout);

        if (chrome.runtime.lastError || !result || result.classification === "Server Error") {
          setError("No response from security engine.");
          return;
        }

        applyResult(
          result.riskScore,
          result.classification,
          result.reasons,
          result.xaiExplanations
        );
      });
    });
  });
}

function loadCachedResult() {
  getCurrentHostname((tab, hostname) => {
    const cacheKey = `scan:${CACHE_VERSION}:${hostname}`;

    chrome.storage.local.get([cacheKey], (result) => {
      const data = result[cacheKey];

      if (
        data &&
        typeof data.classification === "string" &&
        typeof data.riskScore === "number"
      ) {
        applyResult(data.riskScore, data.classification, data.reasons, data.xaiExplanations);
        return;
      }

      chrome.storage.sync.get(["autoScan"], (settings) => {
        if (settings.autoScan !== false) {
          analyzePage();
        }
      });
    });
  });
}

chrome.storage.sync.get(["autoScan"], (result) => {
  autoToggle.checked = result.autoScan !== false;
});

autoToggle.addEventListener("change", () => {
  chrome.storage.sync.set({ autoScan: autoToggle.checked });
});

analyzeBtn.addEventListener("click", analyzePage);

if (learnMoreBtn && learnMorePanel) {
  learnMoreBtn.addEventListener("click", () => {
    const isOpen = learnMorePanel.style.display === "block";
    learnMorePanel.style.display = isOpen ? "none" : "block";
    learnMoreBtn.textContent = isOpen ? "Learn More" : "Hide Guide";
  });
}

loadCachedResult();
