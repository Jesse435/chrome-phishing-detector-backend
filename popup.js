const statusEl = document.getElementById("status");
const scoreEl = document.getElementById("riskScore");
const reasonsEl = document.getElementById("reasons");
const autoToggle = document.getElementById("autoToggle");


// -----------------------------
// LOAD AUTO SCAN SETTING
// -----------------------------
chrome.storage.sync.get(["autoScan"], (result) => {

  if (result.autoScan) {
    autoToggle.checked = true;
  }

});


// -----------------------------
// SAVE AUTO SCAN SETTING
// -----------------------------
autoToggle.addEventListener("change", () => {

  chrome.storage.sync.set({
    autoScan: autoToggle.checked
  });

});


// -----------------------------
// ANALYZE BUTTON
// -----------------------------
document.getElementById("analyzeBtn").addEventListener("click", analyzePage);


function analyzePage() {

  statusEl.innerText = "Analyzing...";
  scoreEl.innerText = "";
  reasonsEl.innerHTML = "";

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

    chrome.tabs.sendMessage(
      tabs[0].id,
      { action: "extract_features" },
      (features) => {

        if (chrome.runtime.lastError || !features) {

          statusEl.innerText = "Cannot analyze this page.";
          return;

        }

        chrome.runtime.sendMessage(
          {
            action: "process_features",
            data: features
          },

          (response) => {

            if (!response) {

              statusEl.innerText = "No response from security engine.";
              return;

            }

            // -----------------------------
            // DISPLAY RESULTS
            // -----------------------------
            statusEl.innerText = response.classification;

            scoreEl.innerText = `Risk Score: ${response.riskScore}/100`;

            if (response.reasons && response.reasons.length > 0) {

              let list = "<strong>Reasons:</strong><ul>";

              response.reasons.forEach(reason => {
                list += `<li>${reason}</li>`;
              });

              list += "</ul>";

              reasonsEl.innerHTML = list;

            }

          }
        );

      }
    );

  });

}


// -----------------------------
// AUTO SCAN ON POPUP OPEN
// -----------------------------
chrome.storage.sync.get(["autoScan"], (result) => {

  if (result.autoScan) {

    analyzePage();

  }

});