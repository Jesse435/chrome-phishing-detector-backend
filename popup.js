document.getElementById("analyzeBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.tabs.sendMessage(
      tabs[0].id,
      { action: "extract_features" },
      (features) => {
        if (chrome.runtime.lastError) {
          document.getElementById("status").innerText =
            "Cannot analyze this page.";
          return;
        }

        // Send features to background for processing
        chrome.runtime.sendMessage(
          {
            action: "process_features",
            data: features
          },
          (response) => {
            document.getElementById("status").innerHTML = `
            ${response.classification}<br>
      <strong>Risk Score:</strong> ${response.riskScore}/100
    `;
          }
        );
      }
    );
  });
});
