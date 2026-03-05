chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (request.action === "process_features") {

    const features = request.data;

    fetch("https://chrome-phishing-detector-backend.onrender.com/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(features)
    })
      .then(response => response.json())
      .then(data => {

        let classification = "Safe";

        if (data.prediction === "phishing") {
          classification = "Phishing";
        }

        sendResponse({
          classification: classification,
          riskScore: Math.round(data.confidence * 100)
        });

      })
      .catch(error => {
        console.error("API error:", error);

        sendResponse({
          classification: "Error contacting AI server",
          riskScore: 0
        });
      });

    return true; // keeps sendResponse async
  }

});