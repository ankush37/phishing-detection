let warningBanner = null;

// Create and show warning banner
function showWarningBanner(data) {
  if (warningBanner) {
    document.body.removeChild(warningBanner);
  }

  warningBanner = document.createElement('div');
  warningBanner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background-color: #ff4444;
    color: white;
    padding: 10px;
    text-align: center;
    z-index: 999999;
    font-family: Arial, sans-serif;
    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  `;

  warningBanner.innerHTML = `
    <strong>⚠️ Warning: Potential Phishing Site Detected!</strong>
    <br>
    Risk Score: ${data.risk_score}
    <button onclick="this.parentElement.style.display='none'" style="
      margin-left: 10px;
      padding: 5px 10px;
      border: none;
      border-radius: 3px;
      background: white;
      cursor: pointer;
    ">Dismiss</button>
  `;

  document.body.insertBefore(warningBanner, document.body.firstChild);
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PHISHING_WARNING') {
    showWarningBanner(message.data);
  }
});
