const API_URL = 'http://localhost:8000';
let analyzedUrls = new Map();

async function analyzeUrl(url) {
  try {
    // Check if URL was recently analyzed (within last 5 minutes)
    const cachedResult = analyzedUrls.get(url);
    if (cachedResult && (Date.now() - cachedResult.timestamp) < 300000) {
      return { status: 'success', data: cachedResult.data };
    }

    console.log(url);
    const response = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });


    if (!response.ok) {
      throw new Error(`Server responded with status ${response.status}`);
    }

    const data = await response.json();
    console.log('Backend response:', data); // For debugging

    // Cache the result
    analyzedUrls.set(url, {
      timestamp: Date.now(),
      data: data
    });


    return { status: 'success', data };
  } catch (error) {
    console.error('Error analyzing URL:', error);
    return { status: 'error', error: error.message };
  }
}

// Clean up old cached results periodically
const cleanupInterval = setInterval(() => {
  const fiveMinutesAgo = Date.now() - 300000;
  for (const [url, data] of analyzedUrls.entries()) {
    if (data.timestamp < fiveMinutesAgo) {
      analyzedUrls.delete(url);
    }
  }
}, 60000);

// Cleanup handler for when extension is unloaded
chrome.runtime.onSuspend.addListener(() => {
  clearInterval(cleanupInterval);
});

// Listen for URL changes
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {  // Main frame only
    console.log("Analyzing URL:", details.url);
    
    try {
      const analysis = await analyzeUrl(details.url);
      
      if (analysis.status === 'success' && analysis.data.risk_score > 70) {
        // Store the analysis result
        await chrome.storage.session.set({
          [`analysis_${details.tabId}`]: analysis.data
        });

        // Show warning notification
        await chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/warning.png',
          title: 'Phishing Warning!',
          message: `Risk Score: ${analysis.data.risk_score}. This website might be a phishing attempt. Proceed with caution.`,
          priority: 2
        });
        
        // Send warning to content script
        try {
          await chrome.tabs.sendMessage(details.tabId, {
            type: 'PHISHING_WARNING',
            data: analysis.data
          });
        } catch (error) {
          console.error('Error sending message to content script:', error);
        }
      }
    } catch (error) {
      console.error('Error in navigation listener:', error);
    }
  }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_ANALYSIS') {
    analyzeUrl(request.url)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ status: 'error', error: error.message }));
    return true; // Will respond asynchronously
  }
});