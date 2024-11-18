function getRiskLevel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

function getRiskIcon(level) {
  const icons = {
    'Critical': '🔴',
    'High': '🟠',
    'Medium': '🟡',
    'Low': '🟢'
  };
  return icons[level] || '⚪';
}

function formatDateTime(isoString) {
  try {
    const date = new Date(isoString);
    return date.toLocaleString();
  } catch (e) {
    return 'Unknown';
  }
}

function renderList(items, emptyMessage = 'None found') {
  if (!Array.isArray(items) || items.length === 0) {
    return `<li class="empty-list">${emptyMessage}</li>`;
  }
  return items.map(item => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderObjectProperties(obj) {
  if (!obj || Object.keys(obj).length === 0) {
    return '<li class="empty-list">No information available</li>';
  }
  
  return Object.entries(obj)
    .map(([key, value]) => {
      const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      return `<li><strong>${escapeHtml(formattedKey)}:</strong> ${escapeHtml(value)}</li>`;
    })
    .join('');
}

async function getCurrentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url;
  } catch (error) {
    throw new Error('Failed to get current tab URL');
  }
}

async function getAnalysis() {
  const status = document.getElementById('status');
  const analysis = document.getElementById('analysis');
  
  if (!status || !analysis) {
    console.error('Required DOM elements not found');
    return;
  }

  try {
    const url = await getCurrentTabUrl();
    
    if (!url) {
      throw new Error('No active tab URL found');
    }

    status.innerHTML = `
      <div class="loading">
        <div class="loading-spinner"></div>
        Analyzing URL...
      </div>
    `;

    const result = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Analysis request timed out'));
      }, 15000);

      chrome.runtime.sendMessage(
        { type: 'GET_ANALYSIS', url },
        (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(response);
          }
        }
      );
    });
    
    if (result.status === 'success' && result.data) {
      const data = result.data.data;
      const riskScore = data.risk_score || 0;
      const riskLevel = getRiskLevel(riskScore);
      const riskIcon = getRiskIcon(riskLevel);
      const isValidUrl = data.is_valid_url ? '✅ Valid URL' : '❌ Invalid URL';

      status.innerHTML = `
        <div class="risk-level ${riskLevel.toLowerCase()}">
          <h3>${riskIcon} Risk Level: ${riskLevel}</h3>
          <div class="risk-score">
            <span>Risk Score</span>
            <strong>${riskScore}</strong>
          </div>
          <div class="url-status">${isValidUrl}</div>
        </div>
      `;

      let analysisContent = `
        <div class="details">
          <div class="analysis-section">
            <h3>URL Information</h3>
            <ul>
              <li><strong>URL:</strong> ${escapeHtml(data.url)}</li>
              <li><strong>Analyzed at:</strong> ${formatDateTime(data.timestamp)}</li>
            </ul>
          </div>

          <div class="analysis-section">
            <h3>Domain Information</h3>
            <ul>
              ${renderObjectProperties(data.domain_info)}
            </ul>
          </div>

          <div class="analysis-section">
            <h3>Risk Factors</h3>
            <ul>
              ${renderList(data.risk_factors, 'No risk factors detected')}
            </ul>
          </div>
      `;

      if (data.redirect_chain && data.redirect_chain.length > 0) {
        analysisContent += `
          <div class="analysis-section">
            <h3>Redirect Chain</h3>
            <ul>
              ${renderList(data.redirect_chain, 'No redirects detected')}
            </ul>
          </div>
        `;
      }

      analysisContent += '</div>';
      analysis.innerHTML = analysisContent;

    } else {
      throw new Error(result.error || 'Failed to analyze URL');
    }
  } catch (error) {
    console.error('Analysis error:', error);
    status.innerHTML = `
      <div class="error">
        Error analyzing URL: ${escapeHtml(error.message)}
        <button onclick="getAnalysis()" class="retry-button">Retry Analysis</button>
      </div>
    `;
    analysis.innerHTML = '';
  }
}

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', getAnalysis);