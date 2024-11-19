// Helper function to get current tab URL
async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.url;
}

function getRiskLevel(data) {
  return data.risk_assessment?.risk_level || 'Unknown';
}

function getRiskScore(data) {
  return data.risk_assessment?.risk_score?.toFixed(1) || 0;
}

function getRiskIcon(level) {
  const icons = {
    'Critical': '🔴',
    'High': '🟠',
    'Medium': '🟡',
    'Low': '🟢',
    'Unknown': '⚪'
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

function formatDomainAge(days) {
  if (days < 30) return `${days} days old (Very New!) ⚠️`;
  if (days < 90) return `${days} days old (New)`;
  if (days < 365) return `${days} days old`;
  return `${Math.floor(days/365)} years old`;
}

function getSecurityIndicators(data) {
  const indicators = [];
  
  // SSL Status
  const hasSSL = data.security_features?.ssl_info?.has_ssl;
  indicators.push({
    icon: hasSSL ? '🔒' : '🔓',
    text: hasSSL ? 'SSL Protected' : 'No SSL Protection',
    status: hasSSL ? 'secure' : 'warning'
  });

  // Domain Age
  const domainAgeDays = data.security_features?.domain_age?.age_days;
  if (domainAgeDays !== undefined) {
    indicators.push({
      icon: domainAgeDays < 30 ? '⚠️' : '📅',
      text: formatDomainAge(domainAgeDays),
      status: domainAgeDays < 30 ? 'warning' : 'info'
    });
  }

  // Threat Intelligence
  const isMalicious = data.threat_intel?.is_malicious;
  if (isMalicious) {
    indicators.push({
      icon: '⛔',
      text: 'Detected in Threat Feeds',
      status: 'danger'
    });
  }

  return indicators;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function renderList(items, emptyMessage) {
  if (!items || items.length === 0) {
    return `<li class="empty-list">${escapeHtml(emptyMessage)}</li>`;
  }
  return items.map(item => `<li>${escapeHtml(item)}</li>`).join('');
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
      const riskLevel = getRiskLevel(data);
      const riskScore = getRiskScore(data);
      const riskIcon = getRiskIcon(riskLevel);
      const securityIndicators = getSecurityIndicators(data);

      status.innerHTML = `
        <div class="risk-level ${riskLevel.toLowerCase()}">
          <h3>${riskIcon} Risk Level: ${riskLevel}</h3>
          <div class="risk-score">
            <span>Risk Score</span>
            <strong>${riskScore}</strong>
          </div>
          <div class="security-indicators">
            ${securityIndicators.map(indicator => `
              <div class="indicator ${indicator.status}">
                ${indicator.icon} ${indicator.text}
              </div>
            `).join('')}
          </div>
        </div>
      `;

      let analysisContent = `
        <div class="details">
          <div class="analysis-section">
            <h3>URL Information</h3>
            <ul>
              <li><strong>URL:</strong> ${escapeHtml(data.url)}</li>
              <li><strong>Domain:</strong> ${escapeHtml(data.domain_info?.full_domain || 'Unknown')}</li>
              <li><strong>Analyzed:</strong> ${formatDateTime(data.timestamp)}</li>
            </ul>
          </div>

          <div class="analysis-section">
            <h3>Risk Factors</h3>
            <ul>
              ${renderList(data.risk_assessment?.risk_factors, 'No risk factors detected')}
            </ul>
          </div>

          <div class="analysis-section">
            <h3>Threat Intelligence</h3>
            <ul>
              ${data.threat_intel?.is_malicious ? 
                data.threat_intel.sources.map(source => 
                  `<li>⚠️ Detected in ${escapeHtml(source.feed)} as ${escapeHtml(source.type)}</li>`
                ).join('') : 
                '<li class="empty-list">No threats detected</li>'
              }
            </ul>
          </div>
        </div>
      `;

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

// Add event listener to start analysis when popup loads
document.addEventListener('DOMContentLoaded', getAnalysis);

// Add debug logging
function debugLog(message) {
  const debugLogElement = document.getElementById('debugLog');
  if (debugLogElement) {
    debugLogElement.textContent += `${new Date().toISOString()}: ${message}\n`;
  }
  console.log(message);
}