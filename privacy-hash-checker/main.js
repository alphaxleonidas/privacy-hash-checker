// Firefox PC version – with inline results, new‑tab toggle, notification toggle, and history links
let scanHistory = [];

// --- Preference defaults ---
const DEFAULT_OPEN_NEW_TAB = true;
const DEFAULT_NOTIFICATIONS = false;

// --- Helper: should open new tab for manual scans? ---
function shouldOpenNewTab() {
  const checkbox = document.getElementById('openNewTabCheckbox');
  return checkbox ? checkbox.checked : DEFAULT_OPEN_NEW_TAB;
}

// --- Load and save preferences ---
async function loadNewTabPref() {
  const result = await browser.storage.local.get('openNewTab');
  const enabled = result.openNewTab !== undefined ? result.openNewTab : DEFAULT_OPEN_NEW_TAB;
  document.getElementById('openNewTabCheckbox').checked = enabled;
}

async function loadNotificationPref() {
  const result = await browser.storage.local.get('notificationsEnabled');
  const enabled = result.notificationsEnabled !== undefined ? result.notificationsEnabled : DEFAULT_NOTIFICATIONS;
  document.getElementById('notificationsCheckbox').checked = enabled;
  browser.runtime.sendMessage({ action: 'setNotifications', enabled: enabled });
}

document.getElementById('openNewTabCheckbox').addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  await browser.storage.local.set({ openNewTab: enabled });
});

document.getElementById('notificationsCheckbox').addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  await browser.storage.local.set({ notificationsEnabled: enabled });
  browser.runtime.sendMessage({ action: 'setNotifications', enabled: enabled });
});

// --- Check for stored error from background ---
async function checkForStoredError() {
  const result = await browser.storage.local.get('lastError');
  const error = result.lastError;
  if (error && error.filename && error.message) {
    const status = document.getElementById('uploadStatus');
    status.innerHTML = `
      ⚠️ Auto‑scan failed for "<strong>${escapeHtml(error.filename)}</strong>": ${escapeHtml(error.message)}
      <br>Please upload the file manually.
    `;
    status.className = 'status warning';
    status.style.display = 'block';
    await browser.storage.local.remove('lastError');
  }
}
document.addEventListener('DOMContentLoaded', checkForStoredError);

// --- Load API key ---
async function loadApiKey() {
  const result = await browser.storage.local.get('apiKey');
  if (result.apiKey) {
    document.getElementById('apiStatus').textContent = '✓ API key loaded';
    document.getElementById('apiStatus').className = 'status success';
    setTimeout(() => document.getElementById('apiStatus').style.display = 'none', 3000);
  }
}

document.getElementById('saveKey').onclick = async () => {
  const key = document.getElementById('apiKey').value.trim();
  if (!key) {
    showStatus('apiStatus', 'Please enter an API key', 'error');
    return;
  }
  await browser.storage.local.set({ apiKey: key });
  showStatus('apiStatus', 'API key saved!', 'success');
  document.getElementById('apiKey').value = '';
  loadApiKey();
};

// Upload & scan
document.getElementById('scanFile').onclick = async () => {
  const file = document.getElementById('fileInput').files[0];
  if (!file) {
    showStatus('uploadStatus', 'Select a file first', 'error');
    return;
  }
  showStatus('uploadStatus', 'Hashing...', 'info');
  try {
    const arrayBuffer = await file.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    document.getElementById('uploadHash').innerHTML = `<strong>SHA-256:</strong><br>${hash}`;
    document.getElementById('uploadHash').style.display = 'block';
    showStatus('uploadStatus', 'Checking with VirusTotal...', 'info');
    const result = await checkHash(hash, file.name, 'upload');
    showDetailedResult('uploadStatus', result);
    if (shouldOpenNewTab()) {
      await browser.tabs.create({ url: result.vtUrl, active: true });
    }
    document.getElementById('fileInput').value = '';
  } catch (e) {
    showStatus('uploadStatus', e.message, 'error');
  }
};

// Manual hash lookup
document.getElementById('checkHash').onclick = async () => {
  const hash = document.getElementById('hashInput').value.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    showStatus('hashStatus', 'Invalid SHA-256 hash', 'error');
    return;
  }
  try {
    const result = await checkHash(hash, hash.substring(0, 16)+'...', 'manual');
    showDetailedResult('hashStatus', result);
    if (shouldOpenNewTab()) {
      await browser.tabs.create({ url: result.vtUrl, active: true });
    }
    document.getElementById('hashInput').value = '';
  } catch (e) {
    showStatus('hashStatus', e.message, 'error');
  }
};

async function computeHash(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function checkHash(hash, filename, sourceUrl) {
  const result = await browser.storage.local.get('apiKey');
  const apiKey = result.apiKey;
  if (!apiKey) throw new Error('No API key set');

  const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { 'x-apikey': apiKey }
  });
  let vtResult = { hash, filename, sourceUrl, vtUrl: `https://www.virustotal.com/gui/file/${hash}` };

  if (response.status === 200) {
    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    vtResult.malicious = stats.malicious || 0;
    vtResult.suspicious = stats.suspicious || 0;
    vtResult.harmless = stats.harmless || 0;
    vtResult.undetected = stats.undetected || 0;
  } else if (response.status === 404) {
    vtResult.malicious = 0;
    vtResult.suspicious = 0;
    vtResult.harmless = 0;
    vtResult.undetected = 0;
  } else {
    throw new Error(`API returned ${response.status}`);
  }

  await saveToHistory(vtResult);
  return vtResult;
}

function showDetailedResult(elementId, data) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const isMalicious = data.malicious > 0;
  const isSuspicious = data.suspicious > 0;
  const statusClass = isMalicious ? 'error' : (isSuspicious ? 'warning' : 'success');
  const statusText = isMalicious ? '⚠️ MALICIOUS' : (isSuspicious ? '⚡ Suspicious' : '✅ Clean');

  let html = `
    <div style="font-weight: bold; font-size: 1.1rem; margin-bottom: 6px;">${statusText}</div>
    <div style="display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0;">
      <span><strong>🦠 Malicious:</strong> ${data.malicious}</span>
      <span><strong>⚠️ Suspicious:</strong> ${data.suspicious}</span>
      <span><strong>✅ Harmless:</strong> ${data.harmless}</span>
      <span><strong>❓ Undetected:</strong> ${data.undetected}</span>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-top: 8px;">
      <span style="font-size: 13px; background: #e9ecef; padding: 4px 12px; border-radius: 20px; display: inline-flex; align-items: center; gap: 6px;">
        <span style="font-size: 16px;">📄</span>
        <strong style="color: #333;">${escapeHtml(data.filename || 'Unnamed file')}</strong>
      </span>
      <a href="${data.vtUrl}" target="_blank" class="vt-link-button">🔗 Open VirusTotal Page →</a>
    </div>
  `;

  el.innerHTML = html;
  el.className = `status ${statusClass}`;
  el.style.display = 'block';
}

function showStatus(elementId, message, type) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `status ${type}`;
  el.style.display = 'block';
  if (type !== 'error' && type !== 'warning') {
    setTimeout(() => {
      if (el.textContent === message) {
        el.style.display = 'none';
      }
    }, 5000);
  }
}

async function saveToHistory(scan) {
  scanHistory.unshift({ ...scan, id: Date.now(), time: Date.now() });
  if (scanHistory.length > 100) scanHistory.pop();
  await browser.storage.local.set({ history: scanHistory });
  renderHistory();
}

async function loadHistory() {
  const result = await browser.storage.local.get('history');
  scanHistory = result.history || [];
  renderHistory();
}

// --- RENDER HISTORY with "Results ↗" link on the right ---
function renderHistory() {
  const container = document.getElementById('historyList');
  if (!scanHistory.length) {
    container.innerHTML = '<div class="empty">No scans yet</div>';
    return;
  }
  container.innerHTML = scanHistory.map(item => `
    <div class="history-item" onclick="window.open('${item.vtUrl}', '_blank')">
      <div class="history-item-header">
        <span class="history-filename">${escapeHtml(item.filename)}</span>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span class="history-badge" style="background:${item.malicious > 0 ? '#dc3545' : '#28a745'}">
            ${item.malicious > 0 ? '⚠️ Malicious' : '✅ Clean'}
          </span>
          <a href="${item.vtUrl}" target="_blank" onclick="event.stopPropagation();" class="history-link" style="color: #667eea; text-decoration: none; font-weight: 600; font-size: 14px; white-space: nowrap;">
            Results ↗
          </a>
        </div>
      </div>
      <div class="history-hash" style="font-family: monospace; font-size: 11px; word-break: break-all; color: #333;">${item.hash}</div>
      ${item.sourceUrl ? `<div class="history-url">${escapeHtml(item.sourceUrl)}</div>` : ''}
      <div class="history-time">${new Date(item.time).toLocaleString()}</div>
    </div>
  `).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>]/g, m => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;' })[m]);
}

document.getElementById('clearHistory').onclick = async () => {
  if (confirm('Clear all history?')) {
    scanHistory = [];
    await browser.storage.local.set({ history: [] });
    renderHistory();
  }
};

async function initPreferences() {
  await loadNewTabPref();
  await loadNotificationPref();
}

loadApiKey();
loadHistory();
initPreferences();
