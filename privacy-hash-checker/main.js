// Firefox PC version – with inline results, new‑tab toggle, notification toggle, history link
let scanHistory = [];
let disabledSites = [];

// --- Preference defaults ---
const DEFAULT_OPEN_NEW_TAB = true;
const DEFAULT_NOTIFICATIONS = false;
const DEFAULT_SCAN_IN_PAGE = true;

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

async function loadScanInPagePref() {
  const result = await browser.storage.local.get('scanLinksInPage');
  const enabled = result.scanLinksInPage !== undefined ? result.scanLinksInPage : DEFAULT_SCAN_IN_PAGE;
  document.getElementById('scanInPageCheckbox').checked = enabled;
  browser.runtime.sendMessage({ action: 'setScanLinksInPage', enabled: enabled });
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

document.getElementById('scanInPageCheckbox').addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  await browser.storage.local.set({ scanLinksInPage: enabled });
  browser.runtime.sendMessage({ action: 'setScanLinksInPage', enabled: enabled });
});

// --- Check for stored error from background ---
async function checkForStoredError() {
  const result = await browser.storage.local.get('lastError');
  const error = result.lastError;
  if (error && error.filename && error.message) {
    const status = document.getElementById('uploadStatus');
    status.textContent = '';
    status.appendChild(document.createTextNode('⚠️ '));
    const strong = document.createElement('strong');
    strong.textContent = error.filename;
    status.appendChild(strong);
    status.appendChild(document.createTextNode(`: ${error.message}`));
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

// Shared by both manual-lookup flows (file upload and typed-in hash).
// The API key decides whether we can get a real verdict: with a key, we
// call VirusTotal and log the actual result (malicious/suspicious/etc) to
// history. Without a key, we can't check at all, but the scan is still
// logged — as "unscanned" (found: false), the same shape used when
// VirusTotal itself has never seen the hash — so it still shows up and can
// still be uploaded later from the history list. The "open new tab"
// preference is purely additive on top of either path.
async function runVtLookup(hash, filename, sourceLabel, statusElId) {
  const { apiKey } = await browser.storage.local.get('apiKey');
  const vtUrl = `https://www.virustotal.com/gui/file/${hash}`;

  if (!apiKey) {
    showStatus(statusElId, 'API key not loaded. Saved to history as unscanned.', 'warning');
    await saveToHistory({
      hash, filename, sourceUrl: sourceLabel, vtUrl,
      found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0
    });
    await browser.tabs.create({ url: vtUrl, active: true });
    return;
  }

  showStatus(statusElId, 'Checking with VirusTotal...', 'info');
  const result = await checkHash(hash, filename, sourceLabel);
  showDetailedResult(statusElId, result);
  if (shouldOpenNewTab()) {
    await browser.tabs.create({ url: result.vtUrl, active: true });
  }
}

// Upload & scan
document.getElementById('scanFile').onclick = async () => {
  // Clear any previous auto‑scan error before manual scan
  await browser.storage.local.remove('lastError');

  const file = document.getElementById('fileInput').files[0];
  if (!file) {
    showStatus('uploadStatus', 'Select a file first', 'error');
    return;
  }
  showStatus('uploadStatus', 'Hashing...', 'info');
  try {
    const arrayBuffer = await file.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    const uploadHashEl = document.getElementById('uploadHash');
    uploadHashEl.textContent = '';
    const hashLabel = document.createElement('strong');
    hashLabel.textContent = 'SHA-256:';
    uploadHashEl.appendChild(hashLabel);
    uploadHashEl.appendChild(document.createElement('br'));
    uploadHashEl.appendChild(document.createTextNode(hash));
    uploadHashEl.style.display = 'block';

    await runVtLookup(hash, file.name, 'upload', 'uploadStatus');
    document.getElementById('fileInput').value = '';
  } catch (e) {
    showStatus('uploadStatus', e.message, 'error');
  }
};

// Manual hash lookup
document.getElementById('checkHash').onclick = async () => {
  // Clear any previous auto‑scan error before manual lookup
  await browser.storage.local.remove('lastError');

  const hash = document.getElementById('hashInput').value.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    showStatus('hashStatus', 'Invalid SHA-256 hash', 'error');
    return;
  }
  try {
    await runVtLookup(hash, hash.substring(0, 16) + '...', 'manual', 'hashStatus');
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
    vtResult.found = true;
    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    vtResult.malicious = stats.malicious || 0;
    vtResult.suspicious = stats.suspicious || 0;
    vtResult.harmless = stats.harmless || 0;
    vtResult.undetected = stats.undetected || 0;
  } else if (response.status === 404) {
    vtResult.found = false;
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
  el.textContent = '';

  // --- If hash not found (unscanned) ---
  if (!data.found) {
    const title = makeEl('div', {
      style: 'font-weight: bold; font-size: 1.1rem; margin-bottom: 6px; color: #856404;',
      text: '❓ Unscanned file'
    });

    const uploadLink = makeEl('a', {
      href: 'https://www.virustotal.com/gui/home/upload',
      target: '_blank',
      class: 'vt-link-button',
      style: 'margin-top: 8px; display: inline-block;',
      text: '📤 Upload to VirusTotal →'
    });
    const body = makeEl('div', { style: 'margin: 8px 0;' }, [
      'This file has not been uploaded to VirusTotal yet.',
      document.createElement('br'),
      uploadLink
    ]);

    const filenameBadge = makeEl('div', {
      style: 'font-size: 13px; background: #e9ecef; padding: 4px 12px; border-radius: 20px; display: inline-flex; align-items: center; gap: 6px; margin-top: 8px;'
    }, [
      makeEl('span', { style: 'font-size: 16px;', text: '📄' }),
      makeEl('strong', { style: 'color: #333;', text: data.filename || 'Unnamed file' })
    ]);

    el.appendChild(title);
    el.appendChild(body);
    el.appendChild(filenameBadge);
    el.className = 'status warning';
    el.style.display = 'block';
    return;
  }

  // --- Found – normal display ---
  const isMalicious = data.malicious > 0;
  const isSuspicious = data.suspicious > 0;
  const statusClass = isMalicious ? 'error' : (isSuspicious ? 'warning' : 'success');
  const statusText = isMalicious ? '⚠️ MALICIOUS' : (isSuspicious ? '⚡ Suspicious' : '✅ Clean');

  const statusTitle = makeEl('div', {
    style: 'font-weight: bold; font-size: 1.1rem; margin-bottom: 6px;',
    text: statusText
  });

  const statsRow = makeEl('div', { style: 'display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0;' }, [
    makeEl('span', {}, [makeEl('strong', { text: '🦠 Malicious:' }), ` ${data.malicious}`]),
    makeEl('span', {}, [makeEl('strong', { text: '⚠️ Suspicious:' }), ` ${data.suspicious}`]),
    makeEl('span', {}, [makeEl('strong', { text: '✅ Harmless:' }), ` ${data.harmless}`]),
    makeEl('span', {}, [makeEl('strong', { text: '❓ Undetected:' }), ` ${data.undetected}`])
  ]);

  const filenameBadge2 = makeEl('span', {
    style: 'font-size: 13px; background: #e9ecef; padding: 4px 12px; border-radius: 20px; display: inline-flex; align-items: center; gap: 6px;'
  }, [
    makeEl('span', { style: 'font-size: 16px;', text: '📄' }),
    makeEl('strong', { style: 'color: #333;', text: data.filename || 'Unnamed file' })
  ]);

  const vtLink = makeEl('a', {
    href: data.vtUrl,
    target: '_blank',
    class: 'vt-link-button',
    text: '🔗 Open VirusTotal Page →'
  });

  const footerRow = makeEl('div', {
    style: 'display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; margin-top: 8px;'
  }, [filenameBadge2, vtLink]);

  el.appendChild(statusTitle);
  el.appendChild(statsRow);
  el.appendChild(footerRow);
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

function renderHistory() {
  const container = document.getElementById('historyList');
  container.textContent = '';

  if (!scanHistory.length) {
    container.appendChild(makeEl('div', { class: 'empty', text: 'No scans yet' }));
    return;
  }

  for (const item of scanHistory) {
    // found === false means VirusTotal returned 404 for this hash — it has
    // never been scanned there. The malicious/suspicious/etc counts are
    // placeholder zeros in that case, NOT a real "clean" verdict, so they
    // must never be shown as if they were.
    const isUnscanned = item.found === false;

    const badge = makeEl('span', {
      class: 'history-badge',
      style: `background:${isUnscanned ? '#6c757d' : (item.malicious > 0 ? '#dc3545' : '#28a745')}`,
      text: isUnscanned ? '❓ Unscanned' : (item.malicious > 0 ? '⚠️ Malicious' : '✅ Clean')
    });

    function openUploadPage() {
      window.open('https://www.virustotal.com/gui/home/upload', '_blank');
    }

    const resultsLink = makeEl('a', isUnscanned ? {
      href: 'https://www.virustotal.com/gui/home/upload',
      target: '_blank',
      class: 'history-link',
      style: 'color: #667eea; text-decoration: none; font-weight: 600; font-size: 14px; white-space: nowrap;',
      text: 'Upload ↗'
    } : {
      href: item.vtUrl,
      target: '_blank',
      class: 'history-link',
      style: 'color: #667eea; text-decoration: none; font-weight: 600; font-size: 14px; white-space: nowrap;',
      text: 'Results ↗'
    });
    resultsLink.addEventListener('click', (e) => e.stopPropagation());

    const headerRight = makeEl('div', { style: 'display: flex; align-items: center; gap: 12px;' }, [badge, resultsLink]);

    const header = makeEl('div', { class: 'history-item-header' }, [
      makeEl('span', { class: 'history-filename', text: item.filename }),
      headerRight
    ]);

    const hashLine = makeEl('div', {
      class: 'history-hash',
      style: 'font-family: monospace; font-size: 11px; word-break: break-all; color: #333;',
      text: item.hash
    });

    const row = makeEl('div', { class: 'history-item' }, [header, hashLine]);

    if (item.sourceUrl) {
      row.appendChild(makeEl('div', { class: 'history-url', text: item.sourceUrl }));
    }
    row.appendChild(makeEl('div', { class: 'history-time', text: new Date(item.time).toLocaleString() }));

    row.addEventListener('click', () => {
      if (isUnscanned) openUploadPage();
      else window.open(item.vtUrl, '_blank');
    });

    container.appendChild(row);
  }
}

// Builds a DOM element without ever touching innerHTML, so dynamic values
// (filenames, urls, counts) can never be interpreted as markup.
// attrs.text sets textContent; attrs.style takes a CSS string; any other
// key is set via setAttribute. children may be strings (-> text nodes) or
// already-built elements.
function makeEl(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'style') node.style.cssText = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

document.getElementById('clearHistory').onclick = async () => {
  if (confirm('Clear all history?')) {
    scanHistory = [];
    await browser.storage.local.set({ history: [] });
    renderHistory();
  }
};

// --- Disabled sites (per-website scan skipping) ---
async function loadDisabledSites() {
  const result = await browser.storage.local.get('disabledSites');
  disabledSites = Array.isArray(result.disabledSites) ? result.disabledSites : [];
  renderDisabledSites();
}

function renderDisabledSites() {
  const container = document.getElementById('disabledSitesList');
  container.textContent = '';

  if (!disabledSites.length) {
    container.appendChild(makeEl('div', { class: 'empty', text: 'No sites disabled' }));
    return;
  }

  disabledSites.forEach((site, i) => {
    const pattern = makeEl('span', { class: 'disabled-site-pattern', text: site });
    const removeBtn = makeEl('button', { class: 'small remove-disabled-site', text: '✕' });
    removeBtn.dataset.index = i;
    const row = makeEl('div', { class: 'disabled-site-item' }, [pattern, removeBtn]);
    row.dataset.index = i;
    container.appendChild(row);
  });
}

async function saveDisabledSites() {
  await browser.storage.local.set({ disabledSites });
  browser.runtime.sendMessage({ action: 'setDisabledSites', sites: disabledSites });
}

document.getElementById('addDisabledSite').onclick = async () => {
  const input = document.getElementById('disabledSiteInput');
  const value = input.value.trim();
  if (!value) return;
  if (disabledSites.includes(value)) {
    input.value = '';
    return;
  }
  disabledSites.push(value);
  await saveDisabledSites();
  renderDisabledSites();
  input.value = '';
};

document.getElementById('disabledSiteInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    document.getElementById('addDisabledSite').click();
  }
});

document.getElementById('disabledSitesList').addEventListener('click', async (e) => {
  if (!e.target.classList.contains('remove-disabled-site')) return;
  const idx = parseInt(e.target.dataset.index, 10);
  if (Number.isNaN(idx)) return;
  disabledSites.splice(idx, 1);
  await saveDisabledSites();
  renderDisabledSites();
});

async function initPreferences() {
  await loadNewTabPref();
  await loadNotificationPref();
  await loadScanInPagePref();
  await loadDisabledSites();
}

loadApiKey();
loadHistory();
initPreferences();
