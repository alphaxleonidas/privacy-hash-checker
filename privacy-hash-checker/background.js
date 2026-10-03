// Privacy Hash Checker – Firefox PC (desktop)
console.log("Background loaded (Firefox PC)");

let API_KEY = null;
let notificationsEnabled = false; // default off
let disabledSites = []; // site patterns where scanning is skipped, e.g. "google.com/*"
let scanLinksInPage = true; // default ON: context-menu link scans show results on the page
let pendingDownloads = new Map();

// Load API key
browser.storage.local.get('apiKey').then(res => {
  if (res.apiKey) {
    API_KEY = res.apiKey;
    console.log("API key loaded");
  }
});

// Load notification preference (default false)
browser.storage.local.get('notificationsEnabled').then(res => {
  if (res.notificationsEnabled !== undefined) {
    notificationsEnabled = res.notificationsEnabled;
  }
});

// Load disabled-sites list
browser.storage.local.get('disabledSites').then(res => {
  if (Array.isArray(res.disabledSites)) {
    disabledSites = res.disabledSites;
    console.log("Disabled sites loaded:", disabledSites);
  }
});

// Load in-page link-scan preference (default true)
browser.storage.local.get('scanLinksInPage').then(res => {
  if (res.scanLinksInPage !== undefined) {
    scanLinksInPage = res.scanLinksInPage;
  }
});

// Check whether a URL matches a disabled-site pattern.
// Only gates automatic download scanning (see downloads.onCreated below) —
// the "Scan this link" context-menu action always works regardless of
// this list.
// Pattern forms:
//   "google.com/*"    -> matches only the exact host google.com (or www.google.com),
//                         any path.
//   "*.google.com/*"  -> matches google.com itself AND any subdomain
//                         (docs.google.com, mail.google.com, ...).
//   A trailing path (e.g. "google.com/maps/*") restricts the match to
//   URLs whose path starts with that prefix.
// Matching is done on the parsed hostname/path, not a raw string prefix,
// so "google.com" will never match a lookalike host like
// "google.com.evil-tracker.net".
function isUrlDisabled(url) {
  if (!url || !disabledSites.length) return false;
  let target;
  try {
    target = new URL(url);
  } catch (e) {
    return false; // unparseable URL (e.g. blob:, data:) -> never block
  }
  const targetHost = target.hostname.replace(/^www\./i, '').toLowerCase();
  const targetPath = target.pathname;

  return disabledSites.some(pattern => {
    let p = (pattern || '').trim();
    if (!p) return false;
    p = p.replace(/^https?:\/\//i, '');

    const slashIdx = p.indexOf('/');
    let hostPart = (slashIdx === -1 ? p : p.slice(0, slashIdx)).toLowerCase();
    let pathPart = slashIdx === -1 ? '' : p.slice(slashIdx);
    hostPart = hostPart.replace(/^www\./i, '');

    let hostMatches;
    if (hostPart.startsWith('*.')) {
      const domain = hostPart.slice(2);
      hostMatches = targetHost === domain || targetHost.endsWith('.' + domain);
    } else {
      hostMatches = targetHost === hostPart;
    }
    if (!hostMatches) return false;

    if (!pathPart || pathPart === '/' || pathPart === '/*') return true;
    const pp = pathPart.endsWith('/*') ? pathPart.slice(0, -2)
             : pathPart.endsWith('*') ? pathPart.slice(0, -1)
             : pathPart;
    return targetPath.startsWith(pp);
  });
}

// Helper: compute SHA-256
async function computeHash(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Open dashboard when icon is clicked
browser.browserAction.onClicked.addListener(() => {
  browser.tabs.create({ url: browser.runtime.getURL("main.html"), active: true });
});

// Track downloads
browser.downloads.onCreated.addListener((download) => {
  if (isUrlDisabled(download.url)) {
    console.log(`Privacy Hash Checker: site disabled, skipping download → ${download.url}`);
    return;
  }
  const filename = download.filename.split('/').pop().split('\\').pop();
  pendingDownloads.set(download.id, { filename, url: download.url });
  if (notificationsEnabled) {
    browser.notifications.create(`start-${download.id}`, {
      type: "basic",
      title: "📥 Download Started",
      message: filename
    });
    setTimeout(() => browser.notifications.clear(`start-${download.id}`), 3000);
  }
});

browser.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const info = pendingDownloads.get(delta.id);
    if (!info) return;

    const downloads = await browser.downloads.search({ id: delta.id });
    if (!downloads.length) return;

    const download = downloads[0];
    const filename = download.filename.split('/').pop().split('\\').pop();

    // Open dashboard (active)
    const tab = await browser.tabs.create({
      url: browser.runtime.getURL("main.html"),
      active: true
    });

    if (notificationsEnabled) {
      browser.notifications.create(`scanning-${delta.id}`, {
        type: "basic",
        title: "🔍 Scanning",
        message: `Trying to hash ${filename}...`
      });
    }

    try {
      const response = await fetch(download.url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      if (blob.size > 200 * 1024 * 1024) throw new Error(`File too large (>200MB)`);
      const arrayBuffer = await blob.arrayBuffer();
      const hash = await computeHash(arrayBuffer);

      if (API_KEY) {
        await checkHash(hash, filename, download.url);
        // Clear any previous error on success
        await browser.storage.local.remove('lastError');
      } else {
        throw new Error("No API key set");
      }

    } catch (error) {
      console.error("Auto‑scan failed:", error);
      const userMessage = "Unable to autocheck. Please upload file here.";
      if (notificationsEnabled) {
        browser.notifications.create(`error-${delta.id}`, {
          type: "basic",
          title: "⚠️ Auto‑scan failed",
          message: `${filename}\n${userMessage}`
        });
      }
      // Store error for dashboard (user-facing message only; full error is in console)
      await browser.storage.local.set({
        lastError: { filename, message: userMessage, timestamp: Date.now() }
      });
    }

    if (notificationsEnabled) {
      setTimeout(() => browser.notifications.clear(`scanning-${delta.id}`), 3000);
    }
    pendingDownloads.delete(delta.id);
  }
});

// VirusTotal check
async function checkHash(hash, filename, sourceUrl) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': API_KEY }
    });
    const vtUrl = `https://www.virustotal.com/gui/file/${hash}`;
    browser.tabs.create({ url: vtUrl, active: true });

    if (response.status === 200) {
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;

      let title, message;
      if (malicious > 0) {
        title = "⚠️ MALICIOUS";
        message = `${filename}\n${malicious} detections`;
      } else if (suspicious > 0) {
        title = "⚡ Suspicious";
        message = `${filename}\n${suspicious} suspicious`;
      } else {
        title = "✅ Clean";
        message = `${filename}\nNo malware detected`;
      }

      if (notificationsEnabled) {
        browser.notifications.create(`result-${Date.now()}`, {
          type: "basic",
          title: title,
          message: message,
          buttons: [{ title: "View Report" }]
        });
      }

      const history = (await browser.storage.local.get('history')).history || [];
      history.unshift({ filename, hash, malicious, suspicious, harmless, sourceUrl, vtUrl, time: Date.now(), found: true });
      if (history.length > 100) history.pop();
      await browser.storage.local.set({ history });

    } else if (response.status === 404) {
      if (notificationsEnabled) {
        browser.notifications.create(`result-${Date.now()}`, {
          type: "basic",
          title: "❓ Not Found",
          message: `${filename}\nHash not in VirusTotal database.`,
          buttons: [{ title: "View Report" }]
        });
      }
      // Save to history with found: false
      const history = (await browser.storage.local.get('history')).history || [];
      history.unshift({ filename, hash, malicious: 0, suspicious: 0, harmless: 0, sourceUrl, vtUrl, time: Date.now(), found: false });
      if (history.length > 100) history.pop();
      await browser.storage.local.set({ history });
    } else {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (error) {
    console.error("VirusTotal error:", error);
    if (notificationsEnabled) {
      browser.notifications.create({
        type: "basic",
        title: "API Error",
        message: error.message
      });
    }
  }
}

// Notification button clicks
browser.notifications.onButtonClicked.addListener((id, btn) => {
  if (btn === 0 && id.startsWith('result-')) {
    browser.tabs.create({ url: browser.runtime.getURL("main.html") });
    browser.notifications.clear(id);
  }
});

// Context menu for links
browser.contextMenus.create({
  id: "scan-link-url",
  title: "Scan this link with VirusTotal",
  contexts: ["link"]
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-link-url" && info.linkUrl) {
    handleLinkScan(info, tab);
  }
});

function openVtSearchTab(linkUrl) {
  const vtSearchUrl = `https://www.virustotal.com/gui/search?query=${encodeURIComponent(linkUrl)}`;
  browser.tabs.create({ url: vtSearchUrl, active: true });
}

// Calls VirusTotal's URL-scan API: submit the URL, then poll the analysis
// until it completes. Mirrors the hash-lookup flow used elsewhere in this
// file, but for URLs instead of file hashes.
async function scanUrlWithVT(url) {
  const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: {
      'x-apikey': API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: `url=${encodeURIComponent(url)}`
  });
  if (!submitRes.ok) throw new Error(`VirusTotal submit failed (${submitRes.status})`);
  const submitData = await submitRes.json();
  const analysisId = submitData && submitData.data && submitData.data.id;
  if (!analysisId) throw new Error('No analysis id returned from VirusTotal');

  let stats = null;
  for (let i = 0; i < 6; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': API_KEY }
    });
    if (!analysisRes.ok) throw new Error(`VirusTotal analysis check failed (${analysisRes.status})`);
    const analysisData = await analysisRes.json();
    if (analysisData?.data?.attributes?.status === 'completed') {
      stats = analysisData.data.attributes.stats || {};
      break;
    }
  }
  if (!stats) throw new Error('VirusTotal analysis timed out');

  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0
  };
}

async function handleLinkScan(info, tab) {
  const linkUrl = info.linkUrl;

  // Preference off, or no usable tab (e.g. invoked in a context without
  // one) -> keep the original behavior exactly as before.
  if (!scanLinksInPage || !tab || tab.id === undefined) {
    openVtSearchTab(linkUrl);
    return;
  }

  const requestId = `vt-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const execOpts = { file: 'in-page-scanner.js' };
  if (info.frameId !== undefined) execOpts.frameId = info.frameId;

  try {
    await browser.tabs.executeScript(tab.id, execOpts);
  } catch (err) {
    // Most common cause: the link sits inside a cross-origin iframe, where
    // activeTab does not extend without an explicit host permission.
    // Fall back to the pre-existing new-tab behavior rather than fail silently.
    console.log('Privacy Hash Checker: in-page scan UI could not be injected, falling back to new tab:', err);
    openVtSearchTab(linkUrl);
    return;
  }

  const sendOpts = info.frameId !== undefined ? { frameId: info.frameId } : undefined;

  try {
    await browser.tabs.sendMessage(tab.id, { type: 'vtScanStart', requestId, url: linkUrl }, sendOpts);
  } catch (err) {
    console.log('Privacy Hash Checker: could not reach injected scan UI, falling back to new tab:', err);
    openVtSearchTab(linkUrl);
    return;
  }

  if (!API_KEY) {
    try {
      await browser.tabs.sendMessage(tab.id, {
        type: 'vtScanError', requestId, url: linkUrl,
        message: 'No VirusTotal API key set. Open the extension to add one.'
      }, sendOpts);
    } catch (err) {
      // Page may have navigated away mid-scan; nothing more we can do.
      console.log('Privacy Hash Checker: could not deliver no-API-key message:', err);
    }
    return;
  }

  const vtSearchUrl = `https://www.virustotal.com/gui/search?query=${encodeURIComponent(linkUrl)}`;
  try {
    const verdict = await scanUrlWithVT(linkUrl);
    await browser.tabs.sendMessage(tab.id, {
      type: 'vtScanResult', requestId, url: linkUrl, verdict, vtUrl: vtSearchUrl
    }, sendOpts);
  } catch (err) {
    console.error('Privacy Hash Checker: link scan failed:', err);
    try {
      await browser.tabs.sendMessage(tab.id, {
        type: 'vtScanError', requestId, url: linkUrl, message: err.message || 'Scan failed'
      }, sendOpts);
    } catch (sendErr) {
      // Page may have navigated away mid-scan; nothing more we can do.
      console.log('Privacy Hash Checker: could not deliver scan-error message:', sendErr);
    }
  }
}

// API key management & notification preference updates
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'setApiKey') {
    API_KEY = message.key;
    browser.storage.local.set({ apiKey: message.key });
    sendResponse({ success: true });
    return true;
  }
  if (message.action === 'getApiKey') {
    sendResponse({ key: API_KEY });
    return true;
  }
  if (message.action === 'setNotifications') {
    notificationsEnabled = message.enabled;
    browser.storage.local.set({ notificationsEnabled: message.enabled });
    sendResponse({ success: true });
    return true;
  }
  if (message.action === 'setDisabledSites') {
    disabledSites = Array.isArray(message.sites) ? message.sites : [];
    browser.storage.local.set({ disabledSites });
    sendResponse({ success: true });
    return true;
  }
  if (message.action === 'setScanLinksInPage') {
    scanLinksInPage = !!message.enabled;
    browser.storage.local.set({ scanLinksInPage });
    sendResponse({ success: true });
    return true;
  }
});

console.log("Privacy Hash Checker ready for Firefox PC (notifications off by default)");
