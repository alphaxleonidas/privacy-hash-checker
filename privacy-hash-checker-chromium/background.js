// Privacy Hash Checker – Chromium (Manifest V3)
console.log("Service worker loaded");

let API_KEY = null;
let notificationsEnabled = false; // default off

// Load API key
chrome.storage.local.get('apiKey', (res) => {
  if (res.apiKey) {
    API_KEY = res.apiKey;
    console.log("API key loaded");
  }
});

// Load notification preference
chrome.storage.local.get('notificationsEnabled', (res) => {
  if (res.notificationsEnabled !== undefined) {
    notificationsEnabled = res.notificationsEnabled;
  }
});

// Helper: compute SHA-256
async function computeHash(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Open dashboard
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL("main.html"), active: true });
});

// Pending downloads management
async function getPendingDownloads() {
  const data = await chrome.storage.local.get('pendingDownloads');
  return data.pendingDownloads || {};
}
async function setPendingDownloads(pending) {
  await chrome.storage.local.set({ pendingDownloads: pending });
}

chrome.downloads.onCreated.addListener(async (download) => {
  const filename = download.filename.split('/').pop().split('\\').pop();
  const pending = await getPendingDownloads();
  pending[download.id] = { filename, url: download.url, timestamp: Date.now() };
  await setPendingDownloads(pending);
  if (notificationsEnabled) {
    chrome.notifications.create(`start-${download.id}`, {
      type: "basic",
      title: "📥 Download Started",
      message: filename,
      iconUrl: chrome.runtime.getURL("icon.svg")
    });
    setTimeout(() => chrome.notifications.clear(`start-${download.id}`), 3000);
  }
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const pending = await getPendingDownloads();
    const info = pending[delta.id];
    if (!info) return;

    const downloads = await chrome.downloads.search({ id: delta.id });
    if (!downloads.length) return;
    const download = downloads[0];
    const filename = download.filename.split('/').pop().split('\\').pop();

    // Open dashboard
    chrome.tabs.create({
      url: chrome.runtime.getURL("main.html"),
      active: true
    });

    if (notificationsEnabled) {
      chrome.notifications.create(`scanning-${delta.id}`, {
        type: "basic",
        title: "🔍 Scanning",
        message: `Trying to hash ${filename}...`,
        iconUrl: chrome.runtime.getURL("icon.svg")
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
      } else {
        throw new Error("No API key set");
      }
    } catch (error) {
      console.error("Auto‑scan failed:", error);
      if (notificationsEnabled) {
        chrome.notifications.create(`error-${delta.id}`, {
          type: "basic",
          title: "⚠️ Auto‑scan failed",
          message: `${filename}\n${error.message}\n\nOpen extension to upload manually.`,
          iconUrl: chrome.runtime.getURL("icon.svg")
        });
      }
      await chrome.storage.local.set({
        lastError: { filename, message: error.message, timestamp: Date.now() }
      });
    }

    if (notificationsEnabled) {
      setTimeout(() => chrome.notifications.clear(`scanning-${delta.id}`), 3000);
    }
    delete pending[delta.id];
    await setPendingDownloads(pending);
  }
});

// VirusTotal check
async function checkHash(hash, filename, sourceUrl) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': API_KEY }
    });
    const vtUrl = `https://www.virustotal.com/gui/file/${hash}`;
    chrome.tabs.create({ url: vtUrl, active: true });

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
        chrome.notifications.create(`result-${Date.now()}`, {
          type: "basic",
          title: title,
          message: message,
          buttons: [{ title: "View Report" }],
          iconUrl: chrome.runtime.getURL("icon.svg")
        });
      }

      const history = (await chrome.storage.local.get('history')).history || [];
      history.unshift({ filename, hash, malicious, suspicious, harmless, sourceUrl, vtUrl, time: Date.now() });
      if (history.length > 100) history.pop();
      await chrome.storage.local.set({ history });

    } else if (response.status === 404) {
      if (notificationsEnabled) {
        chrome.notifications.create(`result-${Date.now()}`, {
          type: "basic",
          title: "❓ Not Found",
          message: `${filename}\nHash not in VirusTotal database.`,
          buttons: [{ title: "View Report" }],
          iconUrl: chrome.runtime.getURL("icon.svg")
        });
      }
    } else {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (error) {
    console.error("VirusTotal error:", error);
    if (notificationsEnabled) {
      chrome.notifications.create({
        type: "basic",
        title: "API Error",
        message: error.message,
        iconUrl: chrome.runtime.getURL("icon.svg")
      });
    }
  }
}

chrome.notifications.onButtonClicked.addListener((id, btn) => {
  if (btn === 0 && id.startsWith('result-')) {
    chrome.tabs.create({ url: chrome.runtime.getURL("main.html") });
    chrome.notifications.clear(id);
  }
});

chrome.contextMenus.create({
  id: "scan-link-url",
  title: "Scan this link with VirusTotal",
  contexts: ["link"]
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-link-url" && info.linkUrl) {
    const encodedUrl = encodeURIComponent(info.linkUrl);
    const vtSearchUrl = `https://www.virustotal.com/gui/search?query=${encodedUrl}`;
    chrome.tabs.create({ url: vtSearchUrl, active: true });
  }
});

// Listen for preference changes from the dashboard
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'setApiKey') {
    API_KEY = message.key;
    chrome.storage.local.set({ apiKey: message.key });
    sendResponse({ success: true });
    return true;
  }
  if (message.action === 'getApiKey') {
    sendResponse({ key: API_KEY });
    return true;
  }
  if (message.action === 'setNotifications') {
    notificationsEnabled = message.enabled;
    chrome.storage.local.set({ notificationsEnabled: message.enabled });
    sendResponse({ success: true });
    return true;
  }
});

console.log("Privacy Hash Checker ready for Chromium");
