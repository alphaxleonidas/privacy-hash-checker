// Privacy Hash Checker – Firefox PC (desktop)
console.log("Background loaded (Firefox PC)");

let API_KEY = null;
let notificationsEnabled = false;   // default off
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
  // else keep default false
});

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
      } else {
        throw new Error("No API key set");
      }

    } catch (error) {
      console.error("Auto‑scan failed:", error);
      if (notificationsEnabled) {
        browser.notifications.create(`error-${delta.id}`, {
          type: "basic",
          title: "⚠️ Auto‑scan failed",
          message: `${filename}\n${error.message}\n\nOpen extension to upload manually.`
        });
      }
      // Store error for dashboard
      await browser.storage.local.set({
        lastError: { filename, message: error.message, timestamp: Date.now() }
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
      history.unshift({ filename, hash, malicious, suspicious, harmless, sourceUrl, vtUrl, time: Date.now() });
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

browser.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === "scan-link-url" && info.linkUrl) {
    const encodedUrl = encodeURIComponent(info.linkUrl);
    const vtSearchUrl = `https://www.virustotal.com/gui/search?query=${encodedUrl}`;
    browser.tabs.create({ url: vtSearchUrl, active: true });
  }
});

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
    // Also persist to storage (already saved by main page, but we do it here too)
    browser.storage.local.set({ notificationsEnabled: message.enabled });
    sendResponse({ success: true });
    return true;
  }
});

console.log("Privacy Hash Checker ready for Firefox PC (notifications off by default)");
