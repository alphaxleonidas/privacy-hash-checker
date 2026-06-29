// Privacy Hash Checker – Chromium (Manifest V3)
console.log("Service worker loaded");

// State stored in chrome.storage.local (since service worker can be terminated)
let API_KEY = null;

// Load API key from storage
chrome.storage.local.get("apiKey", (res) => {
  if (res.apiKey) {
    API_KEY = res.apiKey;
    console.log("API key loaded");
  }
});

// Helper: compute SHA-256
async function computeHash(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest("SHA-256", arrayBuffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Open dashboard when extension icon is clicked
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL("main.html"), active: true });
});

// Track downloads – use storage to persist pending IDs across service worker restarts
async function addPendingDownload(id, filename, url) {
  const data = await chrome.storage.local.get("pendingDownloads");
  const pending = data.pendingDownloads || {};
  pending[id] = { filename, url, timestamp: Date.now() };
  await chrome.storage.local.set({ pendingDownloads: pending });
}

async function getPendingDownload(id) {
  const data = await chrome.storage.local.get("pendingDownloads");
  const pending = data.pendingDownloads || {};
  return pending[id] || null;
}

async function removePendingDownload(id) {
  const data = await chrome.storage.local.get("pendingDownloads");
  const pending = data.pendingDownloads || {};
  delete pending[id];
  await chrome.storage.local.set({ pendingDownloads: pending });
}

// Download started
chrome.downloads.onCreated.addListener((download) => {
  const filename = download.filename.split("/").pop().split("\\").pop();
  console.log(`Download started: ${filename} (ID: ${download.id})`);
  addPendingDownload(download.id, filename, download.url);
  chrome.notifications.create(`start-${download.id}`, {
    type: "basic",
    title: "📥 Download Started",
    message: filename,
    iconUrl: chrome.runtime.getURL("icon.svg"),
  });
  setTimeout(() => chrome.notifications.clear(`start-${download.id}`), 3000);
});

// Download changed (completion)
chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === "complete") {
    console.log(`Download complete: ID ${delta.id}`);
    const info = await getPendingDownload(delta.id);
    if (!info) {
      console.log(`No pending info for ID ${delta.id}`);
      return;
    }

    const downloads = await chrome.downloads.search({ id: delta.id });
    if (!downloads.length) {
      console.log(`Download ${delta.id} not found`);
      return;
    }

    const download = downloads[0];
    const filename = download.filename.split("/").pop().split("\\").pop();
    console.log(`File: ${filename}, URL: ${download.url}`);

    // Open dashboard (active)
    try {
      await chrome.tabs.create({
        url: chrome.runtime.getURL("main.html"),
        active: true,
      });
    } catch (e) {
      console.error("Failed to open dashboard:", e);
    }

    chrome.notifications.create(`scanning-${delta.id}`, {
      type: "basic",
      title: "🔍 Scanning",
      message: `Hashing ${filename}...`,
      iconUrl: chrome.runtime.getURL("icon.svg"),
    });

    try {
      // Re‑fetch the file (Chromium cannot read from disk)
      const response = await fetch(download.url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      if (blob.size > 200 * 1024 * 1024)
        throw new Error(`File too large (>200MB)`);
      const arrayBuffer = await blob.arrayBuffer();
      const hash = await computeHash(arrayBuffer);
      console.log(`Hash: ${hash}`);

      if (API_KEY) {
        await checkHash(hash, filename, download.url);
      } else {
        throw new Error("No API key set");
      }
    } catch (error) {
      console.error("Auto‑scan failed:", error);
      chrome.notifications.create(`error-${delta.id}`, {
        type: "basic",
        title: "⚠️ Auto‑scan failed",
        message: `${filename}\n${error.message}\n\nOpen extension to upload manually.`,
        iconUrl: chrome.runtime.getURL("icon.svg"),
      });
      // Store error for dashboard
      await chrome.storage.local.set({
        lastError: { filename, message: error.message, timestamp: Date.now() },
      });
    }

    setTimeout(() => chrome.notifications.clear(`scanning-${delta.id}`), 3000);
    await removePendingDownload(delta.id);
  }
});

// VirusTotal check
async function checkHash(hash, filename, sourceUrl) {
  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      {
        headers: { "x-apikey": API_KEY },
      },
    );
    const vtUrl = `https://www.virustotal.com/gui/file/${hash}`;
    console.log(`Opening VirusTotal tab: ${vtUrl}`);
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

      chrome.notifications.create(`result-${Date.now()}`, {
        type: "basic",
        title: title,
        message: message,
        buttons: [{ title: "View Report" }],
        iconUrl: chrome.runtime.getURL("icon.svg"),
      });

      // Save history
      const history = (await chrome.storage.local.get("history")).history || [];
      history.unshift({
        filename,
        hash,
        malicious,
        suspicious,
        harmless,
        sourceUrl,
        vtUrl,
        time: Date.now(),
      });
      if (history.length > 100) history.pop();
      await chrome.storage.local.set({ history });
    } else if (response.status === 404) {
      chrome.notifications.create(`result-${Date.now()}`, {
        type: "basic",
        title: "❓ Not Found",
        message: `${filename}\nHash not in VirusTotal database.`,
        buttons: [{ title: "View Report" }],
        iconUrl: chrome.runtime.getURL("icon.svg"),
      });
    } else {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (error) {
    console.error("VirusTotal error:", error);
    chrome.notifications.create({
      type: "basic",
      title: "API Error",
      message: error.message,
      iconUrl: chrome.runtime.getURL("icon.svg"),
    });
  }
}

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener((id, btn) => {
  if (btn === 0 && id.startsWith("result-")) {
    chrome.tabs.create({ url: chrome.runtime.getURL("main.html") });
    chrome.notifications.clear(id);
  }
});

// Context menu for links
chrome.contextMenus.create({
  id: "scan-link-url",
  title: "Scan this link with VirusTotal",
  contexts: ["link"],
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-link-url" && info.linkUrl) {
    const encodedUrl = encodeURIComponent(info.linkUrl);
    const vtSearchUrl = `https://www.virustotal.com/gui/search?query=${encodedUrl}`;
    chrome.tabs.create({ url: vtSearchUrl, active: true });
  }
});

// API key management – listen for messages from main page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "setApiKey") {
    API_KEY = message.key;
    chrome.storage.local.set({ apiKey: message.key }).then(() => {
      sendResponse({ success: true });
    });
    return true; // keep channel open for async response
  }
  if (message.action === "getApiKey") {
    sendResponse({ key: API_KEY });
    return true;
  }
});

console.log("Privacy Hash Checker ready (Chromium)");
