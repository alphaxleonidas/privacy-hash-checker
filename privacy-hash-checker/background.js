// Privacy Hash Checker - No telemetry, only file hashes
let vtApiKey = null;
let pendingDownloads = new Map();

// Load API key from storage
browser.storage.local.get('vtApiKey').then((result) => {
  if (result.vtApiKey) {
    vtApiKey = result.vtApiKey;
  }
});

// Open main tab when extension icon is clicked
browser.browserAction.onClicked.addListener(() => {
  browser.tabs.create({
    url: browser.runtime.getURL("main.html"),
    active: true
  });
});

// Monitor downloads
browser.downloads.onCreated.addListener((downloadItem) => {
  pendingDownloads.set(downloadItem.id, {
    filename: downloadItem.filename,
    url: downloadItem.url
  });
});

browser.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === 'complete') {
    const downloadInfo = pendingDownloads.get(delta.id);
    if (downloadInfo) {
      const downloads = await browser.downloads.search({ id: delta.id });
      if (downloads.length > 0) {
        const download = downloads[0];
        
        // Open the main tab with auto-scan
        const tab = await browser.tabs.create({
          url: browser.runtime.getURL("main.html"),
          active: false
        });
        
        // Wait for tab to load then send scan request
        setTimeout(() => {
          browser.tabs.sendMessage(tab.id, {
            action: 'scanDownloadedFile',
            url: download.url,
            filename: download.filename
          }).catch(() => {
            // Tab might not be ready, try again
            setTimeout(() => {
              browser.tabs.sendMessage(tab.id, {
                action: 'scanDownloadedFile',
                url: download.url,
                filename: download.filename
              }).catch(console.error);
            }, 500);
          });
        }, 500);
      }
      pendingDownloads.delete(delta.id);
    }
  }
});

// Context menu for scanning links directly with VirusTotal
browser.contextMenus.create({
  id: "check-link-url",
  title: "Scan this link URL with VirusTotal",
  contexts: ["link"]
});

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "check-link-url" && info.linkUrl) {
    try {
      const url = new URL(info.linkUrl);
      const domain = url.hostname; // Gets "github.com" or "www.github.com"
      const cleanDomain = domain.replace(/^www\./, '');
      const vtSearchUrl = `https://www.virustotal.com/gui/search/${cleanDomain}`;

      await browser.tabs.create({ url: vtSearchUrl, active: true });
    } catch(e) {
      console.error("Invalid URL:", info.linkUrl);
    }
  }
});

// Listen for API key updates from main page
browser.runtime.onMessage.addListener((message) => {
  if (message.action === 'updateApiKey') {
    vtApiKey = message.key;
    browser.storage.local.set({ vtApiKey: message.key });
  }
});
