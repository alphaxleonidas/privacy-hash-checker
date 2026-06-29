// background.js – handles clicks and download events

const MAX_AUTO_SIZE = 50 * 1024 * 1024; // 50 MB

// ----- Safe tab opener with error logging -----
function openTab(url, active = true) {
  try {
    browser.tabs.create({ url, active })
      .then(tab => {
        console.log(`[HashChecker] Tab opened: ${url} (ID: ${tab.id})`);
      })
      .catch(err => {
        console.error(`[HashChecker] Failed to open tab: ${url}`, err);
        browser.notifications.create({
          type: 'basic',
          iconUrl: browser.runtime.getURL('icon.svg'),
          title: 'Privacy Hash Checker',
          message: `Could not open tab: ${err.message}`
        });
      });
  } catch (err) {
    console.error(`[HashChecker] Sync error opening tab: ${url}`, err);
  }
}

// ----- Open dashboard when extension icon is clicked -----
browser.browserAction.onClicked.addListener(() => {
  openTab(browser.runtime.getURL('main.html'), true);
});

// ----- Compute SHA‑256 from an ArrayBuffer -----
async function computeSha256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ----- Main download handler -----
async function onDownloadChanged(delta) {
  if (!delta.state || delta.state.current !== 'complete') return;

  try {
    const [item] = await browser.downloads.search({ id: delta.id });
    if (!item) return;

    console.log(`[HashChecker] Download completed: ${item.filename}`);

    // 1️⃣ Always open the dashboard
    openTab(browser.runtime.getURL('main.html'), true);

    // 2️⃣ Auto‑scan attempt
    if (item.fileSize && item.fileSize > MAX_AUTO_SIZE) {
      console.log(`[HashChecker] ${item.filename} too large – skipping.`);
      return;
    }
    if (item.url.startsWith('blob:') || item.url.startsWith('data:')) {
      console.log(`[HashChecker] ${item.filename} uses blob/data URL – skipping.`);
      return;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    const response = await fetch(item.url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/114.0 Firefox/109.0'
      }
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const buffer = await response.arrayBuffer();
    const hash = await computeSha256(buffer);

    // 3️⃣ Open VirusTotal WEB PAGE (no API call, no 404)
    openTab(`https://www.virustotal.com/gui/file/${hash}`, true);

  } catch (error) {
    console.warn(`[HashChecker] Auto‑scan failed:`, error.message);
    // Dashboard is already open – user can manually upload there.
  }
}

browser.downloads.onChanged.addListener(onDownloadChanged);
console.log('[HashChecker] Background loaded.');