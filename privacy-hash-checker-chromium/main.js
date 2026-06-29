// Chromium version – uses chrome.* APIs
let scanHistory = [];

// --- Check for stored error from background ---
async function checkForStoredError() {
  const result = await chrome.storage.local.get("lastError");
  const error = result.lastError;
  if (error && error.filename && error.message) {
    const status = document.getElementById("uploadStatus");
    status.textContent = `⚠️ Auto‑scan failed for "${error.filename}": ${error.message}\nPlease upload the file manually.`;
    status.className = "status warning";
    status.style.display = "block";
    await chrome.storage.local.remove("lastError");
    console.log("Displayed and cleared lastError");
  }
}
document.addEventListener("DOMContentLoaded", checkForStoredError);

// --- Load API key directly from storage ---
async function loadApiKey() {
  const result = await chrome.storage.local.get("apiKey");
  if (result.apiKey) {
    document.getElementById("apiStatus").textContent = "✓ API key loaded";
    document.getElementById("apiStatus").className = "status success";
    setTimeout(
      () => (document.getElementById("apiStatus").style.display = "none"),
      3000,
    );
  }
}

// Save API key directly to storage
document.getElementById("saveKey").onclick = async () => {
  const key = document.getElementById("apiKey").value.trim();
  if (!key) {
    showStatus("apiStatus", "Please enter an API key", "error");
    return;
  }
  await chrome.storage.local.set({ apiKey: key });
  showStatus("apiStatus", "API key saved!", "success");
  document.getElementById("apiKey").value = "";
  loadApiKey();
};

// Upload & scan
document.getElementById("scanFile").onclick = async () => {
  const file = document.getElementById("fileInput").files[0];
  if (!file) {
    showStatus("uploadStatus", "Select a file first", "error");
    return;
  }
  showStatus("uploadStatus", "Hashing...", "info");
  try {
    const arrayBuffer = await file.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    document.getElementById("uploadHash").innerHTML =
      `<strong>SHA-256:</strong><br>${hash}`;
    document.getElementById("uploadHash").style.display = "block";
    showStatus("uploadStatus", "Checking with VirusTotal...", "info");
    const result = await checkHash(hash, file.name, "upload");
    showResult(result);
    await chrome.tabs.create({ url: result.vtUrl, active: true });
    document.getElementById("fileInput").value = "";
  } catch (e) {
    showStatus("uploadStatus", e.message, "error");
  }
};

// Manual hash lookup
document.getElementById("checkHash").onclick = async () => {
  const hash = document.getElementById("hashInput").value.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    showStatus("hashStatus", "Invalid SHA-256 hash", "error");
    return;
  }
  try {
    const result = await checkHash(
      hash,
      hash.substring(0, 16) + "...",
      "manual",
    );
    showResult(result);
    await chrome.tabs.create({ url: result.vtUrl, active: true });
    document.getElementById("hashInput").value = "";
  } catch (e) {
    showStatus("hashStatus", e.message, "error");
  }
};

// Compute hash
async function computeHash(arrayBuffer) {
  const hashBuf = await crypto.subtle.digest("SHA-256", arrayBuffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Check with VirusTotal – uses storage to get API key
async function checkHash(hash, filename, sourceUrl) {
  const result = await chrome.storage.local.get("apiKey");
  const apiKey = result.apiKey;
  if (!apiKey) throw new Error("No API key set");

  const response = await fetch(
    `https://www.virustotal.com/api/v3/files/${hash}`,
    {
      headers: { "x-apikey": apiKey },
    },
  );
  let vtResult = {
    hash,
    filename,
    sourceUrl,
    vtUrl: `https://www.virustotal.com/gui/file/${hash}`,
  };

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

// Save to history
async function saveToHistory(scan) {
  scanHistory.unshift({ ...scan, id: Date.now(), time: Date.now() });
  if (scanHistory.length > 100) scanHistory.pop();
  await chrome.storage.local.set({ history: scanHistory });
  renderHistory();
}

// Load history
async function loadHistory() {
  const result = await chrome.storage.local.get("history");
  scanHistory = result.history || [];
  renderHistory();
}

// Render history
function renderHistory() {
  const container = document.getElementById("historyList");
  if (!scanHistory.length) {
    container.innerHTML = '<div class="empty">No scans yet</div>';
    return;
  }
  container.innerHTML = scanHistory
    .map(
      (item) => `
    <div class="history-item" onclick="window.open('${item.vtUrl}', '_blank')">
      <div class="history-item-header">
        <span class="history-filename">${escapeHtml(item.filename)}</span>
        <span class="history-badge" style="background:${item.malicious > 0 ? "#dc3545" : "#28a745"}">
          ${item.malicious > 0 ? "⚠️ Malicious" : "✅ Clean"}
        </span>
      </div>
      <div class="history-hash">${item.hash.substring(0, 48)}...</div>
      ${item.sourceUrl ? `<div class="history-url">${escapeHtml(item.sourceUrl)}</div>` : ""}
      <div class="history-time">${new Date(item.time).toLocaleString()}</div>
    </div>
  `,
    )
    .join("");
}

// Show status
function showStatus(id, msg, type) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = `status ${type}`;
  setTimeout(() => (el.style.display = "none"), 5000);
}

// Show result
function showResult(data) {
  const el = document.getElementById("uploadStatus");
  const text =
    data.malicious > 0
      ? `⚠️ ${data.malicious} detections`
      : data.suspicious > 0
        ? `⚡ ${data.suspicious} suspicious`
        : "✅ Clean";
  el.textContent = text;
  el.className = "status success";
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(
    /[&<>]/g,
    (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[m],
  );
}

// Clear history
document.getElementById("clearHistory").onclick = async () => {
  if (confirm("Clear all history?")) {
    scanHistory = [];
    await chrome.storage.local.set({ history: [] });
    renderHistory();
  }
};

// Initialize
loadApiKey();
loadHistory();
