// Main tab logic - handles all scanning

let currentApiKey = null;
let recentScans = [];

// Load saved API key
browser.storage.local.get('vtApiKey').then((result) => {
  if (result.vtApiKey) {
    document.getElementById('apiKey').value = result.vtApiKey;
    currentApiKey = result.vtApiKey;
    showStatus('keyStatus', 'API key loaded', 'success');
  }
});

// Load recent scans
browser.storage.local.get('recentScans').then((result) => {
  if (result.recentScans) {
    recentScans = result.recentScans;
    updateRecentScans();
  }
});

// Save API key
document.getElementById('saveKey').addEventListener('click', () => {
  const apiKey = document.getElementById('apiKey').value.trim();
  if (apiKey) {
    browser.storage.local.set({ vtApiKey: apiKey }).then(() => {
      currentApiKey = apiKey;
      showStatus('keyStatus', '✓ API key saved successfully', 'success');
      
      // Notify background
      browser.runtime.sendMessage({ action: 'updateApiKey', key: apiKey });
      
      setTimeout(() => {
        const statusDiv = document.getElementById('keyStatus');
        if (statusDiv.innerHTML.includes('saved')) {
          statusDiv.style.display = 'none';
        }
      }, 3000);
    });
  } else {
    showStatus('keyStatus', 'Please enter a valid API key', 'error');
  }
});

// Scan uploaded file
document.getElementById('scanFile').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  
  if (!file) {
    showStatus('uploadStatus', 'Please select a file first', 'error');
    return;
  }
  
  if (!currentApiKey) {
    showStatus('uploadStatus', 'Please save your API key first', 'error');
    return;
  }
  
  showStatus('uploadStatus', `📤 Reading ${file.name}...`, 'info');
  document.getElementById('uploadProgress').style.display = 'block';
  
  try {
    // Read file
    const arrayBuffer = await file.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    
    document.getElementById('uploadHash').innerHTML = `<strong>SHA-256 Hash:</strong><br>${hash}`;
    document.getElementById('uploadHash').style.display = 'block';
    
    showStatus('uploadStatus', `🔍 Checking ${file.name} with VirusTotal...`, 'info');
    
    // Check with VirusTotal and open tab
    await checkHashWithVT(hash, file.name);
    
    // Add to recent scans
    addToRecentScans(file.name, hash, 'pending');
    
    // Clear file input
    fileInput.value = '';
    document.getElementById('uploadProgress').style.display = 'none';
    
  } catch (error) {
    showStatus('uploadStatus', `Error: ${error.message}`, 'error');
    document.getElementById('uploadProgress').style.display = 'none';
  }
});

// Manual hash check
document.getElementById('checkHash').addEventListener('click', async () => {
  const hash = document.getElementById('hashInput').value.trim().toLowerCase();
  
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    showStatus('hashStatus', 'Invalid SHA-256 hash (must be 64 hex characters)', 'error');
    return;
  }
  
  if (!currentApiKey) {
    showStatus('hashStatus', 'Please save your API key first', 'error');
    return;
  }
  
  showStatus('hashStatus', 'Checking hash with VirusTotal...', 'info');
  
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': currentApiKey }
    });
    
    // Open VirusTotal tab
    browser.tabs.create({ url: `https://www.virustotal.com/gui/file/${hash}` });
    
    if (response.status === 200) {
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      const malicious = stats.malicious || 0;
      
      if (malicious > 0) {
        showStatus('hashStatus', `⚠️ DETECTED: ${malicious} engines flagged this hash as malicious! Tab opened.`, 'warning');
      } else {
        showStatus('hashStatus', `✅ Clean: No detections found across ${stats.harmless + stats.undetected} engines. Tab opened.`, 'success');
      }
      
      addToRecentScans(`Hash: ${hash.substring(0, 16)}...`, hash, malicious > 0 ? 'malicious' : 'clean');
      
    } else if (response.status === 404) {
      showStatus('hashStatus', '❓ Hash not found in VirusTotal database. Tab opened - you can submit it there.', 'warning');
      addToRecentScans(`Hash: ${hash.substring(0, 16)}...`, hash, 'unknown');
    } else {
      const error = await response.json();
      showStatus('hashStatus', `API Error: ${error.error?.message || 'Unknown error'}`, 'error');
    }
    
    document.getElementById('hashInput').value = '';
    
  } catch (error) {
    showStatus('hashStatus', `Network error: ${error.message}`, 'error');
  }
});

// Clear history
document.getElementById('clearHistory').addEventListener('click', () => {
  recentScans = [];
  browser.storage.local.set({ recentScans: [] }).then(() => {
    updateRecentScans();
    showStatus('keyStatus', '🗑️ History cleared successfully', 'success');
    setTimeout(() => {
      const statusDiv = document.getElementById('keyStatus');
      statusDiv.style.display = 'none';
    }, 3000);
  });
});

// Compute SHA-256 hash
async function computeHash(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Check hash with VirusTotal and open tab
async function checkHashWithVT(hash, filename) {
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': currentApiKey }
    });
    
    // ALWAYS open a new tab
    const vtTab = await browser.tabs.create({ 
      url: `https://www.virustotal.com/gui/file/${hash}`,
      active: true
    });
    
    if (response.status === 200) {
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      const malicious = stats.malicious || 0;
      
      if (malicious > 0) {
        showStatus('uploadStatus', `⚠️ DETECTED: ${malicious} antivirus engines detected malware! Check the new tab.`, 'warning');
        addToRecentScans(filename, hash, 'malicious');
      } else {
        showStatus('uploadStatus', `✅ Clean: No malware detected across ${stats.harmless + stats.undetected} engines. Tab opened.`, 'success');
        addToRecentScans(filename, hash, 'clean');
      }
    } else if (response.status === 404) {
      showStatus('uploadStatus', `🔍 Hash not found. Tab opened - you can submit the file there if desired.`, 'warning');
      addToRecentScans(filename, hash, 'unknown');
    } else {
      showStatus('uploadStatus', `API returned status ${response.status}. Tab opened anyway.`, 'warning');
    }
    
    return true;
    
  } catch (error) {
    showStatus('uploadStatus', `Network error: ${error.message}. Tab may not have opened.`, 'error');
    throw error;
  }
}

// Scan downloaded file (called from background)
async function scanDownloadedFile(url, filename) {
  if (!currentApiKey) {
    showStatus('uploadStatus', '⚠️ Please set your API key to scan downloads', 'warning');
    return;
  }
  
  showStatus('uploadStatus', `📥 Download detected: ${filename.split('/').pop().split('\\').pop()}`, 'info');
  showStatus('uploadStatus', `🔍 Calculating hash...`, 'info');
  
  try {
    const response = await fetch(url);
    const arrayBuffer = await response.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    
    document.getElementById('uploadHash').innerHTML = `<strong>Downloaded File Hash:</strong><br>${hash}`;
    document.getElementById('uploadHash').style.display = 'block';
    
    showStatus('uploadStatus', `📤 Checking with VirusTotal...`, 'info');
    
    await checkHashWithVT(hash, filename);
    
  } catch (error) {
    showStatus('uploadStatus', `Error scanning download: ${error.message}`, 'error');
  }
}

// Scan file from URL (right-click)
async function scanFileUrl(url, filename) {
  if (!currentApiKey) {
    showStatus('uploadStatus', '⚠️ Please set your API key first', 'warning');
    return;
  }
  
  showStatus('uploadStatus', `🔗 Scanning: ${filename}`, 'info');
  
  try {
    const response = await fetch(url);
    const arrayBuffer = await response.arrayBuffer();
    const hash = await computeHash(arrayBuffer);
    
    document.getElementById('uploadHash').innerHTML = `<strong>File Hash:</strong><br>${hash}`;
    document.getElementById('uploadHash').style.display = 'block';
    
    showStatus('uploadStatus', `📤 Checking with VirusTotal...`, 'info');
    
    await checkHashWithVT(hash, filename);
    
  } catch (error) {
    showStatus('uploadStatus', `Error: ${error.message}`, 'error');
  }
}

// Helper: Show status message
function showStatus(elementId, message, type) {
  const element = document.getElementById(elementId);
  element.innerHTML = message;
  element.className = `status ${type}`;
  element.style.display = 'block';
  
  // Auto-hide after 5 seconds for success/info
  if (type === 'success' || type === 'info') {
    setTimeout(() => {
      if (element.innerHTML === message) {
        element.style.display = 'none';
      }
    }, 5000);
  }
}

// Add to recent scans
function addToRecentScans(name, hash, status) {
  const scan = {
    name: name.length > 40 ? name.substring(0, 37) + '...' : name,
    hash: hash.substring,
    fullHash: hash,
    status: status,
    timestamp: new Date().toLocaleTimeString()
  };
  
  recentScans.unshift(scan);
  if (recentScans.length > 10) recentScans.pop();
  
  browser.storage.local.set({ recentScans: recentScans });
  updateRecentScans();
}

// Update recent scans display
function updateRecentScans() {
  const container = document.getElementById('recentScans');
  
  if (recentScans.length === 0) {
    container.innerHTML = '<p style="color: #999; text-align: center;">No scans yet. Upload a file or download something to get started.</p>';
    return;
  }
  
  let html = '<div style="max-height: 300px; overflow-y: auto;">';
  for (const scan of recentScans) {
    const statusIcon = scan.status === 'malicious' ? '🔴' : (scan.status === 'clean' ? '🟢' : '🟡');
    const statusText = scan.status === 'malicious' ? 'Malicious' : (scan.status === 'clean' ? 'Clean' : 'Unknown');
    
    html += `
      <div style="padding: 10px; border-bottom: 1px solid #e0e0e0; cursor: pointer;" onclick="window.open('https://www.virustotal.com/gui/file/${scan.fullHash}', '_blank')">
        <div style="display: flex; justify-content: space-between;">
          <span><strong>${scan.name}</strong></span>
          <span>${statusIcon} ${statusText}</span>
        </div>
        <div style="font-family: monospace; font-size: 11px; color: #666; margin-top: 5px;">
          ${scan.hash} • ${scan.timestamp}
        </div>
      </div>
    `;
  }
  html += '</div>';
  
  container.innerHTML = html;
}

// Listen for messages from background
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scanDownloadedFile') {
    scanDownloadedFile(message.url, message.filename);
    sendResponse({ success: true });
  } else if (message.action === 'scanFileUrl') {
    scanFileUrl(message.url, message.filename);
    sendResponse({ success: true });
  }
  return true;
});
