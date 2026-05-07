// Load saved API key
document.addEventListener('DOMContentLoaded', () => {
  browser.storage.local.get('vtApiKey').then((result) => {
    if (result.vtApiKey) {
      document.getElementById('apiKey').value = result.vtApiKey;
      document.getElementById('keyStatus').textContent = '✓ API key loaded (stored locally)';
      document.getElementById('keyStatus').style.color = '#28a745';
      
      // Update background script
      browser.runtime.sendMessage({ action: 'updateApiKey', key: result.vtApiKey });
    }
  });
});

// Save API key
document.getElementById('saveKey').addEventListener('click', () => {
  const apiKey = document.getElementById('apiKey').value.trim();
  if (apiKey) {
    browser.storage.local.set({ vtApiKey: apiKey }).then(() => {
      document.getElementById('keyStatus').textContent = '✓ API key saved securely';
      document.getElementById('keyStatus').style.color = '#28a745';
      
      // Notify background script
      browser.runtime.sendMessage({ action: 'updateApiKey', key: apiKey });
      
      setTimeout(() => {
        if (document.getElementById('keyStatus').textContent === '✓ API key saved securely') {
          document.getElementById('keyStatus').textContent = '';
        }
      }, 2000);
    });
  } else {
    document.getElementById('keyStatus').textContent = 'Please enter a valid API key';
    document.getElementById('keyStatus').style.color = '#dc3545';
  }
});

// Upload and scan file
document.getElementById('uploadAndScan').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  
  if (!file) {
    document.getElementById('uploadStatus').textContent = 'Please select a file first';
    document.getElementById('uploadStatus').style.color = '#dc3545';
    return;
  }
  
  const apiKey = document.getElementById('apiKey').value.trim();
  if (!apiKey) {
    document.getElementById('uploadStatus').textContent = 'Please save your API key first';
    document.getElementById('uploadStatus').style.color = '#dc3545';
    return;
  }
  
  document.getElementById('uploadStatus').textContent = `📤 Processing ${file.name}...`;
  document.getElementById('uploadStatus').style.color = '#007bff';
  
  try {
    // Send file to background script for processing
    const response = await browser.runtime.sendMessage({ 
      action: 'scanFile', 
      file: {
        name: file.name,
        data: await file.arrayBuffer()
      }
    });
    
    if (response && response.success) {
      document.getElementById('uploadStatus').innerHTML = '✅ File hash sent to VirusTotal!<br>Check the new tab that opened.';
      document.getElementById('uploadStatus').style.color = '#28a745';
      fileInput.value = ''; // Clear file input
    } else {
      document.getElementById('uploadStatus').textContent = 'Error: ' + (response?.error || 'Unknown error');
      document.getElementById('uploadStatus').style.color = '#dc3545';
    }
  } catch (error) {
    document.getElementById('uploadStatus').textContent = 'Error: ' + error.message;
    document.getElementById('uploadStatus').style.color = '#dc3545';
  }
  
  setTimeout(() => {
    if (document.getElementById('uploadStatus').textContent.includes('success')) {
      document.getElementById('uploadStatus').textContent = '';
    }
  }, 5000);
});

// Check a hash directly
document.getElementById('checkHash').addEventListener('click', async () => {
  const hash = document.getElementById('hashInput').value.trim().toLowerCase();
  const apiKey = document.getElementById('apiKey').value.trim();
  
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    document.getElementById('keyStatus').textContent = 'Invalid SHA-256 hash (64 hex characters)';
    document.getElementById('keyStatus').style.color = '#dc3545';
    return;
  }
  
  if (!apiKey) {
    document.getElementById('keyStatus').textContent = 'Please save your API key first';
    document.getElementById('keyStatus').style.color = '#dc3545';
    return;
  }
  
  document.getElementById('keyStatus').textContent = 'Checking hash...';
  document.getElementById('keyStatus').style.color = '#007bff';
  
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': apiKey }
    });
    
    // Open tab regardless of result
    browser.tabs.create({ url: `https://www.virustotal.com/gui/file/${hash}` });
    
    if (response.status === 200) {
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      document.getElementById('keyStatus').innerHTML = `✅ Found! Malicious: ${stats.malicious}, Clean: ${stats.harmless}<br>Tab opened with full report.`;
      document.getElementById('keyStatus').style.color = '#28a745';
    } else if (response.status === 404) {
      document.getElementById('keyStatus').innerHTML = `❓ Hash not found in VirusTotal database<br>Tab opened - you can upload manually there.`;
      document.getElementById('keyStatus').style.color = '#ffc107';
    }
  } catch (error) {
    document.getElementById('keyStatus').textContent = 'Error: ' + error.message;
    document.getElementById('keyStatus').style.color = '#dc3545';
  }
  
  setTimeout(() => {
    if (document.getElementById('keyStatus').textContent.includes('Found') || 
        document.getElementById('keyStatus').textContent.includes('not found')) {
      setTimeout(() => {
        document.getElementById('keyStatus').textContent = '';
      }, 4000);
    }
  }, 1000);
});

// Update background script when API key changes
browser.runtime.onMessage.addListener((message) => {
  if (message.action === 'apiKeyUpdated') {
    // Refresh if needed
  }
});
