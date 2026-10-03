// Injected by background.js (tabs.executeScript) when the user picks
// "Scan this link with VirusTotal" and the "Scan links in-page" preference
// is on. Shows a small panel on the page itself instead of opening a new
// tab. All dynamic content (urls, error text) goes through textContent,
// never innerHTML — a scanned link's URL or an error string is untrusted
// input and must never be interpreted as markup.
(function () {
  if (window.__vtInPageScannerReady) return;
  window.__vtInPageScannerReady = true;

  const activePanels = new Map(); // requestId -> panel element

  function makeEl(tag, attrs, children) {
    attrs = attrs || {};
    children = children || [];
    const node = document.createElement(tag);
    for (const key in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, key)) continue;
      const value = attrs[key];
      if (key === 'style') node.style.cssText = value;
      else if (key === 'text') node.textContent = value;
      else node.setAttribute(key, value);
    }
    children.forEach((child) => {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function buttonStyle(bg) {
    return 'padding:6px 10px; border:0; border-radius:6px; cursor:pointer; font-size:12px; background:' +
      (bg || '#4e5058') + '; color:#fff;';
  }

  function panelBaseStyle(accent) {
    return 'position:fixed; top:16px; right:16px; z-index:2147483647; width:340px; ' +
      'padding:14px; border-radius:10px; font-family:Arial,sans-serif; font-size:13px; ' +
      'line-height:1.4; background:#2b2d31; color:#fff; box-shadow:0 10px 30px rgba(0,0,0,.35);' +
      (accent ? (' border-left:4px solid ' + accent + ';') : '');
  }

  function removePanel(requestId) {
    const el = activePanels.get(requestId);
    if (el && el.parentNode) el.parentNode.removeChild(el);
    activePanels.delete(requestId);
  }

  function mount(requestId, panel) {
    removePanel(requestId);
    document.documentElement.appendChild(panel);
    activePanels.set(requestId, panel);
  }

  function showScanningToast(requestId, url) {
    const panel = makeEl('div', { style: panelBaseStyle() }, [
      makeEl('div', { style: 'font-weight:700; margin-bottom:4px;', text: 'Privacy Hash Checker' }),
      makeEl('div', { style: 'opacity:.85; word-break:break-all;', text: 'Scanning: ' + url })
    ]);
    mount(requestId, panel);
  }

  function showResultPanel(requestId, url, verdict, vtUrl) {
    const isMalicious = verdict.malicious > 0;
    const isSuspicious = verdict.suspicious > 0;
    const accent = isMalicious ? '#dc3545' : (isSuspicious ? '#e0a800' : '#28a745');
    const statusText = isMalicious ? '⚠️ Malicious' : (isSuspicious ? '⚡ Suspicious' : '✅ Clean');

    const statsRow = makeEl('div', { style: 'display:flex; gap:10px; flex-wrap:wrap; margin:8px 0; font-size:12px;' }, [
      makeEl('span', { text: '🦠 ' + verdict.malicious }),
      makeEl('span', { text: '⚠️ ' + verdict.suspicious }),
      makeEl('span', { text: '✅ ' + verdict.harmless }),
      makeEl('span', { text: '❓ ' + verdict.undetected })
    ]);

    const openVtBtn = makeEl('button', { style: buttonStyle(), text: 'Open VT Page' });
    openVtBtn.addEventListener('click', () => window.open(vtUrl, '_blank', 'noopener,noreferrer'));

    const openLinkBtn = makeEl('button', { style: buttonStyle('#3ba55d'), text: 'Open Link' });
    openLinkBtn.addEventListener('click', () => window.open(url, '_blank', 'noopener,noreferrer'));

    const closeBtn = makeEl('button', { style: buttonStyle(), text: 'Dismiss' });
    closeBtn.addEventListener('click', () => removePanel(requestId));

    const panel = makeEl('div', { style: panelBaseStyle(accent) }, [
      makeEl('div', { style: 'font-weight:700; margin-bottom:4px;', text: statusText }),
      makeEl('div', { style: 'opacity:.8; word-break:break-all; margin-bottom:6px;', text: url }),
      statsRow,
      makeEl('div', { style: 'display:flex; gap:6px; flex-wrap:wrap; margin-top:8px;' }, [openVtBtn, openLinkBtn, closeBtn])
    ]);
    mount(requestId, panel);
  }

  function showErrorPanel(requestId, url, message) {
    const openLinkBtn = makeEl('button', { style: buttonStyle('#3ba55d'), text: 'Open Link' });
    openLinkBtn.addEventListener('click', () => window.open(url, '_blank', 'noopener,noreferrer'));
    const closeBtn = makeEl('button', { style: buttonStyle(), text: 'Dismiss' });
    closeBtn.addEventListener('click', () => removePanel(requestId));

    const panel = makeEl('div', { style: panelBaseStyle('#dc3545') }, [
      makeEl('div', { style: 'font-weight:700; margin-bottom:4px;', text: '⚠️ Scan failed' }),
      makeEl('div', { style: 'opacity:.85; word-break:break-all; margin-bottom:6px;', text: message }),
      makeEl('div', { style: 'display:flex; gap:6px; flex-wrap:wrap;' }, [openLinkBtn, closeBtn])
    ]);
    mount(requestId, panel);
  }

  browser.runtime.onMessage.addListener((message) => {
    if (!message || !message.requestId) return;
    if (message.type === 'vtScanStart') {
      showScanningToast(message.requestId, message.url);
    } else if (message.type === 'vtScanResult') {
      showResultPanel(message.requestId, message.url, message.verdict, message.vtUrl);
    } else if (message.type === 'vtScanError') {
      showErrorPanel(message.requestId, message.url, message.message);
    }
  });
})();
