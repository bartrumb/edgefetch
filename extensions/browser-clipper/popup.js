const els = {
  hubUrl: document.getElementById('hubUrl'),
  callerToken: document.getElementById('callerToken'),
  collectionId: document.getElementById('collectionId'),
  agentToken: document.getElementById('agentToken'),
  siteId: document.getElementById('siteId'),
  nodeToggle: document.getElementById('nodeToggle'),
  nodeBadge: document.getElementById('nodeBadge'),
  clipBtn: document.getElementById('clipBtn'),
  saveBtn: document.getElementById('saveBtn'),
  statusBox: document.getElementById('statusBox'),
};

function showStatus(msg) {
  els.statusBox.hidden = false;
  els.statusBox.textContent = msg;
}

async function loadSettings() {
  const cfg = await chrome.storage.local.get([
    'hubUrl',
    'callerToken',
    'collectionId',
    'agentToken',
    'siteId',
    'nodeEnabled',
    'nodeConnected',
  ]);
  els.hubUrl.value = cfg.hubUrl || 'http://127.0.0.1:8787';
  els.callerToken.value = cfg.callerToken || '';
  els.collectionId.value = cfg.collectionId || 'browser-clips';
  els.agentToken.value = cfg.agentToken || '';
  els.siteId.value = cfg.siteId || 'browser-ext-1';
  els.nodeToggle.checked = Boolean(cfg.nodeEnabled);
  updateBadge(Boolean(cfg.nodeEnabled), Boolean(cfg.nodeConnected));
}

function updateBadge(enabled, connected) {
  if (!enabled) {
    els.nodeBadge.textContent = 'Node: Off';
    els.nodeBadge.className = 'badge';
  } else if (connected) {
    els.nodeBadge.textContent = 'Node: Connected';
    els.nodeBadge.className = 'badge live';
  } else {
    els.nodeBadge.textContent = 'Node: Connecting...';
    els.nodeBadge.className = 'badge';
  }
}

async function saveSettings() {
  const cfg = {
    hubUrl: els.hubUrl.value.trim().replace(/\/+$/, ''),
    callerToken: els.callerToken.value.trim(),
    collectionId: els.collectionId.value.trim() || 'browser-clips',
    agentToken: els.agentToken.value.trim(),
    siteId: els.siteId.value.trim() || 'browser-ext-1',
    nodeEnabled: els.nodeToggle.checked,
  };
  await chrome.storage.local.set(cfg);
  const reply = await chrome.runtime.sendMessage({ type: 'SYNC_NODE_CONFIG', cfg });
  updateBadge(cfg.nodeEnabled, Boolean(reply?.connected));
  showStatus('Settings saved.');
}

els.saveBtn.addEventListener('click', () => {
  saveSettings().catch((err) => showStatus(`Save failed: ${err.message}`));
});

els.nodeToggle.addEventListener('change', () => {
  saveSettings().catch((err) => showStatus(`Node toggle error: ${err.message}`));
});

els.clipBtn.addEventListener('click', async () => {
  try {
    await saveSettings();
    showStatus('Capturing active tab DOM...');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url) {
      showStatus('Cannot clip this browser tab.');
      return;
    }
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => ({
        url: window.location.href,
        title: document.title,
        html: document.documentElement.outerHTML,
      }),
    });

    const baseUrl = els.hubUrl.value.trim().replace(/\/+$/, '');
    const headers = { 'content-type': 'application/json' };
    if (els.callerToken.value.trim()) {
      headers.authorization = `Bearer ${els.callerToken.value.trim()}`;
    }

    const res = await fetch(`${baseUrl}/v1/ingest-tab`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        url: result.url,
        title: result.title,
        html: result.html,
        collectionId: els.collectionId.value.trim() || 'browser-clips',
      }),
    });
    const out = await res.json();
    if (!res.ok || !out.ok) {
      showStatus(`Error (${res.status}): ${out.error || out.message || 'failed'}`);
      return;
    }
    showStatus(
      `Clipped "${out.title}" -> collection "${out.collectionId}" (${out.indexedChunks} FTS5 chunks)!\n\n` +
        (out.markdown || '').slice(0, 600),
    );
  } catch (err) {
    showStatus(`Clip failed: ${err.message}`);
  }
});

loadSettings();
