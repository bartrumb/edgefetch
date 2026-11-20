// Manifest V3 Background Service Worker (`extensions/browser-clipper/service-worker.js`).
// Manages the optional Offscreen Document WebSocket connection when the user opts into "Connect Browser as Edge Node".

async function ensureOffscreenDocument() {
  if (await chrome.offscreen.hasDocument()) return;
  await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['WORKERS'],
    justification: 'Maintain opt-in EdgeFetch /agent/ws WebSocket connection while Browser Node toggle is enabled.',
  });
}

async function syncOffscreenState(cfg) {
  if (!cfg.nodeEnabled || !cfg.hubUrl || !cfg.agentToken) {
    if (await chrome.offscreen.hasDocument()) {
      await chrome.runtime.sendMessage({ type: 'OFFSCREEN_DISCONNECT' }).catch(() => undefined);
      await chrome.offscreen.closeDocument().catch(() => undefined);
    }
    await chrome.storage.local.set({ nodeConnected: false });
    return { connected: false };
  }
  await ensureOffscreenDocument();
  const res = await chrome.runtime.sendMessage({ type: 'OFFSCREEN_CONNECT', cfg }).catch(() => ({ connected: false }));
  await chrome.storage.local.set({ nodeConnected: Boolean(res?.connected) });
  return res;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'SYNC_NODE_CONFIG') {
    syncOffscreenState(msg.cfg)
      .then((res) => sendResponse(res))
      .catch(() => sendResponse({ connected: false }));
    return true;
  }
  if (msg?.type === 'NODE_STATUS_CHANGED') {
    chrome.storage.local.set({ nodeConnected: Boolean(msg.connected) });
  }
  return false;
});
