// Offscreen Document Worker (`extensions/browser-clipper/offscreen.js`).
// Connects to `wss://<hub>/agent/ws` ONLY when explicitly enabled by the user in popup settings.
// Note: Standard browser `WebSocket` cannot attach custom `Authorization` headers on handshake, so this worker
// pairs with local/Tailscale Hubs or OAuth/session-authorized gateways and uploads results via authenticated `POST /agent/reply`.

let ws = null;
let pingTimer = null;
let activeCfg = null;

function disconnect() {
  if (pingTimer) {
    clearInterval(pingTimer);
    pingTimer = null;
  }
  if (ws) {
    try {
      ws.close(1000, 'user_disabled');
    } catch {
      // ignore
    }
    ws = null;
  }
  chrome.runtime.sendMessage({ type: 'NODE_STATUS_CHANGED', connected: false }).catch(() => undefined);
}

async function executeDispatchedJob(cfg, frame) {
  const payload = typeof frame.payload === 'string' ? JSON.parse(frame.payload) : frame.payload;
  const requests = Array.isArray(payload?.requests) ? payload.requests : [];
  const results = [];

  for (const req of requests) {
    const t0 = performance.now();
    try {
      const u = new URL(req.url);
      if (u.protocol !== 'https:') {
        results.push({ id: req.id, url: req.url, kind: req.kind || 'page', outcome: 'invalid_url', status: 0, bytes: 0, attempts: 1, durationMs: 0 });
        continue;
      }
      const res = await fetch(u.toString(), { credentials: 'omit', redirect: 'follow' });
      const body = await res.text();
      results.push({
        id: req.id,
        url: req.url,
        finalUrl: res.url || req.url,
        kind: req.kind || 'page',
        outcome: res.ok ? 'ok' : `http_${res.status}`,
        status: res.status,
        contentType: res.headers.get('content-type') || 'text/html',
        bytes: new TextEncoder().encode(body).byteLength,
        attempts: 1,
        durationMs: Math.round(performance.now() - t0),
        body,
        bodyEncoding: 'utf-8',
      });
    } catch (err) {
      results.push({
        id: req.id,
        url: req.url,
        kind: req.kind || 'page',
        outcome: 'network_error',
        status: 0,
        bytes: 0,
        attempts: 1,
        durationMs: Math.round(performance.now() - t0),
        error: String(err?.message || err),
      });
    }
  }

  await fetch(`${cfg.hubUrl.replace(/\/+$/, '')}/agent/reply`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${cfg.agentToken}`,
      'content-type': 'application/json',
      'x-agent-site': cfg.siteId || 'browser-ext-1',
      'x-job-id': frame.jobId,
      'x-job-nonce': frame.nonce,
    },
    body: JSON.stringify({ results }),
  });
}

function connect(cfg) {
  disconnect();
  activeCfg = cfg;
  const wsBase = cfg.hubUrl.replace(/^http:\/\//i, 'ws://').replace(/^https:\/\//i, 'wss://').replace(/\/+$/, '');
  const wsUrl = wsBase.endsWith('/agent/ws') ? wsBase : `${wsBase}/agent/ws`;

  return new Promise((resolveConn) => {
    let settled = false;
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          type: 'agent_hello',
          version: '2.2.0',
          arch: 'browser-mv3',
          goVersion: 'mv3-extension',
          capabilities: [],
          reconnectAttempt: 0,
        }),
      );
      pingTimer = setInterval(() => {
        if (ws?.readyState === WebSocket.OPEN) ws.send('ping');
      }, 25_000);
      chrome.runtime.sendMessage({ type: 'NODE_STATUS_CHANGED', connected: true }).catch(() => undefined);
      if (!settled) {
        settled = true;
        resolveConn({ connected: true });
      }
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string' || ev.data === 'pong') return;
      try {
        const frame = JSON.parse(ev.data);
        if (frame.type === 'dispatch' && frame.jobId && frame.nonce && activeCfg) {
          executeDispatchedJob(activeCfg, frame).catch(() => undefined);
        }
      } catch {
        // ignore
      }
    };
    ws.onerror = () => {
      if (!settled) {
        settled = true;
        resolveConn({ connected: false });
      }
    };
    ws.onclose = () => {
      disconnect();
      if (!settled) {
        settled = true;
        resolveConn({ connected: false });
      }
    };
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'OFFSCREEN_CONNECT') {
    connect(msg.cfg).then(sendResponse);
    return true;
  }
  if (msg?.type === 'OFFSCREEN_DISCONNECT') {
    disconnect();
    sendResponse({ connected: false });
  }
  return false;
});
