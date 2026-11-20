// Offscreen Document Worker (`extensions/browser-clipper/offscreen.js`).
// Connects to `wss://<hub>/agent/ws` ONLY when explicitly enabled by the user in popup settings.

let ws = null;
let pingTimer = null;
let activeCfg = null;

const MAX_EXT_BODY_BYTES = 4 * 1024 * 1024; // 4 MiB streaming cap per fetched URL (H8)
const MAX_EXT_REDIRECTS = 5;
const DISALLOWED_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.arpa',
  '.intranet',
  '.corp',
  '.lan',
  '.nip.io',
  '.sslip.io',
  '.xip.io',
  '.localtest.me',
  '.lvh.me',
  '.vcap.me',
  '.traefik.me',
  '.1u.ms',
  '.rebind.network',
];
const DISALLOWED_EXACT_HOSTS = new Set([
  'localhost',
  'nip.io',
  'sslip.io',
  'xip.io',
  'localtest.me',
  'lvh.me',
  'vcap.me',
  'traefik.me',
  '1u.ms',
  'rebind.network',
  'metadata.goog',
  'metadata.google.internal',
  'instance-data.ec2.internal',
]);

function isSafePublicExtensionUrl(rawUrl, selfHost) {
  let u;
  try {
    u = new URL(String(rawUrl || '').trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) {
    return null;
  }
  const host = u.hostname.toLowerCase().replace(/\.+$/, '');
  if (!host || host.length > 253 || !host.includes('.') || host.includes(':') || host.startsWith('[') || host.endsWith(']')) {
    return null;
  }
  if (DISALLOWED_EXACT_HOSTS.has(host)) return null;
  if (selfHost && host === selfHost.toLowerCase().replace(/\.+$/, '')) return null;
  for (const suffix of DISALLOWED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return null;
  }
  const labels = host.split('.');
  if (labels.some((lbl) => !lbl || lbl.startsWith('-') || lbl.endsWith('-'))) return null;
  const tld = labels[labels.length - 1];
  // Reject IPv4 dotted/octal/hex/integer literals (`192.168.1.1`, `127.1`, `0x7f.0.0.1`)
  if (/^(?:\d+|0x[0-9a-f]+)$/i.test(tld)) return null;
  return u;
}

async function readStreamTextBounded(body, maxBytes) {
  if (!body) return { text: '', bytes: 0, truncated: false };
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        if (total + value.byteLength > maxBytes) {
          const sliceLen = Math.max(0, maxBytes - total);
          if (sliceLen > 0) {
            chunks.push(value.subarray(0, sliceLen));
            total += sliceLen;
          }
          truncated = true;
          await reader.cancel('maxBytes reached').catch(() => undefined);
          break;
        }
        chunks.push(value);
        total += value.byteLength;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.byteLength;
  }
  return { text: new TextDecoder().decode(joined), bytes: total, truncated };
}

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
  let hubHost = '';
  try {
    hubHost = new URL(cfg.hubUrl).hostname;
  } catch {
    // ignore
  }

  for (const req of requests) {
    const t0 = performance.now();
    try {
      let curUrl = isSafePublicExtensionUrl(req.url, hubHost);
      if (!curUrl) {
        results.push({ id: req.id, url: req.url, kind: req.kind || 'page', outcome: 'invalid_url', status: 0, bytes: 0, attempts: 1, durationMs: 0 });
        continue;
      }

      let res = null;
      let blockedRedirect = false;
      for (let hop = 0; hop <= MAX_EXT_REDIRECTS; hop++) {
        res = await fetch(curUrl.toString(), {
          credentials: 'omit',
          redirect: 'manual',
          signal: AbortSignal.timeout(25_000),
        });
        if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
          const loc = res.headers.get('location');
          await res.body?.cancel().catch(() => undefined);
          if (!loc || hop === MAX_EXT_REDIRECTS) {
            blockedRedirect = true;
            break;
          }
          const resolvedNext = new URL(loc, curUrl).toString();
          const nextSafe = isSafePublicExtensionUrl(resolvedNext, hubHost);
          if (!nextSafe) {
            blockedRedirect = true;
            break;
          }
          curUrl = nextSafe;
          continue;
        }
        break;
      }

      if (blockedRedirect || !res) {
        results.push({
          id: req.id,
          url: req.url,
          kind: req.kind || 'page',
          outcome: 'error',
          status: 0,
          bytes: 0,
          attempts: 1,
          durationMs: Math.round(performance.now() - t0),
          problem: 'disallowed_or_opaque_redirect',
        });
        continue;
      }

      const { text: body, bytes, truncated } = await readStreamTextBounded(res.body, MAX_EXT_BODY_BYTES);
      results.push({
        id: req.id,
        url: req.url,
        finalUrl: curUrl.toString(),
        kind: req.kind || 'page',
        outcome: truncated ? 'error' : res.ok ? 'ok' : `http_${res.status}`,
        status: res.status,
        contentType: res.headers.get('content-type') || 'text/html',
        bytes,
        truncated,
        attempts: 1,
        durationMs: Math.round(performance.now() - t0),
        body: truncated ? '' : body,
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
    redirect: 'error',
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
          version: '2.5.3',
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
