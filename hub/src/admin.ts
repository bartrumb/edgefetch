/**
 * Built-in Zero-Dependency `/admin` Web Control Center (`GET /admin`, `POST /admin/login`, `POST /admin/logout`,
 * `GET /admin/api/state`, `POST /admin/api/fetch`, `POST /admin/api/affinity/clear`, `POST /admin/api/grants/revoke`).
 *
 * Protected by an 8-hour HMAC-SHA256 `HttpOnly; Secure; SameSite=Strict` cookie + per-session CSRF token + SQLite
 * brute-force rate limiting. Gives operators a single browser dashboard for:
 *  1. Live Home Assistant OS fleet cards (`site-arm64`, `site-x86`, `site-win-vm`, CPU arch, uptime, job counters).
 *  2. Active 15-minute SQLite domain-affinity pins (`host -> siteId`) + 1-click pin reset.
 *  3. Interactive URL Crawl Runner (`auto` / `container` / `agent`, site pinning, politeness tuning, visual DNS/TCP/TLS/TTFB bar).
 *  4. Self-hosted OAuth 2.1 MCP grants (`Claude Code`, scopes, expiry) + 1-click session revocation + copyable CLI command.
 *  5. Cloudflare Workers Observability (`Traces` & `Logs`) filter cheat sheet.
 */
import type { AffinityPin, AgentAttachment, FetchTarget } from './agent-hub';
import { MIN_TOKEN_LENGTH, SITE_ID_PATTERN, sameBytes } from './auth';
import {
  ADMIN_COOKIE_NAME,
  createAdminSessionValue,
  escapeHtml,
  formatCookie,
  verifyAdminSessionCookie,
  type OAuthGrantSummary,
  type OAuthStore,
} from './oauth';

const RATE_LIMIT_WINDOW_MS = 5 * 60_000;
const RATE_LIMIT_MAX_FAILURES = 5;

const ADMIN_HTML_HEADERS: Record<string, string> = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy':
    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

export interface AdminPortalDeps {
  serviceName: string;
  mcpSlug: string;
  sampleUrl?: string;
  ownerSecret?: string;
  oauthStore: OAuthStore;
  allowedTargets: FetchTarget[];
  defaultTarget: FetchTarget;
  getState: () => Promise<{
    connected: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
  }>;
  clearAffinities: (siteId?: string) => Promise<void>;
  revokeGrant: (grantId: string) => Promise<boolean>;
  executeFetch: (params: {
    target: FetchTarget;
    site?: string;
    body: string;
  }) => Promise<{ status: number; via: string; bodyText: string }>;
}

function renderLoginHtml(serviceName: string, errorMsg?: string): string {
  const err = errorMsg ? `<div class="err">${escapeHtml(errorMsg)}</div>` : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(serviceName)} — Admin Sign In</title>
  <style>
    :root { color-scheme: dark light; }
    body { font: 15px/1.55 system-ui, -apple-system, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b1120; color: #e2e8f0; padding: 16px; }
    main { width: 100%; max-width: 420px; background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 28px; box-shadow: 0 16px 40px rgba(0,0,0,.45); }
    h1 { margin: 0 0 6px; font-size: 1.25rem; color: #f8fafc; }
    p { margin: 0 0 18px; color: #94a3b8; font-size: 0.92rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px; color: #cbd5e1; }
    input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; margin-bottom: 16px; }
    button { width: 100%; padding: 10px 16px; border-radius: 8px; border: 1px solid #3b82f6; background: #2563eb; color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
    button:hover { background: #1d4ed8; }
    .err { background: #450a0a; border: 1px solid #dc2626; color: #fecaca; padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; font-size: 0.88rem; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(serviceName)}</h1>
    <p>Sign in with your hub caller token (<code>CALLER_TOKEN</code>) to inspect standby sites, test fetches, and manage MCP OAuth grants.</p>
    ${err}
    <form method="post" action="/admin/login">
      <label for="token">Caller Token</label>
      <input id="token" name="token" type="password" required autofocus autocomplete="current-password" placeholder="Paste bearer token...">
      <button type="submit">Open Control Center</button>
    </form>
  </main>
</body>
</html>`;
}

function renderDashboardHtml(params: {
  serviceName: string;
  mcpSlug: string;
  sampleUrl: string;
  origin: string;
  csrf: string;
  allowedTargets: FetchTarget[];
  defaultTarget: FetchTarget;
}): string {
  const mcpCmd = `claude mcp add --transport http ${params.mcpSlug} ${params.origin}/mcp`;
  const targetOptions = params.allowedTargets
    .map((t) => {
      const label =
        t === 'auto'
          ? 'auto (Load-balance remote HAOS pool -> Cloudflare on 429)'
          : t === 'container'
            ? 'container (Cloudflare Go container only)'
            : 'agent (Remote HAOS pool only — LRU load-balanced)';
      return `<option value="${escapeHtml(t)}"${t === params.defaultTarget ? ' selected' : ''}>${escapeHtml(label)}</option>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(params.serviceName)} — Control Center</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body { font: 14px/1.5 system-ui, -apple-system, sans-serif; margin: 0; background: #0b1120; color: #e2e8f0; }
    header { background: #111827; border-bottom: 1px solid #1f2937; padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    header h1 { font-size: 1.1rem; margin: 0; display: flex; align-items: center; gap: 10px; color: #f8fafc; }
    .pill { font-size: 0.75rem; padding: 2px 8px; border-radius: 999px; background: #064e3b; color: #6ee7b7; border: 1px solid #059669; font-weight: 600; }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 22px; display: grid; gap: 20px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 18px 20px; }
    .card h2 { margin: 0 0 12px; font-size: 0.98rem; color: #f8fafc; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .muted { color: #94a3b8; font-size: 0.85rem; }
    .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
    .site-card { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 14px; }
    .site-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .site-name { font-weight: 700; font-size: 0.95rem; color: #38bdf8; }
    .arch { font-size: 0.75rem; background: #1e293b; border: 1px solid #475569; padding: 1px 7px; border-radius: 6px; color: #cbd5e1; }
    .kv { display: flex; justify-content: space-between; font-size: 0.82rem; color: #94a3b8; margin-top: 4px; }
    .kv strong { color: #e2e8f0; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.83rem; }
    .cmd-bar { display: flex; gap: 8px; align-items: center; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; overflow-x: auto; }
    .cmd-bar code { color: #38bdf8; white-space: nowrap; flex: 1; }
    button { font: inherit; font-size: 0.84rem; font-weight: 600; padding: 7px 13px; border-radius: 7px; border: 1px solid #475569; background: #334155; color: #f8fafc; cursor: pointer; }
    button:hover { background: #475569; }
    button.primary { background: #2563eb; border-color: #3b82f6; color: #fff; }
    button.primary:hover { background: #1d4ed8; }
    button.danger { background: #7f1d1d; border-color: #b91c1c; color: #fecaca; padding: 4px 10px; font-size: 0.78rem; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-top: 10px; }
    label { display: block; font-size: 0.78rem; font-weight: 600; color: #cbd5e1; margin-bottom: 4px; }
    input[type="text"], input[type="url"], input[type="number"], select { width: 100%; padding: 8px 10px; border-radius: 7px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; }
    table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .03em; }
    .timing-bar { display: flex; height: 10px; border-radius: 6px; overflow: hidden; background: #0f172a; margin: 10px 0 6px; }
    .seg-dns { background: #a855f7; }
    .seg-tcp { background: #f59e0b; }
    .seg-tls { background: #ec4899; }
    .seg-ttfb { background: #22c55e; }
    pre.out { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; max-height: 360px; overflow: auto; margin: 10px 0 0; color: #cbd5e1; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .chip { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 4px 9px; color: #93c5fd; }
  </style>
</head>
<body>
  <header>
    <h1>${escapeHtml(params.serviceName)} <span class="pill" id="conn-pill">Loading...</span></h1>
    <div style="display:flex;gap:8px;align-items:center">
      <button type="button" id="refresh-btn">Refresh</button>
      <form method="post" action="/admin/logout" style="margin:0">
        <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}">
        <button type="submit">Sign Out</button>
      </form>
    </div>
  </header>

  <div class="wrap">
    <section class="card">
      <h2>Connect Claude Code via Self-Hosted OAuth 2.1 MCP</h2>
      <p class="muted" style="margin:0 0 10px">Run once in your terminal — Claude Code auto-discovers RFC 9728 / RFC 8414 metadata, registers via PKCE S256, and opens a browser consent prompt (zero raw tokens stored in config files):</p>
      <div class="cmd-bar">
        <code id="mcp-cmd">${escapeHtml(mcpCmd)}</code>
        <button type="button" id="copy-mcp-btn">Copy</button>
      </div>
    </section>

    <section class="card">
      <h2>Connected Standby Fleet (<span id="site-count">0</span>) <span class="muted">Auto-refreshes every 10s</span></h2>
      <div id="fleet-grid" class="grid-3"><div class="muted">Loading connected agents...</div></div>
    </section>

    <section class="card">
      <h2>Interactive Crawl &amp; Tuning Tester</h2>
      <form id="fetch-form">
        <div style="display:grid;grid-template-columns:1fr auto;gap:10px">
          <div>
            <label for="f-url">Public HTTPS URL</label>
            <input id="f-url" type="url" required value="${escapeHtml(params.sampleUrl)}" placeholder="https://example.com/feed.json">
          </div>
          <div style="align-self:end">
            <button type="submit" class="primary" id="run-fetch-btn" style="padding:8px 18px">Fetch URL</button>
          </div>
        </div>
        <div class="form-grid">
          <div>
            <label for="f-kind">Kind</label>
            <select id="f-kind">
              <option value="feed" selected>feed (JSON)</option>
              <option value="page">page (HTML)</option>
            </select>
          </div>
          <div>
            <label for="f-target">Target Tier</label>
            <select id="f-target">${targetOptions}</select>
          </div>
          <div>
            <label for="f-site">Pin Remote Site (optional)</label>
            <select id="f-site"><option value="">Load-Balance All Remote Sites (LRU)</option></select>
          </div>
          <div>
            <label for="f-pause">pauseMs / pauseJitterMs</label>
            <div style="display:flex;gap:6px">
              <input id="f-pause" type="number" min="0" max="30000" value="1500">
              <input id="f-jitter" type="number" min="0" max="15000" value="750">
            </div>
          </div>
        </div>
        <div style="display:flex;gap:18px;margin-top:10px;font-size:0.84rem;color:#cbd5e1">
          <label style="display:inline-flex;align-items:center;gap:6px;margin:0"><input id="f-robots" type="checkbox" checked> Respect robots.txt</label>
          <label style="display:inline-flex;align-items:center;gap:6px;margin:0"><input id="f-body" type="checkbox" checked> Include body preview</label>
        </div>
      </form>
      <div id="fetch-result" style="display:none;margin-top:14px">
        <div id="fetch-summary" class="muted"></div>
        <div class="timing-bar" id="timing-bar"></div>
        <div id="timing-legend" class="muted" style="font-size:0.78rem"></div>
        <pre class="out" id="fetch-json"></pre>
      </div>
    </section>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:20px">
      <section class="card">
        <h2>
          <span>Remote Site 429 Cooldowns</span>
          <button type="button" id="clear-affinity-btn" style="padding:4px 10px;font-size:0.78rem">Clear Cooldowns</button>
        </h2>
        <table>
          <thead><tr><th>Origin Host</th><th>Cooled-Down Site</th><th>Cooldown Left</th></tr></thead>
          <tbody id="affinity-tbody"><tr><td colspan="3" class="muted">No active 429 site cooldowns</td></tr></tbody>
        </table>
      </section>

      <section class="card">
        <h2>Active OAuth 2.1 MCP Sessions</h2>
        <table>
          <thead><tr><th>Client</th><th>Scopes</th><th>Expires</th><th></th></tr></thead>
          <tbody id="grants-tbody"><tr><td colspan="4" class="muted">No OAuth grants issued yet</td></tr></tbody>
        </table>
      </section>
    </div>

    <section class="card">
      <h2>Cloudflare Workers Observability — Single Pane of Glass Filters</h2>
      <p class="muted" style="margin:0">Open <strong>Cloudflare Dashboard -&gt; Workers &amp; Pages -&gt; Observability (Traces &amp; Logs)</strong> and filter with:</p>
      <div class="chips">
        <code class="chip">crawler.via</code>
        <code class="chip">net.timing.ttfb_ms &gt; 500</code>
        <code class="chip">net.timing.conn_reused = true</code>
        <code class="chip">event = "agent_ready"</code>
        <code class="chip">event = "agent_failover"</code>
        <code class="chip">crawler.outcome = "ok"</code>
      </div>
    </section>
  </div>

  <script>
    const CSRF = ${JSON.stringify(params.csrf)};
    const el = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
    const relTime = (ts) => {
      if (!ts) return 'never';
      const sec = Math.round((Date.now() - ts) / 1000);
      if (sec < 0) {
        const rem = Math.abs(sec);
        return rem < 60 ? rem + 's' : Math.round(rem / 60) + 'm';
      }
      return sec < 60 ? sec + 's ago' : sec < 3600 ? Math.round(sec / 60) + 'm ago' : Math.round(sec / 3600) + 'h ago';
    };

    async function loadState() {
      const res = await fetch('/admin/api/state', { headers: { 'accept': 'application/json' } });
      if (res.status === 401) { location.reload(); return; }
      const data = await res.json();
      el('site-count').textContent = data.connected;
      el('conn-pill').textContent = data.connected + ' site' + (data.connected === 1 ? '' : 's') + ' online';

      const grid = el('fleet-grid');
      const siteSelect = el('f-site');
      const prevSelected = siteSelect.value;
      siteSelect.innerHTML = '<option value="">Load-Balance All Remote Sites (LRU)</option>' +
        data.agents.map((a) => '<option value="' + esc(a.siteId) + '">' + esc(a.siteId) + ' (' + esc(a.arch) + ')</option>').join('');
      siteSelect.value = prevSelected;

      if (!data.agents.length) {
        grid.innerHTML = '<div class="muted">No standby agents currently connected over WebSocket.</div>';
      } else {
        grid.innerHTML = data.agents.map((a) =>
          '<div class="site-card">' +
            '<div class="site-top"><span class="site-name">' + esc(a.siteId) + '</span><span class="arch">' + esc(a.arch) + '</span></div>' +
            '<div class="kv"><span>Connected</span><strong>' + esc(relTime(a.connectedAt)) + '</strong></div>' +
            '<div class="kv"><span>Last Job</span><strong>' + esc(relTime(a.lastJobAt)) + '</strong></div>' +
            '<div class="kv"><span>Jobs OK / Err</span><strong>' + Number(a.jobsOk) + ' / ' + Number(a.jobsErr) + '</strong></div>' +
          '</div>'
        ).join('');
      }

      const affBody = el('affinity-tbody');
      affBody.innerHTML = data.affinities.length
        ? data.affinities.map((p) => '<tr><td><code>' + esc(p.host) + '</code></td><td>' + esc(p.siteId) + '</td><td>' + esc(relTime(p.expiresAt)) + '</td></tr>').join('')
        : '<tr><td colspan="3" class="muted">No active 429 site cooldowns</td></tr>';

      const grantsBody = el('grants-tbody');
      grantsBody.innerHTML = data.grants.length
        ? data.grants.map((g) =>
            '<tr><td><strong>' + esc(g.clientName) + '</strong></td><td><code>' + esc(g.scopes.join(' ')) + '</code></td><td>' + esc(relTime(g.expiresAt)) + '</td>' +
            '<td><button type="button" class="danger" data-revoke="' + esc(g.grantId) + '">Revoke</button></td></tr>'
          ).join('')
        : '<tr><td colspan="4" class="muted">No active OAuth grants</td></tr>';
    }

    el('copy-mcp-btn').addEventListener('click', async () => {
      await navigator.clipboard.writeText(el('mcp-cmd').textContent);
      el('copy-mcp-btn').textContent = 'Copied!';
      setTimeout(() => { el('copy-mcp-btn').textContent = 'Copy'; }, 1500);
    });

    el('refresh-btn').addEventListener('click', loadState);

    el('clear-affinity-btn').addEventListener('click', async () => {
      await fetch('/admin/api/affinity/clear', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF }, body: '{}' });
      await loadState();
    });

    el('grants-tbody').addEventListener('click', async (ev) => {
      const btn = ev.target.closest('[data-revoke]');
      if (!btn) return;
      await fetch('/admin/api/grants/revoke', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
        body: JSON.stringify({ grantId: btn.getAttribute('data-revoke') }),
      });
      await loadState();
    });

    el('fetch-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = el('run-fetch-btn');
      btn.disabled = true;
      btn.textContent = 'Fetching...';
      try {
        const res = await fetch('/admin/api/fetch', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
          body: JSON.stringify({
            url: el('f-url').value,
            kind: el('f-kind').value,
            target: el('f-target').value,
            site: el('f-site').value || undefined,
            pauseMs: Number(el('f-pause').value || 1500),
            pauseJitterMs: Number(el('f-jitter').value || 750),
            robots: el('f-robots').checked,
            includeBody: el('f-body').checked,
          }),
        });
        const out = await res.json();
        el('fetch-result').style.display = 'block';
        const r = out.reply?.results?.[0];
        const t = r?.timing || {};
        const total = Math.max(1, (t.dnsMs || 0) + (t.connectMs || 0) + (t.tlsMs || 0) + (t.ttfbMs || 0));
        el('fetch-summary').innerHTML =
          'Via: <code>' + esc(out.via) + '</code> &middot; HTTP Status: <strong>' + esc(r?.status ?? out.status) + '</strong> &middot; Outcome: <strong>' + esc(r?.outcome ?? 'n/a') + '</strong> &middot; Duration: <strong>' + esc(r?.durationMs ?? out.reply?.durationMs ?? 0) + ' ms</strong>';
        el('timing-bar').innerHTML =
          '<div class="seg-dns" style="width:' + ((t.dnsMs || 0) / total * 100) + '%"></div>' +
          '<div class="seg-tcp" style="width:' + ((t.connectMs || 0) / total * 100) + '%"></div>' +
          '<div class="seg-tls" style="width:' + ((t.tlsMs || 0) / total * 100) + '%"></div>' +
          '<div class="seg-ttfb" style="width:' + ((t.ttfbMs || 0) / total * 100) + '%"></div>';
        el('timing-legend').textContent =
          'DNS: ' + (t.dnsMs || 0) + 'ms | TCP: ' + (t.connectMs || 0) + 'ms | TLS: ' + (t.tlsMs || 0) + 'ms | TTFB: ' + (t.ttfbMs || 0) + 'ms | Reused: ' + Boolean(t.reused) + ' | Proto: ' + (t.proto || 'n/a');
        el('fetch-json').textContent = JSON.stringify(out, null, 2);
        await loadState();
      } finally {
        btn.disabled = false;
        btn.textContent = 'Fetch URL';
      }
    });

    loadState();
    setInterval(loadState, 10000);
  </script>
</body>
</html>`;
}

export async function handleAdminRoute(request: Request, url: URL, deps: AdminPortalDeps): Promise<Response | null> {
  const path = url.pathname;
  if (path !== '/admin' && !path.startsWith('/admin/')) return null;

  const isSecure = url.protocol === 'https:';
  if (!deps.ownerSecret || deps.ownerSecret.length < MIN_TOKEN_LENGTH) {
    return Response.json({ error: 'owner_secret_unconfigured' }, { status: 503 });
  }

  const session = await verifyAdminSessionCookie(request.headers.get('cookie'), deps.ownerSecret);

  if (path === '/admin' && request.method === 'GET') {
    if (!session.ok) {
      return new Response(renderLoginHtml(deps.serviceName), { status: 200, headers: ADMIN_HTML_HEADERS });
    }
    return new Response(
      renderDashboardHtml({
        serviceName: deps.serviceName,
        mcpSlug: deps.mcpSlug,
        sampleUrl: deps.sampleUrl ?? 'https://example.com/',
        origin: url.origin,
        csrf: session.csrf,
        allowedTargets: deps.allowedTargets,
        defaultTarget: deps.defaultTarget,
      }),
      { status: 200, headers: ADMIN_HTML_HEADERS },
    );
  }

  if (path === '/admin/login' && request.method === 'POST') {
    const formText = await request.text();
    const supplied = (new URLSearchParams(formText).get('token') ?? '').trim();
    const clientIp = request.headers.get('cf-connecting-ip') ?? 'local';
    if (!supplied || !sameBytes(supplied, deps.ownerSecret)) {
      const rl = await deps.oauthStore.recordAuthFailure(`admin:${clientIp}`, Date.now(), RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_FAILURES);
      if (!rl.allowed) {
        return new Response(renderLoginHtml(deps.serviceName, 'Too many failed attempts. Try again in 5 minutes.'), {
          status: 429,
          headers: { ...ADMIN_HTML_HEADERS, 'retry-after': String(rl.retryAfterSec) },
        });
      }
      return new Response(renderLoginHtml(deps.serviceName, 'Invalid caller token.'), {
        status: 401,
        headers: ADMIN_HTML_HEADERS,
      });
    }

    await deps.oauthStore.clearAuthFailures(`admin:${clientIp}`);
    const minted = await createAdminSessionValue(deps.ownerSecret);
    const headers = new Headers({ location: '/admin', 'cache-control': 'no-store' });
    // Path='/' allows `/oauth/authorize` on the same origin to detect an active owner session seamlessly.
    headers.append('set-cookie', formatCookie(ADMIN_COOKIE_NAME, minted.value, { maxAge: minted.maxAgeSec, path: '/', sameSite: 'Lax', secure: isSecure }));
    return new Response(null, { status: 302, headers });
  }

  if (path === '/admin/logout' && request.method === 'POST') {
    const formCsrf = new URLSearchParams(await request.text()).get('csrf') ?? '';
    if (!session.ok || !sameBytes(formCsrf, session.csrf)) {
      return Response.json({ error: 'invalid_csrf' }, { status: 403 });
    }
    const headers = new Headers({ location: '/admin', 'cache-control': 'no-store' });
    headers.append('set-cookie', formatCookie(ADMIN_COOKIE_NAME, '', { maxAge: 0, path: '/', sameSite: 'Lax', secure: isSecure }));
    return new Response(null, { status: 302, headers });
  }

  // Protected JSON API routes under `/admin/api/*`
  if (!session.ok) {
    return Response.json({ error: 'unauthorized' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }

  if (path === '/admin/api/state' && request.method === 'GET') {
    const state = await deps.getState();
    return Response.json(state, { status: 200, headers: { 'cache-control': 'no-store' } });
  }

  if (request.method === 'POST') {
    const hdrCsrf = request.headers.get('x-csrf-token') ?? '';
    if (!hdrCsrf || !sameBytes(hdrCsrf, session.csrf)) {
      return Response.json({ error: 'invalid_csrf' }, { status: 403, headers: { 'cache-control': 'no-store' } });
    }

    if (path === '/admin/api/affinity/clear') {
      const body = (await request.json().catch(() => ({}))) as { siteId?: string };
      await deps.clearAffinities(body.siteId);
      return Response.json({ ok: true }, { status: 200, headers: { 'cache-control': 'no-store' } });
    }

    if (path === '/admin/api/grants/revoke') {
      const body = (await request.json().catch(() => ({}))) as { grantId?: string };
      if (!body.grantId || typeof body.grantId !== 'string') {
        return Response.json({ error: 'missing_grant_id' }, { status: 400 });
      }
      const revoked = await deps.revokeGrant(body.grantId);
      return Response.json({ ok: true, revoked }, { status: 200, headers: { 'cache-control': 'no-store' } });
    }

    if (path === '/admin/api/fetch') {
      const body = (await request.json().catch(() => ({}))) as {
        url?: string;
        kind?: string;
        target?: string;
        site?: string;
        pauseMs?: number;
        pauseJitterMs?: number;
        robots?: boolean;
        includeBody?: boolean;
      };
      if (!body.url || typeof body.url !== 'string') {
        return Response.json({ error: 'missing_url' }, { status: 400 });
      }
      const target = (typeof body.target === 'string' ? body.target.toLowerCase() : deps.defaultTarget) as FetchTarget;
      if (!deps.allowedTargets.includes(target)) {
        return Response.json({ error: 'invalid_target' }, { status: 400 });
      }
      const site = typeof body.site === 'string' && body.site.trim() ? body.site.trim().toLowerCase() : undefined;
      if (site && !SITE_ID_PATTERN.test(site)) {
        return Response.json({ error: 'invalid_site' }, { status: 400 });
      }

      const callPayload = JSON.stringify({
        maxSeconds: 60,
        options: {
          includeBody: Boolean(body.includeBody),
          robots: body.robots !== false,
          pauseMs: Math.min(30_000, Math.max(0, Math.floor(Number(body.pauseMs ?? 1500)))),
          pauseJitterMs: Math.min(15_000, Math.max(0, Math.floor(Number(body.pauseJitterMs ?? 750)))),
        },
        requests: [{ id: 'admin-1', url: body.url.trim(), kind: body.kind === 'feed' ? 'feed' : 'page' }],
      });

      const out = await deps.executeFetch({ target, ...(site ? { site } : {}), body: callPayload });
      let reply: unknown = out.bodyText;
      try {
        reply = JSON.parse(out.bodyText);
        if (reply && typeof reply === 'object' && Array.isArray((reply as { results?: unknown[] }).results)) {
          for (const r of (reply as { results: Array<Record<string, unknown>> }).results) {
            if (typeof r.body === 'string' && r.body.length > 32_768) {
              r.body = r.body.slice(0, 32_768) + '\n... [truncated in Admin UI preview]';
            }
          }
        }
      } catch {
        // leave raw
      }
      return Response.json({ status: out.status, via: out.via, reply }, { status: 200, headers: { 'cache-control': 'no-store' } });
    }
  }

  return Response.json({ error: 'not_found' }, { status: 404 });
}
