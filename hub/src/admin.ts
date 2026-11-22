/**
 * Built-in Zero-Dependency `/admin` Web Control Center (`GET /admin`, `POST /admin/login`, `POST /admin/logout`,
 * `GET /admin/api/state`, `POST /admin/api/fetch`, `POST /admin/api/affinity/clear`, `POST /admin/api/grants/revoke`,
 * `POST /admin/api/events/clear`).
 *
 * Protected by an 8-hour HMAC-SHA256 `HttpOnly; Secure; SameSite=Lax` cookie + per-session CSRF token + SQLite
 * brute-force rate limiting. Gives operators a single real-time browser dashboard for:
 *  1. KPI Telemetry Strip (connected remote nodes, total remote jobs OK/Err, avg TTFB / H2 reuse, MCP calls & sessions).
 *  2. Live System Activity & Crawl Telemetry Stream (300-event SQLite ring buffer, filterable by Crawl / MCP / Agent /
 *     OAuth / Warn+Err, expandable JSON payloads, auto-refreshing every 5s).
 *  3. Connected Remote Fleet cards (`site-arm64`, `site-x86`, `site-win-vm`, CPU arch, uptime, job counters).
 *  4. Interactive URL Crawl & Tuning Runner with visual DNS / TCP / TLS / TTFB waterfall bar.
 *  5. Remote Site 429 Cooldowns + Active MCP Client Connections (both OAuth 2.1 grants and Bearer clients).
 */
import type { HubEventRecord, McpClientActivity } from './activity-log';
import type { AffinityPin, AgentAttachment, FetchTarget } from './agent-hub';
import { MIN_TOKEN_LENGTH, SITE_ID_PATTERN, sameBytes } from './auth';
import { getActiveRequestTracer, sanitizeUrlForSpan, type ActiveSpanHandle } from './otel';
import { normalizeClientRateLimitIp, readBodyTextCapped } from './safe-input';
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
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

const ADMIN_JSON_HEADERS: Record<string, string> = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

function adminJson(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: ADMIN_JSON_HEADERS });
}

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
    distinctPublicIps?: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
    mcpClients?: McpClientActivity[];
    events?: HubEventRecord[];
  }>;
  clearAffinities: (siteId?: string) => Promise<void>;
  clearEvents?: () => Promise<void>;
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
    <p>Sign in with your hub caller token (<code>CALLER_TOKEN</code>) to view live crawl &amp; MCP logs, inspect remote sites, and manage OAuth grants.</p>
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
    .wrap { max-width: 1240px; margin: 0 auto; padding: 20px; display: grid; gap: 18px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
    .kpi { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 16px; }
    .kpi .k-label { font-size: 0.76rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
    .kpi .k-val { font-size: 1.35rem; font-weight: 700; color: #f8fafc; margin-top: 4px; }
    .kpi .k-sub { font-size: 0.78rem; color: #64748b; margin-top: 2px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 18px 20px; }
    .card h2 { margin: 0 0 12px; font-size: 0.98rem; color: #f8fafc; display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
    .muted { color: #94a3b8; font-size: 0.84rem; }
    .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
    .site-card { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 14px; }
    .site-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .site-name { font-weight: 700; font-size: 0.95rem; color: #38bdf8; }
    .arch { font-size: 0.74rem; background: #1e293b; border: 1px solid #475569; padding: 1px 7px; border-radius: 6px; color: #cbd5e1; }
    .ver { font-size: 0.74rem; background: #064e3b; border: 1px solid #059669; padding: 1px 7px; border-radius: 6px; color: #6ee7b7; font-weight: 600; }
    .ver-legacy { background: #78350f; border-color: #d97706; color: #fde68a; }
    .kv { display: flex; justify-content: space-between; font-size: 0.82rem; color: #94a3b8; margin-top: 4px; }
    .kv strong { color: #e2e8f0; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }
    .cmd-bar { display: flex; gap: 8px; align-items: center; background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; overflow-x: auto; }
    .cmd-bar code { color: #38bdf8; white-space: nowrap; flex: 1; }
    button { font: inherit; font-size: 0.82rem; font-weight: 600; padding: 6px 12px; border-radius: 7px; border: 1px solid #475569; background: #334155; color: #f8fafc; cursor: pointer; }
    button:hover { background: #475569; }
    button.primary { background: #2563eb; border-color: #3b82f6; color: #fff; }
    button.primary:hover { background: #1d4ed8; }
    button.danger { background: #7f1d1d; border-color: #b91c1c; color: #fecaca; padding: 4px 10px; font-size: 0.76rem; }
    a.btn-link { display: inline-flex; align-items: center; gap: 6px; text-decoration: none; font-size: 0.78rem; font-weight: 600; padding: 5px 11px; border-radius: 7px; border: 1px solid #0284c7; background: #0369a1; color: #f0f9ff; }
    a.btn-link:hover { background: #0284c7; }
    a.btn-cf { border-color: #ea580c; background: #9a3412; color: #ffedd5; }
    a.btn-cf:hover { background: #c2410c; }
    .tab-bar { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
    .tab { padding: 4px 10px; font-size: 0.78rem; border-radius: 999px; background: #0f172a; border: 1px solid #334155; color: #94a3b8; cursor: pointer; }
    .tab.active { background: #1d4ed8; border-color: #3b82f6; color: #fff; }
    .log-box { background: #090d16; border: 1px solid #334155; border-radius: 9px; max-height: 360px; overflow-y: auto; margin-top: 10px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.79rem; }
    .log-row { padding: 7px 12px; border-bottom: 1px solid #1e293b; cursor: pointer; }
    .log-row:hover { background: #111827; }
    .log-line { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
    .log-ts { color: #64748b; white-space: nowrap; }
    .badge { font-size: 0.7rem; padding: 1px 6px; border-radius: 4px; font-weight: 700; text-transform: uppercase; }
    .lvl-info { background: #0c4a6e; color: #7dd3fc; }
    .lvl-warn { background: #78350f; color: #fcd34d; }
    .lvl-error { background: #7f1d1d; color: #fca5a5; }
    .cat { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
    .tier-fat { font-size: 0.68rem; padding: 1px 6px; border-radius: 4px; font-weight: 700; background: #14532d; color: #86efac; border: 1px solid #166534; }
    .tier-lite { font-size: 0.68rem; padding: 1px 6px; border-radius: 4px; font-weight: 700; background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
    .log-detail { display: none; margin: 6px 0 2px; padding: 8px 10px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #93c5fd; white-space: pre-wrap; word-break: break-all; }
    .log-row.open .log-detail { display: block; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-top: 10px; }
    label { display: block; font-size: 0.78rem; font-weight: 600; color: #cbd5e1; margin-bottom: 4px; }
    input[type="text"], input[type="url"], input[type="number"], select { width: 100%; padding: 8px 10px; border-radius: 7px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: .03em; }
    .timing-bar { display: flex; height: 10px; border-radius: 6px; overflow: hidden; background: #0f172a; margin: 10px 0 6px; }
    .seg-dns { background: #a855f7; }
    .seg-tcp { background: #f59e0b; }
    .seg-tls { background: #ec4899; }
    .seg-ttfb { background: #22c55e; }
    pre.out { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; max-height: 320px; overflow: auto; margin: 10px 0 0; color: #cbd5e1; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .chip { background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 4px 9px; color: #93c5fd; }
  </style>
</head>
<body>
  <header>
    <h1>${escapeHtml(params.serviceName)} <span class="pill" id="conn-pill">Loading...</span></h1>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span class="chip" title="Cloudflare Content Signals in robots.txt">Content Signals: honored (ai-input)</span>
      <span class="muted" id="last-poll">Live (15s)</span>
      <button type="button" id="refresh-btn">Refresh</button>
      <form method="post" action="/admin/logout" style="margin:0">
        <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}">
        <button type="submit">Sign Out</button>
      </form>
    </div>
  </header>

  <div class="wrap">
    <div class="kpi-grid">
      <div class="kpi">
        <div class="k-label">Remote Fleet Online</div>
        <div class="k-val" id="kpi-sites">0</div>
        <div class="k-sub" id="kpi-sites-sub">LRU load-balanced primary</div>
      </div>
      <div class="kpi">
        <div class="k-label">Remote Jobs (OK / Err)</div>
        <div class="k-val" id="kpi-jobs">0 / 0</div>
        <div class="k-sub" id="kpi-cooldowns">0 active 429 cooldowns</div>
      </div>
      <div class="kpi">
        <div class="k-label">Recent Crawl Latency</div>
        <div class="k-val" id="kpi-ttfb">—</div>
        <div class="k-sub" id="kpi-reuse">Click any log row for phase timing</div>
      </div>
      <div class="kpi">
        <div class="k-label">MCP Clients &amp; Calls</div>
        <div class="k-val" id="kpi-mcp">0 clients</div>
        <div class="k-sub" id="kpi-grants">0 OAuth 2.1 grants</div>
      </div>
    </div>

    <section class="card">
      <h2>
        <span>Live System Activity &amp; Crawl Log (<span id="event-count">0</span>)</span>
        <div class="tab-bar">
          <button type="button" class="tab active" data-cat="all">All</button>
          <button type="button" class="tab" data-cat="crawl">Crawls</button>
          <button type="button" class="tab" data-cat="mcp">MCP</button>
          <button type="button" class="tab" data-cat="agent">Agents</button>
          <button type="button" class="tab" data-cat="oauth">OAuth</button>
          <button type="button" class="tab" data-cat="warn">Warn / Err</button>
          <input id="log-search" type="text" placeholder="Filter URL, site, client..." style="width:185px;padding:4px 9px;font-size:0.78rem">
          <button type="button" id="clear-events-btn" style="padding:4px 10px;font-size:0.76rem">Clear Log</button>
        </div>
      </h2>
      <div class="log-box" id="log-box"><div class="log-row muted">Waiting for crawl, MCP, or agent events...</div></div>
    </section>

    <section class="card">
      <h2>
        <span>Connected Remote Fleet (<span id="site-count">0</span>)</span>
        <span style="display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span class="muted" id="fleet-ip-summary">Public-IP load balanced</span>
          <button type="button" id="toggle-ip-btn" style="padding:4px 10px;font-size:0.76rem">Show Full IPs</button>
          <button type="button" class="primary" id="toggle-wizard-btn" style="padding:4px 11px;font-size:0.78rem">+ Connect Edge Node</button>
          <a class="btn-link" href="https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbartrumb%2Fedgefetch" target="_blank" rel="noopener noreferrer" title="1-click add EdgeFetch repository to your Home Assistant OS instance">+ Add HAOS Add-on</a>
          <a class="btn-link btn-cf" href="https://deploy.workers.cloudflare.com/?url=https://github.com/bartrumb/edgefetch/tree/main/hub" target="_blank" rel="noopener noreferrer" title="1-click deploy an EdgeFetch Hub on Cloudflare Workers">Deploy Hub on Cloudflare</a>
        </span>
      </h2>
      <div id="node-wizard" style="display:none;margin-bottom:14px;padding:14px;background:#0f172a;border:1px solid #3b82f6;border-radius:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <div>
            <strong style="color:#f8fafc">Connect Any Machine (Zero Inbound Ports)</strong>
            <div class="muted">Multi-arch <code>amd64</code> + <code>arm64</code> images work on Linux, macOS, Windows, NAS, Raspberry Pi, or VPS.</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <label for="wiz-site" style="margin:0">Site ID:</label>
            <input id="wiz-site" type="text" value="node-1" style="width:140px;padding:5px 8px;font-size:0.8rem">
            <div class="tab-bar" id="wiz-tabs">
              <button type="button" class="tab active" data-wiz="docker">Docker (Fat)</button>
              <button type="button" class="tab" data-wiz="lite">Docker (Lite 9MB)</button>
              <button type="button" class="tab" data-wiz="compose">Compose</button>
              <button type="button" class="tab" data-wiz="go">Go CLI</button>
            </div>
            <button type="button" class="primary" id="copy-wiz-btn" style="padding:5px 11px;font-size:0.78rem">Copy Command</button>
          </div>
        </div>
        <pre class="out" id="wiz-code" style="margin:0;color:#7dd3fc"></pre>
      </div>
      <div id="fleet-grid" class="grid-3"><div class="muted">Loading connected agents...</div></div>
    </section>

    <section class="card">
      <h2><span>Interactive Crawl &amp; Tuning Tester</span></h2>
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
              <option value="scrape" selected>scrape (Markdown + llms.txt)</option>
              <option value="render">render (Headless Chromium)</option>
              <option value="pdf">pdf (Poppler / Pure-Go)</option>
              <option value="page">page (Raw HTML)</option>
              <option value="feed">feed (JSON Products)</option>
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

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:18px">
      <section class="card">
        <h2>
          <span>Remote Site 429 Cooldowns</span>
          <button type="button" id="clear-affinity-btn" style="padding:4px 10px;font-size:0.76rem">Clear Cooldowns</button>
        </h2>
        <table>
          <thead><tr><th>Origin Host</th><th>Cooled-Down Site</th><th>Cooldown Left</th></tr></thead>
          <tbody id="affinity-tbody"><tr><td colspan="3" class="muted">No active 429 site cooldowns</td></tr></tbody>
        </table>
      </section>

      <section class="card">
        <h2>
          <span>MCP Clients &amp; OAuth 2.1 Grants</span>
          <span style="display:inline-flex;gap:6px;flex-wrap:wrap">
            <a class="btn-link" id="cursor-mcp-btn" href="#">+ Cursor MCP</a>
            <a class="btn-link" id="vscode-mcp-btn" href="#">+ VS Code MCP</a>
          </span>
        </h2>
        <div style="margin-bottom:10px">
          <div class="cmd-bar">
            <code id="mcp-cmd">${escapeHtml(mcpCmd)}</code>
            <button type="button" id="copy-mcp-btn">Copy</button>
          </div>
        </div>
        <table>
          <thead><tr><th>Active MCP Client</th><th>Auth</th><th>Calls</th><th>Last Method</th><th>Seen</th></tr></thead>
          <tbody id="mcp-clients-tbody"><tr><td colspan="5" class="muted">No MCP calls recorded yet</td></tr></tbody>
        </table>
        <h2 style="margin-top:14px;font-size:0.86rem;color:#cbd5e1"><span>Issued OAuth 2.1 Grants</span></h2>
        <table>
          <thead><tr><th>Client</th><th>Scopes</th><th>Expires</th><th></th></tr></thead>
          <tbody id="grants-tbody"><tr><td colspan="4" class="muted">No OAuth 2.1 grants issued yet</td></tr></tbody>
        </table>
      </section>
    </div>

    <section class="card">
      <h2><span>Cloudflare Workers Observability — Single Pane of Glass Filters</span></h2>
      <p class="muted" style="margin:0">Open <strong>Cloudflare Dashboard -&gt; Workers &amp; Pages -&gt; Observability (Traces &amp; Logs)</strong> for long-term retention &amp; OTel waterfall traces:</p>
      <div class="chips">
        <code class="chip">crawler.via</code>
        <code class="chip">net.ttfb_ms &gt; 500</code>
        <code class="chip">net.conn_reused = true</code>
        <code class="chip">event = "agent_ready"</code>
        <code class="chip">event = "agent_failover"</code>
        <code class="chip">crawler.outcome = "ok"</code>
      </div>
    </section>
  </div>

  <script>
    const CSRF = ${JSON.stringify(params.csrf)};
    const HUB_ORIGIN = ${JSON.stringify(params.origin)};
    const el = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
    let latestEvents = [];
    let lastStateData = null;
    let showFullIps = false;
    let activeCat = 'all';
    const openEventIds = new Set();

    const relTime = (ts) => {
      if (!ts) return 'never';
      const sec = Math.round((Date.now() - ts) / 1000);
      if (sec < 0) {
        const rem = Math.abs(sec);
        return rem < 60 ? rem + 's' : rem < 3600 ? Math.round(rem / 60) + 'm' : Math.round(rem / 3600) + 'd';
      }
      return sec < 60 ? sec + 's ago' : sec < 3600 ? Math.round(sec / 60) + 'm ago' : Math.round(sec / 3600) + 'h ago';
    };

    const fmtClock = (ts) => {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
    };

    function renderLogs() {
      const q = (el('log-search').value || '').trim().toLowerCase();
      const filtered = latestEvents.filter((ev) => {
        if (activeCat === 'warn' && ev.level === 'info') return false;
        if (activeCat !== 'all' && activeCat !== 'warn' && ev.category !== activeCat) return false;
        if (q) {
          const hay = (ev.summary + ' ' + ev.event + ' ' + JSON.stringify(ev.details || {})).toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      el('event-count').textContent = filtered.length;
      const box = el('log-box');
      if (!filtered.length) {
        box.innerHTML = '<div class="log-row muted">No matching events in buffer. Trigger a fetch or MCP tool call to watch live telemetry.</div>';
        return;
      }
      box.innerHTML = filtered.map((ev) => {
        const isOpen = openEventIds.has(ev.id) ? ' open' : '';
        return '<div class="log-row' + isOpen + '" data-ev-id="' + Number(ev.id) + '">' +
          '<div class="log-line">' +
            '<span class="log-ts">' + esc(fmtClock(ev.ts)) + '</span>' +
            '<span class="badge lvl-' + esc(ev.level) + '">' + esc(ev.level) + '</span>' +
            '<span class="badge cat">' + esc(ev.category) + '</span>' +
            '<span>' + esc(ev.summary) + '</span>' +
          '</div>' +
          '<div class="log-detail">' + esc(JSON.stringify(ev.details || {}, null, 2)) + '</div>' +
        '</div>';
      }).join('');
    }

    function renderState(data) {
      lastStateData = data;
      const agents = data.agents || [];
      const affinities = data.affinities || [];
      const grants = data.grants || [];
      const mcpClients = data.mcpClients || [];
      latestEvents = data.events || [];

      el('last-poll').textContent = 'Updated ' + new Date().toLocaleTimeString([], { hour12: false });
      el('site-count').textContent = data.connected;
      el('conn-pill').textContent = data.connected + ' site' + (data.connected === 1 ? '' : 's') + ' online';

      const totalOk = agents.reduce((s, a) => s + Number(a.jobsOk || 0), 0);
      const totalErr = agents.reduce((s, a) => s + Number(a.jobsErr || 0), 0);
      const ipCounts = {};
      agents.forEach((a) => {
        if (a.publicIp) ipCounts[a.publicIp] = (ipCounts[a.publicIp] || 0) + 1;
      });
      const distinctIps = data.distinctPublicIps ?? (Object.keys(ipCounts).length || agents.length);
      el('kpi-sites').textContent = data.connected + ' online';
      el('kpi-sites-sub').textContent = agents.length
        ? distinctIps + ' egress IP' + (distinctIps === 1 ? '' : 's') + ' · ' + agents.map((a) => a.siteId + (a.version ? ' v' + a.version : '')).join(', ')
        : 'Waiting for HAOS check-in';
      el('fleet-ip-summary').textContent = agents.length
        ? distinctIps + ' distinct public IP' + (distinctIps === 1 ? '' : 's') + ' · 15s poll'
        : 'Hibernation-friendly 15s poll';
      el('kpi-jobs').textContent = totalOk + ' / ' + totalErr;
      el('kpi-cooldowns').textContent = affinities.length + ' active 429 cooldown' + (affinities.length === 1 ? '' : 's');

      const crawlEvs = latestEvents.filter((e) => e.category === 'crawl' && e.details && typeof e.details.ttfbMs === 'number' && e.details.ttfbMs > 0);
      if (crawlEvs.length) {
        const avgTtfb = Math.round(crawlEvs.reduce((s, e) => s + Number(e.details.ttfbMs || 0), 0) / crawlEvs.length);
        const reusedCount = crawlEvs.filter((e) => e.details.reused).length;
        el('kpi-ttfb').textContent = avgTtfb + ' ms avg TTFB';
        el('kpi-reuse').textContent = reusedCount + '/' + crawlEvs.length + ' recent fetches reused HTTP/2';
      }

      const totalMcpCalls = mcpClients.reduce((s, c) => s + Number(c.calls || 0), 0);
      el('kpi-mcp').textContent = mcpClients.length + ' client' + (mcpClients.length === 1 ? '' : 's') + ' (' + totalMcpCalls + ' calls)';
      el('kpi-grants').textContent = grants.length + ' active OAuth 2.1 grant' + (grants.length === 1 ? '' : 's');

      const grid = el('fleet-grid');
      const siteSelect = el('f-site');
      const prevSelected = siteSelect.value;
      siteSelect.innerHTML = '<option value="">Auto (Public-IP split + 30m host-sticky)</option>' +
        agents.map((a) => '<option value="' + esc(a.siteId) + '">' + esc(a.siteId) + ' (' + esc(a.version ? 'v' + a.version + ', ' : '') + esc(a.arch) + ')</option>').join('');
      siteSelect.value = prevSelected;

      const fmtIp = (ip) => {
        if (!ip) return 'pending reconnect';
        if (showFullIps) return ip;
        if (ip.includes('.')) {
          const p = ip.split('.');
          return p.length === 4 ? p[0] + '.' + p[1] + '.xxx.' + p[3] : ip;
        }
        const h = ip.split(':');
        return h.slice(0, 2).join(':') + ':xxxx::';
      };

      grid.innerHTML = agents.length
        ? agents.map((a) => {
            const verBadge = a.version
              ? '<span class="ver">v' + esc(a.version) + '</span>'
              : '<span class="ver ver-legacy" title="Update add-on to report release version">pre-1.0.5</span>';
            const caps = Array.isArray(a.capabilities) ? a.capabilities : [];
            const isFat = caps.includes('browser-v1');
            const tierBadge = isFat
              ? '<span class="tier-fat" title="Headless Chromium + Poppler PDF">FAT</span>'
              : '<span class="tier-lite" title="Distroless HTTP/2 Lite">LITE</span>';
            const verDetail = (a.version ? 'v' + a.version : 'legacy') + (a.goVersion ? ' · ' + a.goVersion : '');
            const capsDetail = caps.length ? caps.join(', ') : 'http2-lite';
            const sharedCount = a.publicIp ? (ipCounts[a.publicIp] || 1) : 1;
            const ipNote = sharedCount > 1 ? ' (shared x' + sharedCount + ')' : '';
            return '<div class="site-card">' +
              '<div class="site-top"><span class="site-name">' + esc(a.siteId) + '</span><span style="display:inline-flex;gap:5px;align-items:center">' + tierBadge + verBadge + '<span class="arch">' + esc(a.arch) + '</span></span></div>' +
              '<div class="kv"><span>Version</span><strong>' + esc(verDetail) + '</strong></div>' +
              '<div class="kv"><span>Capabilities</span><strong><code>' + esc(capsDetail) + '</code></strong></div>' +
              '<div class="kv"><span>Public IP</span><strong><code>' + esc(fmtIp(a.publicIp)) + '</code>' + esc(ipNote) + '</strong></div>' +
              '<div class="kv"><span>Connected</span><strong>' + esc(relTime(a.connectedAt)) + '</strong></div>' +
              '<div class="kv"><span>Last Job</span><strong>' + esc(relTime(a.lastJobAt)) + '</strong></div>' +
              '<div class="kv"><span>Jobs OK / Err</span><strong>' + Number(a.jobsOk) + ' / ' + Number(a.jobsErr) + '</strong></div>' +
            '</div>';
          }).join('')
        : '<div class="muted">No remote agents currently connected over WebSocket.</div>';

      el('affinity-tbody').innerHTML = affinities.length
        ? affinities.map((p) => '<tr><td><code>' + esc(p.host) + '</code></td><td>' + esc(p.siteId) + '</td><td>' + esc(relTime(p.expiresAt)) + '</td></tr>').join('')
        : '<tr><td colspan="3" class="muted">No active 429 site cooldowns</td></tr>';

      el('mcp-clients-tbody').innerHTML = mcpClients.length
        ? mcpClients.map((c) =>
            '<tr><td><strong>' + esc(c.principal) + '</strong></td>' +
            '<td><span class="badge ' + (c.authType === 'oauth' ? 'lvl-info' : 'cat') + '">' + esc(c.authType === 'oauth' ? 'OAuth 2.1' : 'Owner Token') + '</span></td>' +
            '<td>' + Number(c.calls) + '</td>' +
            '<td><code>' + esc(c.lastMethod) + '</code></td>' +
            '<td>' + esc(relTime(c.lastSeenAt)) + '</td></tr>'
          ).join('')
        : '<tr><td colspan="5" class="muted">No MCP calls recorded yet</td></tr>';

      el('grants-tbody').innerHTML = grants.length
        ? grants.map((g) =>
            '<tr><td><strong>' + esc(g.clientName) + '</strong></td><td><code>' + esc(g.scopes.join(' ')) + '</code></td><td>' + esc(relTime(g.expiresAt)) + '</td>' +
            '<td><button type="button" class="danger" data-revoke="' + esc(g.grantId) + '">Revoke</button></td></tr>'
          ).join('')
        : '<tr><td colspan="4" class="muted">No OAuth 2.1 grants issued yet</td></tr>';

      renderLogs();
    }

    async function loadState() {
      const res = await fetch('/admin/api/state', { headers: { 'accept': 'application/json' } });
      if (res.status === 401) { location.reload(); return; }
      renderState(await res.json());
    }

    el('toggle-ip-btn').addEventListener('click', () => {
      showFullIps = !showFullIps;
      el('toggle-ip-btn').textContent = showFullIps ? 'Mask IPs' : 'Show Full IPs';
      if (lastStateData) renderState(lastStateData);
    });

    document.querySelectorAll('.tab[data-cat]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab[data-cat]').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        activeCat = btn.getAttribute('data-cat');
        renderLogs();
      });
    });

    el('log-search').addEventListener('input', renderLogs);

    el('log-box').addEventListener('click', (ev) => {
      const row = ev.target.closest('.log-row[data-ev-id]');
      if (!row) return;
      const id = Number(row.getAttribute('data-ev-id'));
      if (openEventIds.has(id)) openEventIds.delete(id);
      else openEventIds.add(id);
      row.classList.toggle('open');
    });

    el('clear-events-btn').addEventListener('click', async () => {
      await fetch('/admin/api/events/clear', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF }, body: '{}' });
      openEventIds.clear();
      await loadState();
    });

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
            respectRobots: el('f-robots').checked,
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

    let activeWiz = 'docker';
    function renderWizardSnippet() {
      const site = (el('wiz-site').value || 'node-1').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'node-1';
      const snippets = {
        docker: [
          'docker run -d --name edgefetch-agent --restart=unless-stopped \\\\',
          '  --security-opt no-new-privileges:true \\\\',
          '  -e EDGEFETCH_HUB_URL=' + HUB_ORIGIN + ' \\\\',
          '  -e EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \\\\',
          '  -e EDGEFETCH_SITE_ID="' + site + '" \\\\',
          '  ghcr.io/bartrumb/edgefetch-agent:latest',
        ].join('\\n'),
        lite: [
          'docker run -d --name edgefetch-lite --restart=unless-stopped --read-only \\\\',
          '  -e EDGEFETCH_HUB_URL=' + HUB_ORIGIN + ' \\\\',
          '  -e EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \\\\',
          '  -e EDGEFETCH_SITE_ID="' + site + '" \\\\',
          '  ghcr.io/bartrumb/edgefetch-agent:lite --mode=agent',
        ].join('\\n'),
        compose: [
          '# Save .env with EDGEFETCH_HUB_URL, EDGEFETCH_AGENT_TOKEN, EDGEFETCH_SITE_ID=' + site,
          'curl -fsSLO https://raw.githubusercontent.com/bartrumb/edgefetch/main/compose.agent.yaml',
          'EDGEFETCH_HUB_URL=' + HUB_ORIGIN + ' EDGEFETCH_SITE_ID=' + site + ' EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \\\\',
          '  docker compose -f compose.agent.yaml up -d',
        ].join('\\n'),
        go: [
          'go install github.com/bartrumb/edgefetch/v2/cmd/edgefetch@latest',
          'EDGEFETCH_HUB_URL=' + HUB_ORIGIN + ' EDGEFETCH_SITE_ID=' + site + ' EDGEFETCH_AGENT_TOKEN="<YOUR_AGENT_TOKEN>" \\\\',
          '  edgefetch --mode=agent',
        ].join('\\n'),
      };
      el('wiz-code').textContent = snippets[activeWiz] || snippets.docker;
    }
    el('toggle-wizard-btn').addEventListener('click', () => {
      const box = el('node-wizard');
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
      renderWizardSnippet();
    });
    el('wiz-site').addEventListener('input', renderWizardSnippet);
    el('wiz-tabs').addEventListener('click', (ev) => {
      const tab = ev.target.closest('[data-wiz]');
      if (!tab) return;
      activeWiz = tab.getAttribute('data-wiz');
      for (const b of el('wiz-tabs').querySelectorAll('.tab')) b.classList.toggle('active', b === tab);
      renderWizardSnippet();
    });
    el('copy-wiz-btn').addEventListener('click', async () => {
      await navigator.clipboard.writeText(el('wiz-code').textContent || '');
      const b = el('copy-wiz-btn');
      b.textContent = 'Copied!';
      setTimeout(() => { b.textContent = 'Copy Command'; }, 1500);
    });
    const mcpEndpoint = HUB_ORIGIN + '/mcp';
    el('cursor-mcp-btn').href = 'cursor://anysphere.cursor-deeplink/mcp/install?name=${encodeURIComponent(params.mcpSlug)}&config=' + encodeURIComponent(btoa(JSON.stringify({ url: mcpEndpoint })));
    el('vscode-mcp-btn').href = 'vscode:mcp/install?' + encodeURIComponent(JSON.stringify({ name: ${JSON.stringify(params.mcpSlug)}, type: 'http', url: mcpEndpoint }));

    loadState();
    setInterval(() => {
      if (!document.hidden) loadState();
    }, 15000);
  </script>
</body>
</html>`;
}

type AdminAuditSpan = Pick<ActiveSpanHandle, 'setAttribute' | 'setAttributes' | 'setStatus'>;
const NOOP_ADMIN_AUDIT_SPAN: AdminAuditSpan = {
  setAttribute() {},
  setAttributes() {},
  setStatus() {},
};

async function withAdminAuditSpan<T>(
  op: 'login' | 'logout' | 'events_clear' | 'affinity_clear' | 'grant_revoke' | 'fetch',
  fn: (span: AdminAuditSpan) => Promise<T>,
): Promise<T> {
  const tracer = getActiveRequestTracer();
  if (!tracer) return fn(NOOP_ADMIN_AUDIT_SPAN);
  return tracer.withSpan(`edgefetch.admin.${op}`, { kind: 1, attributes: { 'admin.op': op } }, (span) => fn(span));
}

export async function handleAdminRoute(request: Request, url: URL, deps: AdminPortalDeps): Promise<Response | null> {
  const path = url.pathname;
  if (path !== '/admin' && !path.startsWith('/admin/')) return null;

  const isSecure = url.protocol === 'https:';
  const ownerSecret = deps.ownerSecret;
  if (!ownerSecret || ownerSecret.length < MIN_TOKEN_LENGTH) {
    return adminJson({ error: 'owner_secret_unconfigured' }, 503);
  }

  let session = await verifyAdminSessionCookie(request.headers.get('cookie'), ownerSecret);
  if (session.ok && typeof deps.oauthStore.checkAuthLockout === 'function') {
    const revoked = await deps.oauthStore.checkAuthLockout(`revoked_admin:${session.csrf}`, Date.now(), 1);
    if (!revoked.allowed) {
      session = { ok: false };
    }
  }

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
    return withAdminAuditSpan('login', async (span) => {
      const now = Date.now();
      const clientIp = normalizeClientRateLimitIp(request.headers.get('cf-connecting-ip'));
      const cappedForm = await readBodyTextCapped(request, 8_192);
      if (!cappedForm.ok) {
        span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': 413 });
        span.setStatus(false, 'payload_too_large');
        return new Response(renderLoginHtml(deps.serviceName, 'Login payload too large.'), {
          status: 413,
          headers: ADMIN_HTML_HEADERS,
        });
      }
      const supplied = (new URLSearchParams(cappedForm.text).get('token') ?? '').trim();
      // `R3-M4`: Verify constant-time `CALLER_TOKEN` match FIRST so an attacker spoofing `X-Forwarded-For` or sharing a
      // reverse-proxy / IPv6 `/64` bucket can NEVER lock out the legitimate admin, while invalid tokens get `429` after 5 failures!
      if (!supplied || !sameBytes(supplied, ownerSecret)) {
        const preLock = await deps.oauthStore.checkAuthLockout(`admin:${clientIp}`, now, RATE_LIMIT_MAX_FAILURES);
        if (!preLock.allowed) {
          span.setAttributes({ 'admin.outcome': 'rate_limited', 'http.response.status_code': 429 });
          span.setStatus(false, 'rate_limited');
          return new Response(renderLoginHtml(deps.serviceName, 'Too many failed attempts. Try again in 5 minutes.'), {
            status: 429,
            headers: { ...ADMIN_HTML_HEADERS, 'retry-after': String(preLock.retryAfterSec) },
          });
        }
        const rl = await deps.oauthStore.recordAuthFailure(`admin:${clientIp}`, now, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_FAILURES);
        if (!rl.allowed) {
          span.setAttributes({ 'admin.outcome': 'rate_limited', 'http.response.status_code': 429 });
          span.setStatus(false, 'rate_limited');
          return new Response(renderLoginHtml(deps.serviceName, 'Too many failed attempts. Try again in 5 minutes.'), {
            status: 429,
            headers: { ...ADMIN_HTML_HEADERS, 'retry-after': String(rl.retryAfterSec) },
          });
        }
        span.setAttributes({ 'admin.outcome': 'unauthorized', 'http.response.status_code': 401 });
        span.setStatus(false, 'unauthorized');
        return new Response(renderLoginHtml(deps.serviceName, 'Invalid caller token.'), {
          status: 401,
          headers: ADMIN_HTML_HEADERS,
        });
      }

      await deps.oauthStore.clearAuthFailures(`admin:${clientIp}`);
      const minted = await createAdminSessionValue(ownerSecret);
      const headers = new Headers({ location: '/admin', 'cache-control': 'no-store' });
      headers.append('set-cookie', formatCookie(ADMIN_COOKIE_NAME, minted.value, { maxAge: minted.maxAgeSec, path: '/', sameSite: 'Lax', secure: isSecure }));
      span.setAttributes({ 'admin.outcome': 'authenticated', 'http.response.status_code': 302 });
      return new Response(null, { status: 302, headers });
    });
  }

  if (path === '/admin/logout' && request.method === 'POST') {
    return withAdminAuditSpan('logout', async (span) => {
      const cappedLogout = await readBodyTextCapped(request, 4_096);
      const formCsrf = cappedLogout.ok ? new URLSearchParams(cappedLogout.text).get('csrf') ?? '' : '';
      if (!session.ok || !sameBytes(formCsrf, session.csrf)) {
        span.setAttributes({ 'admin.outcome': 'invalid_csrf', 'http.response.status_code': 403 });
        span.setStatus(false, 'invalid_csrf');
        return adminJson({ error: 'invalid_csrf' }, 403);
      }
      // Server-side revocation of this exact admin session cookie (`Low`): replay of the logged-out cookie fails closed!
      if (typeof deps.oauthStore.recordAuthFailure === 'function') {
        await deps.oauthStore.recordAuthFailure(`revoked_admin:${session.csrf}`, Date.now(), 8 * 60 * 60_000, 1);
      }
      const headers = new Headers({ location: '/admin', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      headers.append('set-cookie', formatCookie(ADMIN_COOKIE_NAME, '', { maxAge: 0, path: '/', sameSite: 'Lax', secure: isSecure }));
      span.setAttributes({ 'admin.outcome': 'logged_out', 'http.response.status_code': 302 });
      return new Response(null, { status: 302, headers });
    });
  }

  const apiOp =
    request.method === 'POST'
      ? path === '/admin/api/events/clear'
        ? ('events_clear' as const)
        : path === '/admin/api/affinity/clear'
          ? ('affinity_clear' as const)
          : path === '/admin/api/grants/revoke'
            ? ('grant_revoke' as const)
            : path === '/admin/api/fetch'
              ? ('fetch' as const)
              : null
      : null;

  if (!session.ok) {
    if (apiOp) {
      return withAdminAuditSpan(apiOp, async (span) => {
        span.setAttributes({ 'admin.outcome': 'unauthorized', 'http.response.status_code': 401 });
        span.setStatus(false, 'unauthorized');
        return adminJson({ error: 'unauthorized' }, 401);
      });
    }
    return adminJson({ error: 'unauthorized' }, 401);
  }

  if (path === '/admin/api/state' && request.method === 'GET') {
    const state = await deps.getState();
    return adminJson(state, 200);
  }

  if (request.method === 'POST') {
    const hdrCsrf = request.headers.get('x-csrf-token') ?? '';
    if (!hdrCsrf || !sameBytes(hdrCsrf, session.csrf)) {
      if (apiOp) {
        return withAdminAuditSpan(apiOp, async (span) => {
          span.setAttributes({ 'admin.outcome': 'invalid_csrf', 'http.response.status_code': 403 });
          span.setStatus(false, 'invalid_csrf');
          return adminJson({ error: 'invalid_csrf' }, 403);
        });
      }
      return adminJson({ error: 'invalid_csrf' }, 403);
    }

    if (path === '/admin/api/events/clear') {
      return withAdminAuditSpan('events_clear', async (span) => {
        await deps.clearEvents?.();
        span.setAttributes({ 'admin.outcome': 'cleared', 'http.response.status_code': 200 });
        return adminJson({ ok: true }, 200);
      });
    }

    if (path === '/admin/api/affinity/clear') {
      return withAdminAuditSpan('affinity_clear', async (span) => {
        const capped = await readBodyTextCapped(request, 65_536);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: { siteId?: string } = {};
        if (capped.text.trim()) {
          try {
            body = JSON.parse(capped.text) as { siteId?: string };
          } catch {
            body = {};
          }
        }
        await deps.clearAffinities(body.siteId);
        span.setAttributes({
          'admin.site_id': typeof body.siteId === 'string' && body.siteId.trim() ? body.siteId.trim() : 'all',
          'admin.outcome': 'cleared',
          'http.response.status_code': 200,
        });
        return adminJson({ ok: true }, 200);
      });
    }

    if (path === '/admin/api/grants/revoke') {
      return withAdminAuditSpan('grant_revoke', async (span) => {
        const capped = await readBodyTextCapped(request, 65_536);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: { grantId?: string } = {};
        if (capped.text.trim()) {
          try {
            body = JSON.parse(capped.text) as { grantId?: string };
          } catch {
            body = {};
          }
        }
        if (!body.grantId || typeof body.grantId !== 'string') {
          span.setAttributes({ 'admin.outcome': 'missing_grant_id', 'http.response.status_code': 400 });
          span.setStatus(false, 'missing_grant_id');
          return adminJson({ error: 'missing_grant_id' }, 400);
        }
        const revoked = await deps.revokeGrant(body.grantId);
        span.setAttributes({
          'admin.grant_id': body.grantId,
          'admin.revoked': revoked,
          'admin.outcome': revoked ? 'revoked' : 'not_found',
          'http.response.status_code': 200,
        });
        return adminJson({ ok: true, revoked }, 200);
      });
    }

    if (path === '/admin/api/fetch') {
      return withAdminAuditSpan('fetch', async (span) => {
        const capped = await readBodyTextCapped(request, 65_536);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: {
          url?: string;
          kind?: string;
          target?: string;
          site?: string;
          pauseMs?: number;
          pauseJitterMs?: number;
          respectRobots?: boolean;
          robots?: boolean;
          includeBody?: boolean;
        } = {};
        if (capped.text.trim()) {
          try {
            body = JSON.parse(capped.text) as typeof body;
          } catch {
            span.setAttributes({ 'admin.outcome': 'invalid_json', 'http.response.status_code': 400 });
            span.setStatus(false, 'invalid_json');
            return adminJson({ error: 'invalid_json' }, 400);
          }
        }
        if (!body.url || typeof body.url !== 'string') {
          span.setAttributes({ 'admin.outcome': 'missing_url', 'http.response.status_code': 400 });
          span.setStatus(false, 'missing_url');
          return adminJson({ error: 'missing_url' }, 400);
        }
        const sanitizedUrl = sanitizeUrlForSpan(body.url.trim());
        span.setAttribute('url.full', sanitizedUrl);
        const target = (typeof body.target === 'string' ? body.target.toLowerCase() : deps.defaultTarget) as FetchTarget;
        if (!deps.allowedTargets.includes(target)) {
          span.setAttributes({ 'admin.outcome': 'invalid_target', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_target');
          return adminJson({ error: 'invalid_target' }, 400);
        }
        const site = typeof body.site === 'string' && body.site.trim() ? body.site.trim().toLowerCase() : undefined;
        if (site && !SITE_ID_PATTERN.test(site)) {
          span.setAttributes({ 'admin.outcome': 'invalid_site', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_site');
          return adminJson({ error: 'invalid_site' }, 400);
        }

        const respectRobots =
          typeof body.respectRobots === 'boolean' ? body.respectRobots : body.robots !== false;

        const allowedAdminKinds = new Set(['feed', 'page', 'scrape', 'render', 'pdf', 'json']);
        const adminKind = typeof body.kind === 'string' && allowedAdminKinds.has(body.kind) ? body.kind : 'scrape';
        span.setAttributes({ 'crawler.target': target, 'crawler.kind': adminKind });
        const callPayload = JSON.stringify({
          maxSeconds: 60,
          options: {
            includeBody: Boolean(body.includeBody),
            respectRobots,
            pauseMs: Math.min(30_000, Math.max(0, Math.floor(Number(body.pauseMs ?? 1500)))),
            pauseJitterMs: Math.min(15_000, Math.max(0, Math.floor(Number(body.pauseJitterMs ?? 750)))),
          },
          requests: [{ id: 'admin-1', url: body.url.trim(), kind: adminKind }],
        });

        const out = await deps.executeFetch({ target, ...(site ? { site } : {}), body: callPayload });
        span.setAttributes({
          'crawler.via': out.via,
          'admin.outcome': 'ok',
          'http.response.status_code': 200,
        });
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
        return adminJson({ status: out.status, via: out.via, reply }, 200);
      });
    }
  }

  return adminJson({ error: 'not_found' }, 404);
}
