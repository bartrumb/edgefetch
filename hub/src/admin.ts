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
import type { DevTelemetrySettingsView } from './dev-telemetry';
import {
  handleGitHubOAuthCallback,
  isGitHubAuthConfigured,
  resolveSessionSecret,
  startGitHubOAuthFlow,
  type GitHubAuthEnv,
} from './github-auth';
import { testAndListRemoteMcpTools } from './mcp-federation';
import { discoverMcps, isSafePublicHttpsUrl, slugifyMcpServerName, validateConnectorDomains } from './mcp-registry';
import {
  buildMaskedAuthSummary,
  completeDownstreamMcpOAuthCallback,
  MCP_OAUTH_BIND_COOKIE,
  MCP_OAUTH_BIND_COOKIE_DEV,
  probeRemoteMcpOAuthMetadata,
  resolveCallerUserId,
  sanitizeSecretHeadersInput,
  sealVaultCredentials,
  startDownstreamMcpOAuth,
  toPublicMcpServerSummary,
  unsealVaultCredentials,
  validateVaultMasterKey,
  type McpVaultStore,
  type PublicMcpServerSummary,
  type StoredMcpServerRow,
  type VaultSecretPayload,
} from './mcp-vault';
import { getActiveRequestTracer, sanitizeUrlForSpan, type ActiveSpanHandle } from './otel';
import { queryHostGapRadar } from './gap-radar';
import { normalizeClientRateLimitIp, readBodyTextCapped } from './safe-input';
import { stripInvisibleSmugglingChars } from './scrape';
import type { UpdateCheckStatus } from './update-check';
import {
  ADMIN_COOKIE_NAME,
  ADMIN_COOKIE_NAME_DEV,
  createAdminSessionValue,
  escapeHtml,
  formatCookie,
  isSameOriginFormPost,
  resolveAdminCookieAttrs,
  sha256Base64Url,
  verifyLiveAdminSession,
  type AdminPrincipal,
  type HubUserRecord,
  type OAuthGrantSummary,
  type OAuthStore,
  type UserRole,
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
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};

function safeJsonForInlineScript(val: unknown): string {
  return JSON.stringify(val)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function adminJson(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: ADMIN_JSON_HEADERS });
}

export interface AdminPortalDeps {
  serviceName: string;
  mcpSlug: string;
  sampleUrl?: string;
  publicOrigin?: string;
  ownerSecret?: string;
  githubAuthEnv?: GitHubAuthEnv;
  metaDb?: D1Database;
  vaultMasterKey?: string;
  vaultStore?: McpVaultStore;
  safePublicFetch?: typeof fetch;
  selfHost?: string;
  oauthStore: OAuthStore;
  allowedTargets: FetchTarget[];
  defaultTarget: FetchTarget;
  onEvent?: (ev: {
    level: 'info' | 'warn' | 'error';
    category: 'oauth';
    event: string;
    summary: string;
    details?: Record<string, unknown>;
  }) => Promise<void> | void;
  getState: () => Promise<{
    connected: number;
    distinctPublicIps?: number;
    agents: AgentAttachment[];
    affinities: AffinityPin[];
    grants: OAuthGrantSummary[];
    users?: HubUserRecord[];
    mcpClients?: McpClientActivity[];
    events?: HubEventRecord[];
  }>;
  clearAffinities: (siteId?: string) => Promise<void>;
  clearEvents?: () => Promise<void>;
  revokeGrant: (grantId: string, userId?: string) => Promise<boolean>;
  getUpdateStatus?: (agents: AgentAttachment[]) => Promise<UpdateCheckStatus>;
  getTelemetrySettings?: () => Promise<DevTelemetrySettingsView>;
  setTelemetryOptIn?: (enabled: boolean) => Promise<DevTelemetrySettingsView>;
  getHubSetting?: (key: string) => Promise<string | null>;
  setHubSetting?: (key: string, value: string) => Promise<void>;
  executeFetch: (params: {
    target: FetchTarget;
    site?: string;
    body: string;
  }) => Promise<{ status: number; via: string; bodyText: string }>;
}

function renderLoginHtml(
  serviceName: string,
  errorMsg?: string,
  opts: { githubEnabled?: boolean; ownerTokenEnabled?: boolean } = {},
): string {
  const err = errorMsg ? `<div class="err">${escapeHtml(errorMsg)}</div>` : '';
  const githubEnabled = Boolean(opts.githubEnabled);
  const ownerTokenEnabled = opts.ownerTokenEnabled !== false;
  const ghBlock = githubEnabled
    ? `<a class="gh-btn" href="/admin/auth/github"><svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>Sign in with GitHub</a>`
    : '';
  const divider = githubEnabled && ownerTokenEnabled ? `<div class="divider"><span>or use owner token</span></div>` : '';
  const tokenForm = ownerTokenEnabled
    ? `<form method="post" action="/admin/login">
      <label for="token">Caller Token</label>
      <input id="token" name="token" type="password" required${githubEnabled ? '' : ' autofocus'} autocomplete="current-password" placeholder="Paste bearer token...">
      <button type="submit">Open Control Center</button>
    </form>`
    : '';

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
    .gh-btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; box-sizing: border-box; padding: 10px 16px; border-radius: 8px; border: 1px solid #475569; background: #24292f; color: #fff; text-decoration: none; font-weight: 600; margin-bottom: 14px; }
    .gh-btn:hover { background: #32383f; }
    .divider { display: flex; align-items: center; gap: 10px; color: #94a3b8; font-size: 0.8rem; margin: 4px 0 14px; }
    .divider::before, .divider::after { content: ""; flex: 1; border-top: 1px solid #334155; }
    .err { background: #450a0a; border: 1px solid #dc2626; color: #fecaca; padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; font-size: 0.88rem; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(serviceName)}</h1>
    <p>${
      githubEnabled
        ? 'Sign in with GitHub or your hub caller token (<code>CALLER_TOKEN</code>) to manage MCP OAuth grants and view hub telemetry.'
        : 'Sign in with your hub caller token (<code>CALLER_TOKEN</code>) to view live crawl &amp; MCP logs, inspect remote sites, and manage OAuth grants.'
    }</p>
    ${err}
    ${ghBlock}
    ${divider}
    ${tokenForm}
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
  principal?: Pick<AdminPrincipal, 'userId' | 'role' | 'githubLogin'>;
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
    header h1 { font-size: 1.1rem; margin: 0; display: flex; align-items: center; gap: 10px; color: #f8fafc; flex-wrap: wrap; }
    .pill { font-size: 0.75rem; padding: 2px 8px; border-radius: 999px; background: #064e3b; color: #6ee7b7; border: 1px solid #059669; font-weight: 600; text-decoration: none; }
    .pill-warn { background: #78350f; color: #fde68a; border-color: #d97706; }
    .pill-muted { background: #1e293b; color: #94a3b8; border-color: #475569; }
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
    input[type="text"], input[type="url"], input[type="number"], input[type="password"], select { width: 100%; padding: 8px 10px; border-radius: 7px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font: inherit; }
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
    <h1>${escapeHtml(params.serviceName)} <span class="pill" id="conn-pill">Loading...</span> <a class="pill" id="update-pill" href="https://github.com/bartrumb/edgefetch/releases" target="_blank" rel="noopener noreferrer" style="display:none"></a></h1>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span class="chip" id="viewer-pill">${escapeHtml(params.principal?.githubLogin ? `@${params.principal.githubLogin} (${params.principal.role})` : `${params.principal?.userId ?? 'owner'} (${params.principal?.role ?? 'owner'})`)}</span>
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

    <section class="card" id="gap-radar-card" style="display:none">
      <h2>
        <span>Adapter Gap Radar (7d Browser Fallbacks &amp; Non-OK Hosts)</span>
        <span class="muted">Ranked by headless Chromium time via <code>GET /v1/hosts/gaps</code></span>
      </h2>
      <table>
        <thead><tr><th>Origin Host</th><th>Fetches (Browser %)</th><th>Browser Time</th><th>Adapter</th><th>Scaffold Command</th></tr></thead>
        <tbody id="gap-radar-tbody"><tr><td colspan="5" class="muted">No unadapted browser-heavy hosts recorded in the last 7 days.</td></tr></tbody>
      </table>
    </section>

    <section class="card" id="users-card" style="display:none">
      <h2>
        <span>Hub Users &amp; Stored OAuth Tokens (<span id="users-count">0</span> users &middot; <span id="users-total-tokens">0</span> stored token rows)</span>
      </h2>
      <table>
        <thead><tr><th>User</th><th>Role</th><th>Stored Token Rows (Active / Used)</th><th>Active Grants</th><th>Last Login</th></tr></thead>
        <tbody id="users-tbody"><tr><td colspan="5" class="muted">No users registered yet</td></tr></tbody>
      </table>
    </section>

    <section class="card" id="mcp-connectors">
      <h2>
        <span>MCP Registry &amp; Encrypted Connectors (<span id="mcp-conn-count">0</span> connected)</span>
        <span style="display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span class="pill" id="vault-status-pill" title="AES-256-GCM HKDF Vault Status">AES-256-GCM Vault</span>
          <button type="button" class="primary" id="custom-mcp-btn" style="padding:4px 11px;font-size:0.78rem">+ Connect Custom HTTPS MCP</button>
        </span>
      </h2>
      <p class="muted" style="margin:0 0 12px">Connect downstream Streamable HTTP / SSE MCP servers once in your per-user <code>AES-256-GCM</code> vault. EdgeFetch routes matching domains and <code>query_mcp</code> calls agent-to-agent with zero prompt schema bloat.</p>

      <div style="margin-bottom:14px">
        <table>
          <thead><tr><th>Connector</th><th>Auth Vault</th><th>Domains</th><th>Tools</th><th>Verified</th><th>Actions</th></tr></thead>
          <tbody id="mcp-conn-tbody"><tr><td colspan="6" class="muted">No downstream MCP connectors configured yet. Search the Registry below to add auth.</td></tr></tbody>
        </table>
      </div>

      <div id="mcp-connect-panel" style="display:none;margin-bottom:16px;padding:16px;background:#0f172a;border:1px solid #3b82f6;border-radius:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px">
          <strong id="mcp-form-title" style="color:#f8fafc">Connect Remote MCP Server</strong>
          <button type="button" id="mcp-form-close-btn" style="padding:3px 9px;font-size:0.76rem">Close</button>
        </div>
        <div id="mcp-oauth-banner" style="display:none;margin-bottom:12px;padding:10px 12px;background:#064e3b;border:1px solid #059669;border-radius:8px;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
          <span style="font-size:0.83rem;color:#ecfdf5">OAuth 2.1 PKCE metadata detected on this remote MCP endpoint!</span>
          <button type="button" class="primary" id="mcp-oauth-start-btn">1-Click Connect with OAuth 2.1 (PKCE)</button>
        </div>
        <form id="mcp-connect-form">
          <div class="form-grid">
            <div>
              <label for="mc-name">Display Name</label>
              <input id="mc-name" type="text" required placeholder="Linear MCP">
            </div>
            <div>
              <label for="mc-slug">Connector Slug</label>
              <input id="mc-slug" type="text" required placeholder="linear">
            </div>
            <div>
              <label for="mc-transport">Transport</label>
              <select id="mc-transport">
                <option value="streamable-http" selected>streamable-http (JSON-RPC / SSE)</option>
                <option value="sse">sse</option>
              </select>
            </div>
          </div>
          <div style="margin-top:10px">
            <label for="mc-url">Remote HTTPS MCP Endpoint URL (port 443)</label>
            <input id="mc-url" type="url" required placeholder="https://mcp.linear.app/mcp">
          </div>
          <div style="margin-top:10px">
            <label for="mc-domains">Associated Domains (comma-separated, routed MCP-first in /v1/agent)</label>
            <input id="mc-domains" type="text" placeholder="linear.app">
          </div>
          <div id="mc-manifest-headers" style="margin-top:10px"></div>
          <div class="form-grid" style="margin-top:10px">
            <div>
              <label for="mc-bearer">Bearer Token (write-only, optional)</label>
              <input id="mc-bearer" type="password" autocomplete="new-password" placeholder="Paste API / OAuth token...">
            </div>
            <div>
              <label for="mc-hdr-name">Custom Header Name (optional)</label>
              <input id="mc-hdr-name" type="text" placeholder="X-Api-Key">
            </div>
            <div>
              <label for="mc-hdr-val">Custom Header Secret (write-only)</label>
              <input id="mc-hdr-val" type="password" autocomplete="new-password" placeholder="Paste header secret...">
            </div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:14px">
            <button type="button" id="mc-test-btn">Test Connection (tools/list)</button>
            <button type="submit" class="primary" id="mc-save-btn">Save to Encrypted Vault</button>
            <span id="mc-status" class="muted"></span>
          </div>
        </form>
        <pre class="out" id="mc-test-out" style="display:none"></pre>
      </div>

      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
        <input id="mcp-reg-q" type="text" placeholder="Search Official MCP Registry + Glama (e.g. linear, notion, github, sentry, stripe)..." style="flex:1;min-width:240px">
        <label style="display:inline-flex;align-items:center;gap:6px;margin:0;font-size:0.82rem"><input id="mcp-reg-remote" type="checkbox" checked> Remote HTTP/SSE only</label>
        <button type="button" class="primary" id="mcp-reg-search-btn">Search Registry</button>
      </div>
      <div id="mcp-reg-grid" class="grid-3"><div class="muted">Click "Search Registry" to browse live remote MCP connectors from registry.modelcontextprotocol.io and glama.ai.</div></div>
    </section>

    <section class="card">
      <h2>
        <span>Auto-Updates &amp; Opt-In Dev Error Telemetry</span>
        <span style="display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span class="badge cat" id="telemetry-status-badge">OFF by default</span>
          <button type="button" id="telemetry-toggle-btn" style="padding:5px 12px;font-size:0.78rem">Enable Opt-In Error Telemetry</button>
        </span>
      </h2>
      <p class="muted" style="margin:0 0 8px" id="telemetry-desc">Unattended default is <strong>0 outbound telemetry</strong> (<code>DO_NOT_TRACK=1</code> acts as a hard disable override). When opted in, shares <strong>only</strong> structural adapter &amp; WAF error codes to help fix broken site extractors — <strong>zero URLs, zero hostnames, zero paths, zero content, zero tokens</strong>.</p>
      <div class="chips" style="margin-top:6px">
        <code class="chip">schemaVersion: 1</code>
        <code class="chip">version</code>
        <code class="chip">runtime</code>
        <code class="chip">os / arch</code>
        <code class="chip">spanName</code>
        <code class="chip">adapterId</code>
        <code class="chip">wafVendor</code>
        <code class="chip">httpStatus</code>
        <code class="chip">errorClass</code>
      </div>
      <div class="muted" id="update-fleet-hint" style="margin-top:8px;display:none"></div>
    </section>

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
    const CSRF = ${safeJsonForInlineScript(params.csrf)};
    const HUB_ORIGIN = ${safeJsonForInlineScript(params.origin)};
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
        const safeLvl = ev.level === 'warn' || ev.level === 'error' ? ev.level : 'info';
        return '<div class="log-row' + isOpen + '" data-ev-id="' + Number(ev.id) + '">' +
          '<div class="log-line">' +
            '<span class="log-ts">' + esc(fmtClock(ev.ts)) + '</span>' +
            '<span class="badge lvl-' + safeLvl + '">' + esc(ev.level) + '</span>' +
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

      const upd = data.updateStatus;
      const updPill = el('update-pill');
      const updHint = el('update-fleet-hint');
      if (upd && upd.pillLabel) {
        updPill.style.display = 'inline-block';
        updPill.textContent = upd.pillLabel;
        updPill.href = upd.releaseUrl || 'https://github.com/bartrumb/edgefetch/releases';
        updPill.className =
          upd.pillStatus === 'update_available'
            ? 'pill pill-warn'
            : upd.pillStatus === 'up_to_date'
              ? 'pill'
              : 'pill pill-muted';
        const outdatedNodes = Array.isArray(upd.outdatedAgents) ? upd.outdatedAgents : [];
        if (upd.pillStatus === 'update_available') {
          const parts = [];
          if (upd.hubUpdateAvailable) parts.push('Hub ' + upd.currentVersion + ' -> ' + (upd.latestTag || upd.latestVersion));
          if (outdatedNodes.length) {
            parts.push('Run edgefetch update on: ' + outdatedNodes.map((n) => n.siteId + ' (' + n.version + ')').join(', '));
          }
          updPill.title = parts.join(' · ') || 'Signed GitHub Release available';
          if (updHint) {
            updHint.style.display = 'block';
            updHint.textContent = parts.join(' · ');
          }
        } else {
          updPill.title = 'Signed GitHub Release verified (' + (upd.currentVersion || '') + ')';
          if (updHint) updHint.style.display = 'none';
        }
      } else {
        updPill.style.display = 'none';
        if (updHint) updHint.style.display = 'none';
      }

      const tel = data.devTelemetry;
      const telBadge = el('telemetry-status-badge');
      const telBtn = el('telemetry-toggle-btn');
      if (tel && telBadge && telBtn) {
        if (tel.doNotTrack) {
          telBadge.className = 'badge lvl-warn';
          telBadge.textContent = 'LOCKED OFF (DO_NOT_TRACK=1)';
          telBtn.disabled = true;
          telBtn.className = '';
          telBtn.textContent = 'Disabled by DO_NOT_TRACK=1';
        } else if (tel.enabled) {
          telBadge.className = 'badge lvl-info';
          telBadge.textContent = 'ON (' + (tel.source === 'env' ? 'ENV OPT-IN' : 'ADMIN OPT-IN') + ')';
          telBtn.disabled = false;
          telBtn.className = '';
          telBtn.textContent = 'Disable Dev Error Telemetry';
          telBtn.setAttribute('data-next-enabled', 'false');
        } else {
          telBadge.className = 'badge cat';
          telBadge.textContent = 'OFF (' + (tel.source === 'admin_opt_out' ? 'OPTED OUT' : 'DEFAULT 0 TELEMETRY') + ')';
          telBtn.disabled = false;
          telBtn.className = 'primary';
          telBtn.textContent = 'Enable Opt-In Error Telemetry';
          telBtn.setAttribute('data-next-enabled', 'true');
        }
      }

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
            '<tr><td><strong>' + esc(g.clientName) + '</strong>' + (g.userId ? ' <span class="muted">(' + esc(g.userId) + ')</span>' : '') + '</td><td><code>' + esc(g.scopes.join(' ')) + '</code></td><td>' + esc(relTime(g.expiresAt)) + '</td>' +
            '<td><button type="button" class="danger" data-revoke="' + esc(g.grantId) + '">Revoke</button></td></tr>'
          ).join('')
        : '<tr><td colspan="4" class="muted">No OAuth 2.1 grants issued yet</td></tr>';

      const gapCard = el('gap-radar-card');
      const gapList = Array.isArray(data.hostGaps) ? data.hostGaps : [];
      if (gapCard && data.viewer && data.viewer.role === 'owner' && gapList.length > 0) {
        gapCard.style.display = 'block';
        el('gap-radar-tbody').innerHTML = gapList.map((g) => {
          const adBadge = g.hasAdapter
            ? '<span class="badge lvl-info">' + esc(g.matchedAdapterId || 'adapted') + '</span>'
            : '<span class="badge lvl-warn">unadapted</span>';
          const cmd = g.proposeCommand ? '<code>' + esc(g.proposeCommand) + '</code>' : '<span class="muted">—</span>';
          return '<tr>' +
            '<td><code>' + esc(g.host) + '</code></td>' +
            '<td><strong>' + Number(g.totalFetches || 0) + '</strong> <span class="muted">(' + Number(g.browserFallbacks || 0) + ' render / ' + Number(g.browserSharePct || 0) + '%)</span></td>' +
            '<td>' + Math.round(Number(g.browserMsTotal || 0) / 100) / 10 + 's</td>' +
            '<td>' + adBadge + '</td>' +
            '<td>' + cmd + '</td>' +
          '</tr>';
        }).join('');
      } else if (gapCard) {
        gapCard.style.display = 'none';
      }

      const usersCard = el('users-card');
      const usersList = Array.isArray(data.users) ? data.users : [];
      if (usersCard && data.viewer && data.viewer.role === 'owner') {
        usersCard.style.display = 'block';
        el('users-count').textContent = usersList.length;
        const sumStoredTokens =
          typeof data.totalStoredTokens === 'number'
            ? data.totalStoredTokens
            : usersList.reduce((acc, u) => acc + Number(u.storedTokenCount ?? u.tokenCount ?? 0), 0);
        el('users-total-tokens').textContent = sumStoredTokens;
        el('users-tbody').innerHTML = usersList.length
          ? usersList.map((u) => {
              const totalTok = Number(u.storedTokenCount ?? u.tokenCount ?? 0);
              const activeTok = Number(u.activeTokenCount ?? 0);
              const usedTok = Number(u.usedTokenCount ?? 0);
              const gCount = Number(u.grantCount ?? 0);
              return '<tr>' +
                '<td><strong>' + esc(u.githubLogin ? '@' + u.githubLogin : u.userId) + '</strong> <span class="muted">(<code>' + esc(u.userId) + '</code>)</span></td>' +
                '<td><span class="badge ' + (u.role === 'owner' ? 'lvl-info' : 'cat') + '">' + esc(u.role) + '</span></td>' +
                '<td><strong>' + totalTok + '</strong> <span class="muted">(' + activeTok + ' active / ' + usedTok + ' used)</span></td>' +
                '<td>' + gCount + '</td>' +
                '<td>' + esc(relTime(u.lastLoginAt)) + '</td>' +
              '</tr>';
            }).join('')
          : '<tr><td colspan="5" class="muted">No GitHub users registered yet</td></tr>';
      } else if (usersCard) {
        usersCard.style.display = 'none';
      }

      renderMcpConnectors(data.mcpServers || [], Boolean(data.vaultConfigured));
      renderLogs();
    }

    let lastRegistryResults = [];
    let currentManifestHeaders = [];

    function renderMcpConnectors(servers, vaultConfigured) {
      el('mcp-conn-count').textContent = servers.length;
      const pill = el('vault-status-pill');
      pill.textContent = vaultConfigured ? 'AES-256-GCM Ready' : 'VAULT_MASTER_KEY Unset';
      pill.style.background = vaultConfigured ? '#064e3b' : '#78350f';
      pill.style.borderColor = vaultConfigured ? '#059669' : '#d97706';
      pill.style.color = vaultConfigured ? '#6ee7b7' : '#fde68a';

      const tbody = el('mcp-conn-tbody');
      if (!servers.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No downstream MCP connectors configured yet. Search the Registry below to add auth.</td></tr>';
        return;
      }
      tbody.innerHTML = servers.map((s) => {
        const badge = s.authSummary?.maskedBadge || s.authType;
        const doms = (s.domains || []).map((d) => '<code>' + esc(d) + '</code>').join(', ') || '—';
        return '<tr>' +
          '<td><strong>' + esc(s.name) + '</strong><div class="muted"><code>' + esc(s.slug) + '</code> &middot; ' + esc(s.remoteOrigin) + '</div></td>' +
          '<td><span class="badge lvl-info">' + esc(badge) + '</span></td>' +
          '<td>' + doms + '</td>' +
          '<td><strong>' + Number(s.toolCount || 0) + '</strong> tools</td>' +
          '<td>' + esc(s.lastVerifiedAt ? relTime(s.lastVerifiedAt) : 'unverified') + '</td>' +
          '<td style="display:flex;gap:6px;flex-wrap:wrap">' +
            '<button type="button" data-mcp-retest="' + esc(s.slug) + '" style="padding:4px 8px;font-size:0.75rem">Test tools/list</button>' +
            '<button type="button" data-mcp-rotate="' + esc(s.slug) + '" style="padding:4px 8px;font-size:0.75rem">Rotate Auth</button>' +
            '<button type="button" class="danger" data-mcp-disconnect="' + esc(s.slug) + '">Disconnect</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function openConnectPanel(opts) {
      el('mcp-connect-panel').style.display = 'block';
      el('mcp-form-title').textContent = opts.rotate ? ('Rotate Auth — ' + (opts.title || opts.slug)) : ('Connect / Add Auth — ' + (opts.title || 'Custom HTTPS MCP'));
      el('mc-name').value = opts.title || '';
      el('mc-slug').value = opts.slug || '';
      el('mc-url').value = opts.remoteUrl || '';
      el('mc-transport').value = opts.transport || 'streamable-http';
      el('mc-domains').value = (opts.domains || []).join(', ');
      el('mc-bearer').value = '';
      el('mc-hdr-name').value = '';
      el('mc-hdr-val').value = '';
      el('mc-status').textContent = '';
      el('mc-test-out').style.display = 'none';
      el('mcp-oauth-banner').style.display = 'none';

      currentManifestHeaders = Array.isArray(opts.headers) ? opts.headers : [];
      const container = el('mc-manifest-headers');
      if (currentManifestHeaders.length) {
        container.innerHTML = '<div class="muted" style="margin-bottom:6px">Manifest-required authentication headers (write-only):</div>' +
          '<div class="form-grid">' +
          currentManifestHeaders.map((h, i) =>
            '<div><label>' + esc(h.name) + (h.isRequired ? ' *' : '') + '</label>' +
            '<input type="' + (h.isSecret === false ? 'text' : 'password') + '" data-manifest-hdr="' + i + '" autocomplete="new-password" placeholder="' + esc(h.placeholder || h.description || h.name) + '">' +
            '</div>'
          ).join('') + '</div>';
      } else {
        container.innerHTML = '';
      }

      if (opts.remoteUrl) {
        fetch('/admin/api/mcp/probe', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
          body: JSON.stringify({ remoteUrl: opts.remoteUrl }),
        }).then((r) => r.json()).then((probe) => {
          if (probe && probe.supported) {
            el('mcp-oauth-banner').style.display = 'flex';
          }
        }).catch(() => {});
      }
    }

    function collectSecretHeadersFromForm() {
      const headers = {};
      document.querySelectorAll('[data-manifest-hdr]').forEach((inp) => {
        const idx = Number(inp.getAttribute('data-manifest-hdr'));
        const spec = currentManifestHeaders[idx];
        if (spec && inp.value.trim()) headers[spec.name] = inp.value.trim();
      });
      const customName = el('mc-hdr-name').value.trim();
      const customVal = el('mc-hdr-val').value.trim();
      if (customName && customVal) headers[customName] = customVal;
      return headers;
    }

    el('custom-mcp-btn').addEventListener('click', () => openConnectPanel({}));
    el('mcp-form-close-btn').addEventListener('click', () => { el('mcp-connect-panel').style.display = 'none'; });

    el('mcp-oauth-start-btn').addEventListener('click', async () => {
      el('mc-status').textContent = 'Starting OAuth 2.1 PKCE...';
      const res = await fetch('/admin/mcp/oauth/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
        body: JSON.stringify({
          remoteUrl: el('mc-url').value.trim(),
          slug: el('mc-slug').value.trim(),
          name: el('mc-name').value.trim(),
          transport: el('mc-transport').value,
          domains: el('mc-domains').value.split(',').map((s) => s.trim()).filter(Boolean),
        }),
      });
      const out = await res.json();
      if (out.ok && out.authorizationUrl) {
        location.href = out.authorizationUrl;
      } else {
        el('mc-status').textContent = out.message || out.error || 'OAuth start failed';
      }
    });

    el('mc-test-btn').addEventListener('click', async () => {
      el('mc-status').textContent = 'Testing initialize + tools/list...';
      const res = await fetch('/admin/api/mcp/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
        body: JSON.stringify({
          remoteUrl: el('mc-url').value.trim(),
          transport: el('mc-transport').value,
          bearerToken: el('mc-bearer').value.trim() || undefined,
          headers: collectSecretHeadersFromForm(),
        }),
      });
      const out = await res.json();
      el('mc-test-out').style.display = 'block';
      el('mc-test-out').textContent = JSON.stringify(out, null, 2);
      el('mc-status').textContent = out.ok ? ('Verified ' + out.toolCount + ' tools!') : ('Error: ' + (out.message || out.error));
    });

    el('mcp-connect-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      el('mc-status').textContent = 'Encrypting & verifying...';
      const res = await fetch('/admin/api/mcp/connect', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
        body: JSON.stringify({
          name: el('mc-name').value.trim(),
          slug: el('mc-slug').value.trim(),
          remoteUrl: el('mc-url').value.trim(),
          transport: el('mc-transport').value,
          domains: el('mc-domains').value.split(',').map((s) => s.trim()).filter(Boolean),
          bearerToken: el('mc-bearer').value.trim() || undefined,
          headers: collectSecretHeadersFromForm(),
        }),
      });
      const out = await res.json();
      if (out.ok) {
        el('mc-bearer').value = '';
        el('mc-hdr-val').value = '';
        el('mcp-connect-panel').style.display = 'none';
        await loadState();
      } else {
        el('mc-status').textContent = out.message || out.error || 'Failed to save connector';
      }
    });

    el('mcp-conn-tbody').addEventListener('click', async (ev) => {
      const disc = ev.target.closest('[data-mcp-disconnect]');
      if (disc) {
        await fetch('/admin/api/mcp/disconnect', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
          body: JSON.stringify({ slug: disc.getAttribute('data-mcp-disconnect') }),
        });
        await loadState();
        return;
      }
      const retest = ev.target.closest('[data-mcp-retest]');
      if (retest) {
        await fetch('/admin/api/mcp/test', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
          body: JSON.stringify({ slug: retest.getAttribute('data-mcp-retest') }),
        });
        await loadState();
        return;
      }
      const rot = ev.target.closest('[data-mcp-rotate]');
      if (rot) {
        const slug = rot.getAttribute('data-mcp-rotate');
        const srv = (lastStateData?.mcpServers || []).find((s) => s.slug === slug);
        if (srv) {
          openConnectPanel({
            rotate: true,
            title: srv.name,
            slug: srv.slug,
            remoteUrl: srv.remoteUrl,
            transport: srv.transport,
            domains: srv.domains,
          });
        }
      }
    });

    async function searchMcpRegistry() {
      const q = el('mcp-reg-q').value.trim();
      const remOnly = el('mcp-reg-remote').checked;
      const grid = el('mcp-reg-grid');
      grid.innerHTML = '<div class="muted">Searching Official MCP Registry &amp; Glama...</div>';
      const res = await fetch('/admin/api/mcp/registry?q=' + encodeURIComponent(q) + '&remoteOnly=' + (remOnly ? 'true' : 'false'));
      const out = await res.json();
      lastRegistryResults = out.servers || [];
      if (!lastRegistryResults.length) {
        grid.innerHTML = '<div class="muted">' + esc(out.error ? ('Registry error: ' + out.error) : 'No matching MCP servers found.') + '</div>';
        return;
      }
      grid.innerHTML = lastRegistryResults.map((srv, idx) => {
        const rem = (srv.remotes || [])[0];
        const srcBadges = (srv.sources || []).map((s) => '<span class="arch">' + esc(s) + '</span>').join(' ');
        const domText = (srv.domains || []).slice(0, 3).join(', ') || 'general';
        return '<div class="site-card">' +
          '<div class="site-top"><span class="site-name">' + esc(srv.title || srv.name) + '</span><span>' + srcBadges + '</span></div>' +
          '<div class="muted" style="margin-bottom:8px;font-size:0.8rem">' + esc((srv.description || '').slice(0, 140)) + '</div>' +
          '<div class="kv"><span>Domains</span><strong><code>' + esc(domText) + '</code></strong></div>' +
          '<div class="kv"><span>Transport</span><strong>' + esc(rem ? rem.type : 'local-package') + '</strong></div>' +
          '<div style="margin-top:10px;display:flex;justify-content:flex-end">' +
            (rem
              ? '<button type="button" class="primary" data-reg-connect="' + idx + '" style="padding:4px 10px;font-size:0.76rem">Connect / Add Auth</button>'
              : '<span class="muted" style="font-size:0.75rem">Stdio package only</span>') +
          '</div>' +
        '</div>';
      }).join('');
    }

    el('mcp-reg-search-btn').addEventListener('click', searchMcpRegistry);
    el('mcp-reg-q').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); searchMcpRegistry(); } });
    el('mcp-reg-grid').addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-reg-connect]');
      if (!btn) return;
      const srv = lastRegistryResults[Number(btn.getAttribute('data-reg-connect'))];
      if (!srv) return;
      const rem = (srv.remotes || [])[0];
      openConnectPanel({
        title: srv.title || srv.name,
        slug: srv.slug,
        remoteUrl: rem ? rem.url : '',
        transport: rem ? rem.type : 'streamable-http',
        domains: srv.domains || [],
        headers: rem ? rem.headers : [],
      });
    });

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

    el('telemetry-toggle-btn').addEventListener('click', async () => {
      const btn = el('telemetry-toggle-btn');
      if (btn.disabled) return;
      const nextEnabled = btn.getAttribute('data-next-enabled') === 'true';
      btn.disabled = true;
      try {
        await fetch('/admin/api/telemetry', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF },
          body: JSON.stringify({ enabled: nextEnabled }),
        });
        await loadState();
      } finally {
        btn.disabled = false;
      }
    });

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
    el('vscode-mcp-btn').href = 'vscode:mcp/install?' + encodeURIComponent(JSON.stringify({ name: ${safeJsonForInlineScript(params.mcpSlug)}, type: 'http', url: mcpEndpoint }));

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
  op:
    | 'login'
    | 'logout'
    | 'github_login'
    | 'github_callback'
    | 'events_clear'
    | 'affinity_clear'
    | 'grant_revoke'
    | 'user_role'
    | 'user_delete'
    | 'telemetry_toggle'
    | 'fetch'
    | 'mcp_connect'
    | 'mcp_disconnect'
    | 'mcp_test'
    | 'mcp_oauth',
  fn: (span: AdminAuditSpan) => Promise<T>,
): Promise<T> {
  const tracer = getActiveRequestTracer();
  if (!tracer) return fn(NOOP_ADMIN_AUDIT_SPAN);
  return tracer.withSpan(`edgefetch.admin.${op}`, { kind: 1, attributes: { 'admin.op': op } }, (span) => fn(span));
}

function readCookieFromHeader(cookieHeader: string | null, targetName: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const k = part.slice(0, eq).trim();
    if (k === targetName) return part.slice(eq + 1).trim();
  }
  return null;
}

export async function handleAdminRoute(request: Request, url: URL, deps: AdminPortalDeps): Promise<Response | null> {
  const path = url.pathname;
  if (path !== '/admin' && !path.startsWith('/admin/')) return null;

  const cookieAttrs = resolveAdminCookieAttrs(url, deps.publicOrigin);
  const mcpBindCookieName = cookieAttrs.strictHostPrefix ? MCP_OAUTH_BIND_COOKIE : MCP_OAUTH_BIND_COOKIE_DEV;
  const ownerSecret = deps.ownerSecret;
  const hasOwnerSecret = Boolean(ownerSecret && ownerSecret.length >= MIN_TOKEN_LENGTH);
  const ghEnv: GitHubAuthEnv = {
    ...(deps.githubAuthEnv ?? {}),
    ...(ownerSecret ? { CALLER_TOKEN: ownerSecret } : {}),
  };
  const githubEnabled = isGitHubAuthConfigured(ghEnv);
  const signingSecret = resolveSessionSecret(ghEnv) ?? (hasOwnerSecret ? ownerSecret : undefined);

  if (path === '/admin/auth/github' && request.method === 'GET') {
    return withAdminAuditSpan('github_login', async (span) => {
      const started = await startGitHubOAuthFlow({
        request,
        url,
        env: ghEnv,
        publicOrigin: deps.publicOrigin,
      });
      span.setAttributes({
        'admin.outcome': started.outcome,
        'http.response.status_code': started.response.status,
      });
      if (started.response.status >= 400) {
        span.setStatus(false, started.outcome);
      }
      return started.response;
    });
  }

  if (path === '/admin/auth/github/callback' && request.method === 'GET') {
    return withAdminAuditSpan('github_callback', async (span) => {
      const cb = await handleGitHubOAuthCallback({
        request,
        url,
        env: ghEnv,
        oauthStore: deps.oauthStore,
        ...(deps.metaDb ? { metaDb: deps.metaDb } : {}),
        ...(deps.getHubSetting ? { getHubSetting: deps.getHubSetting } : {}),
        ...(deps.setHubSetting ? { setHubSetting: deps.setHubSetting } : {}),
        serviceName: deps.serviceName,
        publicOrigin: deps.publicOrigin,
        ...(deps.onEvent ? { onEvent: deps.onEvent } : {}),
      });
      span.setAttributes({
        'admin.outcome': cb.outcome,
        ...(cb.userId ? { 'admin.user_id': cb.userId } : {}),
        ...(cb.role ? { 'admin.role': cb.role } : {}),
        'http.response.status_code': cb.response.status,
      });
      if (cb.response.status >= 400) {
        span.setStatus(false, cb.outcome);
      }
      return cb.response;
    });
  }

  if (!signingSecret) {
    return adminJson({ error: 'owner_secret_unconfigured' }, 503);
  }

  const nowMs = Date.now();
  const session = await verifyLiveAdminSession({
    cookieHeader: request.headers.get('cookie'),
    signingSecret,
    store: deps.oauthStore,
    now: nowMs,
    strictHostPrefix: cookieAttrs.strictHostPrefix,
    githubAuthEnv: ghEnv,
  });

  if (
    (request.method === 'POST' || request.method === 'PATCH' || request.method === 'DELETE') &&
    !isSameOriginFormPost(request, url, deps.publicOrigin)
  ) {
    return adminJson({ error: 'invalid_origin' }, 403);
  }

  if (path === '/admin/login' && request.method === 'GET') {
    return new Response(null, {
      status: 302,
      headers: { ...ADMIN_JSON_HEADERS, location: '/admin' },
    });
  }

  if (path === '/admin' && request.method === 'GET') {
    if (!session.ok) {
      return new Response(
        renderLoginHtml(deps.serviceName, undefined, { githubEnabled, ownerTokenEnabled: hasOwnerSecret }),
        { status: 200, headers: ADMIN_HTML_HEADERS },
      );
    }
    return new Response(
      renderDashboardHtml({
        serviceName: deps.serviceName,
        mcpSlug: deps.mcpSlug,
        sampleUrl: deps.sampleUrl ?? 'https://example.com/',
        origin: url.origin,
        csrf: session.csrf,
        principal: {
          userId: session.userId,
          role: session.role,
          ...(session.githubLogin ? { githubLogin: session.githubLogin } : {}),
        },
        allowedTargets: deps.allowedTargets,
        defaultTarget: deps.defaultTarget,
      }),
      { status: 200, headers: ADMIN_HTML_HEADERS },
    );
  }

  if (path === '/admin/login' && request.method === 'POST') {
    return withAdminAuditSpan('login', async (span) => {
      if (!hasOwnerSecret || !ownerSecret) {
        span.setAttributes({ 'admin.outcome': 'owner_token_disabled', 'http.response.status_code': 403 });
        span.setStatus(false, 'owner_token_disabled');
        return new Response(
          renderLoginHtml(deps.serviceName, 'Caller token login is disabled; sign in with GitHub.', {
            githubEnabled,
            ownerTokenEnabled: false,
          }),
          { status: 403, headers: ADMIN_HTML_HEADERS },
        );
      }
      const now = Date.now();
      const clientIp = normalizeClientRateLimitIp(request.headers.get('cf-connecting-ip'));
      const cappedForm = await readBodyTextCapped(request, 8_192);
      if (!cappedForm.ok) {
        span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': 413 });
        span.setStatus(false, 'payload_too_large');
        return new Response(
          renderLoginHtml(deps.serviceName, 'Login payload too large.', { githubEnabled, ownerTokenEnabled: hasOwnerSecret }),
          {
            status: 413,
            headers: ADMIN_HTML_HEADERS,
          },
        );
      }
      const supplied = (new URLSearchParams(cappedForm.text).get('token') ?? '').trim();
      // `R3-M4`: Verify constant-time `CALLER_TOKEN` match FIRST so an attacker spoofing `X-Forwarded-For` or sharing a
      // reverse-proxy / IPv6 `/64` bucket can NEVER lock out the legitimate admin, while invalid tokens get `429` after 5 failures!
      if (!supplied || !sameBytes(supplied, ownerSecret)) {
        const preLock = await deps.oauthStore.checkAuthLockout(`admin:${clientIp}`, now, RATE_LIMIT_MAX_FAILURES);
        if (!preLock.allowed) {
          span.setAttributes({ 'admin.outcome': 'rate_limited', 'http.response.status_code': 429 });
          span.setStatus(false, 'rate_limited');
          return new Response(
            renderLoginHtml(deps.serviceName, 'Too many failed attempts. Try again in 5 minutes.', {
              githubEnabled,
              ownerTokenEnabled: hasOwnerSecret,
            }),
            {
              status: 429,
              headers: { ...ADMIN_HTML_HEADERS, 'retry-after': String(preLock.retryAfterSec) },
            },
          );
        }
        const rl = await deps.oauthStore.recordAuthFailure(`admin:${clientIp}`, now, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_FAILURES);
        if (!rl.allowed) {
          span.setAttributes({ 'admin.outcome': 'rate_limited', 'http.response.status_code': 429 });
          span.setStatus(false, 'rate_limited');
          return new Response(
            renderLoginHtml(deps.serviceName, 'Too many failed attempts. Try again in 5 minutes.', {
              githubEnabled,
              ownerTokenEnabled: hasOwnerSecret,
            }),
            {
              status: 429,
              headers: { ...ADMIN_HTML_HEADERS, 'retry-after': String(rl.retryAfterSec) },
            },
          );
        }
        span.setAttributes({ 'admin.outcome': 'unauthorized', 'http.response.status_code': 401 });
        span.setStatus(false, 'unauthorized');
        return new Response(
          renderLoginHtml(deps.serviceName, 'Invalid caller token.', { githubEnabled, ownerTokenEnabled: hasOwnerSecret }),
          {
            status: 401,
            headers: ADMIN_HTML_HEADERS,
          },
        );
      }

      await deps.oauthStore.clearAuthFailures(`admin:${clientIp}`);
      const minted = await createAdminSessionValue(signingSecret);
      const headers = new Headers({
        location: '/admin',
        ...ADMIN_JSON_HEADERS,
      });
      headers.append(
        'set-cookie',
        formatCookie(cookieAttrs.name, minted.value, {
          maxAge: minted.maxAgeSec,
          path: '/',
          sameSite: 'Lax',
          secure: cookieAttrs.secure,
        }),
      );
      span.setAttributes({ 'admin.outcome': 'authenticated', 'admin.user_id': 'owner', 'http.response.status_code': 302 });
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
      // Server-side revocation of this exact admin session cookie (`Low`): revoke both `csrf` AND JWT `jti`!
      if (typeof deps.oauthStore.recordAuthFailure === 'function') {
        const nowRevoke = Date.now();
        const csrfHash = await sha256Base64Url(session.csrf);
        await deps.oauthStore.recordAuthFailure(`revoked_admin:${csrfHash}`, nowRevoke, 8 * 60 * 60_000, 1);
        if (session.jti) {
          const jtiHash = await sha256Base64Url(session.jti);
          await deps.oauthStore.recordAuthFailure(`revoked_admin:jti:${jtiHash}`, nowRevoke, 8 * 60 * 60_000, 1);
        }
      }
      const headers = new Headers({
        location: '/admin',
        ...ADMIN_JSON_HEADERS,
      });
      headers.append(
        'set-cookie',
        formatCookie(cookieAttrs.name, '', { maxAge: 0, path: '/', sameSite: 'Lax', secure: cookieAttrs.secure }),
      );
      if (cookieAttrs.name !== ADMIN_COOKIE_NAME_DEV) {
        headers.append(
          'set-cookie',
          formatCookie(ADMIN_COOKIE_NAME_DEV, '', { maxAge: 0, path: '/', sameSite: 'Lax', secure: cookieAttrs.secure }),
        );
      }
      span.setAttributes({
        'admin.outcome': 'logged_out',
        'admin.user_id': session.userId,
        'http.response.status_code': 302,
      });
      return new Response(null, { status: 302, headers });
    });
  }

  const userIdPathMatch = /^\/admin\/api\/users\/([^/]+)$/.exec(path);
  const isUserItemPatch = Boolean(
    userIdPathMatch &&
      request.method === 'PATCH' &&
      userIdPathMatch[1] !== 'role' &&
      userIdPathMatch[1] !== 'delete',
  );
  const isUserItemDelete = Boolean(
    userIdPathMatch &&
      request.method === 'DELETE' &&
      userIdPathMatch[1] !== 'role' &&
      userIdPathMatch[1] !== 'delete',
  );

  const apiOp =
    request.method === 'POST' || request.method === 'PATCH' || request.method === 'DELETE'
      ? path === '/admin/api/events/clear'
        ? ('events_clear' as const)
        : path === '/admin/api/affinity/clear'
          ? ('affinity_clear' as const)
          : path === '/admin/api/grants/revoke'
            ? ('grant_revoke' as const)
            : path === '/admin/api/users/role' || isUserItemPatch
              ? ('user_role' as const)
              : path === '/admin/api/users/delete' || path === '/admin/api/users' || isUserItemDelete
                ? ('user_delete' as const)
                : path === '/admin/api/telemetry'
                ? ('telemetry_toggle' as const)
                : path === '/admin/api/fetch'
                  ? ('fetch' as const)
                  : path === '/admin/api/mcp/connect'
                    ? ('mcp_connect' as const)
                    : path === '/admin/api/mcp/disconnect'
                      ? ('mcp_disconnect' as const)
                      : path === '/admin/api/mcp/test'
                        ? ('mcp_test' as const)
                        : path === '/admin/mcp/oauth/start'
                          ? ('mcp_oauth' as const)
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

  const userId = resolveCallerUserId(session as { userId?: string });
  const safeFetch = deps.safePublicFetch ?? fetch;
  const selfHost = deps.selfHost ?? url.hostname;

  if (path === '/admin/api/state' && request.method === 'GET') {
    const state = await deps.getState();
    const viewer = {
      userId: session.userId,
      role: session.role,
      ...(session.githubLogin ? { githubLogin: session.githubLogin } : {}),
      ...(session.avatarUrl ? { avatarUrl: session.avatarUrl } : {}),
    };
    const mcpServers: PublicMcpServerSummary[] = deps.vaultStore
      ? (await deps.vaultStore.listServers(userId)).map(toPublicMcpServerSummary)
      : [];
    const vaultConfigured = validateVaultMasterKey(deps.vaultMasterKey).ok;
    if (session.role !== 'owner') {
      const ownGrants = (state.grants ?? []).filter((g) => (g.userId ?? 'owner') === session.userId);
      return adminJson(
        {
          viewer,
          userId,
          vaultConfigured,
          mcpServers,
          connected: state.connected,
          agents: [],
          affinities: [],
          grants: ownGrants,
          mcpClients: [],
          events: [],
          users: [],
        },
        200,
      );
    }
    const [rawUsers, updateStatus, devTelemetry, gapRadar] = await Promise.all([
      state.users ? Promise.resolve(state.users) : Promise.resolve(deps.oauthStore.listUsers?.() ?? []),
      deps.getUpdateStatus ? deps.getUpdateStatus(state.agents).catch(() => undefined) : Promise.resolve(undefined),
      deps.getTelemetrySettings ? deps.getTelemetrySettings().catch(() => undefined) : Promise.resolve(undefined),
      deps.metaDb ? queryHostGapRadar({ metaDb: deps.metaDb, days: 7, limit: 10 }).catch(() => undefined) : Promise.resolve(undefined),
    ]);
    const users = rawUsers.map(({ encryptedGhToken: _omitGhSecret, ...u }) => {
      const storedTokenCount = Number(u.storedTokenCount ?? u.tokenCount ?? 0);
      return {
        ...u,
        tokenCount: storedTokenCount,
        storedTokenCount,
        activeTokenCount: Number(u.activeTokenCount ?? 0),
        usedTokenCount: Number(u.usedTokenCount ?? 0),
        grantCount: Number(u.grantCount ?? 0),
      };
    });
    const totalStoredTokens = users.reduce((sum, u) => sum + u.storedTokenCount, 0);
    return adminJson(
      {
        ...state,
        viewer,
        users,
        totalStoredTokens,
        userId,
        vaultConfigured,
        mcpServers,
        ...(gapRadar ? { hostGaps: gapRadar.hosts } : {}),
        ...(updateStatus ? { updateStatus } : {}),
        ...(devTelemetry ? { devTelemetry } : {}),
      },
      200,
    );
  }

  if (path === '/admin/api/users' && request.method === 'GET') {
    if (session.role !== 'owner') {
      return adminJson({ error: 'forbidden_role', message: 'Owner role required' }, 403);
    }
    const rawUsers = await Promise.resolve(deps.oauthStore.listUsers?.() ?? []);
    const users = rawUsers.map(({ encryptedGhToken: _omitGhSecret, ...u }) => {
      const storedTokenCount = Number(u.storedTokenCount ?? u.tokenCount ?? 0);
      return {
        ...u,
        tokenCount: storedTokenCount,
        storedTokenCount,
        activeTokenCount: Number(u.activeTokenCount ?? 0),
        usedTokenCount: Number(u.usedTokenCount ?? 0),
        grantCount: Number(u.grantCount ?? 0),
      };
    });
    const totalStoredTokens = users.reduce((sum, u) => sum + u.storedTokenCount, 0);
    return adminJson({ ok: true, users, totalStoredTokens }, 200);
  }

  if (path === '/admin/api/mcp/registry' && request.method === 'GET') {
    const q = url.searchParams.get('q') ?? url.searchParams.get('query') ?? '';
    const remoteOnly = url.searchParams.get('remoteOnly') === 'true' || url.searchParams.get('remoteOnly') === '1';
    const rawLim = Number(url.searchParams.get('limit') ?? 20);
    const out = await discoverMcps({
      query: q,
      remoteOnly,
      ...(Number.isFinite(rawLim) ? { limit: rawLim } : {}),
      fetchFn: safeFetch,
      selfHost,
    });
    return adminJson(out, out.status);
  }

  if (path === '/admin/api/mcp/servers' && request.method === 'GET') {
    if (!deps.vaultStore) {
      return adminJson({ ok: true, userId, servers: [] }, 200);
    }
    const rows = await deps.vaultStore.listServers(userId);
    return adminJson(
      {
        ok: true,
        userId,
        vaultConfigured: validateVaultMasterKey(deps.vaultMasterKey).ok,
        servers: rows.map(toPublicMcpServerSummary),
      },
      200,
    );
  }

  if (path === '/admin/mcp/oauth/start' && request.method === 'GET') {
    return withAdminAuditSpan('mcp_oauth', async () => {
      const qCsrf = url.searchParams.get('csrf') ?? '';
      if (!qCsrf || !sameBytes(qCsrf, session.csrf)) {
        return adminJson({ error: 'invalid_csrf' }, 403);
      }
      if (!deps.vaultStore) return adminJson({ error: 'vault_not_configured' }, 503);
      const rawDomainsParam = url.searchParams.get('domains');
      const parsedDomains = rawDomainsParam
        ? rawDomainsParam
            .split(/[\s,]+/)
            .map((d) => d.trim())
            .filter(Boolean)
        : undefined;
      const started = await startDownstreamMcpOAuth({
        userId,
        sessionCsrf: session.csrf,
        hubOrigin: deps.publicOrigin ?? url.origin,
        remoteUrl: url.searchParams.get('remoteUrl') ?? '',
        slug: url.searchParams.get('slug') ?? undefined,
        name: url.searchParams.get('name') ?? undefined,
        ...(parsedDomains && parsedDomains.length > 0 ? { domains: parsedDomains } : {}),
        autoRouteScrape: url.searchParams.get('autoRouteScrape') === 'true',
        clientId: url.searchParams.get('clientId') ?? undefined,
        scope: url.searchParams.get('scope') ?? undefined,
        confirmedAuthOrigin: url.searchParams.get('confirmedAuthOrigin') ?? undefined,
        vaultMasterKey: deps.vaultMasterKey,
        vaultStore: deps.vaultStore,
        fetchFn: safeFetch,
        selfHost,
      });
      if (!started.ok) return adminJson(started, started.status);
      const headers = new Headers({
        location: started.authorizationUrl,
        ...ADMIN_JSON_HEADERS,
      });
      headers.append(
        'set-cookie',
        formatCookie(mcpBindCookieName, started.bindCookieValue, {
          maxAge: 600,
          path: '/',
          sameSite: 'Lax',
          secure: cookieAttrs.secure,
        }),
      );
      return new Response(null, { status: 302, headers });
    });
  }

  if (path === '/admin/mcp/oauth/callback' && request.method === 'GET') {
    return withAdminAuditSpan('mcp_oauth', async () => {
      if (!deps.vaultStore) return adminJson({ error: 'vault_not_configured' }, 503);
      const bindCookie = readCookieFromHeader(request.headers.get('cookie'), mcpBindCookieName);
      const completed = await completeDownstreamMcpOAuthCallback({
        userId,
        sessionCsrf: session.csrf,
        bindCookieHeader: bindCookie,
        code: url.searchParams.get('code') ?? '',
        state: url.searchParams.get('state') ?? '',
        iss: url.searchParams.get('iss'),
        vaultMasterKey: deps.vaultMasterKey,
        vaultStore: deps.vaultStore,
        fetchFn: safeFetch,
        selfHost,
      });
      if (!completed.ok) {
        return adminJson(completed, completed.status);
      }
      // Best-effort live `tools/list` populate right after OAuth connect
      const unsealed = completed.server.encryptedCredentials
        ? await unsealVaultCredentials({
            vaultMasterKey: deps.vaultMasterKey,
            userId,
            id: completed.server.id,
            slug: completed.server.slug,
            authType: completed.server.authType,
            secretVersion: completed.server.secretVersion,
            remoteOrigin: completed.server.remoteOrigin,
            remoteUrl: completed.server.remoteUrl,
            ciphertext: completed.server.encryptedCredentials,
          })
        : null;
      if (unsealed?.ok) {
        if (unsealed.resealedCiphertext) {
          completed.server.encryptedCredentials = unsealed.resealedCiphertext;
          completed.server.secretVersion = unsealed.resealedSecretVersion ?? 2;
        }
        const listed = await testAndListRemoteMcpTools({
          remoteUrl: completed.server.remoteUrl,
          secret: unsealed.payload,
          fetchFn: safeFetch,
          selfHost,
        });
        if (listed.ok) {
          completed.server.cachedTools = listed.tools;
          completed.server.toolCount = listed.tools.length;
          await deps.vaultStore.upsertServer(completed.server);
        } else if (unsealed.resealedCiphertext) {
          await deps.vaultStore.upsertServer(completed.server);
        }
      }
      const clearBindCookie = formatCookie(mcpBindCookieName, '', {
        maxAge: 0,
        path: '/',
        sameSite: 'Lax',
        secure: cookieAttrs.secure,
      });
      if ((request.headers.get('accept') ?? '').toLowerCase().includes('application/json')) {
        const headers = new Headers(ADMIN_JSON_HEADERS);
        headers.append('set-cookie', clearBindCookie);
        return Response.json({ ok: true, server: toPublicMcpServerSummary(completed.server) }, { status: 200, headers });
      }
      const headers = new Headers({
        location: '/admin#mcp-connectors',
        ...ADMIN_JSON_HEADERS,
      });
      headers.append('set-cookie', clearBindCookie);
      return new Response(null, { status: 302, headers });
    });
  }

  if (request.method === 'POST' || request.method === 'PATCH' || request.method === 'DELETE') {
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
        const scopedUserId = session.role === 'owner' ? undefined : session.userId;
        const revoked = await deps.revokeGrant(body.grantId, scopedUserId);
        span.setAttributes({
          'admin.grant_id': body.grantId,
          'admin.user_id': session.userId,
          'admin.revoked': revoked,
          'admin.outcome': revoked ? 'revoked' : 'not_found',
          'http.response.status_code': 200,
        });
        return adminJson({ ok: true, revoked }, 200);
      });
    }

    // Per-user MCP Registry & Encrypted Vault connectors (`user_id`-scoped): accessible to both `owner` and `member` users!
    if (path === '/admin/api/mcp/probe') {
      const capped = await readBodyTextCapped(request, 16_384);
      if (!capped.ok) return adminJson({ error: 'payload_too_large' }, capped.error === 'too_large' ? 413 : 400);
      let body: { remoteUrl?: unknown; confirmedAuthOrigin?: unknown } = {};
      try {
        body = JSON.parse(capped.text || '{}') as { remoteUrl?: unknown; confirmedAuthOrigin?: unknown };
      } catch {
        return adminJson({ error: 'invalid_json' }, 400);
      }
      const check = isSafePublicHttpsUrl(body.remoteUrl, selfHost);
      if (!check.ok) return adminJson({ ok: false, supported: false, error: 'invalid_remote_url', message: check.reason }, 400);
      const confirmedAuthOrigin =
        typeof body.confirmedAuthOrigin === 'string' && body.confirmedAuthOrigin.trim()
          ? body.confirmedAuthOrigin.trim()
          : undefined;
      const probe = await probeRemoteMcpOAuthMetadata({
        remoteUrl: check.normalized,
        confirmedAuthOrigin,
        fetchFn: safeFetch,
        selfHost,
      });
      return adminJson({ ok: true, ...probe }, 200);
    }

    if (path === '/admin/mcp/oauth/start') {
      return withAdminAuditSpan('mcp_oauth', async () => {
        if (!deps.vaultStore) return adminJson({ ok: false, error: 'vault_not_configured' }, 503);
        const capped = await readBodyTextCapped(request, 32_768);
        if (!capped.ok) return adminJson({ ok: false, error: 'payload_too_large' }, capped.error === 'too_large' ? 413 : 400);
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(capped.text || '{}') as Record<string, unknown>;
        } catch {
          return adminJson({ ok: false, error: 'invalid_json' }, 400);
        }
        const started = await startDownstreamMcpOAuth({
          userId,
          sessionCsrf: session.csrf,
          hubOrigin: deps.publicOrigin ?? url.origin,
          remoteUrl: typeof body.remoteUrl === 'string' ? body.remoteUrl : '',
          slug: typeof body.slug === 'string' ? body.slug : undefined,
          name: typeof body.name === 'string' ? body.name : undefined,
          transport: body.transport === 'sse' ? 'sse' : 'streamable-http',
          domains: Array.isArray(body.domains) ? body.domains.filter((d): d is string => typeof d === 'string') : undefined,
          autoRouteScrape: body.autoRouteScrape === true || body.routeScrapeDomains === true,
          clientId: typeof body.clientId === 'string' ? body.clientId : undefined,
          clientSecret: typeof body.clientSecret === 'string' ? body.clientSecret : undefined,
          scope: typeof body.scope === 'string' ? body.scope : undefined,
          confirmedAuthOrigin:
            typeof body.confirmedAuthOrigin === 'string' && body.confirmedAuthOrigin.trim()
              ? body.confirmedAuthOrigin.trim()
              : undefined,
          vaultMasterKey: deps.vaultMasterKey,
          vaultStore: deps.vaultStore,
          fetchFn: safeFetch,
          selfHost,
        });
        if (!started.ok) return adminJson(started, started.status);
        const headers = new Headers(ADMIN_JSON_HEADERS);
        headers.append(
          'set-cookie',
          formatCookie(mcpBindCookieName, started.bindCookieValue, {
            maxAge: 600,
            path: '/',
            sameSite: 'Lax',
            secure: cookieAttrs.secure,
          }),
        );
        return Response.json(
          { ok: true, slug: started.slug, authorizationUrl: started.authorizationUrl },
          { status: 200, headers },
        );
      });
    }

    if (path === '/admin/api/mcp/test') {
      return withAdminAuditSpan('mcp_test', async () => {
        const capped = await readBodyTextCapped(request, 65_536);
        if (!capped.ok) return adminJson({ ok: false, error: 'payload_too_large' }, capped.error === 'too_large' ? 413 : 400);
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(capped.text || '{}') as Record<string, unknown>;
        } catch {
          return adminJson({ ok: false, error: 'invalid_json' }, 400);
        }

        // Case 1: Re-test an already stored connector by `slug` using server-side decrypted credentials
        if (typeof body.slug === 'string' && body.slug.trim() && !body.remoteUrl) {
          if (!deps.vaultStore) return adminJson({ ok: false, error: 'vault_not_configured' }, 503);
          const existing = await deps.vaultStore.getServer(userId, body.slug.trim());
          if (!existing) return adminJson({ ok: false, error: 'mcp_server_not_found' }, 404);
          let secret: VaultSecretPayload | null = { kind: 'none', pinnedOrigin: existing.remoteOrigin };
          let resealedCiphertext: string | undefined;
          let resealedSecretVersion: number | undefined;
          if (existing.encryptedCredentials && existing.authType !== 'none') {
            const unsealed = await unsealVaultCredentials({
              vaultMasterKey: deps.vaultMasterKey,
              userId,
              id: existing.id,
              slug: existing.slug,
              authType: existing.authType,
              secretVersion: existing.secretVersion,
              remoteOrigin: existing.remoteOrigin,
              remoteUrl: existing.remoteUrl,
              ciphertext: existing.encryptedCredentials,
            });
            if (!unsealed.ok) return adminJson({ ok: false, error: unsealed.error, message: unsealed.message }, 500);
            secret = unsealed.payload;
            resealedCiphertext = unsealed.resealedCiphertext;
            resealedSecretVersion = unsealed.resealedSecretVersion;
          }
          const tested = await testAndListRemoteMcpTools({
            remoteUrl: existing.remoteUrl,
            secret,
            fetchFn: safeFetch,
            selfHost,
          });
          const now = Date.now();
          if (!tested.ok) {
            await deps.vaultStore.upsertServer({
              ...existing,
              ...(resealedCiphertext
                ? { encryptedCredentials: resealedCiphertext, secretVersion: resealedSecretVersion ?? 2 }
                : {}),
              lastError: tested.message.slice(0, 240),
              updatedAt: now,
            });
            return adminJson({ ok: false, error: tested.error, message: tested.message }, tested.status);
          }
          const updated: StoredMcpServerRow = {
            ...existing,
            ...(resealedCiphertext
              ? { encryptedCredentials: resealedCiphertext, secretVersion: resealedSecretVersion ?? 2 }
              : {}),
            cachedTools: tested.tools,
            toolCount: tested.tools.length,
            lastVerifiedAt: now,
            lastError: null,
            updatedAt: now,
          };
          await deps.vaultStore.upsertServer(updated);
          return adminJson(
            {
              ok: true,
              slug: updated.slug,
              toolCount: tested.tools.length,
              tools: tested.tools,
              ...(tested.serverInfo ? { serverInfo: tested.serverInfo } : {}),
            },
            200,
          );
        }

        // Case 2: Test unsaved form credentials before saving
        const urlCheck = isSafePublicHttpsUrl(body.remoteUrl, selfHost);
        if (!urlCheck.ok) {
          return adminJson({ ok: false, error: 'invalid_remote_url', message: urlCheck.reason }, 400);
        }
        const hdrCheck = sanitizeSecretHeadersInput({ bearerToken: body.bearerToken, headers: body.headers });
        if (!hdrCheck.ok) {
          return adminJson({ ok: false, error: 'invalid_headers', message: hdrCheck.error }, 400);
        }
        const secret: VaultSecretPayload =
          Object.keys(hdrCheck.headers).length > 0
            ? { kind: 'headers', pinnedOrigin: urlCheck.origin, headers: hdrCheck.headers }
            : { kind: 'none', pinnedOrigin: urlCheck.origin };

        const tested = await testAndListRemoteMcpTools({
          remoteUrl: urlCheck.normalized,
          secret,
          fetchFn: safeFetch,
          selfHost,
        });
        if (!tested.ok) {
          return adminJson({ ok: false, error: tested.error, message: tested.message }, tested.status);
        }
        return adminJson(
          {
            ok: true,
            remoteOrigin: urlCheck.origin,
            toolCount: tested.tools.length,
            tools: tested.tools,
            ...(tested.serverInfo ? { serverInfo: tested.serverInfo } : {}),
          },
          200,
        );
      });
    }

    if (path === '/admin/api/mcp/connect') {
      return withAdminAuditSpan('mcp_connect', async () => {
        if (!deps.vaultStore) return adminJson({ ok: false, error: 'vault_not_configured' }, 503);
        const capped = await readBodyTextCapped(request, 65_536);
        if (!capped.ok) return adminJson({ ok: false, error: 'payload_too_large' }, capped.error === 'too_large' ? 413 : 400);
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(capped.text || '{}') as Record<string, unknown>;
        } catch {
          return adminJson({ ok: false, error: 'invalid_json' }, 400);
        }

        const urlCheck = isSafePublicHttpsUrl(body.remoteUrl, selfHost);
        if (!urlCheck.ok) {
          return adminJson({ ok: false, error: 'invalid_remote_url', message: urlCheck.reason }, 400);
        }
        const hdrCheck = sanitizeSecretHeadersInput({ bearerToken: body.bearerToken, headers: body.headers });
        if (!hdrCheck.ok) {
          return adminJson({ ok: false, error: 'invalid_headers', message: hdrCheck.error }, 400);
        }

        const autoRouteScrape = body.autoRouteScrape === true || body.routeScrapeDomains === true;
        const rawDomains = Array.isArray(body.domains)
          ? body.domains.filter((d): d is string => typeof d === 'string')
          : undefined;
        const domValidation = validateConnectorDomains(rawDomains, urlCheck.origin, autoRouteScrape);
        if (!domValidation.ok) {
          return adminJson({ ok: false, error: 'invalid_domains', message: domValidation.error }, 400);
        }
        const domains = domValidation.domains;

        const hasSecrets = Object.keys(hdrCheck.headers).length > 0;
        const authType = hasSecrets ? ('headers' as const) : ('none' as const);
        const secretPayload: VaultSecretPayload = hasSecrets
          ? { kind: 'headers', pinnedOrigin: urlCheck.origin, pinnedUrl: urlCheck.normalized, headers: hdrCheck.headers }
          : { kind: 'none', pinnedOrigin: urlCheck.origin, pinnedUrl: urlCheck.normalized };

        const cleanName =
          stripInvisibleSmugglingChars(typeof body.name === 'string' ? body.name : '').trim().slice(0, 120) ||
          urlCheck.url.hostname;
        const slug = slugifyMcpServerName(typeof body.slug === 'string' && body.slug.trim() ? body.slug : cleanName);

        const now = Date.now();
        const existing = await deps.vaultStore.getServer(userId, slug);
        const serverId = existing?.id ?? `mcp_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;

        let encryptedCredentials: string | null = null;
        let secretVersion = 2;
        if (hasSecrets) {
          const sealed = await sealVaultCredentials({
            vaultMasterKey: deps.vaultMasterKey,
            userId,
            id: serverId,
            slug,
            authType,
            remoteOrigin: urlCheck.origin,
            payload: secretPayload,
          });
          if (!sealed.ok) {
            return adminJson(sealed, sealed.status);
          }
          encryptedCredentials = sealed.ciphertext;
          secretVersion = sealed.secretVersion;
        }

        let cachedTools = existing?.cachedTools ?? [];
        let lastVerifiedAt = existing?.lastVerifiedAt ?? null;
        let lastError: string | null = null;

        if (body.skipVerify !== true) {
          const tested = await testAndListRemoteMcpTools({
            remoteUrl: urlCheck.normalized,
            secret: secretPayload,
            fetchFn: safeFetch,
            selfHost,
          });
          if (tested.ok) {
            cachedTools = tested.tools;
            lastVerifiedAt = now;
          } else {
            lastError = tested.message.slice(0, 240);
            if (body.requireVerify === true) {
              return adminJson({ ok: false, error: tested.error, message: tested.message }, tested.status);
            }
          }
        }

        const row: StoredMcpServerRow = {
          id: serverId,
          userId,
          slug,
          name: cleanName,
          remoteUrl: urlCheck.normalized,
          remoteOrigin: urlCheck.origin,
          transport: body.transport === 'sse' ? 'sse' : 'streamable-http',
          authType,
          secretVersion,
          encryptedCredentials,
          authSummary: buildMaskedAuthSummary(secretPayload),
          domains,
          autoRouteScrape,
          cachedTools,
          toolCount: cachedTools.length,
          enabled: body.enabled !== false,
          lastVerifiedAt,
          lastError,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now,
        };

        await deps.vaultStore.upsertServer(row);
        return adminJson({ ok: true, server: toPublicMcpServerSummary(row) }, 200);
      });
    }

    if (path === '/admin/api/mcp/disconnect') {
      return withAdminAuditSpan('mcp_disconnect', async () => {
        if (!deps.vaultStore) return adminJson({ ok: false, error: 'vault_not_configured' }, 503);
        const capped = await readBodyTextCapped(request, 16_384);
        if (!capped.ok) return adminJson({ ok: false, error: 'payload_too_large' }, capped.error === 'too_large' ? 413 : 400);
        let body: { slug?: unknown } = {};
        try {
          body = JSON.parse(capped.text || '{}') as { slug?: unknown };
        } catch {
          return adminJson({ error: 'invalid_json' }, 400);
        }
        const slug = typeof body.slug === 'string' ? body.slug.trim() : '';
        if (!slug) return adminJson({ ok: false, error: 'missing_slug' }, 400);
        const deleted = await deps.vaultStore.deleteServer(userId, slug);
        return adminJson({ ok: true, deleted }, 200);
      });
    }

    // All remaining `/admin/api/*` mutations (`events/clear`, `affinity/clear`, `users/role`, `fetch`) are owner-only!
    if (session.role !== 'owner') {
      if (apiOp) {
        return withAdminAuditSpan(apiOp, async (span) => {
          span.setAttributes({
            'admin.user_id': session.userId,
            'admin.outcome': 'forbidden_role',
            'http.response.status_code': 403,
          });
          span.setStatus(false, 'forbidden_role');
          return adminJson({ error: 'forbidden_role', message: 'Owner role required' }, 403);
        });
      }
      return adminJson({ error: 'forbidden_role', message: 'Owner role required' }, 403);
    }

    const envOwnerId = (ghEnv.GITHUB_OWNER_ID ?? '').trim();
    const configuredFounderUserId = /^[1-9][0-9]{0,19}$/.test(envOwnerId) ? `gh_${envOwnerId}` : null;
    const isImmutableFounderCaller =
      session.userId === 'owner' || (configuredFounderUserId !== null && session.userId === configuredFounderUserId);
    const isImmutableFounderTarget = (targetId: string): boolean =>
      targetId === 'owner' || (configuredFounderUserId !== null && targetId === configuredFounderUserId);

    const disableAndRevokeTargetUser = async (
      existingUser: HubUserRecord,
      opts?: { allowAlreadyDisabled?: boolean },
    ): Promise<{ ok: true } | { ok: false; status: number; error: string; message?: string }> => {
      if (deps.oauthStore.upsertUser) {
        const saved = await deps.oauthStore.upsertUser({
          ...existingUser,
          role: 'member',
          disabled: true,
          admittedVia: undefined,
          admittedOrg: undefined,
          encryptedGhToken: undefined,
          orgVerifiedAt: undefined,
          mutationKind: 'admin_disable',
          callerIsImmutableFounder: isImmutableFounderCaller,
          configuredFounderUserId,
          allowAlreadyDisabled: opts?.allowAlreadyDisabled === true,
        });
        if (saved.mutationAborted) {
          if (saved.disableFailedReason === 'founder_protected') {
            return {
              ok: false,
              status: 403,
              error: 'founder_protected',
              message: 'Immutable founder/owner cannot be disabled, demoted, or modified',
            };
          }
          if (saved.disableFailedReason === 'owner_protected' || (saved.role === 'owner' && !isImmutableFounderCaller)) {
            return {
              ok: false,
              status: 403,
              error: 'owner_protected',
              message: 'Only the immutable founder may promote, disable, demote, or delete an owner account',
            };
          }
          return { ok: false, status: 404, error: 'user_not_found' };
        }
      }
      if (deps.metaDb) {
        await deps.metaDb
          .prepare(
            `UPDATE users
                SET role = 'member',
                    promoted_by_owner_id = NULL,
                    disabled = 1,
                    session_epoch = COALESCE(session_epoch, 1) + 1,
                    admitted_via = NULL,
                    admitted_org = NULL,
                    encrypted_gh_token = NULL,
                    org_verified_at = NULL
              WHERE user_id = ?1
                AND user_id != 'owner'
                AND (?2 = '' OR user_id != ?2)
                AND (?3 = 1 OR role != 'owner')`,
          )
          .bind(existingUser.userId, configuredFounderUserId ?? '', isImmutableFounderCaller ? 1 : 0)
          .run()
          .catch(() => undefined);
      }
      const userGrants = await Promise.resolve(deps.oauthStore.listGrants(Date.now(), existingUser.userId)).catch(() => []);
      for (const g of userGrants) {
        await Promise.resolve(deps.revokeGrant(g.grantId, existingUser.userId)).catch(() => false);
      }
      if (deps.vaultStore) {
        const userServers = await Promise.resolve(deps.vaultStore.listServers(existingUser.userId)).catch(() => []);
        for (const s of userServers) {
          await Promise.resolve(deps.vaultStore.deleteServer(existingUser.userId, s.slug)).catch(() => false);
        }
      }
      return { ok: true };
    };

    if ((path === '/admin/api/users/role' && request.method === 'POST') || isUserItemPatch) {
      return withAdminAuditSpan('user_role', async (span) => {
        const capped = await readBodyTextCapped(request, 16_384);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: { userId?: string; role?: string; disabled?: boolean } = {};
        try {
          body = JSON.parse(capped.text || '{}') as typeof body;
        } catch {
          body = {};
        }
        let pathUserId = '';
        if (isUserItemPatch && userIdPathMatch?.[1]) {
          try {
            pathUserId = decodeURIComponent(userIdPathMatch[1]).trim();
          } catch {
            return adminJson({ error: 'invalid_params' }, 400);
          }
        }
        const targetUserId = pathUserId || (typeof body.userId === 'string' ? body.userId.trim() : '');
        const wantsDisable = body.disabled === true;
        const targetRole: UserRole | null = body.role === 'owner' ? 'owner' : body.role === 'member' ? 'member' : null;
        if (!targetUserId || (!targetRole && !wantsDisable)) {
          span.setAttributes({ 'admin.outcome': 'invalid_params', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_params');
          return adminJson({ error: 'invalid_params' }, 400);
        }
        if (targetUserId === session.userId) {
          span.setAttributes({ 'admin.outcome': 'self_modification_forbidden', 'http.response.status_code': 400 });
          span.setStatus(false, 'self_modification_forbidden');
          return adminJson({ ok: false, error: 'self_modification_forbidden', message: 'Cannot modify your own role' }, 400);
        }
        if (isImmutableFounderTarget(targetUserId)) {
          span.setAttributes({ 'admin.outcome': 'founder_protected', 'http.response.status_code': 403 });
          span.setStatus(false, 'founder_protected');
          return adminJson(
            { ok: false, error: 'founder_protected', message: 'Immutable founder/owner cannot be disabled, demoted, or modified' },
            403,
          );
        }
        const existingTarget = (await deps.oauthStore.getUser?.(targetUserId)) ?? null;
        if (!existingTarget || existingTarget.disabled) {
          span.setAttributes({ 'admin.target_user_id': targetUserId, 'admin.outcome': 'not_found', 'http.response.status_code': 404 });
          return adminJson({ ok: false, error: 'user_not_found' }, 404);
        }
        if ((existingTarget.role === 'owner' || targetRole === 'owner') && !isImmutableFounderCaller) {
          span.setAttributes({ 'admin.outcome': 'owner_protected', 'http.response.status_code': 403 });
          span.setStatus(false, 'owner_protected');
          return adminJson(
            {
              ok: false,
              error: 'owner_protected',
              message: 'Only the immutable founder may promote, disable, demote, or delete an owner account',
            },
            403,
          );
        }
        if (wantsDisable) {
          const disRes = await disableAndRevokeTargetUser(existingTarget);
          if (!disRes.ok) {
            span.setAttributes({
              'admin.target_user_id': targetUserId,
              'admin.outcome': disRes.error,
              'http.response.status_code': disRes.status,
            });
            span.setStatus(false, disRes.error);
            return adminJson(
              { ok: false, error: disRes.error, ...(disRes.message ? { message: disRes.message } : {}) },
              disRes.status,
            );
          }
          span.setAttributes({
            'admin.target_user_id': targetUserId,
            'admin.outcome': 'disabled',
            'http.response.status_code': 200,
          });
          return adminJson({ ok: true, disabled: true, userId: targetUserId }, 200);
        }
        const promotedByOwnerId =
          targetRole === 'owner'
            ? session.userId === 'owner'
              ? 'owner'
              : configuredFounderUserId !== null && session.userId === configuredFounderUserId
                ? envOwnerId
                : 'owner'
            : null;
        let updated = false;
        if (deps.oauthStore.upsertUser) {
          const saved = await deps.oauthStore.upsertUser({
            ...existingTarget,
            role: targetRole!,
            promotedByOwnerId: promotedByOwnerId ?? undefined,
            mutationKind: 'admin_role',
          });
          updated = !saved.mutationAborted && !saved.disabled && saved.role === targetRole!;
        } else if (deps.oauthStore.updateUserRole) {
          updated = await deps.oauthStore.updateUserRole(targetUserId, targetRole!, promotedByOwnerId);
        }
        if (updated && deps.metaDb) {
          await deps.metaDb.prepare('ALTER TABLE users ADD COLUMN promoted_by_owner_id TEXT').run().catch(() => undefined);
          await deps.metaDb
            .prepare(
              'UPDATE users SET role = ?1, promoted_by_owner_id = ?2, session_epoch = COALESCE(session_epoch, 1) + 1 WHERE user_id = ?3',
            )
            .bind(targetRole!, promotedByOwnerId, targetUserId)
            .run()
            .catch(() => undefined);
        }
        span.setAttributes({
          'admin.target_user_id': targetUserId,
          'admin.target_role': targetRole!,
          'admin.outcome': updated ? 'updated' : 'not_found',
          'http.response.status_code': updated ? 200 : 404,
        });
        return adminJson({ ok: updated, userId: targetUserId, role: targetRole! }, updated ? 200 : 404);
      });
    }

    if (
      (path === '/admin/api/users/delete' && request.method === 'POST') ||
      (path === '/admin/api/users' && request.method === 'DELETE') ||
      isUserItemDelete
    ) {
      return withAdminAuditSpan('user_delete', async (span) => {
        const capped = await readBodyTextCapped(request, 16_384);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: { userId?: string } = {};
        try {
          body = JSON.parse(capped.text || '{}') as typeof body;
        } catch {
          body = {};
        }
        let pathUserId = '';
        if (isUserItemDelete && userIdPathMatch?.[1]) {
          try {
            pathUserId = decodeURIComponent(userIdPathMatch[1]).trim();
          } catch {
            return adminJson({ ok: false, error: 'invalid_params' }, 400);
          }
        }
        const targetUserId = (
          pathUserId ||
          (typeof body.userId === 'string' && body.userId.trim()
            ? body.userId.trim()
            : (url.searchParams.get('userId') ?? '').trim())
        );
        if (!targetUserId) {
          span.setAttributes({ 'admin.outcome': 'invalid_params', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_params');
          return adminJson({ ok: false, error: 'invalid_params' }, 400);
        }
        if (targetUserId === session.userId) {
          span.setAttributes({ 'admin.outcome': 'self_modification_forbidden', 'http.response.status_code': 400 });
          span.setStatus(false, 'self_modification_forbidden');
          return adminJson({ ok: false, error: 'self_modification_forbidden', message: 'Cannot delete your own account' }, 400);
        }
        if (isImmutableFounderTarget(targetUserId)) {
          span.setAttributes({ 'admin.outcome': 'founder_protected', 'http.response.status_code': 403 });
          span.setStatus(false, 'founder_protected');
          return adminJson({ ok: false, error: 'founder_protected', message: 'Immutable founder/owner cannot be deleted' }, 403);
        }
        const existingUser = (await deps.oauthStore.getUser?.(targetUserId)) ?? null;
        if (!existingUser) {
          span.setAttributes({ 'admin.target_user_id': targetUserId, 'admin.outcome': 'not_found', 'http.response.status_code': 404 });
          return adminJson({ ok: false, error: 'user_not_found' }, 404);
        }
        if (existingUser.role === 'owner' && !isImmutableFounderCaller) {
          span.setAttributes({ 'admin.outcome': 'owner_protected', 'http.response.status_code': 403 });
          span.setStatus(false, 'owner_protected');
          return adminJson(
            { ok: false, error: 'owner_protected', message: 'Only the immutable founder may disable or delete another owner account' },
            403,
          );
        }
        const delRes = await disableAndRevokeTargetUser(existingUser, { allowAlreadyDisabled: true });
        if (!delRes.ok) {
          span.setAttributes({
            'admin.target_user_id': targetUserId,
            'admin.outcome': delRes.error,
            'http.response.status_code': delRes.status,
          });
          span.setStatus(false, delRes.error);
          return adminJson(
            { ok: false, error: delRes.error, ...(delRes.message ? { message: delRes.message } : {}) },
            delRes.status,
          );
        }
        span.setAttributes({
          'admin.target_user_id': targetUserId,
          'admin.outcome': 'deleted',
          'http.response.status_code': 200,
        });
        return adminJson({ ok: true, deleted: true, userId: targetUserId }, 200);
      });
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

    if (path === '/admin/api/telemetry') {
      return withAdminAuditSpan('telemetry_toggle', async (span) => {
        if (!deps.setTelemetryOptIn) {
          span.setAttributes({ 'admin.outcome': 'unsupported', 'http.response.status_code': 501 });
          span.setStatus(false, 'unsupported');
          return adminJson({ error: 'telemetry_settings_unavailable' }, 501);
        }
        const capped = await readBodyTextCapped(request, 4_096);
        if (!capped.ok) {
          const st = capped.error === 'too_large' ? 413 : 400;
          span.setAttributes({ 'admin.outcome': 'payload_too_large', 'http.response.status_code': st });
          span.setStatus(false, 'payload_too_large');
          return adminJson({ error: 'payload_too_large' }, st);
        }
        let body: { enabled?: unknown } = {};
        try {
          body = JSON.parse(capped.text) as { enabled?: unknown };
        } catch {
          span.setAttributes({ 'admin.outcome': 'invalid_json', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_json');
          return adminJson({ error: 'invalid_json' }, 400);
        }
        if (typeof body.enabled !== 'boolean') {
          span.setAttributes({ 'admin.outcome': 'invalid_enabled_flag', 'http.response.status_code': 400 });
          span.setStatus(false, 'invalid_enabled_flag');
          return adminJson({ error: 'invalid_enabled_flag' }, 400);
        }
        const devTelemetry = await deps.setTelemetryOptIn(body.enabled);
        span.setAttributes({
          'admin.telemetry_enabled': devTelemetry.enabled,
          'admin.outcome': 'updated',
          'http.response.status_code': 200,
        });
        return adminJson({ ok: true, devTelemetry }, 200);
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
