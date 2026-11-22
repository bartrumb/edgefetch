/**
 * 1-Click Opt-In OTLP Structural Error Telemetry Exporter & `hub_settings` Store (`hub/src/dev-telemetry.ts`).
 *
 * Strict Privacy & Opt-In Invariants:
 *  1. Unattended default is ALWAYS `OFF` (`EDGEFETCH_DEV_TELEMETRY` unset / `0` / `false` -> `0` outbound telemetry).
 *  2. `DO_NOT_TRACK=1` acts as an unconditional hard disable override even if `EDGEFETCH_DEV_TELEMETRY=1` or `/admin` toggle is ON!
 *  3. Exports ONLY failed (`status.code === 2` / `statusOk === false`) or WAF/adapter-failure spans, scrubbed to the exact 11
 *     allowlisted structural fields:
 *       `{ schemaVersion: 1, version, runtime, os, arch, mode, spanName, adapterId, wafVendor, httpStatus, errorClass }`
 *     — ZERO URLs, ZERO hostnames, ZERO paths, ZERO query strings, ZERO HTML/Markdown content, ZERO raw stack messages, ZERO tokens!
 */
import hubPkg from '../package.json';
import type { SqlStorageLike } from './oauth';
import type { OtlpSpanInput } from './otel';

export const DEFAULT_DEV_TELEMETRY_ENDPOINT = 'https://telemetry.edgefetch.dev/v1/dev-errors';
export const DEV_TELEMETRY_SETTING_KEY = 'dev_error_telemetry';

export const HUB_SETTINGS_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS hub_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
`;

export interface HubSettingsStore {
  getSetting(key: string): Promise<string | null>;
  setSetting(key: string, value: string, now?: number): Promise<void>;
}

export function createSqliteHubSettingsStore(sql: SqlStorageLike): HubSettingsStore {
  return {
    async getSetting(key: string): Promise<string | null> {
      const row = sql
        .exec<{ value: string }>('SELECT value FROM hub_settings WHERE key = ?', key)
        .toArray()[0];
      return typeof row?.value === 'string' ? row.value : null;
    },
    async setSetting(key: string, value: string, now = Date.now()): Promise<void> {
      sql.exec(
        'INSERT OR REPLACE INTO hub_settings (key, value, updated_at) VALUES (?, ?, ?)',
        key,
        value,
        now,
      );
    },
  };
}

export function createMemoryHubSettingsStore(): HubSettingsStore {
  const map = new Map<string, string>();
  return {
    async getSetting(key: string): Promise<string | null> {
      return map.get(key) ?? null;
    },
    async setSetting(key: string, value: string): Promise<void> {
      map.set(key, value);
    },
  };
}

export type TelemetryRuntime = 'workers' | 'node' | 'deno' | 'go';

export interface DevErrorReport {
  schemaVersion: 1;
  version: string;
  runtime: TelemetryRuntime;
  os: string;
  arch: string;
  mode: string;
  spanName: string;
  adapterId: string;
  wafVendor: string;
  httpStatus: number;
  errorClass: string;
}

export interface DevTelemetryEnvConfig {
  EDGEFETCH_DEV_TELEMETRY?: string;
  EDGEFETCH_DEV_TELEMETRY_ENDPOINT?: string;
  EDGEFETCH_DEV_TELEMETRY_URL?: string;
  DO_NOT_TRACK?: string;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  SAFE_FETCH?: typeof fetch;
}

export interface DevTelemetrySettingsView {
  enabled: boolean;
  source: 'default_off' | 'env' | 'admin_opt_in' | 'admin_opt_out' | 'do_not_track';
  doNotTrack: boolean;
  endpoint: string;
  allowlistedFields: readonly string[];
}

export const DEV_ERROR_ALLOWLISTED_FIELDS = [
  'schemaVersion',
  'version',
  'runtime',
  'os',
  'arch',
  'mode',
  'spanName',
  'adapterId',
  'wafVendor',
  'httpStatus',
  'errorClass',
] as const;

const ALLOWLISTED_FIELD_SET: ReadonlySet<string> = new Set(DEV_ERROR_ALLOWLISTED_FIELDS);
const VALID_RUNTIMES: ReadonlySet<string> = new Set(['workers', 'node', 'deno', 'go']);
const SAFE_VERSION_RE = /^[A-Za-z0-9._+-]{1,32}$/;
const SAFE_SHORT_TOKEN_RE = /^[a-z0-9_-]{1,32}$/;
const SAFE_MODE_RE = /^[a-z0-9_,-]{1,32}$/;
const SAFE_SPAN_NAME_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const SAFE_ADAPTER_ID_RE = /^[A-Za-z0-9._:-]{0,64}$/;
const SAFE_WAF_VENDOR_RE = /^[a-z0-9_-]{0,32}$/;
const SAFE_ERROR_CLASS_RE = /^[a-z0-9_:-]{1,64}$/;

export function isTruthyTelemetryFlag(raw?: string | null): boolean {
  const clean = (raw ?? '').trim().toLowerCase();
  return clean === '1' || clean === 'true' || clean === 'yes' || clean === 'on';
}

export function isFalsyTelemetryFlag(raw?: string | null): boolean {
  const clean = (raw ?? '').trim().toLowerCase();
  return clean === '0' || clean === 'false' || clean === 'no' || clean === 'off';
}

export function resolveDevTelemetryEndpoint(env?: DevTelemetryEnvConfig): string | null {
  const raw = (env?.EDGEFETCH_DEV_TELEMETRY_URL ?? env?.EDGEFETCH_DEV_TELEMETRY_ENDPOINT ?? '').trim();
  const target = raw || DEFAULT_DEV_TELEMETRY_ENDPOINT;
  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = '/v1/dev-errors';
  }
  return parsed.toString();
}

export function resolveDevTelemetryState(params: {
  env?: DevTelemetryEnvConfig;
  dbSettingValue?: string | boolean | null;
}): DevTelemetrySettingsView {
  const endpoint = resolveDevTelemetryEndpoint(params.env) ?? DEFAULT_DEV_TELEMETRY_ENDPOINT;
  // `DO_NOT_TRACK=1` is an unconditional hard disable override across all settings & env vars!
  if (isTruthyTelemetryFlag(params.env?.DO_NOT_TRACK)) {
    return {
      enabled: false,
      source: 'do_not_track',
      doNotTrack: true,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }

  const dbRaw =
    typeof params.dbSettingValue === 'boolean'
      ? params.dbSettingValue
        ? '1'
        : '0'
      : params.dbSettingValue;

  if (isTruthyTelemetryFlag(dbRaw)) {
    return {
      enabled: true,
      source: 'admin_opt_in',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  if (isFalsyTelemetryFlag(dbRaw)) {
    return {
      enabled: false,
      source: 'admin_opt_out',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  if (isTruthyTelemetryFlag(params.env?.EDGEFETCH_DEV_TELEMETRY)) {
    return {
      enabled: true,
      source: 'env',
      doNotTrack: false,
      endpoint,
      allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
    };
  }
  return {
    enabled: false,
    source: 'default_off',
    doNotTrack: false,
    endpoint,
    allowlistedFields: DEV_ERROR_ALLOWLISTED_FIELDS,
  };
}

export function detectRuntimeEnvironment(): {
  runtime: TelemetryRuntime;
  os: string;
  arch: string;
} {
  const g = globalThis as Record<string, unknown>;
  const denoObj = g.Deno as { build?: { os?: string; arch?: string } } | undefined;
  if (denoObj && typeof denoObj === 'object') {
    return {
      runtime: 'deno',
      os: sanitizeStructuralField(denoObj.build?.os ?? 'unknown', 24, false) || 'unknown',
      arch: sanitizeStructuralField(denoObj.build?.arch ?? 'unknown', 24, false) || 'unknown',
    };
  }
  const navUa = typeof navigator !== 'undefined' && typeof navigator.userAgent === 'string' ? navigator.userAgent : '';
  if (navUa.includes('Cloudflare-Workers')) {
    return { runtime: 'workers', os: 'cloudflare', arch: 'v8' };
  }
  const proc = g.process as { versions?: { node?: string }; platform?: string; arch?: string } | undefined;
  if (proc?.versions?.node) {
    return {
      runtime: 'node',
      os: sanitizeStructuralField(proc.platform ?? 'unknown', 24, false) || 'unknown',
      arch: sanitizeStructuralField(proc.arch ?? 'unknown', 24, false) || 'unknown',
    };
  }
  return { runtime: 'workers', os: 'cloudflare', arch: 'v8' };
}

function sanitizeStructuralField(raw: unknown, maxLen: number, allowUpper: boolean): string {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const lower = trimmed.toLowerCase();
  if (lower.includes('http://') || lower.includes('https://') || lower.includes('://')) {
    return '';
  }
  const src = allowUpper ? trimmed : lower;
  let out = '';
  for (let i = 0; i < src.length && out.length < maxLen; i++) {
    const ch = src.charCodeAt(i);
    const isLower = ch >= 97 && ch <= 122;
    const isUpper = allowUpper && ch >= 65 && ch <= 90;
    const isDigit = ch >= 48 && ch <= 57;
    if (isLower || isUpper || isDigit || ch === 95 || ch === 45 || ch === 46 || ch === 58) {
      out += src[i]!;
    }
  }
  return out;
}

export function classifyTelemetryErrorClass(params: {
  httpStatus: number;
  outcome?: string;
  wafVendor?: string;
  errorMessage?: string;
}): string {
  const out = (params.outcome ?? '').trim().toLowerCase();
  const waf = (params.wafVendor ?? '').trim().toLowerCase();
  const msg = (params.errorMessage ?? '').trim().toLowerCase();

  if (out === 'challenge') return 'waf_challenge';
  if (out === 'rate_limited') return 'rate_limited';
  if (out === 'payment_required') return 'payment_required';
  if (out === 'blocked') {
    return msg.includes('robots') ? 'robots_disallowed' : 'waf_block';
  }
  if (waf) {
    return params.httpStatus === 429 ? 'rate_limited' : 'waf_challenge';
  }
  if (msg.includes('robots')) return 'robots_disallowed';
  if (msg.includes('ssrf') || msg.includes('non-public') || msg.includes('private')) return 'ssrf_blocked';
  if (msg.includes('timeout') || msg.includes('timed out') || msg.includes('aborted')) return 'timeout';
  if (msg.includes('tls') || msg.includes('certificate')) return 'tls_error';
  if (msg.includes('dns') || msg.includes('enotfound')) return 'dns_error';
  if (msg.includes('econnrefused') || msg.includes('econnreset') || msg.includes('connect')) return 'connect_error';
  if (msg.includes('browser') || msg.includes('chromium') || msg.includes('cdp')) return 'browser_error';
  if (msg.includes('adapter') || msg.includes('extractor')) return 'adapter_error';

  if (params.httpStatus === 401) return 'http_401';
  if (params.httpStatus === 402) return 'payment_required';
  if (params.httpStatus === 403) return 'http_403';
  if (params.httpStatus === 404) return 'http_404';
  if (params.httpStatus === 429) return 'rate_limited';
  if (params.httpStatus >= 400 && params.httpStatus < 500) return 'http_4xx';
  if (params.httpStatus >= 500 && params.httpStatus < 600) return 'http_5xx';
  return 'internal_error';
}

export function validateDevErrorReport(candidate: unknown): { ok: true; value: DevErrorReport } | { ok: false; error: string } {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return { ok: false, error: 'event must be a JSON object' };
  }
  const obj = candidate as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== ALLOWLISTED_FIELD_SET.size) {
    return { ok: false, error: 'unexpected or missing keys on telemetry event' };
  }
  for (const k of keys) {
    if (!ALLOWLISTED_FIELD_SET.has(k)) {
      return { ok: false, error: `disallowed key: ${k}` };
    }
  }
  for (const [, val] of Object.entries(obj)) {
    if (typeof val === 'string') {
      const lower = val.toLowerCase();
      if (lower.includes('http://') || lower.includes('https://') || lower.includes('://')) {
        return { ok: false, error: 'URL substring forbidden in telemetry field' };
      }
    }
  }
  if (obj.schemaVersion !== 1) {
    return { ok: false, error: 'schemaVersion must equal 1' };
  }
  if (typeof obj.version !== 'string' || !SAFE_VERSION_RE.test(obj.version)) {
    return { ok: false, error: 'invalid version' };
  }
  if (typeof obj.runtime !== 'string' || !VALID_RUNTIMES.has(obj.runtime)) {
    return { ok: false, error: 'invalid runtime' };
  }
  if (typeof obj.os !== 'string' || !SAFE_SHORT_TOKEN_RE.test(obj.os)) {
    return { ok: false, error: 'invalid os' };
  }
  if (typeof obj.arch !== 'string' || !SAFE_SHORT_TOKEN_RE.test(obj.arch)) {
    return { ok: false, error: 'invalid arch' };
  }
  if (typeof obj.mode !== 'string' || !SAFE_MODE_RE.test(obj.mode)) {
    return { ok: false, error: 'invalid mode' };
  }
  if (typeof obj.spanName !== 'string' || !SAFE_SPAN_NAME_RE.test(obj.spanName)) {
    return { ok: false, error: 'invalid spanName' };
  }
  if (typeof obj.adapterId !== 'string' || !SAFE_ADAPTER_ID_RE.test(obj.adapterId)) {
    return { ok: false, error: 'invalid adapterId' };
  }
  if (typeof obj.wafVendor !== 'string' || !SAFE_WAF_VENDOR_RE.test(obj.wafVendor)) {
    return { ok: false, error: 'invalid wafVendor' };
  }
  if (typeof obj.httpStatus !== 'number' || !Number.isInteger(obj.httpStatus) || obj.httpStatus < 0 || obj.httpStatus > 599) {
    return { ok: false, error: 'invalid httpStatus' };
  }
  if (typeof obj.errorClass !== 'string' || !SAFE_ERROR_CLASS_RE.test(obj.errorClass)) {
    return { ok: false, error: 'invalid errorClass' };
  }
  return {
    ok: true,
    value: {
      schemaVersion: 1,
      version: obj.version,
      runtime: obj.runtime as TelemetryRuntime,
      os: obj.os,
      arch: obj.arch,
      mode: obj.mode,
      spanName: obj.spanName,
      adapterId: obj.adapterId,
      wafVendor: obj.wafVendor,
      httpStatus: obj.httpStatus,
      errorClass: obj.errorClass,
    },
  };
}

/**
 * Scrubs an `OtlpSpanInput` to ONLY the 11 allowlisted structural fields when the span represents an error
 * (`statusOk === false` / `status.code === 2`) or WAF/adapter failure. Healthy spans return `null`.
 */
export function scrubSpanToDevErrorReport(
  span: OtlpSpanInput,
  meta?: {
    version?: string;
    runtime?: TelemetryRuntime;
    os?: string;
    arch?: string;
    mode?: string;
  },
): DevErrorReport | null {
  const attrs = span.attributes ?? {};
  const rawWaf =
    typeof attrs['edgefetch.waf.vendor'] === 'string'
      ? attrs['edgefetch.waf.vendor']
      : typeof attrs['waf.vendor'] === 'string'
        ? attrs['waf.vendor']
        : '';
  const wafVendor = sanitizeStructuralField(rawWaf, 32, false);
  const rawOutcome =
    typeof attrs['crawler.outcome'] === 'string'
      ? attrs['crawler.outcome']
      : typeof attrs['edgefetch.outcome'] === 'string'
        ? attrs['edgefetch.outcome']
        : '';
  const isErrorOrWaf =
    span.statusOk === false ||
    Boolean(wafVendor) ||
    rawOutcome === 'challenge' ||
    rawOutcome === 'rate_limited' ||
    rawOutcome === 'error';

  if (!isErrorOrWaf) {
    return null;
  }

  const detected = detectRuntimeEnvironment();
  const rawVersion = (meta?.version ?? (typeof hubPkg?.version === 'string' ? hubPkg.version : '2.6.3')).replace(/^v/i, '');
  const version = SAFE_VERSION_RE.test(rawVersion) ? rawVersion : 'unknown';
  const runtime = meta?.runtime && VALID_RUNTIMES.has(meta.runtime) ? meta.runtime : detected.runtime;
  const os = sanitizeStructuralField(meta?.os ?? detected.os, 24, false) || 'unknown';
  const arch = sanitizeStructuralField(meta?.arch ?? detected.arch, 24, false) || 'unknown';
  const mode = sanitizeStructuralField(meta?.mode ?? 'hub', 32, false) || 'hub';
  const spanName = sanitizeStructuralField(span.name, 96, true) || 'edgefetch.span';
  const rawAdapter =
    typeof attrs['edgefetch.adapter_id'] === 'string'
      ? attrs['edgefetch.adapter_id']
      : typeof attrs['adapter.id'] === 'string'
        ? attrs['adapter.id']
        : '';
  const adapterId = sanitizeStructuralField(rawAdapter.split(',')[0] ?? '', 64, true);

  const rawStatus = attrs['http.response.status_code'] ?? attrs['http.status_code'] ?? 0;
  const parsedStatus = typeof rawStatus === 'number' ? Math.floor(rawStatus) : Number(rawStatus);
  const httpStatus = Number.isInteger(parsedStatus) && parsedStatus >= 0 && parsedStatus <= 599 ? parsedStatus : 0;

  const errorClass = classifyTelemetryErrorClass({
    httpStatus,
    outcome: rawOutcome,
    wafVendor,
    errorMessage: span.errorMessage,
  });

  const report: DevErrorReport = {
    schemaVersion: 1,
    version,
    runtime,
    os,
    arch,
    mode,
    spanName,
    adapterId,
    wafVendor,
    httpStatus,
    errorClass,
  };
  const checked = validateDevErrorReport(report);
  return checked.ok ? checked.value : null;
}

/**
 * Exports scrubbed `status=ERROR` / WAF-failure spans asynchronously when opt-in telemetry is enabled.
 * Never throws and sends `0` bytes when disabled or when `DO_NOT_TRACK=1` is set.
 */
export async function flushDevErrorTelemetry(params: {
  env: DevTelemetryEnvConfig;
  spans: OtlpSpanInput[];
  dbSettingValue?: string | boolean | null;
  version?: string;
  mode?: string;
  fetchFn?: typeof fetch;
}): Promise<boolean> {
  if (params.spans.length === 0) return false;
  const state = resolveDevTelemetryState({
    env: params.env,
    dbSettingValue: params.dbSettingValue,
  });
  if (!state.enabled) return false;

  const endpoint = resolveDevTelemetryEndpoint(params.env);
  if (!endpoint) return false;

  const seen = new Set<string>();
  const events: DevErrorReport[] = [];
  for (const sp of params.spans) {
    const scrubbed = scrubSpanToDevErrorReport(sp, {
      ...(params.version ? { version: params.version } : {}),
      ...(params.mode ? { mode: params.mode } : {}),
    });
    if (!scrubbed) continue;
    const dedupKey = `${scrubbed.spanName}|${scrubbed.adapterId}|${scrubbed.wafVendor}|${scrubbed.httpStatus}|${scrubbed.errorClass}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    events.push(scrubbed);
    if (events.length >= 16) break;
  }
  if (events.length === 0) return false;

  const bodyStr = JSON.stringify(events.length === 1 ? events[0]! : { events });
  if (new TextEncoder().encode(bodyStr).byteLength > 8_192) {
    return false;
  }

  const doFetch = params.fetchFn ?? params.env.SAFE_PUBLIC_FETCH ?? params.env.SAFE_FETCH ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('Dev error telemetry export timed out', 'TimeoutError'));
  }, 2_500);
  (timer as { unref?: () => void }).unref?.();

  try {
    const res = await doFetch(endpoint, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/json' },
      body: bodyStr,
      signal: ctrl.signal,
    });
    await res.body?.cancel().catch(() => undefined);
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
