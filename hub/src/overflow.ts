/**
 * Cloudflare overflow fetch & RFC 9309 `robots.txt` evaluator (`H-S4`, `A4`, `A5`).
 *
 * Security & Politeness Invariants:
 *  - `RobotsMaxBytes = 524_288` (`512 KiB`, >= RFC 9309 §2.5 500 KiB minimum) with UTF-8 BOM stripping,
 *    RFC 9309 §2.2.2 percent-encoding normalization, exact product-token matching, and iterative O(P*T) wildcard matching.
 *  - `redirect: 'manual'` up to 5 hops: EVERY hop re-validates `https://` on port `443`, blocks credentials / IP literals /
 *    recursive self-hub hostnames, enforces per-host `pauseMs` / `Crawl-delay`, and re-checks `/robots.txt` BEFORE fetching.
 *  - Per-request (`30s`) AND total-call (`maxSeconds`) `AbortSignal` deadlines prevent hung streams from ignoring budgets.
 *  - `respectRobots: false` is rejected unless every target host matches the owner's explicit `ROBOTS_BYPASS_HOSTS` allowlist
 *    (empty/off by default) and emits a security event when used.
 */
import { parseExactRetryAfterMs, recomputeSummary, type CrawlResultItem } from './agent-hub';
import { signOutboundBotHeaders } from './bot-auth';
import { filterSafeResponseHeaders } from './framework-detect';
import { classifyWafAndChallenge } from './waf';

export const ROBOTS_MAX_BYTES = 1024 * 1024; // 1 MiB >= RFC 9309 500 KiB minimum
export const MAX_OVERFLOW_BATCH_BYTES = 18 * 1024 * 1024; // 18 MiB aggregate batch cap across all requests (`Low`)
const ROBOTS_TIMEOUT_MS = 10_000;
const PER_REQ_TIMEOUT_MS = 30_000;
const MAX_REDIRECT_HOPS = 5;
const ROBOTS_CACHE_MIN_MS = 60_000;
const ROBOTS_CACHE_MAX_MS = 86_400_000;
const ROBOTS_CACHE_DEFAULT_MS = 3_600_000;
const MAX_ROBOTS_CACHE_ENTRIES = 512;
export const MARKDOWN_FOR_AGENTS_ACCEPT =
  'text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, */*;q=0.7';

export interface ContentSignals {
  search?: boolean;
  aiInput?: boolean;
  aiTrain?: boolean;
}

export interface ParsedRobots {
  unreachable: boolean;
  reason?: string;
  crawlDelayMs: number;
  rules: Array<{ pattern: string; allow: boolean }>;
  contentSignals?: ContentSignals;
  disallowAiInput?: boolean;
  cacheTtlMs?: number;
}

function isUnreservedAsciiByte(b: number): boolean {
  return (
    (b >= 0x41 && b <= 0x5a) || // A-Z
    (b >= 0x61 && b <= 0x7a) || // a-z
    (b >= 0x30 && b <= 0x39) || // 0-9
    b === 0x2d || // -
    b === 0x2e || // .
    b === 0x5f || // _
    b === 0x7e // ~
  );
}

/** Normalizes percent-encoding in `/robots.txt` rules and target paths per RFC 9309 §2.2.2. */
export function normalizeRobotsURI(raw: string): string {
  const bytes = new TextEncoder().encode(raw);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b === 0x25 && i + 2 < bytes.length) {
      const hex = String.fromCharCode(bytes[i + 1]!, bytes[i + 2]!);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        const decoded = parseInt(hex, 16);
        if (isUnreservedAsciiByte(decoded)) {
          out += String.fromCharCode(decoded);
        } else {
          out += `%${hex.toUpperCase()}`;
        }
        i += 2;
        continue;
      }
    }
    if (b >= 0x80) {
      out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
    } else {
      out += String.fromCharCode(b);
    }
  }
  return out;
}

function canonicalProductToken(raw: string): string {
  const trimmed = raw.replace(/[\u200B-\u200F\u2060\uFEFF]/g, '').trim().toLowerCase();
  if (!trimmed) return '';
  if (trimmed === '*') return '*';
  const slash = trimmed.indexOf('/');
  const head = slash >= 0 ? trimmed.slice(0, slash) : trimmed;
  const token = head.split(/\s+/)[0] ?? '';
  const cleanMatch = /^[a-z_-]+/.exec(token);
  return cleanMatch ? cleanMatch[0] : '';
}

/** Iterative O(P*T) wildcard matcher (`*` and trailing `$`) with zero ReDoS surface. */
export function matchRobotsPattern(rawPattern: string, target: string): boolean {
  const anchoredEnd = rawPattern.endsWith('$');
  const pattern = anchoredEnd ? rawPattern.slice(0, -1) : rawPattern;
  if (!pattern.includes('*')) {
    return anchoredEnd ? target === pattern : target.startsWith(pattern);
  }
  const trailingStar = pattern.endsWith('*');
  const parts = pattern.split('*');
  let pos = 0;
  let lastNonEmpty = '';
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (!part) continue;
    lastNonEmpty = part;
    if (i === 0) {
      if (!target.startsWith(part)) return false;
      pos = part.length;
    } else {
      const idx = target.indexOf(part, pos);
      if (idx < 0) return false;
      pos = idx + part.length;
    }
  }
  if (anchoredEnd && !trailingStar && lastNonEmpty) {
    return target.endsWith(lastNonEmpty);
  }
  return true;
}

function trimAsciiSpaceTab(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && (s.charCodeAt(start) === 32 || s.charCodeAt(start) === 9)) start++;
  while (end > start && (s.charCodeAt(end - 1) === 32 || s.charCodeAt(end - 1) === 9)) end--;
  return start === 0 && end === s.length ? s : s.slice(start, end);
}

function applySingleContentSignalPair(rawKey: string, rawValue: string, target: ContentSignals): boolean {
  const k = trimAsciiSpaceTab(rawKey).toLowerCase();
  if (k !== 'search' && k !== 'ai-input' && k !== 'ai-train') return false;
  let v = trimAsciiSpaceTab(rawValue);
  if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
    v = trimAsciiSpaceTab(v.slice(1, -1));
  }
  v = v.toLowerCase();
  if (v !== 'yes' && v !== 'no') return false;
  const allowed = v === 'yes';
  if (k === 'search') target.search = allowed;
  else if (k === 'ai-input') target.aiInput = allowed;
  else if (k === 'ai-train') target.aiTrain = allowed;
  return true;
}

function parseContentSignalLine(rawVal: string, target: ContentSignals): void {
  const bounded = rawVal.length > 524_288 ? rawVal.slice(0, 524_288) : rawVal;
  for (const seg of bounded.split(/[,;]/)) {
    const eq = seg.indexOf('=');
    if (eq <= 0) continue;
    applySingleContentSignalPair(seg.slice(0, eq), seg.slice(eq + 1), target);
  }
}

function mergeGroupSignals(into: ContentSignals, from: ContentSignals): void {
  for (const key of ['search', 'aiInput', 'aiTrain'] as const) {
    if (from[key] !== undefined) {
      // Across multiple combined groups of the same specificity, explicit `no` (`false`) takes restrictive precedence.
      into[key] = into[key] === false ? false : from[key];
    }
  }
}

export function parseRobotsCacheControlTtlMs(cacheControlHeader: string | null | undefined, defaultMs = ROBOTS_CACHE_DEFAULT_MS): number {
  if (typeof cacheControlHeader === 'string' && cacheControlHeader.trim()) {
    const m = /(?:^|[,\s])max-age\s*=\s*"?(\d+)"?/i.exec(cacheControlHeader);
    if (m?.[1]) {
      const secs = Number(m[1]);
      if (Number.isFinite(secs) && secs >= 0) {
        return Math.min(ROBOTS_CACHE_MAX_MS, Math.max(ROBOTS_CACHE_MIN_MS, Math.round(secs * 1_000)));
      }
    }
  }
  return Math.min(ROBOTS_CACHE_MAX_MS, Math.max(ROBOTS_CACHE_MIN_MS, defaultMs));
}

export function parseOverflowRobotsTxt(rawBody: string, userAgent = 'EdgeFetch/2.6.0'): ParsedRobots {
  // Strip repeated UTF-8 BOMs (decoded U+FEFF or byte-decoded \xEF\xBB\xBF) and normalize all Unicode/ASCII line breaks.
  const body = rawBody
    .replace(/^(?:\uFEFF|\xEF\xBB\xBF)+/, '')
    .replace(/\r\n|\r|\u0085|\u2028|\u2029/g, '\n');
  const uaToken = canonicalProductToken(userAgent);
  const preGroupSignals: ContentSignals = {};
  const groups: Array<{
    agents: string[];
    rules: Array<{ pattern: string; allow: boolean }>;
    crawlDelayMs: number;
    signals: ContentSignals;
  }> = [];
  let cur = {
    agents: [] as string[],
    rules: [] as Array<{ pattern: string; allow: boolean }>,
    crawlDelayMs: 0,
    signals: {} as ContentSignals,
  };
  let seenDirective = false;

  for (const rawLine of body.split('\n')) {
    const hashIdx = rawLine.indexOf('#');
    const noComment = hashIdx >= 0 ? rawLine.slice(0, hashIdx) : rawLine;
    const line = noComment.trim();
    if (!line) {
      // RFC 9309 §2.2.1: blank lines inside a group do NOT close the current User-agent group.
      continue;
    }
    const colon = noComment.indexOf(':');
    if (colon <= 0) continue;
    const rawField = noComment.slice(0, colon);
    if (rawField.includes('\0')) continue;
    const field = rawField.trim().toLowerCase();
    const rawValAfterColon = noComment.slice(colon + 1);
    const val = rawValAfterColon.trim();
    if (field === 'user-agent') {
      const parsedUa = canonicalProductToken(val);
      if (!val || !parsedUa) {
        // Ignore empty `User-agent:` lines consistently with Go without closing the active group.
        continue;
      }
      if (seenDirective && cur.agents.length > 0) {
        groups.push(cur);
        cur = { agents: [], rules: [], crawlDelayMs: 0, signals: {} };
        seenDirective = false;
      }
      cur.agents.push(parsedUa);
    } else if (field === 'allow' && cur.agents.length > 0 && val) {
      seenDirective = true;
      const norm = normalizeRobotsURI(val);
      if (norm.startsWith('/') || norm.startsWith('*')) {
        cur.rules.push({ pattern: norm, allow: true });
      }
    } else if (field === 'disallow' && cur.agents.length > 0) {
      seenDirective = true;
      if (val === '') {
        cur.rules.push({ pattern: '/', allow: true });
      } else {
        const norm = normalizeRobotsURI(val);
        if (norm.startsWith('/') || norm.startsWith('*')) {
          cur.rules.push({ pattern: norm, allow: false });
        }
      }
    } else if (field === 'crawl-delay' && cur.agents.length > 0) {
      seenDirective = true;
      const secs = Number(val);
      if (Number.isFinite(secs) && secs > 0) {
        cur.crawlDelayMs = Math.min(30_000, Math.round(secs * 1000));
      }
    } else if (field === 'content-signal') {
      const csVal = trimAsciiSpaceTab(rawValAfterColon);
      if (csVal) {
        if (cur.agents.length === 0) {
          parseContentSignalLine(csVal, preGroupSignals);
        } else {
          seenDirective = true;
          parseContentSignalLine(csVal, cur.signals);
        }
      }
    }
  }
  if (cur.agents.length > 0) groups.push(cur);

  const specific: Array<{ pattern: string; allow: boolean }> = [];
  const wildcard: Array<{ pattern: string; allow: boolean }> = [];
  const specificSignals: ContentSignals = {};
  const wildcardSignals: ContentSignals = {};
  let specificDelay = 0;
  let wildcardDelay = 0;
  let hasSpecific = false;

  for (const g of groups) {
    const matchesSpecific = Boolean(uaToken && g.agents.includes(uaToken));
    const matchesWildcard = g.agents.includes('*');
    if (matchesSpecific) {
      hasSpecific = true;
      specific.push(...g.rules);
      specificDelay = Math.max(specificDelay, g.crawlDelayMs);
      mergeGroupSignals(specificSignals, g.signals);
    }
    if (matchesWildcard) {
      wildcard.push(...g.rules);
      wildcardDelay = Math.max(wildcardDelay, g.crawlDelayMs);
      mergeGroupSignals(wildcardSignals, g.signals);
    }
  }

  // Inherit unset Content-Signal keys from `*` groups, and fall back to pre-group `Content-Signal:` lines.
  const winningSignals: ContentSignals = {};
  for (const key of ['search', 'aiInput', 'aiTrain'] as const) {
    const resolved =
      hasSpecific && specificSignals[key] !== undefined
        ? specificSignals[key]
        : wildcardSignals[key] !== undefined
          ? wildcardSignals[key]
          : preGroupSignals[key];
    if (resolved !== undefined) {
      winningSignals[key] = resolved;
    }
  }

  const hasAnySignal =
    winningSignals.search !== undefined || winningSignals.aiInput !== undefined || winningSignals.aiTrain !== undefined;
  const disallowAiInput = winningSignals.aiInput === false;

  return {
    unreachable: false,
    ...(disallowAiInput ? { reason: 'content-signal: ai-input=no in robots.txt', disallowAiInput: true } : {}),
    ...(hasAnySignal ? { contentSignals: winningSignals } : {}),
    crawlDelayMs: hasSpecific ? specificDelay : wildcardDelay,
    rules: hasSpecific ? specific : wildcard,
  };
}

export function isRobotsAllowed(entry: ParsedRobots, rawPathAndQuery: string): boolean {
  if (entry.unreachable || entry.disallowAiInput) return false;
  if (entry.rules.length === 0) return true;
  const target = normalizeRobotsURI(rawPathAndQuery || '/');
  let bestLen = -1;
  let bestAllow = true;
  for (const r of entry.rules) {
    if (!r.pattern) continue;
    if (matchRobotsPattern(r.pattern, target)) {
      if (r.pattern.length > bestLen || (r.pattern.length === bestLen && r.allow)) {
        bestLen = r.pattern.length;
        bestAllow = r.allow;
      }
    }
  }
  return bestAllow;
}

export function parseHostAllowlist(raw?: string): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, ''))
    .filter((s) => Boolean(s) && s !== '*' && s !== 'none');
}

export function isHostInAllowlist(host: string, allowlist: string[]): boolean {
  const h = host.trim().toLowerCase().replace(/\.+$/, '');
  if (!h || allowlist.length === 0) return false;
  return allowlist.some((allowed) => h === allowed || h.endsWith(`.${allowed}`));
}

/** Validates a raw JSON call body against the owner's `ROBOTS_BYPASS_HOSTS` policy (`A5`). */
export function validateCallRobotsPolicy(
  rawBody: string,
  bypassAllowlist: string[],
): { ok: true; bypassedHosts: string[] } | { ok: false; error: string; message: string } {
  let parsed: {
    requests?: Array<{ url?: unknown }>;
    options?: { respectRobots?: unknown; robots?: unknown };
  };
  try {
    parsed = JSON.parse(rawBody) as typeof parsed;
  } catch {
    return { ok: true, bypassedHosts: [] }; // downstream handles malformed JSON
  }
  const explicitRespect =
    typeof parsed.options?.respectRobots === 'boolean'
      ? parsed.options.respectRobots
      : typeof parsed.options?.robots === 'boolean'
        ? parsed.options.robots
        : true;
  if (explicitRespect) return { ok: true, bypassedHosts: [] };

  const reqs = Array.isArray(parsed.requests) ? parsed.requests : [];
  const bypassedHosts = new Set<string>();
  for (let i = 0; i < reqs.length; i++) {
    let host = '';
    try {
      host = new URL(String(reqs[i]?.url ?? '')).hostname.toLowerCase().replace(/\.+$/, '');
    } catch {
      continue;
    }
    if (!isHostInAllowlist(host, bypassAllowlist)) {
      return {
        ok: false,
        error: 'robots_required',
        message: `request ${i}: disabling robots.txt is not permitted for host '${host}'`,
      };
    }
    bypassedHosts.add(host);
  }
  return { ok: true, bypassedHosts: [...bypassedHosts] };
}

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

/**
 * Validates that a hostname is a public internet DNS name and NOT an IP literal, numeric/hex IPv4 obfuscation,
 * loopback/LAN/metadata name, wildcard DNS-rebinding domain, or recursive self-hub hostname.
 */
export function isSafePublicHostname(rawHost: string, selfHost?: string): boolean {
  const host = rawHost.trim().toLowerCase().replace(/\.+$/, '');
  if (!host || host.length > 253 || !host.includes('.') || /[\s\0-\x1f]/.test(host)) {
    return false;
  }
  if (host.includes(':') || host.startsWith('[') || host.endsWith(']')) {
    return false;
  }
  if (DISALLOWED_EXACT_HOSTS.has(host)) {
    return false;
  }
  for (const suffix of DISALLOWED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return false;
  }
  const canonicalSelf = selfHost?.trim().toLowerCase().replace(/\.+$/, '') ?? '';
  if (canonicalSelf && host === canonicalSelf) {
    return false;
  }
  const labels = host.split('.');
  if (labels.some((lbl) => !lbl || lbl.startsWith('-') || lbl.endsWith('-'))) {
    return false;
  }
  // ICANN TLDs are never purely numeric or hex; rejecting numeric/hex final labels blocks dotted IPv4,
  // 2/3-part IPv4 (`127.1`), octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), and integer IPv4s (`2130706433`).
  const tld = labels[labels.length - 1]!;
  if (/^(?:\d+|0x[0-9a-f]+)$/i.test(tld)) {
    return false;
  }
  return true;
}

/** Validates a public `https://` target URL on port 443 against SSRF, DNS-rebinding, and recursive self-hub fetching. */
export function validatePublicHttpsTargetUrl(
  raw: unknown,
  selfHost?: string,
): { ok: true; url: URL; normalized: string } | { ok: false; error: 'invalid_url'; message: string } {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, error: 'invalid_url', message: 'url must be a non-empty https:// string' };
  }
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { ok: false, error: 'invalid_url', message: `invalid URL: ${raw}` };
  }
  if (u.protocol !== 'https:') {
    return { ok: false, error: 'invalid_url', message: 'only https:// URLs are permitted' };
  }
  if (u.username || u.password) {
    return { ok: false, error: 'invalid_url', message: 'URLs with embedded credentials are not permitted' };
  }
  if (u.port && u.port !== '443') {
    return { ok: false, error: 'invalid_url', message: 'only port 443 is permitted' };
  }
  if (!isSafePublicHostname(u.hostname, selfHost)) {
    return { ok: false, error: 'invalid_url', message: `disallowed hostname: ${u.hostname}` };
  }
  return { ok: true, url: u, normalized: u.toString() };
}

/** Validates all target URLs inside a serialized Hub fetch call payload before dispatching to any agent or container. */
export function validateCallTargetUrls(
  rawBody: string,
  selfHost?: string,
): { ok: true } | { ok: false; error: 'invalid_url'; message: string } {
  let parsed: {
    requests?: Array<{
      url?: unknown;
      sessionId?: unknown;
      actions?: Array<{ type?: unknown; url?: unknown }>;
      interact?: {
        sessionId?: unknown;
        actions?: Array<{ type?: unknown; url?: unknown }>;
      };
    }>;
  };
  try {
    parsed = JSON.parse(rawBody) as typeof parsed;
  } catch {
    return { ok: true }; // downstream handles malformed JSON
  }
  const reqs = Array.isArray(parsed.requests) ? parsed.requests : [];
  for (let i = 0; i < reqs.length; i++) {
    const req = reqs[i];
    if (!req || typeof req !== 'object') continue;
    const rawUrl = req.url;
    const resumeSessionId =
      (typeof req.sessionId === 'string' && req.sessionId.trim()) ||
      (req.interact && typeof req.interact === 'object' && typeof req.interact.sessionId === 'string' && req.interact.sessionId.trim()) ||
      '';
    const hasSessionResume = resumeSessionId.length > 0;
    if ((rawUrl === undefined || (typeof rawUrl === 'string' && rawUrl.trim() === '')) && hasSessionResume) {
      // Allowed for `interact` session resume / close turns where `url` is omitted.
    } else if (rawUrl !== undefined) {
      const check = validatePublicHttpsTargetUrl(rawUrl, selfHost);
      if (!check.ok) {
        return { ok: false, error: 'invalid_url', message: `request ${i}: ${check.message}` };
      }
    }
    const allActions = [
      ...(Array.isArray(req.actions) ? req.actions : []),
      ...(req.interact && typeof req.interact === 'object' && Array.isArray(req.interact.actions) ? req.interact.actions : []),
    ];
    for (let j = 0; j < allActions.length; j++) {
      const act = allActions[j];
      if (act && typeof act === 'object' && String(act.type ?? '').toLowerCase() === 'navigate') {
        const navCheck = validatePublicHttpsTargetUrl(act.url, selfHost);
        if (!navCheck.ok) {
          return { ok: false, error: 'invalid_url', message: `request ${i} action ${j}: ${navCheck.message}` };
        }
      }
    }
  }
  return { ok: true };
}

function isDisallowedOverflowUrl(u: URL, canonicalSelf: string): boolean {
  return (
    u.protocol !== 'https:' ||
    Boolean(u.username || u.password) ||
    Boolean(u.port && u.port !== '443') ||
    !isSafePublicHostname(u.hostname, canonicalSelf)
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.byteLength; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(bytes.byteLength, i + chunkSize));
    parts.push(String.fromCharCode(...slice));
  }
  return btoa(parts.join(''));
}

export function encodeBodyForWire(bytes: Uint8Array): { body: string; bodyEncoding: 'utf-8' | 'base64' } {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { body: text, bodyEncoding: 'utf-8' };
  } catch {
    return { body: bytesToBase64(bytes), bodyEncoding: 'base64' };
  }
}

async function readBoundedBytes(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!body) return { bytes: new Uint8Array(0), truncated: false };
  const reader = body.getReader();
  const onAbort = () => {
    reader.cancel('aborted').catch(() => undefined);
  };
  signal.addEventListener('abort', onAbort, { once: true });
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      if (signal.aborted) throw signal.reason ?? new Error('aborted');
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        if (total + value.byteLength > maxBytes) {
          truncated = true;
          const keep = Math.max(0, maxBytes - total);
          if (keep > 0) {
            chunks.push(value.subarray(0, keep));
            total += keep;
          }
          await reader.cancel().catch(() => undefined);
          break;
        }
        chunks.push(value);
        total += value.byteLength;
      }
    }
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return { bytes: out, truncated };
}

const hubRobotsTtlCache = new Map<string, { entry: ParsedRobots; expiresAt: number }>();

export function resetOverflowRobotsCacheForTests(): void {
  hubRobotsTtlCache.clear();
}

function readCachedHubRobots(cacheKey: string, now: number): ParsedRobots | undefined {
  const hit = hubRobotsTtlCache.get(cacheKey);
  if (!hit) return undefined;
  if (now >= hit.expiresAt) {
    hubRobotsTtlCache.delete(cacheKey);
    return undefined;
  }
  return hit.entry;
}

function storeCachedHubRobots(cacheKey: string, entry: ParsedRobots, now: number): void {
  const ttl = entry.cacheTtlMs ?? (entry.unreachable ? ROBOTS_CACHE_MIN_MS : ROBOTS_CACHE_DEFAULT_MS);
  const clampedTtl = Math.min(ROBOTS_CACHE_MAX_MS, Math.max(ROBOTS_CACHE_MIN_MS, ttl));
  hubRobotsTtlCache.delete(cacheKey);
  hubRobotsTtlCache.set(cacheKey, { entry, expiresAt: now + clampedTtl });
  while (hubRobotsTtlCache.size > MAX_ROBOTS_CACHE_ENTRIES) {
    const oldest = hubRobotsTtlCache.keys().next().value;
    if (oldest === undefined) break;
    hubRobotsTtlCache.delete(oldest);
  }
}

const AUTO_KIND_ACCEPTABLE_CT_RE =
  /^(?:text\/[a-z0-9.+-]+|application\/(?:[a-z0-9.+-]*\+)?(?:json|xml)|application\/(?:xhtml\+xml|rss\+xml|atom\+xml|x-ndjson|yaml|x-yaml|csv|javascript|ecmascript))(?:[;\s]|$)/i;

function readCallerHeaderCaseInsensitive(
  hdrs: Record<string, unknown> | undefined,
  targetNameLower: string,
): string | undefined {
  if (!hdrs || typeof hdrs !== 'object' || Array.isArray(hdrs)) return undefined;
  for (const [k, v] of Object.entries(hdrs)) {
    if (k.toLowerCase() === targetNameLower && typeof v === 'string' && v.trim() && !/[\r\n\0]/.test(v)) {
      return v.trim();
    }
  }
  return undefined;
}

export async function fetchOverflowRobots(
  origin: string,
  userAgent: string,
  fetchFn: typeof fetch,
  budgetDeadlineAt: number,
  canonicalSelf = '',
): Promise<ParsedRobots> {
  const remMs = budgetDeadlineAt - Date.now();
  if (remMs <= 0) {
    return {
      unreachable: true,
      reason: 'robots_unreachable: request budget exhausted before robots.txt check',
      crawlDelayMs: 0,
      rules: [],
      cacheTtlMs: ROBOTS_CACHE_MIN_MS,
    };
  }
  const signal = AbortSignal.timeout(Math.min(ROBOTS_TIMEOUT_MS, remMs));
  try {
    let curUrl = `${origin}/robots.txt`;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      const parsedCur = new URL(curUrl);
      if (isDisallowedOverflowUrl(parsedCur, canonicalSelf)) {
        return {
          unreachable: true,
          reason: 'robots_unreachable: robots.txt disallowed redirect target',
          crawlDelayMs: 15_000,
          rules: [],
          cacheTtlMs: ROBOTS_CACHE_MIN_MS,
        };
      }
      const resp = await fetchFn(curUrl, {
        method: 'GET',
        headers: { 'user-agent': userAgent, accept: 'text/plain,*/*;q=0.8' },
        redirect: 'manual',
        signal,
      });
      if (resp.status >= 300 && resp.status < 400) {
        await resp.body?.cancel().catch(() => undefined);
        const loc = resp.headers.get('location')?.trim();
        if (!loc) {
          return {
            unreachable: true,
            reason: `robots_unreachable: robots.txt redirect failed (HTTP ${resp.status})`,
            crawlDelayMs: 15_000,
            rules: [],
            cacheTtlMs: ROBOTS_CACHE_MIN_MS,
          };
        }
        let nextUrl: URL;
        try {
          nextUrl = new URL(loc, curUrl);
        } catch {
          return {
            unreachable: true,
            reason: `robots_unreachable: robots.txt invalid redirect location (HTTP ${resp.status})`,
            crawlDelayMs: 15_000,
            rules: [],
            cacheTtlMs: ROBOTS_CACHE_MIN_MS,
          };
        }
        if (isDisallowedOverflowUrl(nextUrl, canonicalSelf)) {
          return {
            unreachable: true,
            reason: 'robots_unreachable: robots.txt disallowed redirect target',
            crawlDelayMs: 15_000,
            rules: [],
            cacheTtlMs: ROBOTS_CACHE_MIN_MS,
          };
        }
        if (hop === MAX_REDIRECT_HOPS) {
          // RFC 9309 §2.3.1.2: after 5 consecutive valid public https:// redirects, treat /robots.txt as unavailable (allow all).
          const ttlMs = parseRobotsCacheControlTtlMs(resp.headers.get('cache-control'));
          return { unreachable: false, crawlDelayMs: 0, rules: [], cacheTtlMs: ttlMs };
        }
        curUrl = nextUrl.toString();
        continue;
      }
      if (resp.status === 429 || resp.status >= 500) {
        await resp.body?.cancel().catch(() => undefined);
        return {
          unreachable: true,
          reason: `robots_unreachable: robots.txt returned HTTP ${resp.status} (disallow assumed per RFC 9309)`,
          crawlDelayMs: 15_000,
          rules: [],
          cacheTtlMs: ROBOTS_CACHE_MIN_MS,
        };
      }
      if (resp.status >= 400 && resp.status < 500) {
        await resp.body?.cancel().catch(() => undefined);
        const ttlMs = parseRobotsCacheControlTtlMs(resp.headers.get('cache-control'));
        return { unreachable: false, crawlDelayMs: 0, rules: [], cacheTtlMs: ttlMs };
      }
      if (resp.ok) {
        const { bytes } = await readBoundedBytes(resp.body, ROBOTS_MAX_BYTES, signal);
        const rawText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        const parsed = parseOverflowRobotsTxt(rawText, userAgent);
        parsed.cacheTtlMs = parseRobotsCacheControlTtlMs(resp.headers.get('cache-control'));
        return parsed;
      }
      await resp.body?.cancel().catch(() => undefined);
      return {
        unreachable: true,
        reason: `robots_unreachable: robots.txt returned unexpected HTTP ${resp.status}`,
        crawlDelayMs: 15_000,
        rules: [],
        cacheTtlMs: ROBOTS_CACHE_MIN_MS,
      };
    }
    return { unreachable: false, crawlDelayMs: 0, rules: [], cacheTtlMs: ROBOTS_CACHE_DEFAULT_MS };
  } catch (e) {
    return {
      unreachable: true,
      reason: `robots_unreachable: robots.txt unreachable (disallow assumed per RFC 9309): ${e instanceof Error ? e.message : String(e)}`,
      crawlDelayMs: 15_000,
      rules: [],
      cacheTtlMs: ROBOTS_CACHE_MIN_MS,
    };
  }
}

export interface OverflowDeps {
  fetchFn?: typeof fetch;
  sleepFn?: (ms: number) => Promise<void>;
  bypassAllowlist?: string[];
  botAuth?: {
    privateKey: string;
    directoryUrl?: string;
  };
}

export async function cloudflareOverflowFetch(
  rawBody: string,
  userAgent: string,
  selfHost: string,
  deps: OverflowDeps = {},
): Promise<Response> {
  const fetchFn = deps.fetchFn ?? fetch;
  const useSharedRobotsCache = deps.fetchFn === undefined;
  const sleepFn = deps.sleepFn ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const bypassAllowlist = deps.bypassAllowlist ?? [];

  const started = Date.now();
  let call: {
    maxSeconds?: number;
    requests?: Array<{
      id?: string;
      url?: string;
      method?: string;
      requestBody?: string;
      contentType?: string;
      kind?: string;
      kindAuto?: boolean;
      accept?: string;
      acceptLanguage?: string;
      headers?: Record<string, unknown>;
      ifNoneMatch?: string;
      ifModifiedSince?: string;
      maxBytes?: number;
    }>;
    options?: { includeBody?: boolean; maxBytes?: number; pauseMs?: number; timeoutMs?: number; respectRobots?: boolean; robots?: boolean };
  };
  try {
    call = JSON.parse(rawBody) as typeof call;
  } catch {
    return Response.json({ error: 'bad_json' }, { status: 400 });
  }

  const policy = validateCallRobotsPolicy(rawBody, bypassAllowlist);
  if (!policy.ok) {
    return Response.json({ error: policy.error, message: policy.message }, { status: 400 });
  }

  const maxSeconds = Math.min(300, Math.max(1, call.maxSeconds && call.maxSeconds > 0 ? call.maxSeconds : 60));
  const budgetDeadlineAt = started + maxSeconds * 1000;
  const perReqCapMs = Math.min(PER_REQ_TIMEOUT_MS, Math.max(500, call.options?.timeoutMs ?? PER_REQ_TIMEOUT_MS));

  const reqs = Array.isArray(call.requests) ? call.requests : [];
  const rawOptMaxBytes = call.options?.maxBytes;
  const maxBytes =
    typeof rawOptMaxBytes === 'number' && Number.isFinite(rawOptMaxBytes) && rawOptMaxBytes > 0
      ? Math.min(16 << 20, Math.max(1024, Math.floor(rawOptMaxBytes)))
      : 8 << 20;
  const includeBody = Boolean(call.options?.includeBody);
  const pauseMs = Math.min(30_000, Math.max(0, Math.floor(call.options?.pauseMs ?? 2000)));
  const callerWantsRobots = call.options?.respectRobots ?? call.options?.robots ?? true;
  const canonicalSelf = selfHost.toLowerCase().replace(/\.+$/, '');
  const uaCacheToken = canonicalProductToken(userAgent);

  const results: CrawlResultItem[] = [];
  const hostLastDone = new Map<string, number>();
  const robotsCache = new Map<string, ParsedRobots>();

  let aggregateBatchBytes = 0;
  for (const r of reqs) {
    const reqStart = Date.now();
    if (Date.now() >= budgetDeadlineAt) {
      results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'not_tried', problem: 'maxSeconds budget exhausted' });
      continue;
    }
    if (aggregateBatchBytes >= MAX_OVERFLOW_BATCH_BYTES) {
      results.push({
        id: r.id,
        url: r.url,
        kind: r.kind,
        status: 0,
        outcome: 'not_tried',
        problem: 'batch byte budget (18 MiB) exhausted',
      });
      continue;
    }

    let curUrlStr = r.url ?? '';
    let finished = false;

    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(curUrlStr);
      } catch {
        results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'bad_url' });
        finished = true;
        break;
      }

      if (isDisallowedOverflowUrl(parsedUrl, canonicalSelf)) {
        results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'disallowed_url' });
        finished = true;
        break;
      }

      const host = parsedUrl.hostname.toLowerCase().replace(/\.+$/, '');
      const enforceRobotsOnHop = callerWantsRobots || !isHostInAllowlist(host, bypassAllowlist);

      let robotsEntry: ParsedRobots | undefined;
      if (enforceRobotsOnHop) {
        robotsEntry = robotsCache.get(host);
        if (!robotsEntry && useSharedRobotsCache) {
          robotsEntry = readCachedHubRobots(`${parsedUrl.origin.toLowerCase()}|${uaCacheToken}`, Date.now());
          if (robotsEntry) robotsCache.set(host, robotsEntry);
        }
        if (!robotsEntry) {
          robotsEntry = await fetchOverflowRobots(parsedUrl.origin, userAgent, fetchFn, budgetDeadlineAt, canonicalSelf);
          robotsCache.set(host, robotsEntry);
          if (useSharedRobotsCache) {
            storeCachedHubRobots(`${parsedUrl.origin.toLowerCase()}|${uaCacheToken}`, robotsEntry, Date.now());
          }
        }
        const pathAndQuery = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;
        if (!isRobotsAllowed(robotsEntry, pathAndQuery)) {
          const outcome = robotsEntry.unreachable
            ? 'stop'
            : robotsEntry.disallowAiInput
              ? 'content_signal_disallowed'
              : r.kind === 'page' || r.kind === 'text'
                ? 'skip'
                : 'error';
          results.push({
            id: r.id,
            url: r.url,
            kind: r.kind,
            status: 0,
            outcome,
            problem: robotsEntry.reason ?? `robots.txt disallowed ${parsedUrl.pathname || '/'}`,
            durationMs: Date.now() - reqStart,
          });
          finished = true;
          break;
        }
      }

      const effectivePause = Math.max(pauseMs, robotsEntry?.crawlDelayMs ?? 0);
      const prevDone = hostLastDone.get(host);
      if (prevDone !== undefined && effectivePause > 0) {
        const wait = prevDone + effectivePause - Date.now();
        if (wait > 0) {
          if (Date.now() + wait > budgetDeadlineAt) {
            results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'not_tried', problem: 'maxSeconds budget exhausted' });
            finished = true;
            break;
          }
          await sleepFn(wait);
        }
      }

      const remainingBudget = budgetDeadlineAt - Date.now();
      if (remainingBudget <= 0) {
        results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'maxSeconds budget exhausted' });
        finished = true;
        break;
      }

      try {
        const callerExplicitAccept =
          (typeof r.accept === 'string' && r.accept.trim() && !/[\r\n\0]/.test(r.accept) ? r.accept.trim() : undefined) ??
          readCallerHeaderCaseInsensitive(r.headers, 'accept');
        const acceptHeader = callerExplicitAccept
          ? callerExplicitAccept
          : r.kindAuto === true
            ? 'text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, application/json;q=0.8, application/xml;q=0.8, text/xml;q=0.8, text/plain;q=0.8, */*;q=0.7'
            : r.kind === 'feed' || r.kind === 'json'
              ? 'application/json'
              : MARKDOWN_FOR_AGENTS_ACCEPT;
        const callerAcceptLang =
          (typeof r.acceptLanguage === 'string' && r.acceptLanguage.trim() && !/[\r\n\0]/.test(r.acceptLanguage)
            ? r.acceptLanguage.trim()
            : undefined) ?? readCallerHeaderCaseInsensitive(r.headers, 'accept-language');

        let reqMethod = 'GET';
        let reqBody: string | undefined;
        if (hop === 0 && typeof r.method === 'string' && r.method.trim().toUpperCase() === 'POST') {
          reqMethod = 'POST';
          reqBody = typeof r.requestBody === 'string' ? r.requestBody : '';
        }

        let resp!: Response;
        let activeSignal!: AbortSignal;
        let cfMitigated: string | undefined;

        // 3-strikes adaptive backoff on non-challenge HTTP 429 responses (up to 3 total attempts per hop).
        for (let strike = 1; strike <= 3; strike++) {
          const strikeRemainingMs = budgetDeadlineAt - Date.now();
          if (strikeRemainingMs <= 0) {
            throw new Error('maxSeconds budget exhausted');
          }
          activeSignal = AbortSignal.timeout(Math.min(perReqCapMs, strikeRemainingMs));
          const headers = new Headers({
            'user-agent': userAgent,
            accept: acceptHeader,
          });
          if (callerAcceptLang) {
            headers.set('accept-language', callerAcceptLang);
          }
          if (hop === 0) {
            if (r.ifNoneMatch) headers.set('if-none-match', r.ifNoneMatch);
            if (r.ifModifiedSince) headers.set('if-modified-since', r.ifModifiedSince);
            if (reqMethod === 'POST') {
              headers.set('content-type', r.contentType?.trim() || 'application/json');
            }
          }
          if (deps.botAuth?.privateKey) {
            try {
              const sigHdrs = await signOutboundBotHeaders({
                url: parsedUrl.toString(),
                method: reqMethod,
                privateKeyEncoded: deps.botAuth.privateKey,
                ...(deps.botAuth.directoryUrl ? { directoryUrl: deps.botAuth.directoryUrl } : {}),
              });
              for (const [sk, sv] of Object.entries(sigHdrs)) headers.set(sk, sv);
            } catch {
              // Non-fatal if optional bot signing key is invalid.
            }
          }

          resp = await fetchFn(parsedUrl.toString(), {
            method: reqMethod,
            headers,
            ...(reqBody !== undefined ? { body: reqBody } : {}),
            redirect: 'manual',
            signal: activeSignal,
          });
          hostLastDone.set(host, Date.now());
          cfMitigated = resp.headers.get('cf-mitigated') ?? undefined;

          if (resp.status === 429 && !cfMitigated && strike < 3) {
            const hdrWaf = classifyWafAndChallenge({ status: 429, headers: resp.headers });
            if (!hdrWaf) {
              const now429 = Date.now();
              const exactRetryMs = parseExactRetryAfterMs(resp.headers.get('retry-after'), now429);
              const jitterMs = 250 + Math.floor(Math.random() * 501);
              const waitMs =
                exactRetryMs !== null && exactRetryMs > 0
                  ? exactRetryMs + jitterMs
                  : strike === 1
                    ? 4_000
                    : 10_000;
              if (now429 + waitMs + 1_500 < budgetDeadlineAt) {
                await resp.body?.cancel().catch(() => undefined);
                await sleepFn(waitMs);
                hostLastDone.set(host, Date.now());
                continue;
              }
            }
          }
          break;
        }

        const loc = resp.headers.get('location')?.trim();
        if (
          !cfMitigated &&
          loc &&
          (resp.status === 301 || resp.status === 302 || resp.status === 303 || resp.status === 307 || resp.status === 308)
        ) {
          await resp.body?.cancel().catch(() => undefined);
          if (hop === MAX_REDIRECT_HOPS) {
            results.push({
              id: r.id,
              url: r.url,
              kind: r.kind,
              status: resp.status,
              outcome: 'error',
              problem: `more than ${MAX_REDIRECT_HOPS} redirects`,
              durationMs: Date.now() - reqStart,
            });
            finished = true;
            break;
          }
          curUrlStr = new URL(loc, parsedUrl).toString();
          continue;
        }

        const remainingBatchBytes = Math.max(0, MAX_OVERFLOW_BATCH_BYTES - aggregateBatchBytes);
        const reqMaxBytes =
          typeof r.maxBytes === 'number' && Number.isFinite(r.maxBytes) && r.maxBytes > 0
            ? Math.min(16 << 20, Math.max(1024, Math.floor(r.maxBytes)))
            : maxBytes;
        const perItemMaxBytes = Math.min(reqMaxBytes, remainingBatchBytes);
        const { bytes, truncated } = await readBoundedBytes(resp.body, perItemMaxBytes, activeSignal);
        aggregateBatchBytes += bytes.byteLength;

        const isPaymentRequired = resp.status === 402;
        const decodedPreview =
          !truncated && bytes.byteLength <= 98_304 ? new TextDecoder('utf-8', { fatal: false }).decode(bytes) : '';
        const wafMatch =
          !truncated && !isPaymentRequired
            ? classifyWafAndChallenge({ status: resp.status, headers: resp.headers, rawBody: decodedPreview })
            : null;
        const encodedBody =
          (includeBody || (isPaymentRequired && bytes.byteLength <= 65_536)) && !truncated
            ? encodeBodyForWire(bytes)
            : undefined;
        const isNotModified = resp.status === 304 && Boolean(r.ifNoneMatch || r.ifModifiedSince);
        const respCt = (resp.headers.get('content-type') ?? '').trim();
        const isAutoKindSkip =
          r.kindAuto === true &&
          resp.status >= 200 &&
          resp.status < 300 &&
          Boolean(respCt) &&
          !AUTO_KIND_ACCEPTABLE_CT_RE.test(respCt);
        const outcome = truncated
          ? 'error'
          : isPaymentRequired
            ? 'payment_required'
            : wafMatch || cfMitigated
              ? 'challenge'
              : isAutoKindSkip
                ? 'skip'
                : (resp.status >= 200 && resp.status < 300) || isNotModified
                  ? 'ok'
                  : resp.status === 404 || resp.status === 410
                    ? 'gone'
                    : resp.status === 429
                      ? 'rate_limited'
                      : resp.status === 403 || resp.status === 503
                        ? 'stop'
                        : 'error';
        const paymentHeaders: Record<string, string> = {};
        if (isPaymentRequired) {
          for (const hName of ['payment-required', 'x-payment-required', 'www-authenticate']) {
            const hv = resp.headers.get(hName);
            if (hv) paymentHeaders[hName] = hv;
          }
        }
        const safeHeaders = filterSafeResponseHeaders(resp.headers);
        results.push({
          id: r.id,
          url: r.url,
          ...(curUrlStr !== r.url ? { finalUrl: curUrlStr } : {}),
          kind: r.kind,
          ...(r.kindAuto === true ? { kindAuto: true } : {}),
          status: resp.status,
          outcome,
          ...(outcome === 'rate_limited' ? { rateLimited: true } : {}),
          ...(wafMatch ? { problem: wafMatch.summary, waf: wafMatch } : {}),
          ...(isPaymentRequired && !wafMatch ? { problem: 'HTTP 402 Payment Required' } : {}),
          ...(outcome === 'rate_limited' && !wafMatch ? { problem: 'HTTP 429 Too Many Requests' } : {}),
          ...(isAutoKindSkip ? { problem: `Unsupported binary content-type "${respCt}" for auto-detected fetch` } : {}),
          ...(Object.keys(paymentHeaders).length > 0 ? { paymentHeaders } : {}),
          ...(safeHeaders ? { headers: safeHeaders } : {}),
          bytes: bytes.byteLength,
          truncated,
          durationMs: Date.now() - reqStart,
          contentType: respCt || undefined,
          etag: resp.headers.get('etag') ?? undefined,
          lastModified: resp.headers.get('last-modified') ?? undefined,
          retryAfter: resp.headers.get('retry-after') ?? undefined,
          ...(cfMitigated ? { cfMitigated } : {}),
          ...(encodedBody ? { body: encodedBody.body, bodyEncoding: encodedBody.bodyEncoding } : {}),
        });
        finished = true;
        break;
      } catch (e) {
        hostLastDone.set(host, Date.now());
        results.push({
          id: r.id,
          url: r.url,
          kind: r.kind,
          status: 0,
          outcome: 'error',
          problem: e instanceof Error ? e.message : String(e),
          durationMs: Date.now() - reqStart,
        });
        finished = true;
        break;
      }
    }

    if (!finished) {
      results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'error', problem: 'redirect loop' });
    }
  }

  return Response.json({
    results,
    summary: recomputeSummary(results),
    durationMs: Date.now() - started,
  });
}
