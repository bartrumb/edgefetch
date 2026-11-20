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
import { recomputeSummary, type CrawlResultItem } from './agent-hub';
import { signOutboundBotHeaders } from './bot-auth';
import { classifyWafAndChallenge } from './waf';

export const ROBOTS_MAX_BYTES = 512 * 1024; // 512 KiB >= RFC 9309 500 KiB minimum
const ROBOTS_TIMEOUT_MS = 10_000;
const PER_REQ_TIMEOUT_MS = 30_000;
const MAX_REDIRECT_HOPS = 5;

export interface ParsedRobots {
  unreachable: boolean;
  reason?: string;
  crawlDelayMs: number;
  rules: Array<{ pattern: string; allow: boolean }>;
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
  const trimmed = raw.trim().toLowerCase();
  if (trimmed === '*') return '*';
  const slash = trimmed.indexOf('/');
  const head = slash >= 0 ? trimmed.slice(0, slash) : trimmed;
  return head.split(/\s+/)[0] ?? '';
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

export function parseOverflowRobotsTxt(rawBody: string, userAgent: string): ParsedRobots {
  const body = rawBody.replace(/^\uFEFF/, '');
  const uaToken = canonicalProductToken(userAgent);
  const groups: Array<{ agents: string[]; rules: Array<{ pattern: string; allow: boolean }>; crawlDelayMs: number }> = [];
  let cur = { agents: [] as string[], rules: [] as Array<{ pattern: string; allow: boolean }>, crawlDelayMs: 0 };
  let seenDirective = false;

  for (const rawLine of body.split('\n')) {
    const noComment = rawLine.includes('#') ? rawLine.slice(0, rawLine.indexOf('#')) : rawLine;
    const line = noComment.trim();
    if (!line) {
      if (seenDirective && cur.agents.length > 0) {
        groups.push(cur);
        cur = { agents: [], rules: [], crawlDelayMs: 0 };
        seenDirective = false;
      }
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    if (field === 'user-agent') {
      if (seenDirective && cur.agents.length > 0) {
        groups.push(cur);
        cur = { agents: [], rules: [], crawlDelayMs: 0 };
        seenDirective = false;
      }
      cur.agents.push(canonicalProductToken(val));
    } else if (field === 'allow' && cur.agents.length > 0 && val) {
      seenDirective = true;
      cur.rules.push({ pattern: normalizeRobotsURI(val), allow: true });
    } else if (field === 'disallow' && cur.agents.length > 0) {
      seenDirective = true;
      cur.rules.push(val === '' ? { pattern: '/', allow: true } : { pattern: normalizeRobotsURI(val), allow: false });
    } else if (field === 'crawl-delay' && cur.agents.length > 0) {
      seenDirective = true;
      const secs = Number(val);
      if (Number.isFinite(secs) && secs > 0) {
        cur.crawlDelayMs = Math.min(30_000, Math.round(secs * 1000));
      }
    }
  }
  if (cur.agents.length > 0) groups.push(cur);

  const specific: Array<{ pattern: string; allow: boolean }> = [];
  const wildcard: Array<{ pattern: string; allow: boolean }> = [];
  let specificDelay = 0;
  let wildcardDelay = 0;
  let hasSpecific = false;

  for (const g of groups) {
    for (const ua of g.agents) {
      if (uaToken && ua === uaToken) {
        hasSpecific = true;
        specific.push(...g.rules);
        specificDelay = Math.max(specificDelay, g.crawlDelayMs);
      } else if (ua === '*') {
        wildcard.push(...g.rules);
        wildcardDelay = Math.max(wildcardDelay, g.crawlDelayMs);
      }
    }
  }
  return {
    unreachable: false,
    crawlDelayMs: hasSpecific ? specificDelay : wildcardDelay,
    rules: hasSpecific ? specific : wildcard,
  };
}

export function isRobotsAllowed(entry: ParsedRobots, rawPathAndQuery: string): boolean {
  if (entry.unreachable) return false;
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

async function fetchOverflowRobots(
  origin: string,
  userAgent: string,
  fetchFn: typeof fetch,
  budgetDeadlineAt: number,
  canonicalSelf = '',
): Promise<ParsedRobots> {
  const remMs = budgetDeadlineAt - Date.now();
  if (remMs <= 0) {
    return { unreachable: true, reason: 'request budget exhausted before robots.txt check', crawlDelayMs: 0, rules: [] };
  }
  const signal = AbortSignal.timeout(Math.min(ROBOTS_TIMEOUT_MS, remMs));
  try {
    let curUrl = `${origin}/robots.txt`;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      const parsedCur = new URL(curUrl);
      if (isDisallowedOverflowUrl(parsedCur, canonicalSelf)) {
        return { unreachable: true, reason: 'robots.txt disallowed redirect target', crawlDelayMs: 15_000, rules: [] };
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
        if (!loc || hop === MAX_REDIRECT_HOPS) {
          return {
            unreachable: true,
            reason: `robots.txt redirect failed (HTTP ${resp.status})`,
            crawlDelayMs: 15_000,
            rules: [],
          };
        }
        curUrl = new URL(loc, curUrl).toString();
        continue;
      }
      if (resp.status === 429 || resp.status >= 500) {
        await resp.body?.cancel().catch(() => undefined);
        return {
          unreachable: true,
          reason: `robots.txt returned HTTP ${resp.status} (disallow assumed per RFC 9309)`,
          crawlDelayMs: 15_000,
          rules: [],
        };
      }
      if (resp.status >= 400 && resp.status < 500) {
        await resp.body?.cancel().catch(() => undefined);
        return { unreachable: false, crawlDelayMs: 0, rules: [] };
      }
      if (resp.ok) {
        const { bytes } = await readBoundedBytes(resp.body, ROBOTS_MAX_BYTES, signal);
        const rawText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        return parseOverflowRobotsTxt(rawText.replace(/^\xef\xbb\xbf/, ''), userAgent);
      }
      await resp.body?.cancel().catch(() => undefined);
      return {
        unreachable: true,
        reason: `robots.txt returned unexpected HTTP ${resp.status}`,
        crawlDelayMs: 15_000,
        rules: [],
      };
    }
    return { unreachable: true, reason: `robots.txt exceeded ${MAX_REDIRECT_HOPS} redirects`, crawlDelayMs: 15_000, rules: [] };
  } catch (e) {
    return {
      unreachable: true,
      reason: `robots.txt unreachable (disallow assumed per RFC 9309): ${e instanceof Error ? e.message : String(e)}`,
      crawlDelayMs: 15_000,
      rules: [],
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
      accept?: string;
      ifNoneMatch?: string;
      ifModifiedSince?: string;
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
  const maxBytes = Math.min(16 << 20, Math.max(1024, call.options?.maxBytes ?? 8 << 20));
  const includeBody = Boolean(call.options?.includeBody);
  const pauseMs = Math.min(30_000, Math.max(0, Math.floor(call.options?.pauseMs ?? 2000)));
  const callerWantsRobots = call.options?.respectRobots ?? call.options?.robots ?? true;
  const canonicalSelf = selfHost.toLowerCase().replace(/\.+$/, '');

  const results: CrawlResultItem[] = [];
  const hostLastDone = new Map<string, number>();
  const robotsCache = new Map<string, ParsedRobots>();

  for (const r of reqs) {
    const reqStart = Date.now();
    if (Date.now() >= budgetDeadlineAt) {
      results.push({ id: r.id, url: r.url, kind: r.kind, status: 0, outcome: 'not_tried', problem: 'maxSeconds budget exhausted' });
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
        if (!robotsEntry) {
          robotsEntry = await fetchOverflowRobots(parsedUrl.origin, userAgent, fetchFn, budgetDeadlineAt, canonicalSelf);
          robotsCache.set(host, robotsEntry);
        }
        const pathAndQuery = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;
        if (!isRobotsAllowed(robotsEntry, pathAndQuery)) {
          const outcome = robotsEntry.unreachable ? 'stop' : r.kind === 'page' || r.kind === 'text' ? 'skip' : 'error';
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

      const hopSignal = AbortSignal.timeout(Math.min(perReqCapMs, remainingBudget));
      try {
        const acceptHeader =
          r.kind === 'feed' || r.kind === 'json'
            ? 'application/json'
            : r.kind === 'text' && r.accept
              ? r.accept
              : 'text/html,application/xhtml+xml';
        const headers = new Headers({
          'user-agent': userAgent,
          accept: acceptHeader,
        });
        let reqMethod = 'GET';
        let reqBody: string | undefined;
        if (hop === 0) {
          if (r.ifNoneMatch) headers.set('if-none-match', r.ifNoneMatch);
          if (r.ifModifiedSince) headers.set('if-modified-since', r.ifModifiedSince);
          if (typeof r.method === 'string' && r.method.trim().toUpperCase() === 'POST') {
            reqMethod = 'POST';
            reqBody = typeof r.requestBody === 'string' ? r.requestBody : '';
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

        const resp = await fetchFn(parsedUrl.toString(), {
          method: reqMethod,
          headers,
          ...(reqBody !== undefined ? { body: reqBody } : {}),
          redirect: 'manual',
          signal: hopSignal,
        });
        hostLastDone.set(host, Date.now());

        const cfMitigated = resp.headers.get('cf-mitigated') ?? undefined;
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

        const { bytes, truncated } = await readBoundedBytes(resp.body, maxBytes, hopSignal);
        const decodedPreview = !truncated && bytes.byteLength <= 98_304 ? new TextDecoder('utf-8', { fatal: false }).decode(bytes) : '';
        const wafMatch = !truncated
          ? classifyWafAndChallenge({ status: resp.status, headers: resp.headers, rawBody: decodedPreview })
          : null;
        const encodedBody = includeBody && !truncated ? encodeBodyForWire(bytes) : undefined;
        const isNotModified = resp.status === 304 && Boolean(r.ifNoneMatch || r.ifModifiedSince);
        const outcome = truncated
          ? 'error'
          : wafMatch || cfMitigated
            ? 'challenge'
            : (resp.status >= 200 && resp.status < 300) || isNotModified
              ? 'ok'
              : resp.status === 404 || resp.status === 410
                ? 'gone'
                : resp.status === 403 || resp.status === 429 || resp.status === 503
                  ? 'stop'
                  : 'error';
        results.push({
          id: r.id,
          url: r.url,
          ...(curUrlStr !== r.url ? { finalUrl: curUrlStr } : {}),
          kind: r.kind,
          status: resp.status,
          outcome,
          ...(wafMatch ? { problem: wafMatch.summary, waf: wafMatch } : {}),
          bytes: bytes.byteLength,
          truncated,
          durationMs: Date.now() - reqStart,
          contentType: resp.headers.get('content-type') ?? undefined,
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
