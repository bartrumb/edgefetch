/**
 * Authentication gates for EdgeFetch Hub:
 *  1. `isCallerAuthorized`: caller gate (`CALLER_TOKEN` / `MCP_TOKEN`) for `/fetch`, `/agents`, and `/v1/*`.
 *  2. `authorizeAgent`: least-privilege gate (`AGENT_TOKENS` per-site JSON map or `AGENT_TOKEN` + `x-agent-site`)
 *     for outbound worker nodes on `/agent/ws`, `/agent/reply`, and `/agent/artifacts/*`.
 *
 * Both gates fail closed: an unset or short secret (< 24 chars) lets nobody in, comparisons run in length-independent
 * constant time (`sameBytes`), and shared `AGENT_TOKEN` cannot impersonate any site declared in `AGENT_TOKENS`.
 */
export const MIN_TOKEN_LENGTH = 24;
export const SITE_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/** Length-independent constant-time string comparison. */
export function sameBytes(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function bearerToken(request: Request): string | null {
  const m = /^bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  return m ? (m[1] as string) : null;
}

export function callerToken(request: Request): string | null {
  const bearer = bearerToken(request);
  if (bearer) return bearer;
  const apiKey = (request.headers.get('x-api-key') ?? '').trim();
  return apiKey && !/\s/.test(apiKey) ? apiKey : null;
}

export function isValidSecretMatch(presented: string | null | undefined, ...secrets: Array<string | undefined>): boolean {
  if (!presented) return false;
  let matched = false;
  for (const s of secrets) {
    if (s && s.length >= MIN_TOKEN_LENGTH && sameBytes(presented, s)) {
      matched = true;
    }
  }
  return matched;
}

export function isCallerAuthorized(request: Request, token?: string, extraToken?: string): boolean {
  const presented = callerToken(request);
  return isValidSecretMatch(presented, token, extraToken);
}

export const isAuthorized = isCallerAuthorized;

export type AgentAuthResult = { ok: true; siteId: string } | { ok: false };

function decodeBase64UrlUtf8(raw: string): string | null {
  if (!raw || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
  try {
    const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function extractAgentCredentials(request: Request): { token: string | null; siteHint: string } {
  const isWsUpgrade = (request.headers.get('upgrade') ?? '').toLowerCase() === 'websocket';
  let token: string | null = bearerToken(request) ?? (request.headers.get('x-agent-token') ?? '').trim();
  if (token === '') token = null;

  if (!token && isWsUpgrade) {
    const protoHdr = request.headers.get('sec-websocket-protocol') ?? '';
    for (const part of protoHdr.split(',')) {
      const p = part.trim();
      if (p.startsWith('edgefetch-auth.')) {
        const decoded = decodeBase64UrlUtf8(p.slice('edgefetch-auth.'.length));
        if (decoded) {
          token = decoded;
          break;
        }
      } else if (p.startsWith('bearer.')) {
        token = p.slice('bearer.'.length);
        break;
      }
    }
  }

  let siteHint = (request.headers.get('x-agent-site') ?? '').trim().toLowerCase();
  if (isWsUpgrade && (!token || !siteHint)) {
    try {
      const u = new URL(request.url);
      if (!siteHint) {
        siteHint = (u.searchParams.get('site') ?? '').trim().toLowerCase();
      }
      if (!token) {
        const qTok = (u.searchParams.get('token') ?? '').trim();
        if (qTok) token = qTok;
      }
    } catch {
      // ignore malformed request URL
    }
  }
  return { token, siteHint };
}

export function authorizeAgent(
  request: Request,
  env: { AGENT_TOKEN?: string; AGENT_TOKENS?: string },
): AgentAuthResult {
  const { token: presented, siteHint: hdrSite } = extractAgentCredentials(request);
  if (!presented) return { ok: false };
  const mappedSites = new Set<string>();

  if (env.AGENT_TOKENS?.trim()) {
    try {
      const map = JSON.parse(env.AGENT_TOKENS) as Record<string, unknown>;
      if (!map || typeof map !== 'object' || Array.isArray(map)) return { ok: false };
      let matched: string | null = null;
      for (const [k, v] of Object.entries(map)) {
        const s = k.trim().toLowerCase();
        if (SITE_ID_PATTERN.test(s)) {
          mappedSites.add(s);
          if (typeof v === 'string' && v.length >= MIN_TOKEN_LENGTH && sameBytes(presented, v)) {
            matched = s;
          }
        }
      }
      if (matched && (!hdrSite || hdrSite === matched)) return { ok: true, siteId: matched };
    } catch {
      return { ok: false };
    }
  }
  if (env.AGENT_TOKEN && env.AGENT_TOKEN.length >= MIN_TOKEN_LENGTH) {
    const valid = sameBytes(presented, env.AGENT_TOKEN);
    // Shared AGENT_TOKEN may never claim a siteId that has a dedicated token in AGENT_TOKENS (H-S5).
    if (valid && SITE_ID_PATTERN.test(hdrSite) && !mappedSites.has(hdrSite)) {
      return { ok: true, siteId: hdrSite };
    }
  }
  return { ok: false };
}
