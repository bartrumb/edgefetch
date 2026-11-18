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

function bearer(req: Request): string | null {
  const m = /^bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
  return m ? (m[1] as string) : null;
}

export function isCallerAuthorized(req: Request, token?: string): boolean {
  if (!token || token.length < MIN_TOKEN_LENGTH) return false;
  const tok = bearer(req);
  return tok !== null && sameBytes(tok, token);
}

export function authorizeAgent(
  req: Request,
  env: { AGENT_TOKEN?: string; AGENT_TOKENS?: string },
): { ok: true; siteId: string } | { ok: false } {
  const tok = bearer(req);
  if (!tok) return { ok: false };
  const hdrSite = (req.headers.get('x-agent-site') ?? '').trim().toLowerCase();

  if (env.AGENT_TOKENS?.trim()) {
    try {
      const map = JSON.parse(env.AGENT_TOKENS) as Record<string, unknown>;
      let matched: string | null = null;
      for (const [k, v] of Object.entries(map)) {
        const s = k.trim().toLowerCase();
        if (SITE_ID_PATTERN.test(s) && typeof v === 'string' && v.length >= MIN_TOKEN_LENGTH && sameBytes(tok, v)) {
          matched = s;
        }
      }
      if (matched && (!hdrSite || hdrSite === matched)) return { ok: true, siteId: matched };
    } catch {
      // malformed JSON fails closed
    }
  }
  if (env.AGENT_TOKEN && env.AGENT_TOKEN.length >= MIN_TOKEN_LENGTH) {
    const valid = sameBytes(tok, env.AGENT_TOKEN);
    if (valid && SITE_ID_RE_CHECK(hdrSite)) return { ok: true, siteId: hdrSite };
  }
  return { ok: false };
}

function SITE_ID_RE_CHECK(s: string): boolean {
  return SITE_ID_PATTERN.test(s);
}
