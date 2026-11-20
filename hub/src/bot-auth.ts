/**
 * IETF RFC 9421 HTTP Message Signatures (`web-bot-auth`) & Bot Transparency Directory (`hub/src/bot-auth.ts` — `R1`):
 *
 *  - `GET /.well-known/http-message-signatures-directory`: Serves the RFC 9421 / `draft-meunier-http-message-signatures-directory`
 *    Ed25519 JWKS public key directory (`content-type: application/http-message-signatures-directory+json`) with `"nbf"`
 *    key validity metadata AND cryptographic self-signatures (`Content-Digest`, `Signature-Input: directory=...`,
 *    `Signature: directory=:...:`) used by Cloudflare Verified Bots and origin servers.
 *  - `GET /.well-known/edgefetch-bot.json`: Machine-readable bot transparency manifest declaring `User-Agent`,
 *    strict RFC 9309 `robots.txt` compliance, anti-bot challenge halt policy, and operator contact URL.
 *  - Pure WebCrypto (`crypto.subtle` Ed25519 + SHA-256) key derivation, RFC 7638 JWK thumbprint (`kid`),
 *    outbound request signing (`signOutboundBotHeaders`), directory response signing (`signDirectoryResponse`),
 *    and cryptographic verification (`verifyBotRequestSignature` & `verifyDirectoryResponseSignature`).
 */

export const DEFAULT_BOT_KEY_NBF = 1_767_225_600; // 2026-01-01T00:00:00Z deterministic cache-friendly default

export interface PublicEd25519Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  kid: string;
  x: string;
  nbf: number;
  exp?: number;
}

export interface BotAuthEnv {
  BOT_SIGNING_PRIVATE_KEY?: string;
  BOT_SIGNING_PUBLIC_KEY?: string;
  BOT_CONTACT_URL?: string;
  BOT_KEY_NBF?: string;
  BOT_KEY_EXP?: string;
  USER_AGENT?: string;
}

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toBase64Std(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function fromFlexibleBase64(encoded: string): Uint8Array<ArrayBuffer> {
  const clean = encoded.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function resolveValidityBounds(env?: BotAuthEnv): { nbf: number; exp?: number } {
  const rawNbf = env?.BOT_KEY_NBF?.trim() ? Number(env.BOT_KEY_NBF.trim()) : NaN;
  const nbf = Number.isInteger(rawNbf) && rawNbf > 0 ? rawNbf : DEFAULT_BOT_KEY_NBF;
  const rawExp = env?.BOT_KEY_EXP?.trim() ? Number(env.BOT_KEY_EXP.trim()) : NaN;
  const exp = Number.isInteger(rawExp) && rawExp > nbf ? rawExp : undefined;
  return exp !== undefined ? { nbf, exp } : { nbf };
}

/**
 * Computes the RFC 7638 SHA-256 JWK Thumbprint (`kid`) of an Ed25519 public key (`{"crv":"Ed25519","kty":"OKP","x":"..."}`),
 * matching Go `botauth.ComputeJWKThumbprint` byte-for-byte. Per RFC 7638 §3.2, optional metadata members (`nbf`, `exp`)
 * are NEVER included in the canonical thumbprint input.
 */
export async function computeEd25519JwkThumbprint(pubKeyBytes: Uint8Array): Promise<string> {
  if (pubKeyBytes.byteLength !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${pubKeyBytes.byteLength}`);
  }
  const x = toBase64Url(pubKeyBytes);
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return toBase64Url(new Uint8Array(digest));
}

async function importEd25519Seed(
  seed32: Uint8Array,
  bounds: { nbf: number; exp?: number } = { nbf: DEFAULT_BOT_KEY_NBF },
): Promise<{ privateKey: CryptoKey; publicJwk: PublicEd25519Jwk }> {
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed32, ED25519_PKCS8_PREFIX.length);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const exportedJwk = (await crypto.subtle.exportKey('jwk', privateKey)) as { x?: string };
  if (!exportedJwk.x) {
    throw new Error('WebCrypto Ed25519 JWK export missing public coordinate x');
  }
  const pubBytes = fromFlexibleBase64(exportedJwk.x);
  const kid = await computeEd25519JwkThumbprint(pubBytes);
  return {
    privateKey,
    publicJwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      kid,
      x: toBase64Url(pubBytes),
      nbf: bounds.nbf,
      ...(bounds.exp !== undefined ? { exp: bounds.exp } : {}),
    },
  };
}

/** Mints a fresh Ed25519 keypair via WebCrypto for RFC 9421 Web Bot Auth. */
export async function generateBotAuthKeyPair(nowMs = Date.now()): Promise<{
  privateKeySeed: string;
  publicKey: string;
  kid: string;
  jwk: PublicEd25519Jwk;
}> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const privJwk = (await crypto.subtle.exportKey('jwk', kp.privateKey)) as { d?: string; x?: string };
  const pubBytes = fromFlexibleBase64(privJwk.x!);
  const kid = await computeEd25519JwkThumbprint(pubBytes);
  const x = toBase64Url(pubBytes);
  const nbf = Math.floor(nowMs / 1_000);
  return {
    privateKeySeed: privJwk.d!,
    publicKey: x,
    kid,
    jwk: { kty: 'OKP', crv: 'Ed25519', kid, x, nbf },
  };
}

/** Resolves the public Ed25519 JWK(s) configured on the Hub (`BOT_SIGNING_PUBLIC_KEY` and/or `BOT_SIGNING_PRIVATE_KEY`). */
export async function resolveConfiguredBotJwks(env: BotAuthEnv): Promise<PublicEd25519Jwk[]> {
  const seen = new Map<string, PublicEd25519Jwk>();
  const bounds = resolveValidityBounds(env);

  if (env.BOT_SIGNING_PRIVATE_KEY?.trim()) {
    try {
      const raw = fromFlexibleBase64(env.BOT_SIGNING_PRIVATE_KEY);
      const seed = raw.byteLength === 64 ? raw.subarray(0, 32) : raw;
      if (seed.byteLength === 32) {
        const { publicJwk } = await importEd25519Seed(seed, bounds);
        seen.set(publicJwk.kid, publicJwk);
      }
    } catch {
      // Ignore malformed env key so public endpoint degrades cleanly.
    }
  }

  if (env.BOT_SIGNING_PUBLIC_KEY?.trim()) {
    for (const part of env.BOT_SIGNING_PUBLIC_KEY.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      try {
        const pubBytes = fromFlexibleBase64(trimmed);
        if (pubBytes.byteLength === 32) {
          const kid = await computeEd25519JwkThumbprint(pubBytes);
          seen.set(kid, {
            kty: 'OKP',
            crv: 'Ed25519',
            kid,
            x: toBase64Url(pubBytes),
            nbf: bounds.nbf,
            ...(bounds.exp !== undefined ? { exp: bounds.exp } : {}),
          });
        }
      } catch {
        // Ignore invalid entry.
      }
    }
  }

  return [...seen.values()];
}

/**
 * Signs a `/.well-known/http-message-signatures-directory` HTTP response per `draft-meunier-http-message-signatures-directory`
 * and Cloudflare Verified Bots requirements:
 *  - `Content-Digest: sha-256=:<base64>:` (RFC 9530)
 *  - `Signature-Input: directory=("@authority";req "content-digest");created=...;expires=...;keyid="<kid>";alg="ed25519";tag="http-message-signatures-directory"`
 *  - `Signature: directory=:<base64>:`
 */
export async function signDirectoryResponse(params: {
  authority: string;
  body: string;
  privateKeyEncoded: string;
  nowMs?: number;
  ttlSeconds?: number;
}): Promise<Record<string, string>> {
  const raw = fromFlexibleBase64(params.privateKeyEncoded);
  const seed = raw.byteLength === 64 ? raw.subarray(0, 32) : raw;
  if (seed.byteLength !== 32) {
    throw new Error(`Invalid Ed25519 private key length: ${raw.byteLength}`);
  }
  const { privateKey, publicJwk } = await importEd25519Seed(seed);
  const bodyBytes = new TextEncoder().encode(params.body);
  const shaBuf = await crypto.subtle.digest('SHA-256', bodyBytes);
  const contentDigest = `sha-256=:${toBase64Std(new Uint8Array(shaBuf))}:`;

  const authority = params.authority.trim().toLowerCase();
  const created = Math.floor((params.nowMs ?? Date.now()) / 1_000);
  const expires = created + (params.ttlSeconds ?? 300);
  const sigParams = `("@authority";req "content-digest");created=${created};expires=${expires};keyid="${publicJwk.kid}";alg="ed25519";tag="http-message-signatures-directory"`;
  const sigBase = [
    `"@authority";req: ${authority}`,
    `"content-digest": ${contentDigest}`,
    `"@signature-params": ${sigParams}`,
  ].join('\n');

  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, new TextEncoder().encode(sigBase));
  return {
    'content-digest': contentDigest,
    'signature-input': `directory=${sigParams}`,
    signature: `directory=:${toBase64Std(new Uint8Array(sigBuf))}:`,
  };
}

/** Verifies a `draft-meunier-http-message-signatures-directory` response (`Content-Digest` + `directory` Ed25519 signature). */
export async function verifyDirectoryResponseSignature(params: {
  requestUrl: string;
  response: Response;
  publicKeyB64Url: string;
  nowMs?: number;
}): Promise<{ ok: boolean; kid?: string; reason?: string }> {
  const digestHdr = params.response.headers.get('content-digest')?.trim() ?? '';
  const inHdr = params.response.headers.get('signature-input')?.trim() ?? '';
  const sigHdr = params.response.headers.get('signature')?.trim() ?? '';
  const im = /^directory=(\(([^)]*)\)(?:;.*)?)$/.exec(inHdr);
  const sm = /^directory=:([A-Za-z0-9+/=]+):$/.exec(sigHdr);
  if (!digestHdr || !im || !sm) {
    return { ok: false, reason: 'missing_or_malformed_directory_signature_headers' };
  }
  const sigParams = im[1]!;
  if (!sigParams.includes('tag="http-message-signatures-directory"')) {
    return { ok: false, reason: 'missing_directory_tag' };
  }
  const nowUnix = Math.floor((params.nowMs ?? Date.now()) / 1_000);
  const createdMatch = /;created=(\d+)/.exec(sigParams);
  if (createdMatch && Number(createdMatch[1]) > nowUnix + 60) {
    return { ok: false, reason: 'created_in_future' };
  }
  const expiresMatch = /;expires=(\d+)/.exec(sigParams);
  if (expiresMatch && nowUnix > Number(expiresMatch[1])) {
    return { ok: false, reason: 'signature_expired' };
  }

  const bodyBytes = new Uint8Array(await params.response.clone().arrayBuffer());
  const shaBuf = await crypto.subtle.digest('SHA-256', bodyBytes);
  const expectedDigest = `sha-256=:${toBase64Std(new Uint8Array(shaBuf))}:`;
  if (digestHdr !== expectedDigest) {
    return { ok: false, reason: 'content_digest_mismatch' };
  }

  const authority = new URL(params.requestUrl).host.toLowerCase();
  const sigBase = [
    `"@authority";req: ${authority}`,
    `"content-digest": ${digestHdr}`,
    `"@signature-params": ${sigParams}`,
  ].join('\n');

  try {
    const pubBytes = fromFlexibleBase64(params.publicKeyB64Url);
    const cryptoPub = await crypto.subtle.importKey('raw', pubBytes, { name: 'Ed25519' }, false, ['verify']);
    const sigBytes = fromFlexibleBase64(sm[1]!);
    const valid = await crypto.subtle.verify({ name: 'Ed25519' }, cryptoPub, sigBytes, new TextEncoder().encode(sigBase));
    if (!valid) return { ok: false, reason: 'ed25519_verification_failed' };
    const kidMatch = /;keyid="([^"]+)"/.exec(sigParams);
    return { ok: true, ...(kidMatch?.[1] ? { kid: kidMatch[1] } : {}) };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'verify_error' };
  }
}

/**
 * Signs an outbound HTTP request (`Signature-Input`, `Signature`, and optional `Signature-Agent`) per IETF RFC 9421
 * (`tag="web-bot-auth"`, `alg="ed25519"`). Compatible byte-for-byte with Go `botauth.Signer.SignRequest`.
 */
export async function signOutboundBotHeaders(params: {
  url: string;
  method: string;
  privateKeyEncoded: string;
  directoryUrl?: string;
  nowMs?: number;
  ttlSeconds?: number;
}): Promise<Record<string, string>> {
  const raw = fromFlexibleBase64(params.privateKeyEncoded);
  const seed = raw.byteLength === 64 ? raw.subarray(0, 32) : raw;
  if (seed.byteLength !== 32) {
    throw new Error(`Invalid Ed25519 private key length: ${raw.byteLength}`);
  }
  const { privateKey, publicJwk } = await importEd25519Seed(seed);
  const parsedUrl = new URL(params.url);
  const authority = parsedUrl.host.toLowerCase();
  const method = (params.method || 'GET').toUpperCase();
  const targetUri = parsedUrl.toString();
  const created = Math.floor((params.nowMs ?? Date.now()) / 1_000);
  const expires = created + (params.ttlSeconds ?? 300);

  const comps = ['"@authority"', '"@method"', '"@target-uri"'];
  const baseLines = [
    `"@authority": ${authority}`,
    `"@method": ${method}`,
    `"@target-uri": ${targetUri}`,
  ];
  const outHeaders: Record<string, string> = {};

  if (params.directoryUrl?.trim()) {
    const sigAgentVal = `"${params.directoryUrl.trim()}"`;
    outHeaders['signature-agent'] = sigAgentVal;
    comps.push('"signature-agent"');
    baseLines.push(`"signature-agent": ${sigAgentVal}`);
  }

  const sigParams = `(${comps.join(' ')});created=${created};expires=${expires};keyid="${publicJwk.kid}";alg="ed25519";tag="web-bot-auth"`;
  baseLines.push(`"@signature-params": ${sigParams}`);
  const sigBase = baseLines.join('\n');

  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, new TextEncoder().encode(sigBase));
  outHeaders['signature-input'] = `sig1=${sigParams}`;
  outHeaders['signature'] = `sig1=:${toBase64Std(new Uint8Array(sigBuf))}:`;
  return outHeaders;
}

/** Verifies an RFC 9421 `sig1` Ed25519 signature on a `Request` against a base64url 32-byte public key. */
export async function verifyBotRequestSignature(
  request: Request,
  publicKeyB64Url: string,
  nowMs = Date.now(),
): Promise<{ ok: boolean; kid?: string; reason?: string }> {
  const inHdr = request.headers.get('signature-input')?.trim() ?? '';
  const sigHdr = request.headers.get('signature')?.trim() ?? '';
  const im = /^sig1=(\(([^)]*)\)(?:;.*)?)$/.exec(inHdr);
  const sm = /^sig1=:([A-Za-z0-9+/=]+):$/.exec(sigHdr);
  if (!im || !sm) return { ok: false, reason: 'missing_or_malformed_signature_headers' };

  const sigParams = im[1]!;
  const compList = im[2]!.trim().split(/\s+/).filter(Boolean);
  const nowUnix = Math.floor(nowMs / 1_000);

  const createdMatch = /;created=(\d+)/.exec(sigParams);
  if (createdMatch && Number(createdMatch[1]) > nowUnix + 60) {
    return { ok: false, reason: 'created_in_future' };
  }
  const expiresMatch = /;expires=(\d+)/.exec(sigParams);
  if (expiresMatch && nowUnix > Number(expiresMatch[1])) {
    return { ok: false, reason: 'signature_expired' };
  }
  const kidMatch = /;keyid="([^"]+)"/.exec(sigParams);

  const parsedUrl = new URL(request.url);
  const baseLines: string[] = [];
  for (const rawComp of compList) {
    const comp = rawComp.replace(/^"|"$/g, '');
    let val = '';
    if (comp === '@authority') val = parsedUrl.host.toLowerCase();
    else if (comp === '@method') val = (request.method || 'GET').toUpperCase();
    else if (comp === '@target-uri') val = parsedUrl.toString();
    else {
      val = request.headers.get(comp)?.trim() ?? '';
      if (!val) return { ok: false, reason: `missing_covered_header:${comp}` };
    }
    baseLines.push(`"${comp}": ${val}`);
  }
  baseLines.push(`"@signature-params": ${sigParams}`);
  const sigBase = baseLines.join('\n');

  try {
    const pubBytes = fromFlexibleBase64(publicKeyB64Url);
    const cryptoPub = await crypto.subtle.importKey('raw', pubBytes, { name: 'Ed25519' }, false, ['verify']);
    const sigBytes = fromFlexibleBase64(sm[1]!);
    const valid = await crypto.subtle.verify({ name: 'Ed25519' }, cryptoPub, sigBytes, new TextEncoder().encode(sigBase));
    if (!valid) return { ok: false, reason: 'ed25519_verification_failed' };
    return { ok: true, ...(kidMatch?.[1] ? { kid: kidMatch[1] } : {}) };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'verify_error' };
  }
}

/** Handles public unauthenticated `/.well-known/http-message-signatures-directory` and `/.well-known/edgefetch-bot.json` routes. */
export async function handleBotTransparencyRoutes(
  request: Request,
  url: URL,
  env: BotAuthEnv,
  version: string,
): Promise<Response | null> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;

  if (url.pathname === '/.well-known/http-message-signatures-directory') {
    const keys = await resolveConfiguredBotJwks(env);
    const body = JSON.stringify({ keys }, null, 2);
    const headers: Record<string, string> = {
      'content-type': 'application/http-message-signatures-directory+json; charset=utf-8',
      'cache-control': env.BOT_SIGNING_PRIVATE_KEY?.trim() ? 'public, max-age=240' : 'public, max-age=3600',
    };
    if (env.BOT_SIGNING_PRIVATE_KEY?.trim()) {
      try {
        const sigHeaders = await signDirectoryResponse({
          authority: url.host,
          body,
          privateKeyEncoded: env.BOT_SIGNING_PRIVATE_KEY.trim(),
        });
        Object.assign(headers, sigHeaders);
      } catch {
        // Degrade gracefully to unsigned JWKS if env private key is malformed.
      }
    }
    return new Response(request.method === 'HEAD' ? null : body, {
      status: 200,
      headers,
    });
  }

  if (url.pathname === '/.well-known/edgefetch-bot.json') {
    const keys = await resolveConfiguredBotJwks(env);
    const ua = env.USER_AGENT?.trim() || 'EdgeFetch/2.5 (bot@edgefetch.dev)';
    const contact = env.BOT_CONTACT_URL?.trim() || 'https://github.com/bartrumb/edgefetch';
    const doc = {
      bot: 'EdgeFetch',
      version,
      category: 'user-triggered-agent-retrieval',
      userAgent: ua,
      operatorContact: contact,
      policies: {
        robotsTxt: 'strict-rfc9309',
        contentSignals: 'honored (ai-input)',
        crawlDelay: 'honored',
        retryAfter: 'honored',
        antiBotChallenges: 'halt-immediately-never-bypass',
        aiModelTraining: false,
      },
      webBotAuth: {
        rfc9421Supported: true,
        directorySelfSigned: Boolean(env.BOT_SIGNING_PRIVATE_KEY?.trim()),
        directoryUrl: `${url.origin}/.well-known/http-message-signatures-directory`,
        activeKeyIds: keys.map((k) => k.kid),
      },
    };
    return Response.json(doc, {
      status: 200,
      headers: { 'cache-control': 'public, max-age=3600' },
    });
  }

  return null;
}
