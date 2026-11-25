/**
 * Cached (`1h` TTL, opt-out via `EDGEFETCH_DISABLE_UPDATE_CHECK=1`, using `SAFE_PUBLIC_FETCH`)
 * live update status checker for `/admin` (`hub/src/update-check.ts`).
 *
 * Compares `https://api.github.com/repos/bartrumb/edgefetch/releases/latest` `tag_name` against both
 * the running Hub version and connected Go worker fleet versions (`X-Agent-Version` / `agent_hello`),
 * rendering `"Up to date (vX.Y.Z)"` or `"Update available (vX.Y.Z)"` in `/admin`.
 */
import hubPkg from '../package.json';
import { validatePublicHttpsTargetUrl } from './overflow';

async function readResponseTextCapped(res: Response, maxBytes: number): Promise<string> {
  const cl = res.headers.get('content-length');
  if (cl !== null && cl.trim() !== '') {
    const n = Number(cl);
    if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error('too_large');
    }
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel('exceeds maxBytes').catch(() => undefined);
          throw new Error('too_large');
        }
        chunks.push(value);
      }
    }
  } catch (err) {
    await reader.cancel().catch(() => undefined);
    throw err;
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

export const GITHUB_LATEST_RELEASE_URL = 'https://api.github.com/repos/bartrumb/edgefetch/releases/latest';
export const UPDATE_CHECK_TTL_MS = 60 * 60_000; // 1 hour positive cache TTL
export const UPDATE_CHECK_FAILURE_TTL_MS = 5 * 60_000; // 5 minute negative cache TTL on network error
export const RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAv8+ZT9d/404KI0pY1PILOVBzsUvTHWaL0aLghciWy90=';

export const HUB_VERSION: string = typeof hubPkg?.version === 'string' && hubPkg.version.trim() ? hubPkg.version.trim() : '2.8.0';

const SEMVER_TAG_RE = /^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z._-]+))?$/;

export interface UpdateCheckEnv {
  EDGEFETCH_DISABLE_UPDATE_CHECK?: string;
  SAFE_PUBLIC_FETCH?: typeof fetch;
  SAFE_FETCH?: typeof fetch;
}

export interface FleetVersionAgent {
  siteId: string;
  version?: string;
}

export interface OutdatedFleetNode {
  siteId: string;
  version: string;
}

export type UpdatePillStatus = 'up_to_date' | 'update_available' | 'disabled' | 'unknown';

export interface UpdateCheckStatus {
  enabled: boolean;
  pillStatus: UpdatePillStatus;
  pillLabel: string;
  currentVersion: string;
  latestVersion?: string;
  latestTag?: string;
  releaseUrl?: string;
  hubUpdateAvailable: boolean;
  outdatedAgents: OutdatedFleetNode[];
  checkedAt?: number;
  signingKeySpkiB64: string;
}

interface CachedReleaseEntry {
  latestTag: string;
  latestVersion: string;
  releaseUrl: string;
  fetchedAt: number;
  expiresAt: number;
}

interface CachedFailureEntry {
  failedAt: number;
  expiresAt: number;
}

const releaseCache = new Map<string, CachedReleaseEntry>();
const failureCache = new Map<string, CachedFailureEntry>();

export function clearUpdateCheckCache(): void {
  releaseCache.clear();
  failureCache.clear();
}

export function isUpdateCheckDisabled(env?: { EDGEFETCH_DISABLE_UPDATE_CHECK?: string }): boolean {
  const raw = (env?.EDGEFETCH_DISABLE_UPDATE_CHECK ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

export function normalizeSemverVersion(raw: string | undefined | null): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  const m = SEMVER_TAG_RE.exec(trimmed);
  if (!m) return null;
  return `${Number(m[1])}.${Number(m[2])}.${Number(m[3])}${m[4] ? `-${m[4]}` : ''}`;
}

export function compareSemver(a: string, b: string): number {
  const ma = SEMVER_TAG_RE.exec(a.trim());
  const mb = SEMVER_TAG_RE.exec(b.trim());
  if (!ma || !mb) {
    return a.trim() === b.trim() ? 0 : a.trim() < b.trim() ? -1 : 1;
  }
  for (let i = 1; i <= 3; i++) {
    const na = Number(ma[i]);
    const nb = Number(mb[i]);
    if (na !== nb) return na < nb ? -1 : 1;
  }
  const preA = ma[4] ?? '';
  const preB = mb[4] ?? '';
  if (preA === preB) return 0;
  if (!preA) return 1;
  if (!preB) return -1;
  return preA < preB ? -1 : 1;
}

function sanitizeGitHubReleaseUrl(rawUrl: unknown, fallbackTag: string): string {
  const defaultUrl = `https://github.com/bartrumb/edgefetch/releases/tag/${encodeURIComponent(fallbackTag)}`;
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return defaultUrl;
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol === 'https:' && parsed.hostname === 'github.com' && parsed.pathname.startsWith('/bartrumb/edgefetch/releases/')) {
      return parsed.toString();
    }
  } catch {
    // fallback below
  }
  return defaultUrl;
}

function evaluateFleetAgainstRelease(params: {
  currentVersion: string;
  agents: FleetVersionAgent[];
  entry: CachedReleaseEntry;
}): UpdateCheckStatus {
  const hubUpdateAvailable = compareSemver(params.entry.latestVersion, params.currentVersion) > 0;
  const outdatedAgents: OutdatedFleetNode[] = [];
  for (const agent of params.agents) {
    const cleanAgentVer = normalizeSemverVersion(agent.version);
    if (!agent.version) {
      outdatedAgents.push({ siteId: agent.siteId, version: 'legacy' });
    } else if (cleanAgentVer && compareSemver(params.entry.latestVersion, cleanAgentVer) > 0) {
      outdatedAgents.push({ siteId: agent.siteId, version: `v${cleanAgentVer}` });
    }
  }
  const anyUpdateNeeded = hubUpdateAvailable || outdatedAgents.length > 0;
  return {
    enabled: true,
    pillStatus: anyUpdateNeeded ? 'update_available' : 'up_to_date',
    pillLabel: anyUpdateNeeded
      ? `Update available (${params.entry.latestTag})`
      : `Up to date (v${params.currentVersion})`,
    currentVersion: `v${params.currentVersion}`,
    latestVersion: `v${params.entry.latestVersion}`,
    latestTag: params.entry.latestTag,
    releaseUrl: params.entry.releaseUrl,
    hubUpdateAvailable,
    outdatedAgents,
    checkedAt: params.entry.fetchedAt,
    signingKeySpkiB64: RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
  };
}

export async function checkHubUpdateStatus(params: {
  currentVersion?: string;
  agents?: FleetVersionAgent[];
  env?: UpdateCheckEnv;
  fetchFn?: typeof fetch;
  releaseApiUrl?: string;
  nowMs?: number;
  bypassCache?: boolean;
} = {}): Promise<UpdateCheckStatus> {
  const curNorm = normalizeSemverVersion(params.currentVersion ?? HUB_VERSION) ?? '2.8.0';
  const agents = params.agents ?? [];
  const now = params.nowMs ?? Date.now();

  if (isUpdateCheckDisabled(params.env)) {
    return {
      enabled: false,
      pillStatus: 'disabled',
      pillLabel: `v${curNorm}`,
      currentVersion: `v${curNorm}`,
      hubUpdateAvailable: false,
      outdatedAgents: [],
      signingKeySpkiB64: RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
    };
  }

  const apiUrl = (params.releaseApiUrl ?? GITHUB_LATEST_RELEASE_URL).trim();
  const validatedTarget = validatePublicHttpsTargetUrl(apiUrl);
  if (!validatedTarget.ok) {
    return {
      enabled: true,
      pillStatus: 'unknown',
      pillLabel: `v${curNorm}`,
      currentVersion: `v${curNorm}`,
      hubUpdateAvailable: false,
      outdatedAgents: [],
      signingKeySpkiB64: RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
    };
  }

  if (!params.bypassCache) {
    const cached = releaseCache.get(apiUrl);
    if (cached && cached.expiresAt > now) {
      return evaluateFleetAgainstRelease({ currentVersion: curNorm, agents, entry: cached });
    }
    const failed = failureCache.get(apiUrl);
    if (failed && failed.expiresAt > now) {
      return {
        enabled: true,
        pillStatus: 'unknown',
        pillLabel: `v${curNorm}`,
        currentVersion: `v${curNorm}`,
        hubUpdateAvailable: false,
        outdatedAgents: [],
        checkedAt: failed.failedAt,
        signingKeySpkiB64: RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
      };
    }
  }

  const doFetch = params.fetchFn ?? params.env?.SAFE_PUBLIC_FETCH ?? params.env?.SAFE_FETCH ?? fetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('Update check timed out', 'TimeoutError'));
  }, 2_500);
  (timer as { unref?: () => void }).unref?.();

  try {
    const res = await doFetch(validatedTarget.url.toString(), {
      method: 'GET',
      redirect: 'manual',
      headers: {
        accept: 'application/vnd.github+json',
        'user-agent': `EdgeFetch-Hub/${curNorm}`,
      },
      signal: ctrl.signal,
    });
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(`HTTP ${res.status}`);
    }
    const rawText = await readResponseTextCapped(res, 65_536);
    const parsed = JSON.parse(rawText) as {
      tag_name?: unknown;
      html_url?: unknown;
      draft?: unknown;
      prerelease?: unknown;
    };
    if (parsed.draft === true) {
      throw new Error('draft_release');
    }
    const rawTag = typeof parsed.tag_name === 'string' ? parsed.tag_name.trim() : '';
    const latestVer = normalizeSemverVersion(rawTag);
    if (!latestVer) {
      throw new Error('invalid_tag_name');
    }
    const latestTag = rawTag.startsWith('v') ? rawTag : `v${latestVer}`;
    const entry: CachedReleaseEntry = {
      latestTag,
      latestVersion: latestVer,
      releaseUrl: sanitizeGitHubReleaseUrl(parsed.html_url, latestTag),
      fetchedAt: now,
      expiresAt: now + UPDATE_CHECK_TTL_MS,
    };
    if (releaseCache.size >= 16) releaseCache.clear();
    releaseCache.set(apiUrl, entry);
    failureCache.delete(apiUrl);
    return evaluateFleetAgainstRelease({ currentVersion: curNorm, agents, entry });
  } catch {
    if (failureCache.size >= 16) failureCache.clear();
    failureCache.set(apiUrl, { failedAt: now, expiresAt: now + UPDATE_CHECK_FAILURE_TTL_MS });
    return {
      enabled: true,
      pillStatus: 'unknown',
      pillLabel: `v${curNorm}`,
      currentVersion: `v${curNorm}`,
      hubUpdateAvailable: false,
      outdatedAgents: [],
      checkedAt: now,
      signingKeySpkiB64: RELEASE_SIGNING_PUBLIC_KEY_SPKI_B64,
    };
  } finally {
    clearTimeout(timer);
  }
}
