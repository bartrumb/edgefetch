/**
 * Admin-managed Hub secret overrides (`hub_secrets` DO SQLite table) — thin WebCrypto + SQLite glue.
 *
 * All name allowlisting (managed vs bootstrap vs unknown), value validation (trim, <= 8 KiB, no control chars,
 * https-only URLs, enum/ident checks), HKDF info + AAD construction (bound to scope user `hub` and the secret NAME),
 * plaintext verification, and status assembly live in Go (`internal/mcpfed/hub_secrets.go`) behind the
 * `hub_secrets_*` WASM ops. This file only runs HKDF/AES-GCM via WebCrypto (`sealWithVaultKeyAead` /
 * `openWithVaultKeyAead` in `mcp-vault.ts`), SHA-256 fingerprints, SQLite rows, and the in-isolate cache.
 *
 * Invariants:
 *  - Values are never returned by any API here except `applyHubSecretOverlay` (which feeds the request env).
 *    Status rows carry `fingerprint` (first 8 hex of SHA-256) for secret names; plain-config names
 *    (provider ids, base URLs, model names, Cloudflare gateway/provider/alias) also carry `value`.
 *  - Bootstrap names (CALLER_TOKEN, VAULT_MASTER_KEY, ...) are status-only; set/delete reject them.
 *  - Without a valid VAULT_MASTER_KEY, set/delete fail with `vault_master_key_unconfigured` and the overlay is a no-op.
 *  - The overlay cache lives for HUB_SECRETS_CACHE_TTL_MS per isolate and is cleared by set/delete in this isolate;
 *    other isolates converge within the TTL.
 */
import type { EventDetailMap, HubEventInput } from './activity-log';
import { sanitizeDetails } from './activity-log';
import { openWithVaultKeyAead, sealWithVaultKeyAead } from './mcp-vault';
import type { SqlStorageLike } from './oauth';
import { callCoreWasm } from './wasm-bridge';

export const HUB_SECRETS_CACHE_TTL_MS = 30_000;

export const HUB_SECRETS_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS hub_secrets (
    name TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    fingerprint TEXT NOT NULL
  );
`;

export interface HubSecretRow {
  name: string;
  ciphertext: string;
  updatedAt: number;
  updatedBy: string;
  fingerprint: string;
}

/**
 * Storage port. Method names are chosen so an `AgentHubDO` stub exposing the same RPC methods satisfies it directly.
 */
export interface HubSecretsStore {
  listHubSecretRows(): Promise<HubSecretRow[]> | HubSecretRow[];
  putHubSecretRow(row: HubSecretRow): Promise<void> | void;
  deleteHubSecretRow(name: string): Promise<boolean> | boolean;
}

export type HubSecretSource = 'override' | 'env' | 'unset';

export interface HubSecretStatus {
  name: string;
  /** true = settable from /admin; false = bootstrap (status only). */
  managed: boolean;
  /** false for plain-config names whose effective `value` may be shown in full. */
  secret: boolean;
  /** Effective value, ONLY for plain-config names; always null for secrets and bootstrap names. */
  value: string | null;
  source: HubSecretSource;
  fingerprint: string | null;
  envSet: boolean;
  updatedAt: number | null;
  updatedBy: string | null;
}

export interface HubSecretCatalog {
  managed: string[];
  bootstrap: string[];
  urlNames: string[];
  plainConfig: string[];
  maxValueBytes: number;
}

export type HubSecretFailure = {
  ok: false;
  status: number;
  error: string;
  message: string;
};

let catalogMemo: HubSecretCatalog | null = null;

/** Go-owned name catalog (`hub_secrets_catalog`). */
export function getHubSecretCatalog(): HubSecretCatalog {
  if (!catalogMemo) {
    catalogMemo = callCoreWasm<HubSecretCatalog>('hub_secrets_catalog', {});
  }
  return catalogMemo;
}

/** Managed provider-key allowlist (settable). Sourced from Go so the list exists exactly once. */
export function managedSecretNames(): readonly string[] {
  return getHubSecretCatalog().managed;
}

/** Bootstrap names (read-only status, never settable). */
export function bootstrapSecretNames(): readonly string[] {
  return getHubSecretCatalog().bootstrap;
}

export function createSqliteHubSecretsStore(sql: SqlStorageLike): HubSecretsStore {
  return {
    listHubSecretRows(): HubSecretRow[] {
      return sql
        .exec<{ name: string; ciphertext: string; updated_at: number; updated_by: string; fingerprint: string }>(
          'SELECT name, ciphertext, updated_at, updated_by, fingerprint FROM hub_secrets ORDER BY name ASC',
        )
        .toArray()
        .map((r) => ({
          name: String(r.name),
          ciphertext: String(r.ciphertext),
          updatedAt: Number(r.updated_at),
          updatedBy: String(r.updated_by),
          fingerprint: String(r.fingerprint),
        }));
    },
    putHubSecretRow(row: HubSecretRow): void {
      sql.exec(
        'INSERT OR REPLACE INTO hub_secrets (name, ciphertext, updated_at, updated_by, fingerprint) VALUES (?, ?, ?, ?, ?)',
        row.name,
        row.ciphertext,
        row.updatedAt,
        row.updatedBy,
        row.fingerprint,
      );
    },
    deleteHubSecretRow(name: string): boolean {
      const existed = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM hub_secrets WHERE name = ?', name).toArray()[0];
      sql.exec('DELETE FROM hub_secrets WHERE name = ?', name);
      return Number(existed?.n ?? 0) > 0;
    },
  };
}

export function createMemoryHubSecretsStore(): HubSecretsStore {
  const rows = new Map<string, HubSecretRow>();
  return {
    listHubSecretRows: () => [...rows.values()].sort((a, b) => a.name.localeCompare(b.name)).map((r) => ({ ...r })),
    putHubSecretRow: (row) => {
      rows.set(row.name, { ...row });
    },
    deleteHubSecretRow: (name) => rows.delete(name),
  };
}

const hubTextEncoder = new TextEncoder();

async function sha256Fingerprint(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', hubTextEncoder.encode(value)));
  let hex = '';
  for (let i = 0; i < 4; i++) hex += digest[i]!.toString(16).padStart(2, '0');
  return hex;
}

function validateKey(vaultMasterKey: string | undefined): { ok: true; key: string } | HubSecretFailure {
  const res = callCoreWasm<{ ok: boolean; key?: string; message?: string }>('mcp_vault_validate_master_key', {
    vaultMasterKey: vaultMasterKey ?? '',
  });
  if (!res.ok || !res.key) {
    return {
      ok: false,
      status: 503,
      error: 'vault_master_key_unconfigured',
      message: 'VAULT_MASTER_KEY must be configured (>= 24 random characters) before Hub secret overrides can be stored.',
    };
  }
  return { ok: true, key: res.key };
}

interface OverlayCacheEntry {
  expiresAt: number;
  values: Record<string, string>;
  failed: string[];
}

/** Keyed by a string or by the AGENT_HUB binding object (stable per isolate), so separate hubs never share entries. */
export type HubCacheKey = string | object;
const overlayCache = new Map<HubCacheKey, OverlayCacheEntry>();
const overlayInflight = new Map<HubCacheKey, Promise<OverlayCacheEntry>>();
let overlayGeneration = 0;

/** Clears every in-isolate overlay cache entry (called automatically by set/delete). */
export function invalidateHubSecretsCache(): void {
  overlayGeneration++;
  overlayCache.clear();
  overlayInflight.clear();
}

async function decryptRow(cleanKey: string, row: HubSecretRow): Promise<string | null> {
  const prep = callCoreWasm<{
    ok: boolean;
    cleanKey?: string;
    hkdfInfo?: string;
    aad?: string;
    saltB64?: string;
    ivB64?: string;
    ctB64?: string;
  }>('hub_secrets_prepare_unseal', { vaultMasterKey: cleanKey, name: row.name, ciphertext: row.ciphertext });
  if (!prep.ok || !prep.cleanKey || !prep.hkdfInfo || prep.aad === undefined || !prep.saltB64 || !prep.ivB64 || !prep.ctB64) {
    return null;
  }
  const plain = await openWithVaultKeyAead({
    cleanKey: prep.cleanKey,
    hkdfInfo: prep.hkdfInfo,
    aad: prep.aad,
    saltB64: prep.saltB64,
    ivB64: prep.ivB64,
    ctB64: prep.ctB64,
  });
  if (plain === null) return null;
  const verified = callCoreWasm<{ ok: boolean; value?: string }>('hub_secrets_verify_unseal', {
    name: row.name,
    plaintext: plain,
  });
  return verified.ok && typeof verified.value === 'string' ? verified.value : null;
}

async function loadOverlay(
  store: HubSecretsStore,
  cleanKey: string,
  cacheKey: HubCacheKey,
  now: number,
): Promise<OverlayCacheEntry> {
  const cached = overlayCache.get(cacheKey);
  if (cached && cached.expiresAt > now) return cached;
  const pending = overlayInflight.get(cacheKey);
  if (pending) return pending;
  const gen = overlayGeneration;
  const p = (async () => {
    const rows = await store.listHubSecretRows();
    const values: Record<string, string> = {};
    const failed: string[] = [];
    for (const row of rows) {
      const value = await decryptRow(cleanKey, row);
      if (value === null) {
        failed.push(row.name);
      } else {
        values[row.name] = value;
      }
    }
    const entry: OverlayCacheEntry = { expiresAt: now + HUB_SECRETS_CACHE_TTL_MS, values, failed };
    if (gen === overlayGeneration) overlayCache.set(cacheKey, entry);
    return entry;
  })();
  overlayInflight.set(cacheKey, p);
  try {
    return await p;
  } finally {
    if (overlayInflight.get(cacheKey) === p) overlayInflight.delete(cacheKey);
  }
}

/**
 * Returns a shallow copy of `env` where decrypted overrides win over deployment env values. No-op (returns `env`
 * itself) when VAULT_MASTER_KEY is unset/invalid or there are no overrides. Rows that fail to decrypt (rotated key,
 * tampered/swapped ciphertext) are skipped so the env value stays in effect.
 */
export async function applyHubSecretOverlay<E extends object>(
  env: E,
  store: HubSecretsStore,
  vaultMasterKey: string | undefined,
  opts: { cacheKey?: HubCacheKey; now?: number } = {},
): Promise<E> {
  const key = validateKey(vaultMasterKey);
  if (!key.ok) return env;
  let entry: OverlayCacheEntry;
  try {
    entry = await loadOverlay(store, key.key, opts.cacheKey ?? 'default', opts.now ?? Date.now());
  } catch {
    return env;
  }
  const names = Object.keys(entry.values);
  if (names.length === 0) return env;
  return { ...env, ...entry.values } as E;
}

interface HubBindingEnv {
  AGENT_HUB?: { idFromName(name: string): unknown; get(id: unknown): unknown };
  HUB_SHARDS?: string;
  VAULT_MASTER_KEY?: string;
}

/** Primary-shard `AgentHubDO` stub as a `HubSecretsStore` (its RPC method names match the port), or null. */
export function hubSecretsStoreFromBinding(env: object): HubSecretsStore | null {
  const e = env as HubBindingEnv;
  if (!e.AGENT_HUB || typeof e.AGENT_HUB.idFromName !== 'function' || typeof e.AGENT_HUB.get !== 'function') return null;
  const shard =
    String(e.HUB_SHARDS ?? 'global')
      .split(',')
      .map((s) => s.trim())
      .find((s) => /^[a-z0-9_-]{1,32}$/i.test(s)) ?? 'global';
  return e.AGENT_HUB.get(e.AGENT_HUB.idFromName(shard)) as HubSecretsStore;
}

/**
 * Request/workflow entry helper: overlays `hub_secrets` onto `env` using the env's own AGENT_HUB binding (primary
 * shard) and VAULT_MASTER_KEY. Never throws; any failure leaves the deployment env authoritative.
 */
export async function applyHubSecretOverlayFromBinding<E extends object>(env: E): Promise<E> {
  const e = env as HubBindingEnv;
  if (typeof e.VAULT_MASTER_KEY !== 'string' || e.VAULT_MASTER_KEY.trim().length < 24) return env;
  try {
    const store = hubSecretsStoreFromBinding(env);
    if (!store) return env;
    return await applyHubSecretOverlay(env, store, e.VAULT_MASTER_KEY, { cacheKey: e.AGENT_HUB as object });
  } catch {
    return env;
  }
}

export async function setHubSecret(params: {
  store: HubSecretsStore;
  vaultMasterKey: string | undefined;
  name: string;
  value: string;
  actorUserId: string;
  now?: number;
}): Promise<{ ok: true; name: string; fingerprint: string; updatedAt: number; updatedBy: string } | HubSecretFailure> {
  const key = validateKey(params.vaultMasterKey);
  if (!key.ok) return key;
  const prep = callCoreWasm<{
    ok: boolean;
    name?: string;
    cleanKey?: string;
    hkdfInfo?: string;
    aad?: string;
    plaintext?: string;
    envelopeVersion?: string;
    normalizedValue?: string;
    status?: number;
    error?: string;
    message?: string;
  }>('hub_secrets_prepare_seal', {
    vaultMasterKey: key.key,
    name: String(params.name ?? ''),
    value: typeof params.value === 'string' ? params.value : '',
  });
  if (
    !prep.ok ||
    !prep.name ||
    !prep.cleanKey ||
    !prep.hkdfInfo ||
    prep.aad === undefined ||
    prep.plaintext === undefined ||
    !prep.envelopeVersion ||
    prep.normalizedValue === undefined
  ) {
    return {
      ok: false,
      status: prep.status ?? 400,
      error: prep.error ?? 'invalid_secret_value',
      message: prep.message ?? 'Hub secret could not be stored.',
    };
  }
  const sealed = await sealWithVaultKeyAead({
    cleanKey: prep.cleanKey,
    hkdfInfo: prep.hkdfInfo,
    aad: prep.aad,
    plaintext: prep.plaintext,
  });
  const fingerprint = await sha256Fingerprint(prep.normalizedValue);
  const updatedAt = params.now ?? Date.now();
  const updatedBy = String(params.actorUserId ?? '').slice(0, 128) || 'owner';
  await params.store.putHubSecretRow({
    name: prep.name,
    ciphertext: `${prep.envelopeVersion}.${sealed.saltB64}.${sealed.ivB64}.${sealed.ctB64}`,
    updatedAt,
    updatedBy,
    fingerprint,
  });
  invalidateHubSecretsCache();
  return { ok: true, name: prep.name, fingerprint, updatedAt, updatedBy };
}

export async function deleteHubSecret(params: {
  store: HubSecretsStore;
  vaultMasterKey: string | undefined;
  name: string;
}): Promise<{ ok: true; name: string; deleted: boolean } | HubSecretFailure> {
  const key = validateKey(params.vaultMasterKey);
  if (!key.ok) return key;
  const valid = callCoreWasm<{ ok: boolean; name?: string; status?: number; error?: string; message?: string }>(
    'hub_secrets_validate_name',
    { name: String(params.name ?? '') },
  );
  if (!valid.ok || !valid.name) {
    return {
      ok: false,
      status: valid.status ?? 400,
      error: valid.error ?? 'unknown_secret_name',
      message: valid.message ?? 'Unknown secret name.',
    };
  }
  const deleted = await params.store.deleteHubSecretRow(valid.name);
  invalidateHubSecretsCache();
  return { ok: true, name: valid.name, deleted: Boolean(deleted) };
}

/**
 * Admin status for every managed + bootstrap name. Never includes secret values: secrets show only a fingerprint,
 * bootstrap names only set/unset. Plain-config names include their effective value (decrypting overrides needs
 * `vaultMasterKey`; without it, plain overrides report `value: null`).
 */
export async function listHubSecretStatus(
  env: Record<string, unknown>,
  store: HubSecretsStore,
  opts: { vaultMasterKey?: string; cacheKey?: HubCacheKey; now?: number } = {},
): Promise<HubSecretStatus[]> {
  const catalog = getHubSecretCatalog();
  const plain = new Set(catalog.plainConfig);
  const envProbes: Array<{ name: string; fingerprint: string; plainValue?: string }> = [];
  for (const name of catalog.managed) {
    const raw = env[name];
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    const trimmed = raw.trim();
    envProbes.push({
      name,
      fingerprint: await sha256Fingerprint(trimmed),
      ...(plain.has(name) ? { plainValue: trimmed } : {}),
    });
  }
  for (const name of catalog.bootstrap) {
    const raw = env[name];
    if (typeof raw === 'string' && raw.trim() !== '') envProbes.push({ name, fingerprint: '' });
  }
  const rows = await store.listHubSecretRows();
  let plainOverrides: Record<string, string> = {};
  if (opts.vaultMasterKey !== undefined && rows.some((r) => plain.has(r.name))) {
    const key = validateKey(opts.vaultMasterKey);
    if (key.ok) {
      try {
        plainOverrides = (await loadOverlay(store, key.key, opts.cacheKey ?? 'default', opts.now ?? Date.now())).values;
      } catch {
        plainOverrides = {};
      }
    }
  }
  const overrides = rows.map((r) => ({
    name: r.name,
    fingerprint: r.fingerprint,
    updatedAt: r.updatedAt,
    updatedBy: r.updatedBy,
    ...(plain.has(r.name) && typeof plainOverrides[r.name] === 'string' ? { plainValue: plainOverrides[r.name] } : {}),
  }));
  return callCoreWasm<{ secrets: HubSecretStatus[] }>('hub_secrets_build_status', { env: envProbes, overrides }).secrets;
}

/**
 * Activity-log event (`admin` category) for a secret set/delete. Details are names/fingerprints only — never values.
 */
export function buildHubSecretAuditEvent(params: {
  action: 'set' | 'delete' | 'rejected';
  name: string;
  actorUserId: string;
  fingerprint?: string;
  error?: string;
  now?: number;
}): HubEventInput {
  const name = String(params.name ?? '').replace(/[^A-Za-z0-9_]/g, '').slice(0, 64);
  const details: EventDetailMap = sanitizeDetails({
    name,
    actor: String(params.actorUserId ?? '').slice(0, 128),
    ...(params.fingerprint && /^[0-9a-f]{8}$/.test(params.fingerprint) ? { fingerprint: params.fingerprint } : {}),
    ...(params.error ? { error: String(params.error).slice(0, 64) } : {}),
  });
  const summary =
    params.action === 'set'
      ? `Hub secret override ${name} set`
      : params.action === 'delete'
        ? `Hub secret override ${name} deleted`
        : `Hub secret change for ${name} rejected`;
  return {
    ...(params.now !== undefined ? { ts: params.now } : {}),
    level: params.action === 'rejected' ? 'warn' : 'info',
    category: 'admin',
    event: `hub_secret_${params.action}`,
    summary,
    details,
  };
}
