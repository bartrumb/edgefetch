/**
 * Global + per-user tool / route / MCP-server access policy (`access_policies`, `mcp_server_shares` DO SQLite tables)
 * — thin SQLite + cache glue.
 *
 * Rule validation/canonicalization, precedence evaluation, tool filtering, share listing, and shared-ref resolution
 * live in Go (`internal/mcpfed/access_policy.go`) behind the `access_policy_*` WASM ops. Semantics (see the Go file):
 *  - subject-specific beats "*"; exact resource beats "*" prefix (longer prefix beats shorter); deny beats allow.
 *  - Defaults: tool:/route: ALLOW, mcp_server: DENY.
 *  - role "owner" bypasses tool:/route: policy (anti-lockout) but NOT mcp_server: access.
 *  - Shares are allow grants on `mcp_server:<owner>/<slug>`; an explicit user-specific deny still revokes a "*" share.
 *  - Shared servers never expose credentials: callers get name/slug/tools, and federation loads the owner's row
 *    server-side (`resolveMcpServerForCaller`).
 *
 * Snapshot cache: rules+shares are cached per isolate for ACCESS_POLICY_CACHE_TTL_MS and cleared by every write
 * made through this module; other isolates converge within the TTL.
 */
import type { EventDetailMap, HubEventInput } from './activity-log';
import { sanitizeDetails } from './activity-log';
import {
  filterSafeCachedMcpTools,
  type CachedMcpToolSchema,
  type McpVaultStore,
  type StoredMcpServerRow,
} from './mcp-vault';
import type { SqlStorageLike, UserRole } from './oauth';
import { callCoreWasm } from './wasm-bridge';

export const ACCESS_POLICY_CACHE_TTL_MS = 10_000;

export const ACCESS_POLICY_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS access_policies (
    subject TEXT NOT NULL,
    resource TEXT NOT NULL,
    effect TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (subject, resource)
  );
  CREATE TABLE IF NOT EXISTS mcp_server_shares (
    owner_user_id TEXT NOT NULL,
    slug TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_user_id, slug, subject)
  );
  CREATE INDEX IF NOT EXISTS idx_mcp_server_shares_subject ON mcp_server_shares(subject);
`;

export type AccessEffect = 'allow' | 'deny';

export interface AccessPolicyRuleRow {
  subject: string;
  resource: string;
  effect: AccessEffect;
  updatedAt: number;
  updatedBy: string;
}

export interface McpServerShareRow {
  ownerUserId: string;
  slug: string;
  subject: string;
  createdAt: number;
}

/** Storage port; method names let an `AgentHubDO` stub with matching RPC methods satisfy it directly. */
export interface AccessPolicyStore {
  listAccessPolicyRules(): Promise<AccessPolicyRuleRow[]> | AccessPolicyRuleRow[];
  putAccessPolicyRule(row: AccessPolicyRuleRow): Promise<void> | void;
  deleteAccessPolicyRule(subject: string, resource: string): Promise<boolean> | boolean;
  listMcpServerShares(): Promise<McpServerShareRow[]> | McpServerShareRow[];
  putMcpServerShare(row: McpServerShareRow): Promise<void> | void;
  deleteMcpServerShare(ownerUserId: string, slug: string, subject: string): Promise<boolean> | boolean;
}

export interface AccessCallerContext {
  userId: string;
  role: UserRole | string;
}

export interface AccessDecision {
  allowed: boolean;
  reason:
    | 'owner_bypass'
    | 'default_allow'
    | 'default_deny'
    | 'policy_allow'
    | 'policy_deny'
    | 'server_owner'
    | 'invalid_resource';
  matchedRule?: { subject: string; resource: string; effect: AccessEffect };
}

export type AccessPolicyFailure = { ok: false; status: number; error: string; message: string };

export function createSqliteAccessPolicyStore(sql: SqlStorageLike): AccessPolicyStore {
  return {
    listAccessPolicyRules(): AccessPolicyRuleRow[] {
      return sql
        .exec<{ subject: string; resource: string; effect: string; updated_at: number; updated_by: string }>(
          'SELECT subject, resource, effect, updated_at, updated_by FROM access_policies ORDER BY subject ASC, resource ASC',
        )
        .toArray()
        .map((r) => ({
          subject: String(r.subject),
          resource: String(r.resource),
          effect: r.effect === 'deny' ? 'deny' : 'allow',
          updatedAt: Number(r.updated_at),
          updatedBy: String(r.updated_by),
        }));
    },
    putAccessPolicyRule(row: AccessPolicyRuleRow): void {
      sql.exec(
        'INSERT OR REPLACE INTO access_policies (subject, resource, effect, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)',
        row.subject,
        row.resource,
        row.effect,
        row.updatedAt,
        row.updatedBy,
      );
    },
    deleteAccessPolicyRule(subject: string, resource: string): boolean {
      const existed = sql
        .exec<{ n: number }>('SELECT COUNT(*) AS n FROM access_policies WHERE subject = ? AND resource = ?', subject, resource)
        .toArray()[0];
      sql.exec('DELETE FROM access_policies WHERE subject = ? AND resource = ?', subject, resource);
      return Number(existed?.n ?? 0) > 0;
    },
    listMcpServerShares(): McpServerShareRow[] {
      return sql
        .exec<{ owner_user_id: string; slug: string; subject: string; created_at: number }>(
          'SELECT owner_user_id, slug, subject, created_at FROM mcp_server_shares ORDER BY owner_user_id ASC, slug ASC, subject ASC',
        )
        .toArray()
        .map((r) => ({
          ownerUserId: String(r.owner_user_id),
          slug: String(r.slug),
          subject: String(r.subject),
          createdAt: Number(r.created_at),
        }));
    },
    putMcpServerShare(row: McpServerShareRow): void {
      sql.exec(
        'INSERT OR REPLACE INTO mcp_server_shares (owner_user_id, slug, subject, created_at) VALUES (?, ?, ?, ?)',
        row.ownerUserId,
        row.slug,
        row.subject,
        row.createdAt,
      );
    },
    deleteMcpServerShare(ownerUserId: string, slug: string, subject: string): boolean {
      const existed = sql
        .exec<{ n: number }>(
          'SELECT COUNT(*) AS n FROM mcp_server_shares WHERE owner_user_id = ? AND slug = ? AND subject = ?',
          ownerUserId,
          slug,
          subject,
        )
        .toArray()[0];
      sql.exec('DELETE FROM mcp_server_shares WHERE owner_user_id = ? AND slug = ? AND subject = ?', ownerUserId, slug, subject);
      return Number(existed?.n ?? 0) > 0;
    },
  };
}

export function createMemoryAccessPolicyStore(): AccessPolicyStore {
  const rules = new Map<string, AccessPolicyRuleRow>();
  const shares = new Map<string, McpServerShareRow>();
  const rk = (s: string, r: string) => `${s}\u0000${r}`;
  const sk = (o: string, s: string, sub: string) => `${o}\u0000${s}\u0000${sub}`;
  return {
    listAccessPolicyRules: () => [...rules.values()].map((r) => ({ ...r })),
    putAccessPolicyRule: (row) => {
      rules.set(rk(row.subject, row.resource), { ...row });
    },
    deleteAccessPolicyRule: (subject, resource) => rules.delete(rk(subject, resource)),
    listMcpServerShares: () => [...shares.values()].map((s) => ({ ...s })),
    putMcpServerShare: (row) => {
      shares.set(sk(row.ownerUserId, row.slug, row.subject), { ...row });
    },
    deleteMcpServerShare: (o, s, sub) => shares.delete(sk(o, s, sub)),
  };
}

interface PolicySnapshot {
  expiresAt: number;
  rules: Array<{ subject: string; resource: string; effect: AccessEffect }>;
  shares: Array<{ ownerUserId: string; slug: string; subject: string }>;
}

const snapshotCache = new Map<string | object, PolicySnapshot>();
let snapshotGeneration = 0;

/** Clears the in-isolate rules/shares snapshot (called automatically by every write in this module). */
export function invalidateAccessPolicyCache(): void {
  snapshotGeneration++;
  snapshotCache.clear();
}

export interface AccessPolicyOptions {
  store: AccessPolicyStore;
  /** String or the AGENT_HUB binding object (stable per isolate). */
  cacheKey?: string | object;
  now?: number;
}

export async function loadAccessPolicySnapshot(opts: AccessPolicyOptions): Promise<PolicySnapshot> {
  const key = opts.cacheKey ?? 'default';
  const now = opts.now ?? Date.now();
  const hit = snapshotCache.get(key);
  if (hit && hit.expiresAt > now) return hit;
  const gen = snapshotGeneration;
  const [rules, shares] = await Promise.all([opts.store.listAccessPolicyRules(), opts.store.listMcpServerShares()]);
  const snap: PolicySnapshot = {
    expiresAt: now + ACCESS_POLICY_CACHE_TTL_MS,
    rules: rules.map((r) => ({ subject: r.subject, resource: r.resource, effect: r.effect })),
    shares: shares.map((s) => ({ ownerUserId: s.ownerUserId, slug: s.slug, subject: s.subject })),
  };
  if (gen === snapshotGeneration) snapshotCache.set(key, snap);
  return snap;
}

function callerOf(ctx: AccessCallerContext | null | undefined): { userId: string; role: string } {
  return { userId: typeof ctx?.userId === 'string' ? ctx.userId : '', role: typeof ctx?.role === 'string' ? ctx.role : '' };
}

/** Fast path: no rules at all means tool/route access is today's default-allow. */
function noRules(snap: PolicySnapshot): boolean {
  return snap.rules.length === 0;
}

export async function evaluateToolAccess(
  ctx: AccessCallerContext | null | undefined,
  toolName: string,
  opts: AccessPolicyOptions,
): Promise<AccessDecision> {
  if (callerOf(ctx).role === 'owner') return { allowed: true, reason: 'owner_bypass' };
  const snap = await loadAccessPolicySnapshot(opts);
  // Evaluated in Go even with zero rules so malformed tool names are refused consistently.
  return callCoreWasm<AccessDecision>('access_policy_evaluate', {
    rules: snap.rules,
    caller: callerOf(ctx),
    resource: `tool:${String(toolName ?? '')}`,
  });
}

/** `path` is the request pathname (query/fragment and trailing slashes are normalized in Go). Non-/v1 paths are out of scope and allowed. */
export async function evaluateRouteAccess(
  ctx: AccessCallerContext | null | undefined,
  path: string,
  opts: AccessPolicyOptions,
): Promise<AccessDecision> {
  const rawPath = String(path ?? '');
  if (rawPath !== '/v1' && !rawPath.startsWith('/v1/')) return { allowed: true, reason: 'default_allow' };
  if (callerOf(ctx).role === 'owner') return { allowed: true, reason: 'owner_bypass' };
  const snap = await loadAccessPolicySnapshot(opts);
  if (noRules(snap)) return { allowed: true, reason: 'default_allow' };
  const norm = callCoreWasm<{ ok: boolean; path: string }>('access_policy_normalize_route', { path: rawPath });
  // With rules in force, a /v1 path Go can't canonicalize (dot segments, "//", odd bytes) is refused rather than
  // risk a rule bypass via an unnormalized spelling.
  if (!norm.ok) return { allowed: false, reason: 'invalid_resource' };
  return callCoreWasm<AccessDecision>('access_policy_evaluate', {
    rules: snap.rules,
    caller: callerOf(ctx),
    resource: `route:${norm.path}`,
  });
}

/** Filters an MCP `tools/list` array to the tools the caller may call, preserving order and object identity. */
export async function filterToolDefinitions<T extends { name: string }>(
  ctx: AccessCallerContext | null | undefined,
  tools: readonly T[],
  opts: AccessPolicyOptions,
): Promise<T[]> {
  if (callerOf(ctx).role === 'owner') return [...tools];
  const snap = await loadAccessPolicySnapshot(opts);
  if (noRules(snap)) return [...tools];
  const allowed = new Set(
    callCoreWasm<{ names: string[] }>('access_policy_filter_tools', {
      rules: snap.rules,
      caller: callerOf(ctx),
      names: tools.map((t) => t.name),
    }).names,
  );
  return tools.filter((t) => allowed.has(t.name));
}

// ---------------------------------------------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------------------------------------------

export async function listAccessPolicyRules(store: AccessPolicyStore): Promise<AccessPolicyRuleRow[]> {
  return await store.listAccessPolicyRules();
}

export async function putAccessPolicyRule(params: {
  store: AccessPolicyStore;
  subject: string;
  resource: string;
  effect: string;
  actorUserId: string;
  now?: number;
}): Promise<{ ok: true; rule: AccessPolicyRuleRow } | AccessPolicyFailure> {
  const norm = callCoreWasm<{
    ok: boolean;
    rule?: { subject: string; resource: string; effect: AccessEffect };
    status?: number;
    error?: string;
    message?: string;
  }>('access_policy_normalize_rule', {
    rule: { subject: String(params.subject ?? ''), resource: String(params.resource ?? ''), effect: String(params.effect ?? '') },
  });
  if (!norm.ok || !norm.rule) {
    return { ok: false, status: norm.status ?? 400, error: norm.error ?? 'invalid_policy_rule', message: norm.message ?? 'Invalid policy rule.' };
  }
  const row: AccessPolicyRuleRow = {
    ...norm.rule,
    updatedAt: params.now ?? Date.now(),
    updatedBy: String(params.actorUserId ?? '').slice(0, 128) || 'owner',
  };
  await params.store.putAccessPolicyRule(row);
  invalidateAccessPolicyCache();
  return { ok: true, rule: row };
}

export async function deleteAccessPolicyRule(params: {
  store: AccessPolicyStore;
  subject: string;
  resource: string;
}): Promise<{ ok: true; deleted: boolean; subject: string; resource: string } | AccessPolicyFailure> {
  // Canonicalize with a dummy effect so "route:/v1/x/" deletes the stored "route:/v1/x".
  const norm = callCoreWasm<{ ok: boolean; rule?: { subject: string; resource: string }; status?: number; error?: string; message?: string }>(
    'access_policy_normalize_rule',
    { rule: { subject: String(params.subject ?? ''), resource: String(params.resource ?? ''), effect: 'allow' } },
  );
  if (!norm.ok || !norm.rule) {
    return { ok: false, status: norm.status ?? 400, error: norm.error ?? 'invalid_policy_rule', message: norm.message ?? 'Invalid policy rule.' };
  }
  const deleted = await params.store.deleteAccessPolicyRule(norm.rule.subject, norm.rule.resource);
  invalidateAccessPolicyCache();
  return { ok: true, deleted: Boolean(deleted), subject: norm.rule.subject, resource: norm.rule.resource };
}

export async function listMcpServerShares(store: AccessPolicyStore): Promise<McpServerShareRow[]> {
  return await store.listMcpServerShares();
}

/**
 * Shares ownerUserId's server `slug` with `subject` ("*" or a userId). When `vaultStore` is given the server must
 * exist in the owner's vault. Who may call this (the server owner, or a hub owner) is the route's decision.
 */
export async function putMcpServerShare(params: {
  store: AccessPolicyStore;
  vaultStore?: McpVaultStore;
  ownerUserId: string;
  slug: string;
  subject: string;
  now?: number;
}): Promise<{ ok: true; share: McpServerShareRow } | AccessPolicyFailure> {
  const norm = callCoreWasm<{
    ok: boolean;
    share?: { ownerUserId: string; slug: string; subject: string };
    status?: number;
    error?: string;
    message?: string;
  }>('access_policy_normalize_share', {
    share: { ownerUserId: String(params.ownerUserId ?? ''), slug: String(params.slug ?? ''), subject: String(params.subject ?? '') },
  });
  if (!norm.ok || !norm.share) {
    return { ok: false, status: norm.status ?? 400, error: norm.error ?? 'invalid_share', message: norm.message ?? 'Invalid share.' };
  }
  if (params.vaultStore) {
    const row = await params.vaultStore.getServer(norm.share.ownerUserId, norm.share.slug);
    if (!row || row.slug.toLowerCase() !== norm.share.slug) {
      return { ok: false, status: 404, error: 'mcp_server_not_connected', message: 'The owner has no connected MCP server with that slug.' };
    }
  }
  const share: McpServerShareRow = { ...norm.share, createdAt: params.now ?? Date.now() };
  await params.store.putMcpServerShare(share);
  invalidateAccessPolicyCache();
  return { ok: true, share };
}

export async function deleteMcpServerShare(params: {
  store: AccessPolicyStore;
  ownerUserId: string;
  slug: string;
  subject: string;
}): Promise<{ ok: true; deleted: boolean } | AccessPolicyFailure> {
  const norm = callCoreWasm<{ ok: boolean; share?: { ownerUserId: string; slug: string; subject: string }; status?: number; error?: string; message?: string }>(
    'access_policy_normalize_share',
    { share: { ownerUserId: String(params.ownerUserId ?? ''), slug: String(params.slug ?? ''), subject: String(params.subject ?? '') } },
  );
  if (!norm.ok || !norm.share) {
    return { ok: false, status: norm.status ?? 400, error: norm.error ?? 'invalid_share', message: norm.message ?? 'Invalid share.' };
  }
  const deleted = await params.store.deleteMcpServerShare(norm.share.ownerUserId, norm.share.slug, norm.share.subject);
  invalidateAccessPolicyCache();
  return { ok: true, deleted: Boolean(deleted) };
}

// ---------------------------------------------------------------------------------------------------------------
// Shared-server resolution for federation (credentials stay in the owner's vault)
// ---------------------------------------------------------------------------------------------------------------

/** What a member sees about a server shared with them: never URLs, auth summaries, or credentials. */
export interface SharedMcpServerSummary {
  ref: string;
  ownerUserId: string;
  slug: string;
  name: string;
  enabled: boolean;
  toolCount: number;
  tools: CachedMcpToolSchema[];
}

async function listAllowedShareRefs(
  userId: string,
  opts: AccessPolicyOptions,
): Promise<Array<{ ownerUserId: string; slug: string; ref: string }>> {
  const snap = await loadAccessPolicySnapshot(opts);
  if (snap.shares.length === 0) return [];
  return callCoreWasm<{ servers: Array<{ ownerUserId: string; slug: string; ref: string }> }>('access_policy_list_shared', {
    rules: snap.rules,
    shares: snap.shares,
    callerUserId: userId,
  }).servers;
}

/** Servers other users shared with `userId` (that policy still allows and that still exist in the owner's vault). */
export async function listSharedServersFor(
  userId: string,
  opts: AccessPolicyOptions & { vaultStore: McpVaultStore },
): Promise<SharedMcpServerSummary[]> {
  const out: SharedMcpServerSummary[] = [];
  for (const ref of await listAllowedShareRefs(userId, opts)) {
    const row = await opts.vaultStore.getServer(ref.ownerUserId, ref.slug);
    if (!row || row.slug.toLowerCase() !== ref.slug || row.userId !== ref.ownerUserId) continue;
    const tools = filterSafeCachedMcpTools(row.cachedTools);
    out.push({ ref: ref.ref, ownerUserId: ref.ownerUserId, slug: row.slug, name: row.name, enabled: row.enabled, toolCount: tools.length, tools });
  }
  return out;
}

/**
 * Own + shared rows usable by `userId`, for `tryScrapeViaConnectedMcp`. Shared rows whose slug collides with one of
 * the caller's own slugs (or with an earlier shared row) are dropped so a slug-keyed plan stays unambiguous; `refBySlug`
 * maps each returned slug to the ref `executeFederatedMcpQuery` must be called with.
 */
export async function listCallableServersForCaller(
  userId: string,
  opts: AccessPolicyOptions & { vaultStore: McpVaultStore },
): Promise<{ rows: StoredMcpServerRow[]; refBySlug: Map<string, string> }> {
  const own = await opts.vaultStore.listServers(userId);
  const rows: StoredMcpServerRow[] = [...own];
  const refBySlug = new Map<string, string>();
  for (const r of own) refBySlug.set(r.slug.toLowerCase(), r.slug);
  for (const ref of await listAllowedShareRefs(userId, opts)) {
    if (refBySlug.has(ref.slug)) continue;
    const row = await opts.vaultStore.getServer(ref.ownerUserId, ref.slug);
    if (!row || row.slug.toLowerCase() !== ref.slug || row.userId !== ref.ownerUserId) continue;
    rows.push(row);
    refBySlug.set(ref.slug, ref.ref);
  }
  return { rows, refBySlug };
}

/**
 * Resolves a caller-supplied server ref. The caller's own server (by id or slug) always wins; otherwise a share is
 * consulted ("<ownerUserId>/<slug>" or an unambiguous "<slug>"). The returned row is the OWNER's row, so vault
 * unsealing stays bound to `row.userId` and credentials never move between users. Unshared/denied refs return the
 * same 404 as missing ones.
 */
export async function resolveMcpServerForCaller(
  params: AccessPolicyOptions & { vaultStore: McpVaultStore; callerUserId: string; ref: string },
): Promise<{ ok: true; ownerUserId: string; server: StoredMcpServerRow; shared: boolean } | AccessPolicyFailure> {
  const ref = String(params.ref ?? '').trim();
  const refNorm = ref.toLowerCase();
  const notFound: AccessPolicyFailure = {
    ok: false,
    status: 404,
    error: 'mcp_server_not_connected',
    message: 'No connected or shared MCP server matches that reference for the current user.',
  };
  if (!ref) return notFound;
  const own = await params.vaultStore.getServer(params.callerUserId, ref);
  if (own && (own.id.toLowerCase() === refNorm || own.slug.toLowerCase() === refNorm)) {
    return { ok: true, ownerUserId: own.userId, server: own, shared: false };
  }
  const snap = await loadAccessPolicySnapshot(params);
  if (snap.shares.length === 0) return notFound;
  const res = callCoreWasm<{ ok: boolean; ownerUserId?: string; slug?: string; status?: number; error?: string; message?: string }>(
    'access_policy_resolve_shared',
    { rules: snap.rules, shares: snap.shares, callerUserId: params.callerUserId, ref },
  );
  if (!res.ok || !res.ownerUserId || !res.slug) {
    return { ok: false, status: res.status ?? 404, error: res.error ?? notFound.error, message: res.message ?? notFound.message };
  }
  const row = await params.vaultStore.getServer(res.ownerUserId, res.slug);
  if (!row || row.slug.toLowerCase() !== res.slug || row.userId !== res.ownerUserId) return notFound;
  return { ok: true, ownerUserId: res.ownerUserId, server: row, shared: true };
}

// ---------------------------------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------------------------------

function cleanToken(raw: unknown, max: number): string {
  return String(raw ?? '')
    .replace(/[^A-Za-z0-9_.:@/*\-]/g, '')
    .slice(0, max);
}

/** Activity-log event (`admin` category) for a policy rule or share change; subjects/resources/effects only. */
export function buildAccessPolicyAuditEvent(params: {
  action: 'rule_set' | 'rule_delete' | 'share_set' | 'share_delete';
  actorUserId: string;
  subject: string;
  resource?: string;
  effect?: string;
  ownerUserId?: string;
  slug?: string;
  now?: number;
}): HubEventInput {
  const subject = cleanToken(params.subject, 128);
  const details: EventDetailMap = sanitizeDetails({
    actor: cleanToken(params.actorUserId, 128),
    subject,
    ...(params.resource !== undefined ? { resource: cleanToken(params.resource, 300) } : {}),
    ...(params.effect !== undefined ? { effect: params.effect === 'deny' ? 'deny' : 'allow' } : {}),
    ...(params.ownerUserId !== undefined ? { ownerUserId: cleanToken(params.ownerUserId, 128) } : {}),
    ...(params.slug !== undefined ? { slug: cleanToken(params.slug, 48) } : {}),
  });
  const what =
    params.action === 'rule_set' || params.action === 'rule_delete'
      ? `policy ${details.effect ?? ''} ${details.resource ?? ''} for ${subject}`.replace(/\s+/g, ' ').trim()
      : `share ${details.ownerUserId ?? ''}/${details.slug ?? ''} with ${subject}`;
  return {
    ...(params.now !== undefined ? { ts: params.now } : {}),
    level: 'info',
    category: 'admin',
    event: `access_${params.action}`,
    summary: `${params.action.endsWith('delete') ? 'Removed' : 'Set'} ${what}`,
    details,
  };
}
