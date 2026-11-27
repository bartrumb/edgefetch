import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import {
  ACCESS_POLICY_SQLITE_SCHEMA,
  buildAccessPolicyAuditEvent,
  createSqliteAccessPolicyStore,
  deleteAccessPolicyRule,
  deleteMcpServerShare,
  evaluateRouteAccess,
  evaluateToolAccess,
  filterToolDefinitions,
  invalidateAccessPolicyCache,
  listCallableServersForCaller,
  listSharedServersFor,
  putAccessPolicyRule,
  putMcpServerShare,
  resolveMcpServerForCaller,
  type AccessPolicyStore,
} from '../src/access-policy.ts';
import { ACTIVITY_SQLITE_SCHEMA, createSqliteActivityStore } from '../src/activity-log.ts';
import {
  applyHubSecretOverlay,
  bootstrapSecretNames,
  buildHubSecretAuditEvent,
  createSqliteHubSecretsStore,
  deleteHubSecret,
  HUB_SECRETS_CACHE_TTL_MS,
  HUB_SECRETS_SQLITE_SCHEMA,
  invalidateHubSecretsCache,
  listHubSecretStatus,
  managedSecretNames,
  setHubSecret,
  type HubSecretsStore,
} from '../src/hub-secrets.ts';
import { createMemoryMcpVaultStore, type McpVaultStore, type StoredMcpServerRow } from '../src/mcp-vault.ts';
import type { SqlStorageLike } from '../src/oauth.ts';

const KEY = 'ef_test_vault_master_key_for_hub_secrets_0123456789';

function sqlStorage(db: DatabaseSync): SqlStorageLike {
  return {
    exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): { toArray(): T[] } {
      const trimmed = query.trim();
      const upper = trimmed.toUpperCase();
      if (bindings.length === 0 && upper.startsWith('CREATE ')) {
        db.exec(trimmed);
        return { toArray: () => [] };
      }
      const stmt = db.prepare(trimmed);
      if (upper.startsWith('SELECT')) {
        return { toArray: () => stmt.all(...(bindings as Array<string | number | null>)) as unknown as T[] };
      }
      stmt.run(...(bindings as Array<string | number | null>));
      return { toArray: () => [] };
    },
  };
}

function freshDb(): { db: DatabaseSync; sql: SqlStorageLike } {
  const db = new DatabaseSync(':memory:');
  db.exec(HUB_SECRETS_SQLITE_SCHEMA);
  db.exec(ACCESS_POLICY_SQLITE_SCHEMA);
  db.exec(ACTIVITY_SQLITE_SCHEMA);
  return { db, sql: sqlStorage(db) };
}

function countingStore(inner: HubSecretsStore): HubSecretsStore & { lists: number } {
  const wrapped = {
    lists: 0,
    listHubSecretRows() {
      wrapped.lists++;
      return inner.listHubSecretRows();
    },
    putHubSecretRow: (row: Parameters<HubSecretsStore['putHubSecretRow']>[0]) => inner.putHubSecretRow(row),
    deleteHubSecretRow: (name: string) => inner.deleteHubSecretRow(name),
  };
  return wrapped;
}

test('hub secrets: catalog comes from Go and covers the provider + Cloudflare web search names', () => {
  const managed = new Set(managedSecretNames());
  for (const n of [
    'SERPER_API_KEY',
    'BRAVE_API_KEY',
    'TAVILY_API_KEY',
    'SEARXNG_URL',
    'EDGEFETCH_LLM_API_KEY',
    'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY',
    'OLLAMA_HOST',
    'FIRECRAWL_API_KEY',
    'PDF_OCR_TOKEN',
    'OTEL_EXPORTER_OTLP_HEADERS',
    'WEBHOOK_SECRET',
    'GOOGLE_MAPS_API_KEY',
    'CLOUDFLARE_ACCOUNT_ID',
    'CLOUDFLARE_WEBSEARCH_API_TOKEN',
    'CLOUDFLARE_AI_GATEWAY_ID',
    'CLOUDFLARE_WEBSEARCH_PROVIDER',
    'CLOUDFLARE_WEBSEARCH_BYOK_ALIAS',
  ]) {
    assert.ok(managed.has(n), `${n} must be managed`);
  }
  for (const n of bootstrapSecretNames()) assert.ok(!managed.has(n), `${n} must not be managed`);
  assert.ok(bootstrapSecretNames().includes('VAULT_MASTER_KEY'));
});

test('hub secrets: overlay precedence, values never stored or listed in clear, 30s cache + invalidation', async () => {
  invalidateHubSecretsCache();
  const { db, sql } = freshDb();
  const store = countingStore(createSqliteHubSecretsStore(sql));
  const env = {
    VAULT_MASTER_KEY: KEY,
    SERPER_API_KEY: 'env-serper',
    BRAVE_API_KEY: 'env-brave',
    CALLER_TOKEN: 'caller-token-should-never-fingerprint',
    SEARXNG_URL: 'https://env-search.example.com',
  };

  // No overrides -> overlay is a no-op.
  assert.equal(await applyHubSecretOverlay(env, store, env.VAULT_MASTER_KEY, { now: 1_000 }), env);

  const set = await setHubSecret({ store, vaultMasterKey: KEY, name: 'SERPER_API_KEY', value: '  override-serper-123  ', actorUserId: 'gh_1', now: 2_000 });
  assert.equal(set.ok, true);
  assert.ok(set.ok && /^[0-9a-f]{8}$/.test(set.fingerprint));
  const plainSet = await setHubSecret({ store, vaultMasterKey: KEY, name: 'CLOUDFLARE_WEBSEARCH_PROVIDER', value: 'exa', actorUserId: 'gh_1', now: 2_000 });
  assert.equal(plainSet.ok, true);

  // Ciphertext at rest never contains the value.
  const raw = db.prepare('SELECT name, ciphertext, fingerprint FROM hub_secrets').all() as Array<{ name: string; ciphertext: string }>;
  assert.equal(raw.length, 2);
  for (const r of raw) {
    assert.ok(r.ciphertext.startsWith('hs1.'));
    assert.ok(!r.ciphertext.includes('override-serper-123'));
  }

  const overlaid = await applyHubSecretOverlay(env, store, KEY, { now: 3_000 });
  assert.notEqual(overlaid, env);
  assert.equal(overlaid.SERPER_API_KEY, 'override-serper-123', 'override wins over env');
  assert.equal(overlaid.BRAVE_API_KEY, 'env-brave', 'env kept when no override');
  assert.equal((overlaid as Record<string, unknown>).CLOUDFLARE_WEBSEARCH_PROVIDER, 'exa');
  assert.equal(env.SERPER_API_KEY, 'env-serper', 'input env is not mutated');

  // Cached within TTL: no extra store reads.
  const listsBefore = store.lists;
  await applyHubSecretOverlay(env, store, KEY, { now: 3_000 + HUB_SECRETS_CACHE_TTL_MS - 1 });
  assert.equal(store.lists, listsBefore);
  // A direct DB write is invisible until TTL expiry...
  db.prepare('DELETE FROM hub_secrets WHERE name = ?').run('SERPER_API_KEY');
  assert.equal((await applyHubSecretOverlay(env, store, KEY, { now: 3_500 })).SERPER_API_KEY, 'override-serper-123');
  // ...and visible after it.
  assert.equal((await applyHubSecretOverlay(env, store, KEY, { now: 3_000 + HUB_SECRETS_CACHE_TTL_MS + 1 })).SERPER_API_KEY, 'env-serper');

  // set/delete through the API invalidate immediately.
  await setHubSecret({ store, vaultMasterKey: KEY, name: 'BRAVE_API_KEY', value: 'brave-2', actorUserId: 'gh_1', now: 4_000 });
  assert.equal((await applyHubSecretOverlay(env, store, KEY, { now: 4_001 })).BRAVE_API_KEY, 'brave-2');
  const del = await deleteHubSecret({ store, vaultMasterKey: KEY, name: 'BRAVE_API_KEY' });
  assert.deepEqual(del, { ok: true, name: 'BRAVE_API_KEY', deleted: true });
  assert.equal((await applyHubSecretOverlay(env, store, KEY, { now: 4_002 })).BRAVE_API_KEY, 'env-brave');

  // Status never returns secret values.
  await setHubSecret({ store, vaultMasterKey: KEY, name: 'SERPER_API_KEY', value: 'override-serper-123', actorUserId: 'gh_1', now: 5_000 });
  const status = await listHubSecretStatus(env, store, { vaultMasterKey: KEY, now: 5_001 });
  const json = JSON.stringify(status);
  for (const secret of ['override-serper-123', 'env-serper', 'env-brave', 'caller-token-should-never-fingerprint', KEY]) {
    assert.ok(!json.includes(secret), `status must not contain ${secret}`);
  }
  const by = new Map(status.map((s) => [s.name, s]));
  assert.equal(by.get('SERPER_API_KEY')?.source, 'override');
  assert.equal(by.get('SERPER_API_KEY')?.updatedBy, 'gh_1');
  assert.equal(by.get('SERPER_API_KEY')?.value, null);
  assert.ok(/^[0-9a-f]{8}$/.test(by.get('SERPER_API_KEY')?.fingerprint ?? ''));
  assert.equal(by.get('BRAVE_API_KEY')?.source, 'env');
  assert.equal(by.get('TAVILY_API_KEY')?.source, 'unset');
  assert.equal(by.get('CALLER_TOKEN')?.managed, false);
  assert.equal(by.get('CALLER_TOKEN')?.source, 'env');
  assert.equal(by.get('CALLER_TOKEN')?.fingerprint, null);
  assert.equal(by.get('SEARXNG_URL')?.secret, false);
  assert.equal(by.get('SEARXNG_URL')?.value, 'https://env-search.example.com');
  assert.equal(by.get('CLOUDFLARE_WEBSEARCH_PROVIDER')?.value, 'exa');
  assert.equal(by.get('CLOUDFLARE_WEBSEARCH_API_TOKEN')?.secret, true);
});

test('hub secrets: bootstrap/unknown names, bad values, and missing VAULT_MASTER_KEY are rejected', async () => {
  invalidateHubSecretsCache();
  const { sql } = freshDb();
  const store = createSqliteHubSecretsStore(sql);
  for (const name of ['CALLER_TOKEN', 'VAULT_MASTER_KEY', 'SESSION_SECRET', 'AGENT_TOKENS']) {
    const res = await setHubSecret({ store, vaultMasterKey: KEY, name, value: 'x'.repeat(40), actorUserId: 'gh_1' });
    assert.equal(res.ok, false);
    assert.ok(!res.ok && res.error === 'bootstrap_secret_readonly' && res.status === 403);
    const d = await deleteHubSecret({ store, vaultMasterKey: KEY, name });
    assert.ok(!d.ok && d.error === 'bootstrap_secret_readonly');
  }
  const unknown = await setHubSecret({ store, vaultMasterKey: KEY, name: 'PATH', value: 'x', actorUserId: 'gh_1' });
  assert.ok(!unknown.ok && unknown.error === 'unknown_secret_name');
  const bad: Array<[string, string, string]> = [
    ['SERPER_API_KEY', 'a\nb', 'invalid_secret_value'],
    ['SERPER_API_KEY', 'x'.repeat(8 * 1024 + 1), 'secret_value_too_large'],
    ['SEARXNG_URL', 'http://search.example.com', 'invalid_secret_url'],
    ['OLLAMA_HOST', 'http://192.168.1.2:11434', 'invalid_secret_url'],
    ['CLOUDFLARE_WEBSEARCH_PROVIDER', 'bing', 'invalid_secret_value'],
    ['CLOUDFLARE_WEBSEARCH_BYOK_ALIAS', 'has space', 'invalid_secret_value'],
  ];
  for (const [name, value, code] of bad) {
    const res = await setHubSecret({ store, vaultMasterKey: KEY, name, value, actorUserId: 'gh_1' });
    assert.ok(!res.ok && res.error === code, `${name}=${JSON.stringify(value.slice(0, 20))} -> ${JSON.stringify(res)}`);
  }
  assert.equal((await setHubSecret({ store, vaultMasterKey: KEY, name: 'OLLAMA_HOST', value: 'http://localhost:11434', actorUserId: 'gh_1' })).ok, true);
  assert.deepEqual((await store.listHubSecretRows()).map((r) => r.name), ['OLLAMA_HOST']);

  for (const key of [undefined, '', 'too-short']) {
    const res = await setHubSecret({ store, vaultMasterKey: key, name: 'SERPER_API_KEY', value: 'v', actorUserId: 'gh_1' });
    assert.ok(!res.ok && res.error === 'vault_master_key_unconfigured' && res.status === 503);
    const d = await deleteHubSecret({ store, vaultMasterKey: key, name: 'OLLAMA_HOST' });
    assert.ok(!d.ok && d.error === 'vault_master_key_unconfigured');
    const env = { OLLAMA_HOST: 'http://127.0.0.1:1' };
    assert.equal(await applyHubSecretOverlay(env, store, key), env, 'overlay is a no-op without a key');
  }
});

test('hub secrets: AAD binds the name — ciphertext swapped between rows does not decrypt', async () => {
  invalidateHubSecretsCache();
  const { db, sql } = freshDb();
  const store = createSqliteHubSecretsStore(sql);
  assert.equal((await setHubSecret({ store, vaultMasterKey: KEY, name: 'SERPER_API_KEY', value: 'serper-A', actorUserId: 'gh_1' })).ok, true);
  assert.equal((await setHubSecret({ store, vaultMasterKey: KEY, name: 'WEBHOOK_SECRET', value: 'webhook-B', actorUserId: 'gh_1' })).ok, true);
  const a = (db.prepare('SELECT ciphertext FROM hub_secrets WHERE name = ?').get('SERPER_API_KEY') as { ciphertext: string }).ciphertext;
  // Attacker with DB write access copies A's ciphertext onto B's row.
  db.prepare('UPDATE hub_secrets SET ciphertext = ? WHERE name = ?').run(a, 'WEBHOOK_SECRET');
  invalidateHubSecretsCache();
  const env = { WEBHOOK_SECRET: 'env-webhook' };
  const out = (await applyHubSecretOverlay(env, store, KEY)) as Record<string, string>;
  assert.equal(out.SERPER_API_KEY, 'serper-A');
  assert.equal(out.WEBHOOK_SECRET, 'env-webhook', 'swapped ciphertext must not decrypt as WEBHOOK_SECRET');
  // Rotated master key: overrides are skipped, env stays in effect.
  invalidateHubSecretsCache();
  const rotated = (await applyHubSecretOverlay({ SERPER_API_KEY: 'env' }, store, `${KEY}-rotated`)) as Record<string, string>;
  assert.equal(rotated.SERPER_API_KEY, 'env');
});

test('hub secrets + policy: audit events are admin-category and never carry values', async () => {
  const { sql } = freshDb();
  const activity = createSqliteActivityStore(sql);
  const ev = buildHubSecretAuditEvent({ action: 'set', name: 'SERPER_API_KEY', actorUserId: 'gh_1', fingerprint: 'abcd1234' });
  assert.equal(ev.category, 'admin');
  assert.deepEqual(ev.details, { name: 'SERPER_API_KEY', actor: 'gh_1', fingerprint: 'abcd1234' });
  await activity.recordEvent(ev);
  await activity.recordEvent(
    buildAccessPolicyAuditEvent({ action: 'rule_set', actorUserId: 'gh_1', subject: '*', resource: 'tool:agent', effect: 'deny' }),
  );
  await activity.recordEvent(buildAccessPolicyAuditEvent({ action: 'share_set', actorUserId: 'gh_1', subject: 'gh_2', ownerUserId: 'gh_1', slug: 'notes' }));
  const events = await activity.listEvents(10);
  assert.equal(events.length, 3);
  assert.ok(events.every((e) => e.category === 'admin'));
  assert.ok(events.some((e) => e.event === 'access_rule_set' && e.details.resource === 'tool:agent' && e.details.effect === 'deny'));
});

function serverRow(userId: string, slug: string, extra: Partial<StoredMcpServerRow> = {}): StoredMcpServerRow {
  return {
    id: `${userId}-${slug}-id`,
    userId,
    slug,
    name: `${slug} server`,
    remoteUrl: `https://${slug}.example.com/mcp`,
    remoteOrigin: `https://${slug}.example.com`,
    transport: 'streamable-http',
    authType: 'headers',
    encryptedCredentials: 'v2.sealed-owner-only',
    secretVersion: 2,
    authSummary: { kind: 'headers', maskedBadge: 'Authorization: ****' } as unknown as StoredMcpServerRow['authSummary'],
    domains: [`${slug}.example.com`],
    cachedTools: [{ name: 'search_notes', description: 'Search notes', inputSchema: { type: 'object', properties: {} } }],
    toolCount: 1,
    enabled: true,
    lastVerifiedAt: null,
    lastError: null,
    createdAt: 1,
    updatedAt: 1,
    ...extra,
  };
}

async function policyFixture(): Promise<{ store: AccessPolicyStore; vault: McpVaultStore }> {
  invalidateAccessPolicyCache();
  const { sql } = freshDb();
  const store = createSqliteAccessPolicyStore(sql);
  const vault = createMemoryMcpVaultStore();
  await vault.upsertServer(serverRow('gh_1', 'notes'));
  await vault.upsertServer(serverRow('gh_1', 'crm'));
  await vault.upsertServer(serverRow('gh_3', 'notes'));
  await vault.upsertServer(serverRow('gh_2', 'mine'));
  return { store, vault };
}

test('access policy: tool/route precedence, default allow, and owner bypass', async () => {
  const { store } = await policyFixture();
  const member = { userId: 'gh_2', role: 'member' as const };
  const other = { userId: 'gh_5', role: 'member' as const };
  const owner = { userId: 'gh_1', role: 'owner' as const };
  const opts = { store };

  assert.equal((await evaluateToolAccess(member, 'agent', opts)).allowed, true, 'default allow');
  assert.equal((await evaluateRouteAccess(member, '/v1/agent', opts)).allowed, true);

  assert.equal((await putAccessPolicyRule({ store, subject: '*', resource: 'tool:agent', effect: 'deny', actorUserId: 'gh_1' })).ok, true);
  assert.equal((await putAccessPolicyRule({ store, subject: 'gh_2', resource: 'tool:agent', effect: 'allow', actorUserId: 'gh_1' })).ok, true);
  assert.equal((await putAccessPolicyRule({ store, subject: '*', resource: 'route:/v1/agent*', effect: 'deny', actorUserId: 'gh_1' })).ok, true);
  assert.equal((await putAccessPolicyRule({ store, subject: 'gh_2', resource: 'tool:crawl', effect: 'allow', actorUserId: 'gh_1' })).ok, true);
  assert.equal((await putAccessPolicyRule({ store, subject: 'gh_2', resource: 'tool:crawl', effect: 'deny', actorUserId: 'gh_1' })).ok, true, 'upsert replaces same (subject, resource)');

  assert.deepEqual(await evaluateToolAccess(other, 'agent', opts), {
    allowed: false,
    reason: 'policy_deny',
    matchedRule: { subject: '*', resource: 'tool:agent', effect: 'deny' },
  });
  assert.equal((await evaluateToolAccess(member, 'agent', opts)).allowed, true, 'user allow beats global deny');
  assert.equal((await evaluateToolAccess(member, 'crawl', opts)).allowed, false);
  assert.equal((await evaluateRouteAccess(other, '/v1/agent/run?x=1', opts)).allowed, false);
  assert.equal((await evaluateRouteAccess(other, '/v1/scrape', opts)).allowed, true);
  assert.equal((await evaluateRouteAccess(other, '/health', opts)).allowed, true, 'non-/v1 paths are out of scope');

  // Owners bypass tool/route policy even with explicit user-specific deny rules.
  await putAccessPolicyRule({ store, subject: 'gh_1', resource: 'tool:*', effect: 'deny', actorUserId: 'gh_1' });
  assert.deepEqual(await evaluateToolAccess(owner, 'agent', opts), { allowed: true, reason: 'owner_bypass' });
  assert.equal((await evaluateRouteAccess(owner, '/v1/agent', opts)).allowed, true);

  const tools = [{ name: 'scrape' }, { name: 'agent' }, { name: 'crawl' }];
  assert.deepEqual((await filterToolDefinitions(other, tools, opts)).map((t) => t.name), ['scrape', 'crawl']);
  assert.deepEqual((await filterToolDefinitions(member, tools, opts)).map((t) => t.name), ['scrape', 'agent']);
  assert.deepEqual((await filterToolDefinitions(owner, tools, opts)).map((t) => t.name), ['scrape', 'agent', 'crawl']);

  // Delete canonicalizes and invalidates the cache.
  const del = await deleteAccessPolicyRule({ store, subject: '*', resource: ' tool:agent ' });
  assert.ok(del.ok && del.deleted);
  assert.equal((await evaluateToolAccess(other, 'agent', opts)).allowed, true);

  const bad = await putAccessPolicyRule({ store, subject: '*', resource: 'route:/admin', effect: 'deny', actorUserId: 'gh_1' });
  assert.ok(!bad.ok && bad.error === 'invalid_policy_resource');
});

test('access policy: MCP server shares resolve to the owner row, default deny, no credential leakage', async () => {
  const { store, vault } = await policyFixture();
  const opts = { store, vaultStore: vault };

  // Default deny: nothing shared yet.
  const none = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'notes' });
  assert.ok(!none.ok && none.status === 404);
  assert.deepEqual(await listSharedServersFor('gh_2', opts), []);

  // Own server always resolves, unshared.
  const own = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'mine' });
  assert.ok(own.ok && !own.shared && own.ownerUserId === 'gh_2');

  assert.equal((await putMcpServerShare({ ...opts, ownerUserId: 'gh_1', slug: 'notes', subject: '*' })).ok, true);
  assert.equal((await putMcpServerShare({ ...opts, ownerUserId: 'gh_1', slug: 'crm', subject: 'gh_2' })).ok, true);
  assert.equal((await putMcpServerShare({ ...opts, ownerUserId: 'gh_3', slug: 'notes', subject: 'gh_2' })).ok, true);
  const missing = await putMcpServerShare({ ...opts, ownerUserId: 'gh_1', slug: 'nope', subject: '*' });
  assert.ok(!missing.ok && missing.status === 404);
  const self = await putMcpServerShare({ ...opts, ownerUserId: 'gh_1', slug: 'notes', subject: 'gh_1' });
  assert.ok(!self.ok && self.error === 'invalid_share_subject');

  const crm = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'crm' });
  assert.ok(crm.ok && crm.shared && crm.ownerUserId === 'gh_1' && crm.server.userId === 'gh_1');
  const ambiguous = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'notes' });
  assert.ok(!ambiguous.ok && ambiguous.status === 409);
  const explicit = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'gh_3/notes' });
  assert.ok(explicit.ok && explicit.ownerUserId === 'gh_3');
  const notForOthers = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_5', ref: 'crm' });
  assert.ok(!notForOthers.ok && notForOthers.status === 404);
  const globalShare = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_5', ref: 'notes' });
  assert.ok(globalShare.ok && globalShare.ownerUserId === 'gh_1');

  // Owner role does not grant access to someone else's unshared server.
  const ownerRole = await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_1', ref: 'gh_3/notes' });
  assert.ok(!ownerRole.ok);

  // Member listing exposes only name/slug/tools — never URLs, auth summaries, or ciphertext.
  const listed = await listSharedServersFor('gh_2', opts);
  assert.deepEqual(listed.map((s) => s.ref), ['gh_1/crm', 'gh_1/notes', 'gh_3/notes']);
  const listedJson = JSON.stringify(listed);
  for (const forbidden of ['sealed-owner-only', 'remoteUrl', 'example.com/mcp', 'authSummary', 'encryptedCredentials']) {
    assert.ok(!listedJson.includes(forbidden), `shared listing leaked ${forbidden}`);
  }
  assert.equal(listed[0]?.tools[0]?.name, 'search_notes');

  // Callable rows for scrape routing: own slugs win, duplicate shared slugs dropped, refs mapped.
  const callable = await listCallableServersForCaller('gh_2', opts);
  assert.deepEqual([...callable.refBySlug.entries()], [
    ['mine', 'mine'],
    ['crm', 'gh_1/crm'],
    ['notes', 'gh_1/notes'],
  ]);

  // A user-specific deny revokes a "*" share; deleting a share revokes access.
  await putAccessPolicyRule({ store, subject: 'gh_5', resource: 'mcp_server:gh_1/notes', effect: 'deny', actorUserId: 'gh_1' });
  assert.equal((await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_5', ref: 'notes' })).ok, false);
  assert.ok((await deleteMcpServerShare({ store, ownerUserId: 'gh_1', slug: 'crm', subject: 'gh_2' })).ok);
  assert.equal((await resolveMcpServerForCaller({ ...opts, callerUserId: 'gh_2', ref: 'crm' })).ok, false);
});
