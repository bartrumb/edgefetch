/**
 * Pure Node 22.5+ (`node:sqlite`, `node:fs`, `node:path`, `node:crypto`) Cloudflare Worker storage & Durable Object
 * test doubles (`D1Database`, `R2Bucket`, and `DurableObjectNamespace<AgentHubDO>`) for `hub/test/*`.
 * Zero third-party WebSocket or Node HTTP server dependencies.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  ACTIVITY_SQLITE_SCHEMA,
  createSqliteActivityStore,
  sanitizeDetails,
  type ActivityStore,
  type HubEventInput,
} from '../../src/activity-log';
import {
  AgentHubEngine,
  computeNextHostHealth,
  type AffinityStore,
  type AgentAttachment,
  type ArtifactDispatchPolicy,
  type AuthorizeArtifactUploadParams,
  type CooldownStore,
  type HostHealthRecord,
  type HostHealthStore,
  type HostWindowStore,
  type HubSocketLike,
} from '../../src/agent-hub';
import {
  createSqliteHubSettingsStore,
  HUB_SETTINGS_SQLITE_SCHEMA,
  type HubSettingsStore,
} from '../../src/dev-telemetry';
import {
  createSqliteMcpVaultStore,
  MCP_VAULT_SQLITE_SCHEMA,
  type McpVaultStore,
  type PendingMcpOAuthStateRow,
  type StoredMcpServerRow,
} from '../../src/mcp-vault';
import {
  createSqliteOAuthStore,
  OAUTH_SQLITE_SCHEMA,
  type HubUserRecord,
  type OAuthClientRecord,
  type OAuthCodeRecord,
  type OAuthStore,
  type RotateRefreshParams,
  type SqlStorageLike,
  type UserRole,
} from '../../src/oauth';

if (typeof (globalThis.crypto as unknown as { DigestStream?: unknown }).DigestStream !== 'function') {
  class NodeDigestStream extends WritableStream<Uint8Array> {
    public readonly digest: Promise<ArrayBuffer>;
    constructor(algorithm: string) {
      const hasher = createHash(algorithm.toLowerCase().replace('-', ''));
      let resolveDigest!: (buf: ArrayBuffer) => void;
      const digestPromise = new Promise<ArrayBuffer>((res) => {
        resolveDigest = res;
      });
      super({
        write: (chunk) => {
          hasher.update(chunk);
        },
        close: () => {
          const out = hasher.digest();
          resolveDigest(out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength));
        },
      });
      this.digest = digestPromise;
    }
  }
  Object.defineProperty(globalThis.crypto, 'DigestStream', { value: NodeDigestStream, configurable: true });
}

function coerceSqliteParams(params: unknown[]): Array<string | number | bigint | Uint8Array | null> {
  return params.map((v) => {
    if (v === undefined || v === null) return null;
    if (typeof v === 'boolean') return v ? 1 : 0;
    if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
    return JSON.stringify(v);
  });
}

class LocalD1Statement {
  private readonly db: DatabaseSync;
  private readonly sql: string;
  private readonly params: unknown[];

  constructor(db: DatabaseSync, sql: string, params: unknown[] = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...values: unknown[]): LocalD1Statement {
    return new LocalD1Statement(this.db, this.sql, values);
  }

  async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    const stmt = this.db.prepare(this.sql);
    const bound = coerceSqliteParams(this.params);
    const trimmed = this.sql.trimStart().toUpperCase();
    if (trimmed.startsWith('SELECT') || trimmed.startsWith('WITH') || trimmed.startsWith('PRAGMA') || /\bRETURNING\b/i.test(this.sql)) {
      return { results: stmt.all(...bound) as T[], success: true, meta: { changes: 0 } };
    }
    const res = stmt.run(...bound);
    return { results: [], success: true, meta: { changes: Number(res.changes), last_row_id: Number(res.lastInsertRowid) } };
  }

  async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...coerceSqliteParams(this.params)) as Record<string, unknown> | undefined;
    if (!row) return null;
    return colName !== undefined ? ((row[colName] as T) ?? null) : (row as T);
  }

  async run(): Promise<{ success: true; meta: { changes: number; last_row_id: number } }> {
    const res = this.db.prepare(this.sql).run(...coerceSqliteParams(this.params));
    return { success: true, meta: { changes: Number(res.changes), last_row_id: Number(res.lastInsertRowid) } };
  }

  async raw<T = unknown[]>(): Promise<T[]> {
    const out = await this.all<Record<string, unknown>>();
    return out.results.map((r) => Object.values(r) as unknown as T);
  }
}

export class NodeSqliteD1Database {
  public readonly db: DatabaseSync;

  constructor(filePath: string, migrations: Array<{ name: string; sql?: string; path?: string }> | string[] = []) {
    if (filePath !== ':memory:') mkdirSync(dirname(resolve(filePath)), { recursive: true });
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; CREATE TABLE IF NOT EXISTS _ef_migrations (name TEXT PRIMARY KEY);');
    for (const item of migrations) {
      const migKey = typeof item === 'string' ? item.replace(/\\/g, '/').split('/').slice(-2).join('/') : item.name;
      if (this.db.prepare('SELECT 1 FROM _ef_migrations WHERE name = ?').get(migKey)) continue;
      const sql = typeof item === 'string' ? readFileSync(item, 'utf8') : item.sql ?? readFileSync(item.path!, 'utf8');
      this.db.exec(sql);
      this.db.prepare('INSERT INTO _ef_migrations (name) VALUES (?)').run(migKey);
    }
  }

  prepare(query: string): LocalD1Statement {
    return new LocalD1Statement(this.db, query);
  }

  async batch<T = unknown>(statements: LocalD1Statement[]): Promise<Array<{ results: T[]; success: true; meta: Record<string, unknown> }>> {
    const out: Array<{ results: T[]; success: true; meta: Record<string, unknown> }> = [];
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const st of statements) out.push(await st.all<T>());
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  async exec(query: string): Promise<{ count: number; duration: number }> {
    const t0 = Date.now();
    this.db.exec(query);
    return { count: 1, duration: Date.now() - t0 };
  }

  close(): void {
    try {
      this.db.close();
    } catch {
      // ignore
    }
  }
}

function safeRelPath(rootDir: string, key: string): string {
  const clean = key.replace(/^\/+/, '').replace(/\.\.(\/|\\|$)/g, '_');
  const full = resolve(rootDir, clean);
  if (!full.startsWith(resolve(rootDir))) throw new Error('invalid artifact key');
  return full;
}

export class NodeFsR2Bucket {
  private readonly rootDir: string;

  constructor(rootDir: string) {
    this.rootDir = rootDir;
    mkdirSync(resolve(rootDir), { recursive: true });
  }

  async head(key: string): Promise<{ key: string; size: number; uploaded: Date; etag: string } | null> {
    try {
      const st = await stat(safeRelPath(this.rootDir, key));
      return { key, size: st.size, uploaded: st.mtime, etag: `"${st.size}-${st.mtimeMs}"` };
    } catch {
      return null;
    }
  }

  async get(key: string): Promise<{
    key: string;
    size: number;
    uploaded: Date;
    body: ReadableStream<Uint8Array>;
    arrayBuffer(): Promise<ArrayBuffer>;
    text(): Promise<string>;
    json<T = unknown>(): Promise<T>;
    blob(): Promise<Blob>;
  } | null> {
    const file = safeRelPath(this.rootDir, key);
    try {
      const [buf, st] = await Promise.all([readFile(file), stat(file)]);
      const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      return {
        key,
        size: bytes.byteLength,
        uploaded: st.mtime,
        body: new Blob([bytes]).stream() as ReadableStream<Uint8Array>,
        arrayBuffer: async () => bytes.slice().buffer,
        text: async () => new TextDecoder().decode(bytes),
        json: async <T = unknown>() => JSON.parse(new TextDecoder().decode(bytes)) as T,
        blob: async () => new Blob([bytes]),
      };
    } catch {
      return null;
    }
  }

  async put(
    key: string,
    value: ReadableStream<Uint8Array> | ArrayBuffer | ArrayBufferView | string | Blob | null,
    options?: {
      sha256?: string;
      onlyIf?: Headers | { etagDoesNotMatch?: string };
      httpMetadata?: Record<string, string>;
      customMetadata?: Record<string, string>;
    },
  ): Promise<{ key: string; size: number; uploaded: Date } | null> {
    const file = safeRelPath(this.rootDir, key);
    const wantsIfNoneMatch =
      options?.onlyIf instanceof Headers ? options.onlyIf.get('if-none-match') === '*' : options?.onlyIf?.etagDoesNotMatch === '*';
    if (wantsIfNoneMatch && (await this.head(key))) return null;

    let bytes: Uint8Array;
    if (value === null) bytes = new Uint8Array(0);
    else if (typeof value === 'string') bytes = new TextEncoder().encode(value);
    else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
    else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    else if (value instanceof Blob) bytes = new Uint8Array(await value.arrayBuffer());
    else bytes = new Uint8Array(await new Response(value).arrayBuffer());

    if (options?.sha256) {
      const gotSha = createHash('sha256').update(bytes).digest('hex');
      if (gotSha.toLowerCase() !== options.sha256.toLowerCase()) throw new Error('R2 sha256 checksum mismatch');
    }

    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, bytes);
    return { key, size: bytes.byteLength, uploaded: new Date() };
  }

  async delete(keys: string | string[]): Promise<void> {
    for (const k of Array.isArray(keys) ? keys : [keys]) {
      await rm(safeRelPath(this.rootDir, k), { force: true }).catch(() => undefined);
    }
  }
}

class InMemoryAgentSocket implements HubSocketLike {
  private attachment: unknown = null;
  private closed = false;
  public readonly sentMessages: string[] = [];
  public readonly tags: string[];
  private readonly onText: (sock: InMemoryAgentSocket, text: string) => void;
  private readonly onClosed: (sock: InMemoryAgentSocket, code: number, reason: string) => void;
  private readonly onServerMessage?: (msg: string) => void;

  constructor(
    tags: string[],
    onText: (sock: InMemoryAgentSocket, text: string) => void,
    onClosed: (sock: InMemoryAgentSocket, code: number, reason: string) => void,
    onServerMessage?: (msg: string) => void,
  ) {
    this.tags = tags;
    this.onText = onText;
    this.onClosed = onClosed;
    this.onServerMessage = onServerMessage;
  }

  get readyState(): number {
    return this.closed ? 3 : 1;
  }

  send(data: string): void {
    if (this.closed) throw new Error('websocket_closed');
    this.sentMessages.push(data);
    this.onServerMessage?.(data);
  }

  receiveFromClient(text: string): void {
    if (this.closed) return;
    if (text === 'ping') this.send('pong');
    else this.onText(this, text);
  }

  close(code = 1000, reason = ''): void {
    if (this.closed) return;
    this.closed = true;
    this.onClosed(this, code, reason.slice(0, 100));
  }

  serializeAttachment(value: unknown): void {
    this.attachment = structuredClone(value);
  }

  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
}

type HostHealthRow = {
  host: string;
  ok_count: number;
  rate_limit_count: number;
  challenge_count: number;
  error_5xx_count: number;
  rate_limit_streak: number;
  ewma_ttfb_ms: number;
  recommended_pause_ms: number;
  last_waf_vendor: string | null;
  updated_at: number;
};

function rowToHostHealth(row: HostHealthRow): HostHealthRecord {
  return {
    host: row.host,
    okCount: row.ok_count,
    rateLimit429Count: row.rate_limit_count,
    challengeCount: row.challenge_count,
    error5xxCount: row.error_5xx_count,
    rateLimitStreak: row.rate_limit_streak,
    ewmaTtfbMs: row.ewma_ttfb_ms,
    recommendedPauseMs: row.recommended_pause_ms,
    ...(row.last_waf_vendor ? { lastWafVendor: row.last_waf_vendor } : {}),
    updatedAt: row.updated_at,
  };
}

export class LocalAgentHubCoordinator {
  private readonly db: DatabaseSync;
  private readonly sockets = new Set<InMemoryAgentSocket>();
  private readonly lastHelloLogBySite = new Map<string, number>();
  private readonly lastConnectLogByKey = new Map<string, number>();
  public readonly engine: AgentHubEngine;
  public readonly oauth: OAuthStore;
  public readonly mcpVault: McpVaultStore;
  public readonly activity: ActivityStore;
  public readonly settings: HubSettingsStore;

  constructor(sqlitePath: string) {
    if (sqlitePath !== ':memory:') mkdirSync(dirname(resolve(sqlitePath)), { recursive: true });
    this.db = new DatabaseSync(sqlitePath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS site_cooldowns (host TEXT NOT NULL, site_id TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (host, site_id));
      CREATE TABLE IF NOT EXISTS host_windows (host TEXT PRIMARY KEY, next_allowed_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS host_affinities (host TEXT PRIMARY KEY, site_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS host_health (
        host TEXT PRIMARY KEY, ok_count INTEGER NOT NULL, rate_limit_count INTEGER NOT NULL, challenge_count INTEGER NOT NULL,
        error_5xx_count INTEGER NOT NULL, rate_limit_streak INTEGER NOT NULL, ewma_ttfb_ms INTEGER NOT NULL,
        recommended_pause_ms INTEGER NOT NULL, last_waf_vendor TEXT, updated_at INTEGER NOT NULL
      );
      ${OAUTH_SQLITE_SCHEMA}
      ${MCP_VAULT_SQLITE_SCHEMA}
      ${ACTIVITY_SQLITE_SCHEMA}
      ${HUB_SETTINGS_SQLITE_SCHEMA}
    `);

    const sqlLike: SqlStorageLike = {
      exec: <T = Record<string, unknown>>(query: string, ...bindings: unknown[]) => {
        const stmt = this.db.prepare(query);
        const bound = coerceSqliteParams(bindings);
        const upper = query.trimStart().toUpperCase();
        if (upper.startsWith('SELECT') || upper.startsWith('WITH') || /\bRETURNING\b/i.test(query)) {
          return { toArray: () => stmt.all(...bound) as T[] };
        }
        stmt.run(...bound);
        return { toArray: () => [] as T[] };
      },
    };

    const cooldowns: CooldownStore = {
      isCooledDown: (host, siteId, now) => {
        const row = sqlLike.exec<{ expires_at: number }>('SELECT expires_at FROM site_cooldowns WHERE host = ? AND site_id = ?', host.toLowerCase(), siteId.toLowerCase()).toArray()[0];
        if (!row) return false;
        if (row.expires_at <= now) {
          sqlLike.exec('DELETE FROM site_cooldowns WHERE host = ? AND site_id = ?', host.toLowerCase(), siteId.toLowerCase());
          return false;
        }
        return true;
      },
      setCooldown: (host, siteId, expiresAt) => sqlLike.exec('INSERT OR REPLACE INTO site_cooldowns (host, site_id, expires_at) VALUES (?, ?, ?)', host.toLowerCase(), siteId.toLowerCase(), expiresAt),
      clearSite: (siteId) => sqlLike.exec('DELETE FROM site_cooldowns WHERE site_id = ?', siteId.toLowerCase()),
      listPins: (now) => {
        sqlLike.exec('DELETE FROM site_cooldowns WHERE expires_at <= ?', now);
        return sqlLike.exec<{ host: string; site_id: string; expires_at: number }>('SELECT host, site_id, expires_at FROM site_cooldowns ORDER BY host ASC').toArray().map((r) => ({ host: r.host, siteId: r.site_id, expiresAt: r.expires_at }));
      },
      clearAll: () => sqlLike.exec('DELETE FROM site_cooldowns'),
    };

    const hostWindows: HostWindowStore = {
      getNextAllowed: (host, now) => {
        const row = sqlLike.exec<{ next_allowed_at: number }>('SELECT next_allowed_at FROM host_windows WHERE host = ?', host.toLowerCase()).toArray()[0];
        return !row || row.next_allowed_at <= now ? 0 : row.next_allowed_at;
      },
      setNextAllowed: (host, nextAllowedAt) => sqlLike.exec('INSERT OR REPLACE INTO host_windows (host, next_allowed_at) VALUES (?, ?)', host.toLowerCase(), nextAllowedAt),
      clearAll: () => sqlLike.exec('DELETE FROM host_windows'),
    };

    const affinities: AffinityStore = {
      getStickySite: (host, now) => {
        const row = sqlLike.exec<{ site_id: string; expires_at: number }>('SELECT site_id, expires_at FROM host_affinities WHERE host = ?', host.toLowerCase()).toArray()[0];
        return !row || row.expires_at <= now ? null : row.site_id;
      },
      setStickyHost: (host, siteId, expiresAt) => sqlLike.exec('INSERT OR REPLACE INTO host_affinities (host, site_id, expires_at) VALUES (?, ?, ?)', host.toLowerCase(), siteId.toLowerCase(), expiresAt),
      deleteStickyHost: (host) => sqlLike.exec('DELETE FROM host_affinities WHERE host = ?', host.toLowerCase()),
      clearSite: (siteId) => sqlLike.exec('DELETE FROM host_affinities WHERE site_id = ?', siteId.toLowerCase()),
      clearAll: () => sqlLike.exec('DELETE FROM host_affinities'),
    };

    const hostHealth: HostHealthStore = {
      recordOutcome: (params) => {
        const key = params.host.toLowerCase();
        if (!key) return;
        const row = sqlLike.exec<HostHealthRow>('SELECT * FROM host_health WHERE host = ?', key).toArray()[0];
        const next = computeNextHostHealth(row ? rowToHostHealth(row) : undefined, params);
        sqlLike.exec(
          `INSERT OR REPLACE INTO host_health (host, ok_count, rate_limit_count, challenge_count, error_5xx_count, rate_limit_streak, ewma_ttfb_ms, recommended_pause_ms, last_waf_vendor, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          next.host, next.okCount, next.rateLimit429Count, next.challengeCount, next.error5xxCount, next.rateLimitStreak, next.ewmaTtfbMs, next.recommendedPauseMs, next.lastWafVendor ?? null, next.updatedAt,
        );
      },
      getRecommendedPauseMs: (host) => sqlLike.exec<{ recommended_pause_ms: number }>('SELECT recommended_pause_ms FROM host_health WHERE host = ?', host.toLowerCase()).toArray()[0]?.recommended_pause_ms ?? 0,
      listHosts: (limit = 100) => sqlLike.exec<HostHealthRow>('SELECT * FROM host_health ORDER BY updated_at DESC LIMIT ?', Math.max(1, Math.min(500, Math.floor(limit)))).toArray().map(rowToHostHealth),
      clearAll: () => sqlLike.exec('DELETE FROM host_health'),
    };

    this.engine = new AgentHubEngine({
      getSockets: (tag) => (tag ? [...this.sockets].filter((s) => s.tags.includes(tag)) : [...this.sockets]),
      cooldowns,
      hostWindows,
      affinities,
      hostHealth,
    });
    this.oauth = createSqliteOAuthStore(sqlLike);
    this.mcpVault = createSqliteMcpVaultStore(sqlLike);
    this.activity = createSqliteActivityStore(sqlLike);
    this.settings = createSqliteHubSettingsStore(sqlLike);
  }

  connectMockAgent(params: {
    siteId: string;
    arch?: string | null;
    version?: string | null;
    browserVersion?: string | null;
    browserSandbox?: string | null;
    capabilities?: string | null;
    publicIp?: string | null;
    onServerMessage?: (msg: string) => void;
  }): { socket: HubSocketLike; sentMessages: string[]; sendFromAgent: (text: string) => void; close: (code?: number, reason?: string) => void } {
    const wrapped = new InMemoryAgentSocket(
      [`site:${params.siteId}`],
      (sock, text) => {
        if (text.length > 2048) return;
        try {
          const msg = JSON.parse(text) as { type?: string; version?: string; arch?: string; goVersion?: string; browserVersion?: string; browserSandbox?: string | boolean; capabilities?: string[]; reconnectAttempt?: number };
          if (msg.type === 'agent_hello' || msg.type === 'hello') {
            const updated = this.engine.updateAgentHello(sock, msg);
            const verifiedSiteId = (updated ?? (sock.deserializeAttachment() as AgentAttachment | null))?.siteId ?? params.siteId;
            const nowMs = Date.now();
            if (nowMs - (this.lastHelloLogBySite.get(verifiedSiteId) ?? 0) >= 60_000) {
              if (this.lastHelloLogBySite.size >= 512) this.lastHelloLogBySite.clear();
              this.lastHelloLogBySite.set(verifiedSiteId, nowMs);
              void this.activity.recordEvent({
                level: 'info',
                category: 'agent',
                event: (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready',
                summary: `Remote node "${verifiedSiteId}" ready (${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
                details: sanitizeDetails({
                  siteId: verifiedSiteId,
                  version: typeof msg.version === 'string' ? msg.version.slice(0, 64) : null,
                  arch: typeof msg.arch === 'string' ? msg.arch.slice(0, 32) : null,
                  goVersion: typeof msg.goVersion === 'string' ? msg.goVersion.slice(0, 32) : null,
                  capabilities: Array.isArray(msg.capabilities) ? msg.capabilities.slice(0, 16) : [],
                }),
              });
            }
          } else if (msg.type === 'tracker_list_ack') {
            this.engine.noteTrackerListAck(sock, msg.version);
          }
        } catch {
          // ignore
        }
      },
      (sock, code, reason) => {
        this.sockets.delete(sock);
        this.engine.handleDisconnect(sock, reason || `closed_${code}`);
      },
      params.onServerMessage,
    );

    this.sockets.add(wrapped);
    const att = this.engine.registerAgent(wrapped, params.siteId, params.arch ?? null, {
      version: params.version ?? null,
      browserVersion: params.browserVersion ?? null,
      browserSandbox: params.browserSandbox ?? null,
      publicIp: params.publicIp ?? null,
      capabilities: params.capabilities ?? null,
    });
    if (this.sockets.has(wrapped)) {
      try {
        wrapped.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
        this.engine.sendCurrentTrackerListToSocket(wrapped);
      } catch {
        // ignore
      }
      const nowMs = Date.now();
      const siteKey = `site:${att.siteId}`;
      const ipKey = `ip:${params.publicIp ?? 'unknown'}`;
      if (nowMs - (this.lastConnectLogByKey.get(siteKey) ?? 0) >= 60_000 && nowMs - (this.lastConnectLogByKey.get(ipKey) ?? 0) >= 5_000) {
        if (this.lastConnectLogByKey.size >= 512) this.lastConnectLogByKey.clear();
        this.lastConnectLogByKey.set(siteKey, nowMs);
        this.lastConnectLogByKey.set(ipKey, nowMs);
        void this.activity.recordEvent({
          level: 'info',
          category: 'agent',
          event: 'agent_ws_connected',
          summary: `Remote node "${att.siteId}" connected over WebSocket`,
          details: sanitizeDetails({ siteId: att.siteId, arch: att.arch, version: att.version ?? null }),
        });
      }
    }
    return { socket: wrapped, sentMessages: wrapped.sentMessages, sendFromAgent: (t) => wrapped.receiveFromClient(t), close: (c, r) => wrapped.close(c, r) };
  }

  syncTrackerList(version: string | null, frames: string[]): void {
    this.engine.setTrackerListBroadcast(version, frames);
  }

  asNamespace(): { idFromName: (name: string) => string; get: (_id?: unknown) => Record<string, unknown> } {
    const stub = {
      fetch: async () => new Response('use mock agent handler', { status: 426 }),
      listAgents: async () => this.engine.listAgents(),
      syncTrackerList: async (version: string | null, frames: string[]) => this.syncTrackerList(version, frames),
      listAffinities: async () => this.engine.listAffinities(),
      clearAffinities: async (siteId?: string) => this.engine.clearAffinities(siteId),
      listHostHealth: async (limit = 100) => this.engine.listHostHealth(limit),
      recordHostOutcome: async (p: Parameters<AgentHubEngine['recordHostOutcome']>[0]) => this.engine.recordHostOutcome(p),
      recordHubEvents: async (events: HubEventInput[]) => {
        for (const ev of events) await this.activity.recordEvent(ev);
      },
      clearHubEvents: async () => this.activity.clearEvents(),
      recordMcpCall: async (p: Parameters<ActivityStore['recordMcpCall']>[0]) => this.activity.recordMcpCall(p),
      getPortalState: async (now: number) => ({
        ...this.engine.listAgents(),
        affinities: this.engine.listAffinities(),
        grants: await this.oauth.listGrants(now),
        users: (await this.oauth.listUsers?.()) ?? [],
        mcpClients: await this.activity.listMcpClients(),
        events: this.activity.listPortalEvents ? await this.activity.listPortalEvents(75, 75) : await this.activity.listEvents(150),
      }),
      waitForHostWindow: async (hosts: string[], pauseMs?: number, dl?: number) => this.engine.waitForHostWindow(hosts, pauseMs, dl),
      dispatchFetch: async (rawBody: string, trace: Record<string, string>, preferredSite?: string, artifactPolicy?: ArtifactDispatchPolicy) =>
        this.engine.dispatchFetch(rawBody, trace, { preferredSite, ...(artifactPolicy ? { artifactPolicy } : {}) }),
      hasPendingJob: async (jobId: string, siteId: string) => this.engine.hasPendingJob(jobId, siteId),
      verifyPendingJob: async (jobId: string, jobNonce: string, siteId: string) => this.engine.verifyPendingJob(jobId, jobNonce, siteId),
      authorizeArtifactUpload: async (p: AuthorizeArtifactUploadParams) => this.engine.authorizeArtifactUpload(p),
      failJob: async (jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true) => this.engine.failJob(jobId, jobNonce, siteId, reason, permanent),
      completeJob: async (jobId: string, jobNonce: string, siteId: string, bodyText: string) => this.engine.completeJob(jobId, jobNonce, siteId, bodyText),
      oauthPutClient: (c: OAuthClientRecord) => this.oauth.putClient(c),
      oauthGetClient: (id: string) => this.oauth.getClient(id),
      oauthPutCode: (c: OAuthCodeRecord) => this.oauth.putCode(c),
      oauthConsumeCode: (h: string, now: number) => this.oauth.consumeCode(h, now),
      oauthPutTokenPair: (p: Parameters<OAuthStore['putTokenPair']>[0]) => this.oauth.putTokenPair(p),
      oauthGetAccessToken: (h: string, now: number) => this.oauth.getAccessToken(h, now),
      oauthConsumeRefreshToken: (h: string, now: number) => this.oauth.consumeRefreshToken(h, now),
      oauthGetRefreshTokenLineageHint: (h: string, now: number) => this.oauth.getRefreshTokenLineageHint?.(h, now) ?? null,
      oauthRotateRefreshToken: (p: RotateRefreshParams) => this.oauth.rotateRefreshToken(p),
      oauthListGrants: (now: number, userId?: string) => this.oauth.listGrants(now, userId),
      oauthRevokeGrant: (id: string, userId?: string) => this.oauth.revokeGrant(id, userId),
      oauthRevokeByTokenHash: (h: string) => this.oauth.revokeByTokenHash(h),
      oauthUpsertUser: (u: HubUserRecord) => this.oauth.upsertUser?.(u) ?? u,
      oauthGetUser: (id: string) => this.oauth.getUser?.(id) ?? null,
      oauthListUsers: () => this.oauth.listUsers?.() ?? [],
      oauthCountUsers: () => this.oauth.countUsers?.() ?? 0,
      oauthUpdateUserRole: (id: string, role: UserRole, promotedByOwnerId?: string | null) => this.oauth.updateUserRole?.(id, role, promotedByOwnerId) ?? false,
      oauthEnforcePinnedFounderOwners: (pinnedOwnerId: string) => this.oauth.enforcePinnedFounderOwners?.(pinnedOwnerId) ?? 0,
      oauthCheckAuthLockout: (b: string, now: number, m?: number) => this.oauth.checkAuthLockout(b, now, m),
      oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => this.oauth.recordAuthFailure(b, now, w, m),
      oauthClearAuthFailures: (b: string) => this.oauth.clearAuthFailures(b),
      vaultListServers: (userId: string) => this.mcpVault.listServers(userId),
      vaultGetServer: (userId: string, slugOrDomain: string) => this.mcpVault.getServer(userId, slugOrDomain),
      vaultUpsertServer: (row: StoredMcpServerRow) => this.mcpVault.upsertServer(row),
      vaultResealServerSecret: (params: Parameters<NonNullable<McpVaultStore['resealServerSecret']>>[0]) =>
        this.mcpVault.resealServerSecret ? this.mcpVault.resealServerSecret(params) : false,
      vaultDeleteServer: (userId: string, slug: string) => this.mcpVault.deleteServer(userId, slug),
      vaultPutOAuthState: (row: PendingMcpOAuthStateRow) => this.mcpVault.putOAuthState(row),
      vaultConsumeOAuthState: (stateHash: string, userId: string, now: number) => this.mcpVault.consumeOAuthState(stateHash, userId, now),
      getHubSetting: (k: string) => this.settings.getSetting(k),
      setHubSetting: (k: string, v: string) => this.settings.setSetting(k, v),
    };
    return { idFromName: (name: string) => name, get: () => stub };
  }

  close(): void {
    for (const ws of [...this.sockets]) {
      try {
        ws.close(1001, 'shutdown');
      } catch {
        // ignore
      }
    }
    try {
      this.db.close();
    } catch {
      // ignore
    }
  }
}

export function createLocalFetchBinding<Env>(
  worker: { fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> | Response },
  env: Env,
  ctx?: ExecutionContext,
): { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> } {
  return {
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request && !init ? input : new Request(input, init);
      return await worker.fetch(req, env, ctx);
    },
  };
}
