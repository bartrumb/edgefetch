/**
 * Zero-dependency Web-Standards & Node 22.5+ (`node:sqlite`, `node:fs`, `node:crypto`) runtime adapters
 * implementing Cloudflare's `D1Database`, `R2Bucket`, and `DurableObjectNamespace<AgentHubDO>` interfaces.
 *
 * Allows the entire EdgeFetch TypeScript Hub (`/admin`, OAuth 2.1, 11-tool `/mcp`, `.ipynb`/OpenAPI/Defuddle
 * extractors, SQLite FTS5 search, R2/disk artifacts, and `/agent/ws` outbound Go worker fleet) to run unmodified
 * on Fly.io, Railway, Render, Deno/Node containers, and `docker compose up` with zero Postgres or Redis.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Duplex } from 'node:stream';
import {
  ACTIVITY_SQLITE_SCHEMA,
  createSqliteActivityStore,
  sanitizeDetails,
  type ActivityStore,
  type HubEventInput,
} from '../src/activity-log';
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
} from '../src/agent-hub';
import { createSqliteOAuthStore, OAUTH_SQLITE_SCHEMA, type OAuthClientRecord, type OAuthCodeRecord, type OAuthStore, type RotateRefreshParams, type SqlStorageLike } from '../src/oauth';

// Polyfill Cloudflare's streaming `crypto.DigestStream` on Node.js using zero-copy `node:crypto` `createHash`.
if (typeof (globalThis.crypto as unknown as { DigestStream?: unknown }).DigestStream !== 'function') {
  class NodeDigestStream extends WritableStream<Uint8Array> {
    public readonly digest: Promise<ArrayBuffer>;
    constructor(algorithm: string) {
      const nodeAlg = algorithm.toLowerCase().replace('-', '');
      const hasher = createHash(nodeAlg);
      let resolveDigest!: (buf: ArrayBuffer) => void;
      const digestPromise = new Promise<ArrayBuffer>((res) => {
        resolveDigest = res;
      });
      super({
        write(chunk) {
          hasher.update(chunk);
        },
        close() {
          const out = hasher.digest();
          resolveDigest(out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength));
        },
      });
      this.digest = digestPromise;
    }
  }
  Object.defineProperty(globalThis.crypto, 'DigestStream', {
    value: NodeDigestStream,
    configurable: true,
  });
}

// ── 1. D1Database Adapter over built-in `node:sqlite` (SQLite + FTS5) ─────────────────────────────────────────────

function coerceSqliteParams(params: unknown[]): Array<string | number | bigint | Uint8Array | null> {
  return params.map((v) => {
    if (v === undefined || v === null) return null;
    if (typeof v === 'boolean') return v ? 1 : 0;
    if (typeof v === 'number' || typeof v === 'bigint' || typeof v === 'string' || v instanceof Uint8Array) return v;
    return JSON.stringify(v);
  });
}

class LocalD1Statement {
  constructor(
    private readonly db: DatabaseSync,
    private readonly sql: string,
    private readonly params: unknown[] = [],
  ) {}

  bind(...values: unknown[]): LocalD1Statement {
    return new LocalD1Statement(this.db, this.sql, values);
  }

  async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: true; meta: Record<string, unknown> }> {
    const stmt = this.db.prepare(this.sql);
    const bound = coerceSqliteParams(this.params);
    const trimmed = this.sql.trimStart().toUpperCase();
    if (trimmed.startsWith('SELECT') || trimmed.startsWith('WITH') || trimmed.startsWith('PRAGMA') || /\bRETURNING\b/i.test(this.sql)) {
      const rows = stmt.all(...bound) as T[];
      return { results: rows, success: true, meta: { changes: 0 } };
    }
    const res = stmt.run(...bound);
    return { results: [], success: true, meta: { changes: Number(res.changes), last_row_id: Number(res.lastInsertRowid) } };
  }

  async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
    const stmt = this.db.prepare(this.sql);
    const row = stmt.get(...coerceSqliteParams(this.params)) as Record<string, unknown> | undefined;
    if (!row) return null;
    if (colName !== undefined) return (row[colName] as T) ?? null;
    return row as T;
  }

  async run(): Promise<{ success: true; meta: { changes: number; last_row_id: number } }> {
    const stmt = this.db.prepare(this.sql);
    const res = stmt.run(...coerceSqliteParams(this.params));
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
    if (filePath !== ':memory:') {
      mkdirSync(dirname(resolve(filePath)), { recursive: true });
    }
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; CREATE TABLE IF NOT EXISTS _ef_migrations (name TEXT PRIMARY KEY);');
    for (const item of migrations) {
      const migKey = typeof item === 'string' ? item.replace(/\\/g, '/').split('/').slice(-2).join('/') : item.name;
      const already = this.db.prepare('SELECT 1 FROM _ef_migrations WHERE name = ?').get(migKey);
      if (already) continue;
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
      for (const st of statements) {
        out.push(await st.all<T>());
      }
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

// ── 2. R2Bucket Adapter over local persistent filesystem (`/data/artifacts`) ──────────────────────────────────────

function safeRelPath(rootDir: string, key: string): string {
  const clean = key.replace(/^\/+/, '').replace(/\.\.(\/|\\|$)/g, '_');
  const full = resolve(rootDir, clean);
  const resolvedRoot = resolve(rootDir);
  if (!full.startsWith(resolvedRoot)) {
    throw new Error('invalid artifact key');
  }
  return full;
}

export class NodeFsR2Bucket {
  constructor(private readonly rootDir: string) {
    mkdirSync(resolve(rootDir), { recursive: true });
  }

  async head(key: string): Promise<{ key: string; size: number; uploaded: Date; etag: string } | null> {
    const file = safeRelPath(this.rootDir, key);
    try {
      const st = await stat(file);
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
    options?: { sha256?: string; onlyIf?: Headers | { etagDoesNotMatch?: string } },
  ): Promise<{ key: string; size: number; uploaded: Date } | null> {
    const file = safeRelPath(this.rootDir, key);
    const wantsIfNoneMatch =
      options?.onlyIf instanceof Headers
        ? options.onlyIf.get('if-none-match') === '*'
        : options?.onlyIf?.etagDoesNotMatch === '*';
    if (wantsIfNoneMatch) {
      const existing = await this.head(key);
      if (existing) return null;
    }

    let bytes: Uint8Array;
    if (value === null) {
      bytes = new Uint8Array(0);
    } else if (typeof value === 'string') {
      bytes = new TextEncoder().encode(value);
    } else if (value instanceof ArrayBuffer) {
      bytes = new Uint8Array(value);
    } else if (ArrayBuffer.isView(value)) {
      bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } else if (value instanceof Blob) {
      bytes = new Uint8Array(await value.arrayBuffer());
    } else {
      bytes = new Uint8Array(await new Response(value).arrayBuffer());
    }

    if (options?.sha256) {
      const gotSha = createHash('sha256').update(bytes).digest('hex');
      if (gotSha.toLowerCase() !== options.sha256.toLowerCase()) {
        throw new Error('R2 sha256 checksum mismatch');
      }
    }

    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, bytes);
    return { key, size: bytes.byteLength, uploaded: new Date() };
  }

  async delete(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const k of list) {
      await rm(safeRelPath(this.rootDir, k), { force: true }).catch(() => undefined);
    }
  }
}

// ── 3. RFC 6455 Raw TCP WebSocket Wrapper + In-Process `AgentHubDO` Coordinator ───────────────────────────────────

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export class RawServerWebSocket implements HubSocketLike {
  private attachment: unknown = null;
  private closed = false;
  private rxBuf = Buffer.alloc(0);

  constructor(
    private readonly socket: Duplex,
    public readonly tags: string[],
    private readonly onText: (ws: RawServerWebSocket, msg: string) => void,
    private readonly onClosed: (ws: RawServerWebSocket, code: number, reason: string) => void,
  ) {
    socket.on('data', (chunk: Buffer) => this.handleChunk(chunk));
    socket.on('close', () => {
      if (!this.closed) {
        this.closed = true;
        this.onClosed(this, 1006, 'tcp_closed');
      }
    });
    socket.on('error', () => {
      if (!this.closed) {
        this.closed = true;
        this.onClosed(this, 1011, 'socket_error');
      }
    });
  }

  send(data: string): void {
    if (this.closed) throw new Error('websocket_closed');
    const payload = Buffer.from(data, 'utf8');
    this.writeFrame(0x1, payload);
  }

  close(code = 1000, reason = ''): void {
    if (this.closed) return;
    this.closed = true;
    this.rxBuf = Buffer.alloc(0);
    const reasonBuf = Buffer.from(reason.slice(0, 100), 'utf8');
    const body = Buffer.alloc(2 + reasonBuf.length);
    body.writeUInt16BE(code, 0);
    reasonBuf.copy(body, 2);
    try {
      this.writeFrame(0x8, body);
    } catch {
      // best-effort close frame
    }
    try {
      this.socket.end();
    } catch {
      // ignore
    }
    this.socket.destroy();
    this.onClosed(this, code, reason);
  }

  serializeAttachment(value: unknown): void {
    this.attachment = structuredClone(value);
  }

  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }

  private writeFrame(opcode: number, payload: Buffer): void {
    const len = payload.length;
    let header: Buffer;
    if (len < 126) {
      header = Buffer.from([0x80 | opcode, len]);
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    this.socket.write(Buffer.concat([header, payload]));
  }

  private handleChunk(chunk: Buffer): void {
    if (this.closed) {
      this.socket.destroy();
      return;
    }
    this.rxBuf = Buffer.concat([this.rxBuf, chunk]);
    while (this.rxBuf.length >= 2) {
      const b0 = this.rxBuf[0]!;
      const b1 = this.rxBuf[1]!;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let payloadLen = b1 & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this.rxBuf.length < 4) return;
        payloadLen = this.rxBuf.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this.rxBuf.length < 10) return;
        const bigLen = this.rxBuf.readBigUInt64BE(2);
        if (bigLen > 1_048_576n) {
          this.close(1009, 'message_too_big');
          return;
        }
        payloadLen = Number(bigLen);
        offset = 10;
      }
      if (payloadLen > 1_048_576) {
        this.close(1009, 'message_too_big');
        return;
      }

      const maskLen = masked ? 4 : 0;
      if (this.rxBuf.length < offset + maskLen + payloadLen) return;

      const payload = Buffer.from(this.rxBuf.subarray(offset + maskLen, offset + maskLen + payloadLen));
      if (masked) {
        const mask = this.rxBuf.subarray(offset, offset + 4);
        for (let i = 0; i < payload.length; i++) {
          payload[i]! ^= mask[i & 3]!;
        }
      }
      this.rxBuf = this.rxBuf.subarray(offset + maskLen + payloadLen);

      if (opcode === 0x8) {
        // Close frame
        this.close(1000, 'peer_close');
        return;
      }
      if (opcode === 0x9) {
        // Ping -> Pong
        this.writeFrame(0x0a, payload);
        continue;
      }
      if (opcode === 0x1) {
        const text = payload.toString('utf8');
        if (text === 'ping') {
          this.send('pong');
        } else {
          this.onText(this, text);
        }
      }
    }
  }
}

export class LocalAgentHubCoordinator {
  private readonly db: DatabaseSync;
  private readonly sockets = new Set<RawServerWebSocket>();
  private readonly lastHelloLogBySite = new Map<string, number>();
  public readonly engine: AgentHubEngine;
  public readonly oauth: OAuthStore;
  public readonly activity: ActivityStore;

  constructor(sqlitePath: string) {
    if (sqlitePath !== ':memory:') {
      mkdirSync(dirname(resolve(sqlitePath)), { recursive: true });
    }
    this.db = new DatabaseSync(sqlitePath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS site_cooldowns (
        host TEXT NOT NULL,
        site_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (host, site_id)
      );
      CREATE TABLE IF NOT EXISTS host_windows (
        host TEXT PRIMARY KEY,
        next_allowed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS host_affinities (
        host TEXT PRIMARY KEY,
        site_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS host_health (
        host TEXT PRIMARY KEY,
        ok_count INTEGER NOT NULL,
        rate_limit_count INTEGER NOT NULL,
        challenge_count INTEGER NOT NULL,
        error_5xx_count INTEGER NOT NULL,
        rate_limit_streak INTEGER NOT NULL,
        ewma_ttfb_ms INTEGER NOT NULL,
        recommended_pause_ms INTEGER NOT NULL,
        last_waf_vendor TEXT,
        updated_at INTEGER NOT NULL
      );
      ${OAUTH_SQLITE_SCHEMA}
      ${ACTIVITY_SQLITE_SCHEMA}
    `);

    const sqlLike: SqlStorageLike = {
      exec: <T = Record<string, unknown>>(query: string, ...bindings: unknown[]) => {
        const stmt = this.db.prepare(query);
        const bound = coerceSqliteParams(bindings);
        const upper = query.trimStart().toUpperCase();
        if (upper.startsWith('SELECT') || upper.startsWith('WITH') || /\bRETURNING\b/i.test(query)) {
          const rows = stmt.all(...bound) as T[];
          return { toArray: () => rows };
        }
        stmt.run(...bound);
        return { toArray: () => [] as T[] };
      },
    };

    const cooldowns: CooldownStore = {
      isCooledDown: (host, siteId, now) => {
        const row = sqlLike.exec<{ expires_at: number }>(
          'SELECT expires_at FROM site_cooldowns WHERE host = ? AND site_id = ?',
          host.toLowerCase(),
          siteId.toLowerCase(),
        ).toArray()[0];
        if (!row) return false;
        if (row.expires_at <= now) {
          sqlLike.exec('DELETE FROM site_cooldowns WHERE host = ? AND site_id = ?', host.toLowerCase(), siteId.toLowerCase());
          return false;
        }
        return true;
      },
      setCooldown: (host, siteId, expiresAt) => {
        sqlLike.exec(
          'INSERT OR REPLACE INTO site_cooldowns (host, site_id, expires_at) VALUES (?, ?, ?)',
          host.toLowerCase(),
          siteId.toLowerCase(),
          expiresAt,
        );
      },
      clearSite: (siteId) => sqlLike.exec('DELETE FROM site_cooldowns WHERE site_id = ?', siteId.toLowerCase()),
      listPins: (now) => {
        sqlLike.exec('DELETE FROM site_cooldowns WHERE expires_at <= ?', now);
        return sqlLike
          .exec<{ host: string; site_id: string; expires_at: number }>('SELECT host, site_id, expires_at FROM site_cooldowns ORDER BY host ASC')
          .toArray()
          .map((r) => ({ host: r.host, siteId: r.site_id, expiresAt: r.expires_at }));
      },
      clearAll: () => sqlLike.exec('DELETE FROM site_cooldowns'),
    };

    const hostWindows: HostWindowStore = {
      getNextAllowed: (host, now) => {
        const row = sqlLike.exec<{ next_allowed_at: number }>('SELECT next_allowed_at FROM host_windows WHERE host = ?', host.toLowerCase()).toArray()[0];
        if (!row || row.next_allowed_at <= now) return 0;
        return row.next_allowed_at;
      },
      setNextAllowed: (host, nextAllowedAt) => {
        sqlLike.exec('INSERT OR REPLACE INTO host_windows (host, next_allowed_at) VALUES (?, ?)', host.toLowerCase(), nextAllowedAt);
      },
      clearAll: () => sqlLike.exec('DELETE FROM host_windows'),
    };

    const affinities: AffinityStore = {
      getStickySite: (host, now) => {
        const row = sqlLike.exec<{ site_id: string; expires_at: number }>('SELECT site_id, expires_at FROM host_affinities WHERE host = ?', host.toLowerCase()).toArray()[0];
        if (!row || row.expires_at <= now) return null;
        return row.site_id;
      },
      setStickyHost: (host, siteId, expiresAt) => {
        sqlLike.exec('INSERT OR REPLACE INTO host_affinities (host, site_id, expires_at) VALUES (?, ?, ?)', host.toLowerCase(), siteId.toLowerCase(), expiresAt);
      },
      deleteStickyHost: (host) => sqlLike.exec('DELETE FROM host_affinities WHERE host = ?', host.toLowerCase()),
      clearSite: (siteId) => sqlLike.exec('DELETE FROM host_affinities WHERE site_id = ?', siteId.toLowerCase()),
      clearAll: () => sqlLike.exec('DELETE FROM host_affinities'),
    };

    const hostHealth: HostHealthStore = {
      recordOutcome: (params) => {
        const key = params.host.toLowerCase();
        if (!key) return;
        const row = sqlLike
          .exec<{
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
          }>('SELECT * FROM host_health WHERE host = ?', key)
          .toArray()[0];
        const prev: HostHealthRecord | undefined = row
          ? {
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
            }
          : undefined;
        const next = computeNextHostHealth(prev, params);
        sqlLike.exec(
          `INSERT OR REPLACE INTO host_health (
             host, ok_count, rate_limit_count, challenge_count, error_5xx_count,
             rate_limit_streak, ewma_ttfb_ms, recommended_pause_ms, last_waf_vendor, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          next.host,
          next.okCount,
          next.rateLimit429Count,
          next.challengeCount,
          next.error5xxCount,
          next.rateLimitStreak,
          next.ewmaTtfbMs,
          next.recommendedPauseMs,
          next.lastWafVendor ?? null,
          next.updatedAt,
        );
      },
      getRecommendedPauseMs: (host) => {
        const row = sqlLike
          .exec<{ recommended_pause_ms: number }>('SELECT recommended_pause_ms FROM host_health WHERE host = ?', host.toLowerCase())
          .toArray()[0];
        return row?.recommended_pause_ms ?? 0;
      },
      listHosts: (limit = 100) => {
        const cap = Math.max(1, Math.min(500, Math.floor(limit)));
        return sqlLike
          .exec<{
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
          }>('SELECT * FROM host_health ORDER BY updated_at DESC LIMIT ?', cap)
          .toArray()
          .map((row) => ({
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
          }));
      },
      clearAll: () => sqlLike.exec('DELETE FROM host_health'),
    };

    this.engine = new AgentHubEngine({
      getSockets: (tag) => {
        const all = [...this.sockets];
        return tag ? all.filter((s) => s.tags.includes(tag)) : all;
      },
      cooldowns,
      hostWindows,
      affinities,
      hostHealth,
    });
    this.oauth = createSqliteOAuthStore(sqlLike);
    this.activity = createSqliteActivityStore(sqlLike);
  }

  /** Accepts an RFC 6455 HTTP `Upgrade: websocket` socket from `node:http` `server.on('upgrade')`. */
  acceptNodeUpgrade(params: {
    wsKey: string;
    socket: Duplex;
    head: Buffer;
    siteId: string;
    arch: string | null;
    version: string | null;
    capabilities: string | null;
    publicIp: string | null;
    subprotocol?: string | null;
  }): void {
    const acceptKey = createHash('sha1').update(params.wsKey.trim() + WS_GUID).digest('base64');
    const respHeaders = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey}`,
      ...(params.subprotocol ? [`Sec-WebSocket-Protocol: ${params.subprotocol}`] : []),
      '\r\n',
    ];
    params.socket.write(respHeaders.join('\r\n'));

    const ws = new RawServerWebSocket(
      params.socket,
      [`site:${params.siteId}`],
      (sock, text) => {
        if (text.length > 2048) return;
        try {
          const msg = JSON.parse(text) as {
            type?: string;
            version?: string;
            arch?: string;
            goVersion?: string;
            capabilities?: string[];
            reconnectAttempt?: number;
          };
          if (msg.type === 'agent_hello' || msg.type === 'hello') {
            const updated = this.engine.updateAgentHello(sock, msg);
            const att = updated ?? (sock.deserializeAttachment() as AgentAttachment | null);
            const verifiedSiteId = att?.siteId ?? params.siteId;
            const evName = (msg.reconnectAttempt ?? 0) > 0 ? 'agent_reconnected' : 'agent_ready';
            const nowMs = Date.now();
            const lastLoggedAt = this.lastHelloLogBySite.get(verifiedSiteId) ?? 0;
            // M9: Throttle `agent_ready` event logging to at most 1 per 60s per verified `siteId`, and spread `...msg`
            // FIRST so an untrusted `msg.siteId` NEVER overwrites the verified `siteId`!
            if (nowMs - lastLoggedAt >= 60_000) {
              this.lastHelloLogBySite.set(verifiedSiteId, nowMs);
              void this.activity.recordEvent({
                level: 'info',
                category: 'agent',
                event: evName,
                summary: `Remote node "${verifiedSiteId}" ready (${msg.goVersion ?? 'go'}, ${msg.arch ?? ''})`,
                details: sanitizeDetails({ ...msg, siteId: verifiedSiteId }),
              });
            }
          }
        } catch {
          // ignore
        }
      },
      (sock, code, reason) => {
        this.sockets.delete(sock);
        this.engine.handleDisconnect(sock, reason || `closed_${code}`);
      },
    );

    this.sockets.add(ws);
    if (params.head.length > 0) {
      params.socket.emit('data', params.head);
    }
    const att = this.engine.registerAgent(ws, params.siteId, params.arch, {
      version: params.version,
      publicIp: params.publicIp,
      capabilities: params.capabilities,
    });
    ws.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
    void this.activity.recordEvent({
      level: 'info',
      category: 'agent',
      event: 'agent_ws_connected',
      summary: `Remote node "${att.siteId}" connected over WebSocket`,
      details: sanitizeDetails({ siteId: att.siteId, arch: att.arch, version: att.version ?? null }),
    });
  }

  /** Returns a `DurableObjectNamespace<AgentHubDO>`-compatible stub object for `hub/src/index.ts`. */
  asNamespace(): unknown {
    const stub = {
      fetch: async () => new Response('use node upgrade handler', { status: 426 }),
      listAgents: async () => this.engine.listAgents(),
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
        mcpClients: await this.activity.listMcpClients(),
        events: this.activity.listPortalEvents
          ? await this.activity.listPortalEvents(75, 75)
          : await this.activity.listEvents(150),
      }),
      waitForHostWindow: async (hosts: string[], pauseMs?: number, dl?: number) => this.engine.waitForHostWindow(hosts, pauseMs, dl),
      dispatchFetch: async (rawBody: string, trace: Record<string, string>, preferredSite?: string, artifactPolicy?: ArtifactDispatchPolicy) =>
        this.engine.dispatchFetch(rawBody, trace, { preferredSite, ...(artifactPolicy ? { artifactPolicy } : {}) }),
      hasPendingJob: async (jobId: string, siteId: string) => this.engine.hasPendingJob(jobId, siteId),
      verifyPendingJob: async (jobId: string, jobNonce: string, siteId: string) => this.engine.verifyPendingJob(jobId, jobNonce, siteId),
      authorizeArtifactUpload: async (p: AuthorizeArtifactUploadParams) => this.engine.authorizeArtifactUpload(p),
      failJob: async (jobId: string, jobNonce: string, siteId: string, reason: string, permanent = true) =>
        this.engine.failJob(jobId, jobNonce, siteId, reason, permanent),
      completeJob: async (jobId: string, jobNonce: string, siteId: string, bodyText: string) =>
        this.engine.completeJob(jobId, jobNonce, siteId, bodyText),
      oauthPutClient: (c: OAuthClientRecord) => this.oauth.putClient(c),
      oauthGetClient: (id: string) => this.oauth.getClient(id),
      oauthPutCode: (c: OAuthCodeRecord) => this.oauth.putCode(c),
      oauthConsumeCode: (h: string, now: number) => this.oauth.consumeCode(h, now),
      oauthPutTokenPair: (p: Parameters<OAuthStore['putTokenPair']>[0]) => this.oauth.putTokenPair(p),
      oauthGetAccessToken: (h: string, now: number) => this.oauth.getAccessToken(h, now),
      oauthConsumeRefreshToken: (h: string, now: number) => this.oauth.consumeRefreshToken(h, now),
      oauthRotateRefreshToken: (p: RotateRefreshParams) => this.oauth.rotateRefreshToken(p),
      oauthListGrants: (now: number) => this.oauth.listGrants(now),
      oauthRevokeGrant: (id: string) => this.oauth.revokeGrant(id),
      oauthRevokeByTokenHash: (h: string) => this.oauth.revokeByTokenHash(h),
      oauthCheckAuthLockout: (b: string, now: number, m?: number) => this.oauth.checkAuthLockout(b, now, m),
      oauthRecordAuthFailure: (b: string, now: number, w: number, m: number) => this.oauth.recordAuthFailure(b, now, w, m),
      oauthClearAuthFailures: (b: string) => this.oauth.clearAuthFailures(b),
    };
    return {
      idFromName: (name: string) => name,
      get: () => stub,
    };
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
