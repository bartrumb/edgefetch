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
import type { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Duplex } from 'node:stream';
import { WebSocket, WebSocketServer, type RawData } from 'ws';
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
import {
  createSqliteHubSettingsStore,
  HUB_SETTINGS_SQLITE_SCHEMA,
  type HubSettingsStore,
} from '../src/dev-telemetry';
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

// ── 3. `ws` RFC 6455 WebSocket Wrapper + In-Process `AgentHubDO` Coordinator ───────────────────────────────────────

const MAX_WS_MESSAGE_BYTES = 1_048_576; // 1 MiB max frame & reassembled message size (`maxPayload: 1_048_576`)
const MAX_WS_PENDING_OUTBOUND_BYTES = 65_536; // 64 KiB cap on pending outbound `pong` / write queue (`Low`)

const STANDALONE_WSS = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_WS_MESSAGE_BYTES,
  perMessageDeflate: false,
});

function extractWsErrorStatusCode(err: unknown): number {
  if (err && typeof err === 'object') {
    for (const sym of Object.getOwnPropertySymbols(err)) {
      if (sym.description === 'status-code') {
        const val = (err as Record<symbol, unknown>)[sym];
        if (typeof val === 'number' && val >= 1000 && val <= 4999) return val;
      }
    }
    const code = (err as { code?: string }).code;
    if (code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' || code === 'WS_ERR_UNSUPPORTED_DATA_PAYLOAD_LENGTH') {
      return 1009;
    }
    if (code === 'WS_ERR_INVALID_UTF8') return 1007;
    if (code === 'WS_ERR_TOO_MANY_BUFFERED_PARTS') return 1008;
    if (typeof code === 'string' && code.startsWith('WS_ERR_')) return 1002;
  }
  return 1011;
}

function rawDataToUtf8(data: RawData): string {
  if (Buffer.isBuffer(data)) return data.toString('utf8');
  if (Array.isArray(data)) return Buffer.concat(data).toString('utf8');
  return Buffer.from(data).toString('utf8');
}

export class RawServerWebSocket implements HubSocketLike {
  private readonly ws: WebSocket;
  private readonly rawSocket: Duplex | null;
  private attachment: unknown = null;
  private closed = false;

  constructor(
    socketOrWs: Duplex | WebSocket,
    public readonly tags: string[],
    private readonly onText: (ws: RawServerWebSocket, msg: string) => void,
    private readonly onClosed: (ws: RawServerWebSocket, code: number, reason: string) => void,
  ) {
    if (socketOrWs instanceof WebSocket) {
      this.ws = socketOrWs;
      this.rawSocket = (socketOrWs as unknown as { _socket?: Duplex })._socket ?? null;
      this.bindListeners();
    } else {
      const ServerWsCtor = STANDALONE_WSS.options.WebSocket ?? WebSocket;
      const wsInstance = new ServerWsCtor(null, undefined as unknown as string[], STANDALONE_WSS.options as never);
      this.ws = wsInstance;
      this.rawSocket = socketOrWs;
      this.bindListeners();
      (
        wsInstance as unknown as {
          setSocket(
            s: Duplex,
            head: Buffer,
            opts: {
              allowSynchronousEvents: boolean;
              maxBufferedChunks: number;
              maxFragments: number;
              maxPayload: number;
              skipUTF8Validation: boolean;
            },
          ): void;
        }
      ).setSocket(socketOrWs, Buffer.alloc(0), {
        allowSynchronousEvents: true,
        maxBufferedChunks: STANDALONE_WSS.options.maxBufferedChunks ?? 262_144,
        maxFragments: STANDALONE_WSS.options.maxFragments ?? 16_384,
        maxPayload: MAX_WS_MESSAGE_BYTES,
        skipUTF8Validation: false,
      });
    }

    if (this.rawSocket) {
      this.rawSocket.on('data', () => {
        if (this.closed) return;
        const rxErr = (this.ws as unknown as { _receiver?: { _writableState?: { errored?: Error | null } } })._receiver
          ?._writableState?.errored;
        if (rxErr) {
          this.finishClose(
            extractWsErrorStatusCode(rxErr),
            (rxErr as NodeJS.ErrnoException).code ?? 'ws_protocol_error',
            true,
            false,
          );
        }
      });
      this.rawSocket.on('close', () => {
        if (!this.closed) {
          this.finishClose(1006, 'tcp_closed', false, false);
        }
      });
      this.rawSocket.on('error', () => {
        if (!this.closed) {
          this.finishClose(1011, 'socket_error', true, true);
        }
      });
    }
  }

  private bindListeners(): void {
    this.ws.on('error', (err) => {
      if (!this.closed) {
        this.finishClose(
          extractWsErrorStatusCode(err),
          (err as NodeJS.ErrnoException).code ?? 'ws_error',
          true,
          false,
        );
      }
    });

    this.ws.on('message', (data: RawData, isBinary: boolean) => {
      if (this.closed) return;
      if (isBinary) {
        this.close(1003, 'binary_frames_unsupported');
        return;
      }
      const text = rawDataToUtf8(data);
      if (text === 'ping') {
        if (this.ws.bufferedAmount > MAX_WS_PENDING_OUTBOUND_BYTES) {
          this.close(1008, 'pong_queue_exceeded');
          return;
        }
        this.send('pong');
      } else {
        this.onText(this, text);
      }
    });

    this.ws.on('close', (code: number, reason: Buffer) => {
      if (!this.closed) {
        this.finishClose(code || 1006, reason?.length ? reason.toString('utf8') : '', false, false);
      }
    });
  }

  get readyState(): number {
    return this.closed ? WebSocket.CLOSED : this.ws.readyState;
  }

  send(data: string): void {
    if (this.closed || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('websocket_closed');
    }
    if (this.ws.bufferedAmount > MAX_WS_MESSAGE_BYTES) {
      this.close(1008, 'outbound_backpressure');
      return;
    }
    this.ws.send(data);
  }

  close(code = 1000, reason = ''): void {
    this.finishClose(code, reason, true, code === 1001);
  }

  terminate(): void {
    this.finishClose(1001, 'shutdown', true, true);
  }

  private finishClose(code: number, reason: string, sendCloseFrame: boolean, forceImmediateTcpDestroy: boolean): void {
    if (this.closed) return;
    this.closed = true;
    const cleanReason = reason.slice(0, 100);
    if (sendCloseFrame) {
      try {
        if (this.ws.readyState === WebSocket.OPEN) {
          this.ws.close(code, cleanReason);
        }
      } catch {
        // best-effort close frame
      }
      const closeTimer = (this.ws as unknown as { _closeTimer?: ReturnType<typeof setTimeout> | null })._closeTimer;
      if (closeTimer) clearTimeout(closeTimer);

      if (this.rawSocket instanceof Socket && !forceImmediateTcpDestroy) {
        // Flush queued RFC 6455 close frame (`1009`, `1002`, `1000`) cleanly before tearing down TCP socket.
        try {
          this.rawSocket.end();
        } catch {
          // ignore
        }
        const destroyTimer = setTimeout(() => {
          try {
            this.rawSocket?.destroy();
          } catch {
            // ignore
          }
        }, 50);
        destroyTimer.unref?.();
      } else {
        try {
          this.ws.terminate();
        } catch {
          // ignore
        }
        try {
          this.rawSocket?.destroy();
        } catch {
          // ignore
        }
      }
    }
    this.onClosed(this, code, cleanReason);
  }

  serializeAttachment(value: unknown): void {
    this.attachment = structuredClone(value);
  }

  deserializeAttachment(): unknown {
    return this.attachment ? structuredClone(this.attachment) : null;
  }
}

export class LocalAgentHubCoordinator {
  private readonly db: DatabaseSync;
  private readonly wss = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_WS_MESSAGE_BYTES,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has('edgefetch-agent') ? 'edgefetch-agent' : false),
  });
  private readonly sockets = new Set<RawServerWebSocket>();
  private readonly lastHelloLogBySite = new Map<string, number>();
  private readonly lastConnectLogByKey = new Map<string, number>();
  public readonly engine: AgentHubEngine;
  public readonly oauth: OAuthStore;
  public readonly activity: ActivityStore;
  public readonly settings: HubSettingsStore;

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
      ${HUB_SETTINGS_SQLITE_SCHEMA}
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
    this.settings = createSqliteHubSettingsStore(sqlLike);
  }

  /** Registers an already-upgraded `ws` `WebSocket` client with `AgentHubEngine`. */
  acceptWebSocket(params: {
    ws: WebSocket;
    siteId: string;
    arch: string | null;
    version: string | null;
    browserVersion?: string | null;
    browserSandbox?: string | null;
    capabilities: string | null;
    publicIp: string | null;
  }): void {
    const wrapped = new RawServerWebSocket(
      params.ws,
      [`site:${params.siteId}`],
      (sock, text) => {
        if (text.length > 2048) return;
        try {
          const msg = JSON.parse(text) as {
            type?: string;
            version?: string;
            arch?: string;
            goVersion?: string;
            browserVersion?: string;
            browserSandbox?: string | boolean;
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
            // M9: Throttle `agent_ready` event logging to at most 1 per 60s per verified `siteId`, and allowlist fields
            // so untrusted client keys (`msg.siteId`, `msg.level`, `msg.event`) NEVER pollute activity log details!
            if (nowMs - lastLoggedAt >= 60_000) {
              if (this.lastHelloLogBySite.size >= 512) this.lastHelloLogBySite.clear();
              this.lastHelloLogBySite.set(verifiedSiteId, nowMs);
              void this.activity.recordEvent({
                level: 'info',
                category: 'agent',
                event: evName,
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

    this.sockets.add(wrapped);
    const att = this.engine.registerAgent(wrapped, params.siteId, params.arch, {
      version: params.version,
      browserVersion: params.browserVersion,
      browserSandbox: params.browserSandbox,
      publicIp: params.publicIp,
      capabilities: params.capabilities,
    });
    if (!this.sockets.has(wrapped)) return;
    try {
      wrapped.send(JSON.stringify({ type: 'hello', siteId: att.siteId }));
    } catch {
      return;
    }
    // Rate-limit `agent_ws_connected` activity-log entries per site AND per IP (`Low` — prevents 260x reconnect floods from flushing `hub_events`)!
    const nowConnectMs = Date.now();
    const siteLogKey = `site:${att.siteId}`;
    const ipLogKey = `ip:${params.publicIp ?? 'unknown'}`;
    const lastSiteConn = this.lastConnectLogByKey.get(siteLogKey) ?? 0;
    const lastIpConn = this.lastConnectLogByKey.get(ipLogKey) ?? 0;
    if (nowConnectMs - lastSiteConn >= 60_000 && nowConnectMs - lastIpConn >= 5_000) {
      if (this.lastConnectLogByKey.size >= 512) this.lastConnectLogByKey.clear();
      this.lastConnectLogByKey.set(siteLogKey, nowConnectMs);
      this.lastConnectLogByKey.set(ipLogKey, nowConnectMs);
      void this.activity.recordEvent({
        level: 'info',
        category: 'agent',
        event: 'agent_ws_connected',
        summary: `Remote node "${att.siteId}" connected over WebSocket`,
        details: sanitizeDetails({ siteId: att.siteId, arch: att.arch, version: att.version ?? null }),
      });
    }
  }

  /** Accepts an RFC 6455 HTTP `Upgrade: websocket` socket via `ws` `WebSocketServer.handleUpgrade`. */
  acceptNodeUpgrade(params: {
    req?: IncomingMessage;
    wsKey: string;
    socket: Duplex;
    head: Buffer;
    siteId: string;
    arch: string | null;
    version: string | null;
    browserVersion?: string | null;
    browserSandbox?: string | null;
    capabilities: string | null;
    publicIp: string | null;
    subprotocol?: string | null;
  }): void {
    const upgradeReq =
      params.req ??
      ({
        method: 'GET',
        url: '/agent/ws',
        headers: {
          upgrade: 'websocket',
          connection: 'Upgrade',
          'sec-websocket-version': '13',
          'sec-websocket-key': params.wsKey.trim(),
          ...(params.subprotocol ? { 'sec-websocket-protocol': params.subprotocol } : {}),
        },
        socket: params.socket,
      } as unknown as IncomingMessage);

    this.wss.handleUpgrade(upgradeReq, params.socket, params.head, (wsClient) => {
      this.acceptWebSocket({
        ws: wsClient,
        siteId: params.siteId,
        arch: params.arch,
        version: params.version,
        browserVersion: params.browserVersion,
        browserSandbox: params.browserSandbox,
        capabilities: params.capabilities,
        publicIp: params.publicIp,
      });
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
      getHubSetting: (k: string) => this.settings.getSetting(k),
      setHubSetting: (k: string, v: string) => this.settings.setSetting(k, v),
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
      this.wss.close();
    } catch {
      // ignore
    }
    try {
      this.db.close();
    } catch {
      // ignore
    }
  }
}
