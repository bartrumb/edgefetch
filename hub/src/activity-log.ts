/**
 * Bounded SQLite ring-buffer activity log (`hub_events`, max 300 rows) + MCP client session tracker (`mcp_activity`)
 * for `/admin` and single-pane-of-glass debugging.
 *
 * Kept free of `cloudflare:workers` imports so root `tsconfig.json` and Vitest exercise it in memory alongside
 * `createSqliteActivityStore` inside `AgentHubDO`.
 */
import type { SqlStorageLike } from './oauth';

export type ActivityLevel = 'info' | 'warn' | 'error';
export type ActivityCategory = 'crawl' | 'mcp' | 'agent' | 'oauth' | 'failover';

export interface HubEventInput {
  ts?: number;
  level: ActivityLevel;
  category: ActivityCategory;
  event: string;
  summary: string;
  details?: Record<string, unknown>;
}

export interface HubEventRecord {
  id: number;
  ts: number;
  level: ActivityLevel;
  category: ActivityCategory;
  event: string;
  summary: string;
  details: Record<string, unknown>;
}

export interface McpClientActivity {
  principal: string;
  authType: 'oauth' | 'bearer_token';
  userAgent: string;
  calls: number;
  lastMethod: string;
  lastSeenAt: number;
}

export interface ActivityStore {
  recordEvent(input: HubEventInput): Promise<void> | void;
  listEvents(limit?: number): Promise<HubEventRecord[]> | HubEventRecord[];
  clearEvents(): Promise<void> | void;
  recordMcpCall(params: {
    principal: string;
    authType: 'oauth' | 'bearer_token';
    userAgent: string;
    method: string;
    now?: number;
  }): Promise<void> | void;
  listMcpClients(): Promise<McpClientActivity[]> | McpClientActivity[];
}

const MAX_RING_EVENTS = 300;

export const ACTIVITY_SQLITE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS hub_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    event TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS mcp_activity (
    principal TEXT PRIMARY KEY,
    auth_type TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    calls INTEGER NOT NULL,
    last_method TEXT NOT NULL,
    last_seen_at INTEGER NOT NULL
  );
`;

export function createMemoryActivityStore(): ActivityStore {
  let seq = 0;
  const events: HubEventRecord[] = [];
  const mcpMap = new Map<string, McpClientActivity>();

  return {
    recordEvent(input) {
      events.unshift({
        id: ++seq,
        ts: input.ts ?? Date.now(),
        level: input.level,
        category: input.category,
        event: input.event,
        summary: input.summary.slice(0, 320),
        details: { ...(input.details ?? {}) },
      });
      if (events.length > MAX_RING_EVENTS) events.length = MAX_RING_EVENTS;
    },
    listEvents(limit = 120) {
      return events.slice(0, Math.min(MAX_RING_EVENTS, Math.max(1, limit)));
    },
    clearEvents() {
      events.length = 0;
    },
    recordMcpCall({ principal, authType, userAgent, method, now = Date.now() }) {
      const prev = mcpMap.get(principal);
      mcpMap.set(principal, {
        principal,
        authType,
        userAgent: (userAgent || 'unknown').slice(0, 120),
        calls: (prev?.calls ?? 0) + 1,
        lastMethod: method.slice(0, 80),
        lastSeenAt: now,
      });
    },
    listMcpClients() {
      return [...mcpMap.values()].sort((a, b) => b.lastSeenAt - a.lastSeenAt);
    },
  };
}

export function createSqliteActivityStore(sql: SqlStorageLike): ActivityStore {
  return {
    recordEvent(input) {
      const ts = input.ts ?? Date.now();
      sql.exec(
        `INSERT INTO hub_events (ts, level, category, event, summary, details_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
        ts,
        input.level,
        input.category,
        input.event.slice(0, 64),
        input.summary.slice(0, 320),
        JSON.stringify(input.details ?? {}).slice(0, 4096),
      );
      sql.exec(
        `DELETE FROM hub_events
         WHERE id NOT IN (SELECT id FROM hub_events ORDER BY id DESC LIMIT ?)`,
        MAX_RING_EVENTS,
      );
    },
    listEvents(limit = 120) {
      const safeLimit = Math.min(MAX_RING_EVENTS, Math.max(1, Math.floor(limit)));
      return sql
        .exec<{
          id: number;
          ts: number;
          level: ActivityLevel;
          category: ActivityCategory;
          event: string;
          summary: string;
          details_json: string;
        }>('SELECT id, ts, level, category, event, summary, details_json FROM hub_events ORDER BY id DESC LIMIT ?', safeLimit)
        .toArray()
        .map((r) => {
          let details: Record<string, unknown> = {};
          try {
            details = JSON.parse(r.details_json) as Record<string, unknown>;
          } catch {
            details = {};
          }
          return {
            id: r.id,
            ts: r.ts,
            level: r.level,
            category: r.category,
            event: r.event,
            summary: r.summary,
            details,
          };
        });
    },
    clearEvents() {
      sql.exec('DELETE FROM hub_events');
    },
    recordMcpCall({ principal, authType, userAgent, method, now = Date.now() }) {
      const cleanUa = (userAgent || 'unknown').slice(0, 120);
      const cleanMethod = method.slice(0, 80);
      sql.exec(
        `INSERT INTO mcp_activity (principal, auth_type, user_agent, calls, last_method, last_seen_at)
         VALUES (?, ?, ?, 1, ?, ?)
         ON CONFLICT(principal) DO UPDATE SET
           auth_type = excluded.auth_type,
           user_agent = excluded.user_agent,
           calls = mcp_activity.calls + 1,
           last_method = excluded.last_method,
           last_seen_at = excluded.last_seen_at`,
        principal.slice(0, 120),
        authType,
        cleanUa,
        cleanMethod,
        now,
      );
    },
    listMcpClients() {
      return sql
        .exec<{
          principal: string;
          auth_type: 'oauth' | 'bearer_token';
          user_agent: string;
          calls: number;
          last_method: string;
          last_seen_at: number;
        }>('SELECT principal, auth_type, user_agent, calls, last_method, last_seen_at FROM mcp_activity ORDER BY last_seen_at DESC LIMIT 50')
        .toArray()
        .map((r) => ({
          principal: r.principal,
          authType: r.auth_type,
          userAgent: r.user_agent,
          calls: r.calls,
          lastMethod: r.last_method,
          lastSeenAt: r.last_seen_at,
        }));
    },
  };
}

interface CrawlReplyLogShape {
  results?: Array<{
    id?: string;
    url?: string;
    kind?: string;
    status?: number;
    outcome?: string;
    problem?: string;
    bytes?: number;
    durationMs?: number;
    timing?: {
      dnsMs?: number;
      connectMs?: number;
      tlsMs?: number;
      ttfbMs?: number;
      reused?: boolean;
      proto?: string;
      remoteAddr?: string;
    };
  }>;
  durationMs?: number;
}

/** Builds structured `HubEventInput` entries from a completed `/fetch`, `/mcp`, or `/admin` crawl batch. */
export function buildCrawlActivityEvents(params: {
  source: string;
  target: string;
  via: string;
  httpStatus: number;
  replyText: string;
  now?: number;
}): HubEventInput[] {
  const ts = params.now ?? Date.now();
  let parsed: CrawlReplyLogShape | null = null;
  try {
    parsed = JSON.parse(params.replyText) as CrawlReplyLogShape;
  } catch {
    parsed = null;
  }

  const results = Array.isArray(parsed?.results) ? parsed!.results : [];
  if (results.length === 0) {
    return [
      {
        ts,
        level: params.httpStatus >= 400 ? 'error' : 'info',
        category: 'crawl',
        event: 'fetch_call',
        summary: `[${params.source}] HTTP ${params.httpStatus} via ${params.via}`,
        details: { source: params.source, target: params.target, via: params.via, httpStatus: params.httpStatus },
      },
    ];
  }

  return results.slice(0, 10).map((r) => {
    const status = r.status ?? 0;
    const outcome = r.outcome ?? 'error';
    const level: ActivityLevel =
      status === 429 || outcome === 'challenge' || outcome === 'stop'
        ? 'warn'
        : outcome === 'error' || status >= 500 || status === 0
          ? 'error'
          : 'info';
    const tm = r.timing ?? {};
    const urlShort = (r.url ?? '').slice(0, 140);
    return {
      ts,
      level,
      category: 'crawl',
      event: 'fetch_url',
      summary: `[${params.source}] ${status} ${outcome} via ${params.via} — ${urlShort} (${r.durationMs ?? 0}ms, ttfb=${tm.ttfbMs ?? 0}ms${tm.reused ? ', H2-reused' : ''})`,
      details: {
        source: params.source,
        target: params.target,
        via: params.via,
        id: r.id,
        url: r.url,
        kind: r.kind,
        status,
        outcome,
        ...(r.problem ? { problem: r.problem } : {}),
        bytes: r.bytes ?? 0,
        durationMs: r.durationMs ?? 0,
        dnsMs: tm.dnsMs ?? 0,
        connectMs: tm.connectMs ?? 0,
        tlsMs: tm.tlsMs ?? 0,
        ttfbMs: tm.ttfbMs ?? 0,
        reused: Boolean(tm.reused),
        proto: tm.proto ?? '',
        remoteAddr: tm.remoteAddr ?? '',
      },
    };
  });
}
