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
export type EventDetailMap = Record<string, string | number | boolean | null>;

export function redactUrlForLog(rawUrl: string | undefined | null): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  const trimmed = rawUrl.trim();
  if (!trimmed) return '';
  try {
    const u = new URL(trimmed);
    return `${u.origin}${u.pathname}`;
  } catch {
    return trimmed.split(/[?#]/)[0]?.slice(0, 200) ?? '';
  }
}

export function sanitizeDetails(raw?: Record<string, unknown>): EventDetailMap {
  const out: EventDetailMap = {};
  if (!raw) return out;
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    if (v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
      out[k] = v;
    } else {
      out[k] = JSON.stringify(v).slice(0, 512);
    }
  }
  return out;
}

export interface HubEventInput {
  ts?: number;
  level: ActivityLevel;
  category: ActivityCategory;
  event: string;
  summary: string;
  details?: EventDetailMap;
}

export interface HubEventRecord {
  id: number;
  ts: number;
  level: ActivityLevel;
  category: ActivityCategory;
  event: string;
  summary: string;
  details: EventDetailMap;
}

export interface McpClientActivity {
  principal: string;
  authType: 'oauth' | 'bearer_token';
  userAgent: string;
  calls: number;
  lastMethod: string;
  lastSeenAt: number;
}

export interface McpTurnRecordInput {
  principal: string;
  authType: 'oauth' | 'bearer_token';
  userAgent: string;
  method: string;
  now?: number;
  event?: HubEventInput;
}

export interface ActivityStore {
  recordEvent(input: HubEventInput): Promise<void> | void;
  recordEvents?(inputs: HubEventInput[]): Promise<void> | void;
  listEvents(limit?: number): Promise<HubEventRecord[]> | HubEventRecord[];
  listPortalEvents?(maxWarnError?: number, maxInfo?: number): Promise<HubEventRecord[]> | HubEventRecord[];
  clearEvents(): Promise<void> | void;
  recordMcpCall(params: {
    principal: string;
    authType: 'oauth' | 'bearer_token';
    userAgent: string;
    method: string;
    now?: number;
  }): Promise<void> | void;
  recordMcpTurn?(params: McpTurnRecordInput): Promise<void> | void;
  listMcpClients(): Promise<McpClientActivity[]> | McpClientActivity[];
}

const MAX_RING_EVENTS = 300;
const MAX_INFO_RING_EVENTS = 200;
const MAX_SECURITY_RING_EVENTS = 150;

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
  CREATE INDEX IF NOT EXISTS hub_events_level_id_idx ON hub_events(level, id DESC);
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

  const store: ActivityStore = {
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
      // Partition pruning so high-volume info events never evict warn/error security events (H-S1).
      let infoCount = 0;
      let secCount = 0;
      for (let i = 0; i < events.length; ) {
        const isSec = events[i]!.level === 'warn' || events[i]!.level === 'error';
        if (isSec) {
          secCount++;
          if (secCount > MAX_SECURITY_RING_EVENTS) {
            events.splice(i, 1);
            continue;
          }
        } else {
          infoCount++;
          if (infoCount > MAX_INFO_RING_EVENTS) {
            events.splice(i, 1);
            continue;
          }
        }
        i++;
      }
    },
    recordEvents(inputs) {
      for (const ev of inputs) {
        store.recordEvent(ev);
      }
    },
    listEvents(limit = 120) {
      return events.slice(0, Math.min(MAX_RING_EVENTS, Math.max(1, limit)));
    },
    listPortalEvents(maxWarnError = 75, maxInfo = 75) {
      const secCap = Math.max(1, Math.min(MAX_SECURITY_RING_EVENTS, Math.floor(maxWarnError)));
      const infoCap = Math.max(1, Math.min(MAX_INFO_RING_EVENTS, Math.floor(maxInfo)));
      const secOut: HubEventRecord[] = [];
      const infoOut: HubEventRecord[] = [];
      for (const ev of events) {
        if (ev.level === 'warn' || ev.level === 'error') {
          if (secOut.length < secCap) secOut.push(ev);
        } else if (infoOut.length < infoCap) {
          infoOut.push(ev);
        }
        if (secOut.length >= secCap && infoOut.length >= infoCap) break;
      }
      return [...secOut, ...infoOut].sort((a, b) => b.id - a.id);
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
    recordMcpTurn(params) {
      store.recordMcpCall(params);
      if (params.event) {
        store.recordEvent(params.event);
      }
    },
    listMcpClients() {
      return [...mcpMap.values()].sort((a, b) => b.lastSeenAt - a.lastSeenAt);
    },
  };
  return store;
}

export function createSqliteActivityStore(sql: SqlStorageLike): ActivityStore {
  const mapRowToEvent = (r: {
    id: number;
    ts: number;
    level: ActivityLevel;
    category: ActivityCategory;
    event: string;
    summary: string;
    details_json: string;
  }): HubEventRecord => {
    let details: EventDetailMap = {};
    try {
      details = sanitizeDetails(JSON.parse(r.details_json) as Record<string, unknown>);
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
  };

  // Enforce strict per-severity ring quotas (`info <= 200`, `warn/error <= 150`) (`M9`).
  const pruneRingQuotas = (addedInfo: number, addedSec: number) => {
    if (addedSec > 0) {
      sql.exec(
        `DELETE FROM hub_events
         WHERE level IN ('warn', 'error')
           AND id <= COALESCE((SELECT id FROM hub_events WHERE level IN ('warn', 'error') ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`,
        MAX_SECURITY_RING_EVENTS - 1,
      );
    }
    if (addedInfo > 0) {
      sql.exec(
        `DELETE FROM hub_events
         WHERE level = 'info'
           AND id <= COALESCE((SELECT id FROM hub_events WHERE level = 'info' ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`,
        MAX_INFO_RING_EVENTS - 1,
      );
    }
  };

  const store: ActivityStore = {
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
      const isSec = input.level === 'warn' || input.level === 'error';
      pruneRingQuotas(isSec ? 0 : 1, isSec ? 1 : 0);
    },
    recordEvents(inputs) {
      if (inputs.length === 0) return;
      if (inputs.length === 1) {
        store.recordEvent(inputs[0]!);
        return;
      }
      const defaultNow = Date.now();
      const batch = inputs.slice(0, 25);
      const placeholders: string[] = [];
      const bindArgs: Array<string | number> = [];
      let addedInfo = 0;
      let addedSec = 0;
      for (const input of batch) {
        placeholders.push('(?, ?, ?, ?, ?, ?)');
        bindArgs.push(
          input.ts ?? defaultNow,
          input.level,
          input.category,
          input.event.slice(0, 64),
          input.summary.slice(0, 320),
          JSON.stringify(input.details ?? {}).slice(0, 4096),
        );
        if (input.level === 'warn' || input.level === 'error') addedSec++;
        else addedInfo++;
      }
      sql.exec(
        `INSERT INTO hub_events (ts, level, category, event, summary, details_json)
         VALUES ${placeholders.join(', ')}`,
        ...bindArgs,
      );
      pruneRingQuotas(addedInfo, addedSec);
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
        .map(mapRowToEvent);
    },
    listPortalEvents(maxWarnError = 75, maxInfo = 75) {
      const secCap = Math.max(1, Math.min(MAX_SECURITY_RING_EVENTS, Math.floor(maxWarnError)));
      const infoCap = Math.max(1, Math.min(MAX_INFO_RING_EVENTS, Math.floor(maxInfo)));
      const secRows = sql
        .exec<{
          id: number;
          ts: number;
          level: ActivityLevel;
          category: ActivityCategory;
          event: string;
          summary: string;
          details_json: string;
        }>(
          "SELECT id, ts, level, category, event, summary, details_json FROM hub_events WHERE level IN ('warn', 'error') ORDER BY id DESC LIMIT ?",
          secCap,
        )
        .toArray()
        .map(mapRowToEvent);
      const infoRows = sql
        .exec<{
          id: number;
          ts: number;
          level: ActivityLevel;
          category: ActivityCategory;
          event: string;
          summary: string;
          details_json: string;
        }>(
          "SELECT id, ts, level, category, event, summary, details_json FROM hub_events WHERE level = 'info' ORDER BY id DESC LIMIT ?",
          infoCap,
        )
        .toArray()
        .map(mapRowToEvent);
      return [...secRows, ...infoRows].sort((a, b) => b.id - a.id);
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
    recordMcpTurn(params) {
      store.recordMcpCall(params);
      if (params.event) {
        store.recordEvent(params.event);
      }
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
  return store;
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
    blockedTrackers?: number;
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
      status === 429 ||
      status === 402 ||
      outcome === 'challenge' ||
      outcome === 'stop' ||
      outcome === 'payment_required' ||
      outcome === 'content_signal_disallowed'
        ? 'warn'
        : outcome === 'error' || status >= 500 || status === 0
          ? 'error'
          : 'info';
    const tm = r.timing ?? {};
    const safeUrl = redactUrlForLog(r.url);
    const urlShort = safeUrl.slice(0, 140);
    const blockedTrackers =
      typeof r.blockedTrackers === 'number' && Number.isFinite(r.blockedTrackers)
        ? Math.max(0, Math.floor(r.blockedTrackers))
        : undefined;
    return {
      ts,
      level,
      category: 'crawl',
      event: 'fetch_url',
      summary: `[${params.source}] ${status} ${outcome} via ${params.via} — ${urlShort} (${r.durationMs ?? 0}ms, ttfb=${tm.ttfbMs ?? 0}ms${tm.reused ? ', H2-reused' : ''}${blockedTrackers && blockedTrackers > 0 ? `, blocked=${blockedTrackers}` : ''})`,
      details: sanitizeDetails({
        source: params.source,
        target: params.target,
        via: params.via,
        id: r.id,
        url: safeUrl,
        kind: r.kind,
        status,
        outcome,
        ...(r.problem ? { problem: r.problem } : {}),
        ...(blockedTrackers !== undefined ? { blockedTrackers } : {}),
        bytes: r.bytes ?? 0,
        durationMs: r.durationMs ?? 0,
        dnsMs: tm.dnsMs ?? 0,
        connectMs: tm.connectMs ?? 0,
        tlsMs: tm.tlsMs ?? 0,
        ttfbMs: tm.ttfbMs ?? 0,
        reused: Boolean(tm.reused),
        proto: tm.proto ?? '',
        remoteAddr: tm.remoteAddr ?? '',
      }),
    };
  });
}
