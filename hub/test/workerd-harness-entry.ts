import prodWorker, { AgentHubDO as ProdAgentHubDO } from '../src/index.ts';
import { r2ArtifactKey, sanitizeFtsQuery } from '../src/storage.ts';

export class AgentHubDO extends ProdAgentHubDO {
  async __testSql(query: string): Promise<unknown[]> {
    return this.ctx.storage.sql.exec(query).toArray();
  }

  async __testAbort(): Promise<void> {
    (this.ctx as unknown as { abort(reason?: string): void }).abort('test_do_reset');
  }

  async __testSeedHosts(count: number): Promise<void> {
    const base = Date.now() + 2_000;
    for (let i = 0; i < count; i++) {
      await this.waitForHostWindow([`h${i}.example.com`], 0, base + 60_000);
      this.ctx.storage.sql.exec(
        'INSERT OR REPLACE INTO host_windows (host, next_allowed_at) VALUES (?, ?)',
        `raw-${i}.example.com`,
        base + i,
      );
    }
  }
}

export default {
  async fetch(request: Request, env: Record<string, unknown>, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ns = env.AGENT_HUB as DurableObjectNamespace<AgentHubDO>;
    if (url.pathname === '/__test_sql' && request.method === 'POST') {
      const q = await request.text();
      const stub = ns.get(ns.idFromName('global'));
      return Response.json(await stub.__testSql(q));
    }
    if (url.pathname === '/__test_abort') {
      const stub = ns.get(ns.idFromName('global'));
      await stub.__testAbort().catch(() => undefined);
      return Response.json({ aborted: true });
    }
    if (url.pathname === '/__test_storage_verify' && request.method === 'POST') {
      const { metaSql, searchSql } = (await request.json()) as { metaSql: string; searchSql: string };
      const artifacts = env.ARTIFACTS as R2Bucket;
      const meta = env.META as D1Database;
      const search = env.SEARCH as D1Database;

      const splitStatements = (sql: string) =>
        sql
          .replace(/\r\n/g, '\n')
          .split(/\n\s*\n/)
          .map((s) => s.trim())
          .filter(Boolean);
      for (const s of splitStatements(metaSql)) await meta.prepare(s).run();
      for (const s of splitStatements(searchSql)) await search.prepare(s).run();

      const plainBytes = new TextEncoder().encode('<html><body>' + 'edgefetch s1 '.repeat(1000) + '</body></html>');
      const gzBuf = await new Response(new Blob([plainBytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer();
      const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
      const blobSha = hex(await crypto.subtle.digest('SHA-256', gzBuf));
      const contentSha = hex(await crypto.subtle.digest('SHA-256', plainBytes));
      const key = r2ArtifactKey('stored', blobSha);

      const firstPut = await artifacts.put(key, gzBuf, {
        sha256: blobSha,
        onlyIf: new Headers({ 'if-none-match': '*' }),
        httpMetadata: { contentType: 'application/gzip' },
      });
      const dupPut = await artifacts.put(key, gzBuf, {
        sha256: blobSha,
        onlyIf: new Headers({ 'if-none-match': '*' }),
      });

      let badHashFailed = false;
      try {
        await artifacts.put('raw/bad.gz', gzBuf, { sha256: '00'.repeat(32) });
      } catch {
        badHashFailed = true;
      }

      const obj = await artifacts.get(key);
      const digestStream = new crypto.DigestStream('SHA-256');
      await obj!.body.pipeThrough(new DecompressionStream('gzip')).pipeTo(digestStream);
      const streamedContentSha = hex(await digestStream.digest);

      const now = Date.now();
      await meta.batch([
        meta
          .prepare(
            `INSERT INTO pages (id, url, host, latest_content_sha256, first_seen_at, last_fetched_at, last_changed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET last_fetched_at = excluded.last_fetched_at`,
          )
          .bind('p1', 'https://example.com/a', 'example.com', contentSha, now, now, now),
        meta
          .prepare(
            `INSERT INTO pages (id, url, host, latest_content_sha256, first_seen_at, last_fetched_at, last_changed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET last_fetched_at = excluded.last_fetched_at`,
          )
          .bind('p1', 'https://example.com/a', 'example.com', contentSha, now, now, now),
      ]);
      const pageCount = (await meta.prepare('SELECT COUNT(*) AS c FROM pages').first<{ c: number }>())?.c ?? 0;

      await search.batch([
        search
          .prepare(
            `INSERT INTO chunks (collection_id, document_id, page_id, ordinal, url, title, heading, text, fetched_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind('docs', 'd1', 'p1', 0, 'https://example.com/a', 'Running Crawlers', 'Intro', 'Durable Objects coordinate running agents.', now),
      ]);
      const ftsHits = await search
        .prepare(
          `SELECT c.page_id, bm25(chunks_fts, 5.0, 2.0, 1.0) AS rank
           FROM chunks_fts JOIN chunks c ON c.id = chunks_fts.rowid
           WHERE chunks_fts MATCH ? AND c.collection_id = ? ORDER BY rank LIMIT 5`,
        )
        .bind(sanitizeFtsQuery('run agents" (malformed'), 'docs')
        .all();

      return Response.json({
        firstStored: firstPut !== null,
        dupReturnedNull: dupPut === null,
        badHashFailed,
        streamedHashMatches: streamedContentSha === contentSha,
        pageCount,
        ftsHitCount: ftsHits.results.length,
      });
    }
    return (prodWorker as { fetch(req: Request, e: unknown, c?: unknown): Promise<Response> }).fetch(request, env, ctx);
  },
};
