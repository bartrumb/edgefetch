# sdk/ts

## Overview

`sdk/ts` provides the TypeScript/ESM client SDK (`edgefetch-client.ts`) for the EdgeFetch Hub HTTP v1 API. It exposes typed request parameter interfaces, structured HTTP error handling (`EdgeFetchError`), Bearer authentication, and active-standby multi-gateway failover across `baseUrls`.

## Interface

- `[edgefetch-client.ts:ScrapeFormat]` — Union type of supported scrape output formats (`'markdown' | 'text' | 'summary' | 'product' | 'rawBase64' | 'html' | 'rawHtml' | 'links' | 'images' | 'branding' | 'llmsTxt' | 'screenshot' | 'changes' | 'changeTracking'` plus structured `json`, `attributes`, `screenshot`, and `changeTracking` descriptor objects).
- `[edgefetch-client.ts:EdgeFetchClientOptions]` — Client configuration interface `{ baseUrl?: string; baseUrls?: string[]; token: string; fetchFn?: typeof fetch }`.
- `[edgefetch-client.ts:ScrapeParams]`, `[edgefetch-client.ts:ExtractParams]`, `[edgefetch-client.ts:MapParams]`, `[edgefetch-client.ts:CrawlParams]`, `[edgefetch-client.ts:SearchParams]`, `[edgefetch-client.ts:InteractAction]`, `[edgefetch-client.ts:InteractParams]` — Exported TypeScript request parameter interfaces for `/v1/*` endpoints.
- `[edgefetch-client.ts:EdgeFetchError]` — `class EdgeFetchError extends Error` exposing `readonly status: number` and `readonly code: string`.
- `[edgefetch-client.ts:EdgeFetchClient]` — Hub API client class constructed with `EdgeFetchClientOptions`.
- `[edgefetch-client.ts:EdgeFetchClient.capabilities]` — `(): Promise<Record<string, unknown>>` (`GET /v1/capabilities`).
- `[edgefetch-client.ts:EdgeFetchClient.hosts]` — `(limit = 100): Promise<{ ok: boolean; hosts: Array<Record<string, unknown>> }>` (`GET /v1/hosts?limit=<1..500>`).
- `[edgefetch-client.ts:EdgeFetchClient.extractors]` — `(category?: string): Promise<{ ok: boolean; total: number; categories: Record<string, number>; extractors: Array<Record<string, unknown>> }>` (`GET /v1/extractors[?category=...]`).
- `[edgefetch-client.ts:EdgeFetchClient.scrape]` — `(params: ScrapeParams): Promise<Record<string, unknown>>` (`POST /v1/scrape`).
- `[edgefetch-client.ts:EdgeFetchClient.extract]` — `(params: ExtractParams): Promise<Record<string, unknown>>` (`POST /v1/extract`).
- `[edgefetch-client.ts:EdgeFetchClient.map]` — `(params: MapParams): Promise<{ ok: boolean; url: string; total: number; links: string[]; entries: unknown[] }>` (`POST /v1/map`).
- `[edgefetch-client.ts:EdgeFetchClient.crawl]` — `(params: CrawlParams): Promise<{ ok: boolean; id: string; status: string; collectionId?: string; url: string }>` (`POST /v1/crawl`).
- `[edgefetch-client.ts:EdgeFetchClient.getCrawl]` — `(crawlId: string, offset = 0, limit = 25): Promise<Record<string, unknown>>` (`GET /v1/crawl/:crawlId?offset=...&limit=...`).
- `[edgefetch-client.ts:EdgeFetchClient.cancelCrawl]` — `(crawlId: string): Promise<{ ok: boolean; id: string; status: string }>` (`DELETE /v1/crawl/:crawlId`).
- `[edgefetch-client.ts:EdgeFetchClient.search]` — `(params: SearchParams): Promise<{ ok: boolean; query: string; results: Array<Record<string, unknown>> }>` (`POST /v1/search`).
- `[edgefetch-client.ts:EdgeFetchClient.jobs]` — `(params): Promise<Record<string, unknown>>` (`POST /v1/jobs`).
- `[edgefetch-client.ts:EdgeFetchClient.interact]` — `(params: InteractParams): Promise<Record<string, unknown>>` (`POST /v1/interact`).
- `[edgefetch-client.ts:EdgeFetchClient.batchScrape]` — `(params): Promise<Record<string, unknown>>` (`POST /v1/batch/scrape`).
- `[edgefetch-client.ts:EdgeFetchClient.getBatchScrape]` — `(batchId: string): Promise<Record<string, unknown>>` (`GET /v1/batch/scrape/:batchId`).
- `[edgefetch-client.ts:EdgeFetchClient.cancelBatchScrape]` — `(batchId: string): Promise<Record<string, unknown>>` (`DELETE /v1/batch/scrape/:batchId`).
- `[edgefetch-client.ts:EdgeFetchClient.previewCrawlParams]` — `(params: { url: string; prompt: string }): Promise<Record<string, unknown>>` (`POST /v1/crawl/params-preview`).
- `[edgefetch-client.ts:EdgeFetchClient.agent]` — `(params): Promise<Record<string, unknown>>` (`POST /v1/agent`).
- `[edgefetch-client.ts:EdgeFetchClient.getAgent]` — `(agentId: string): Promise<Record<string, unknown>>` (`GET /v1/agent/:agentId`).
- `[edgefetch-client.ts:EdgeFetchClient.getAgentTrace]` — `(agentId: string): Promise<Record<string, unknown>>` (`GET /v1/agent/:agentId/trace`).
- `[edgefetch-client.ts:EdgeFetchClient.cancelAgent]` — `(agentId: string): Promise<Record<string, unknown>>` (`DELETE /v1/agent/:agentId`).
- `[edgefetch-client.ts:EdgeFetchClient.readArtifact]` — `(blobSha256: string, offset = 0, limit = 65_536, format: 'raw' | 'markdown' = 'raw'): Promise<Record<string, unknown>>` (`GET /v1/artifacts/:blobSha256?format=<markdown|json>&offset=...&limit=...`).

## Invariants

- `[edgefetch-client.ts:EdgeFetchClient.constructor]` — Concatenates `options.baseUrls` and `options.baseUrl`, trims whitespace and trailing slashes, deduplicates entries, and throws `Error('EdgeFetchClient requires baseUrl or non-empty baseUrls')` if none remain.
- `[edgefetch-client.ts:EdgeFetchClient.requestJson]` — Attaches `authorization: Bearer <token>` and `accept: application/json` to every request, and attaches `content-type: application/json` with serialized JSON body iff `body !== undefined`.
- `[edgefetch-client.ts:EdgeFetchClient.requestJson]` — Fails over across `baseUrls` in order only on thrown `fetch` errors or HTTP `502`, `503`, or `504` when additional origins exist; all other non-2xx responses immediately throw `EdgeFetchError` without failover.
- `[edgefetch-client.ts:EdgeFetchClient.requestJson]` — Parses response bodies via `res.json().catch(() => ({}))` so empty or non-JSON bodies resolve to `{}`.
- `[edgefetch-client.ts:EdgeFetchClient.hosts]` — Floors and clamps `limit` to `[1, 500]` via `Math.max(1, Math.min(500, Math.floor(limit)))`.
- `[edgefetch-client.ts:EdgeFetchClient.readArtifact]` — Maps `format === 'markdown'` to `format=markdown` and `'raw'` (or non-`'markdown'`) to `format=json`.
- `[edgefetch-client.ts:EdgeFetchClient]` — Encodes dynamic path and query segments (`category`, `crawlId`, `batchId`, `agentId`, `blobSha256`) with `encodeURIComponent`.

## Side Effects

- `[edgefetch-client.ts:EdgeFetchClient.requestJson]` — Executes outbound HTTP `GET`, `POST`, and `DELETE` requests via `options.fetchFn` (defaulting to global `fetch`) against configured Hub endpoints.

## Verification

- Run: `npm --prefix hub test`
