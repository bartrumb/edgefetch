# Metadata Schema Migrations (`hub/migrations/meta`)

## Overview
Defines the SQLite / Cloudflare D1 tracking schema (`0001_tracking.sql`) for EdgeFetch Hub metadata persistence, storing deduplicated blob artifacts, crawl jobs, discovered pages, individual fetch executions, and derived extraction documents.

## Interface
- `CREATE TABLE artifacts (...) STRICT` (`blob_sha256 TEXT PRIMARY KEY`, `content_sha256`, `r2_key`, `retention`, `encoding`, `stored_bytes`, `content_bytes`, `content_type`, `verified_at`, `created_at`, `last_seen_at`) `[0001_tracking.sql:artifacts]`
- `CREATE INDEX artifacts_content_idx ON artifacts(content_sha256)` `[0001_tracking.sql:artifacts_content_idx]`
- `CREATE TABLE crawls (...) STRICT` (`id TEXT PRIMARY KEY`, `root_url`, `status`, `options_json`, `workflow_instance_id`, `discovered_count`, `fetched_count`, `failed_count`, `created_at`, `updated_at`, `finished_at`) `[0001_tracking.sql:crawls]`
- `CREATE TABLE pages (...) STRICT` (`id TEXT PRIMARY KEY`, `url`, `host`, `latest_fetch_id`, `latest_status`, `latest_outcome`, `latest_content_sha256`, `etag`, `last_modified`, `first_seen_at`, `last_fetched_at`, `last_changed_at`) `[0001_tracking.sql:pages]`
- `CREATE INDEX pages_host_fetched_idx ON pages(host, last_fetched_at)` `[0001_tracking.sql:pages_host_fetched_idx]`
- `CREATE TABLE fetches (...) STRICT` (`id TEXT PRIMARY KEY`, `job_id`, `request_id`, `crawl_id`, `page_id`, `site_id`, `via`, `final_host`, `status`, `outcome`, `robots_decision`, `problem`, `attempts`, `duration_ms`, `ttfb_ms`, `content_sha256`, `blob_sha256`, `fetched_at`) `[0001_tracking.sql:fetches]`
- `CREATE INDEX fetches_page_time_idx ON fetches(page_id, fetched_at DESC)` `[0001_tracking.sql:fetches_page_time_idx]`
- `CREATE INDEX fetches_crawl_time_idx ON fetches(crawl_id, fetched_at DESC)` `[0001_tracking.sql:fetches_crawl_time_idx]`
- `CREATE TABLE documents (...) STRICT` (`id TEXT PRIMARY KEY`, `content_sha256`, `format`, `pipeline_version`, `r2_key`, `title`, `language`, `bytes`, `created_at`) `[0001_tracking.sql:documents]`

## Invariants
- All five tables (`artifacts`, `crawls`, `pages`, `fetches`, `documents`) enforce SQLite `STRICT` column typing (`TEXT` / `INTEGER`) `[0001_tracking.sql:artifacts]` `[0001_tracking.sql:crawls]` `[0001_tracking.sql:pages]` `[0001_tracking.sql:fetches]` `[0001_tracking.sql:documents]`.
- `artifacts.r2_key` is `UNIQUE`, `artifacts.retention` enforces `CHECK (retention IN ('transient', 'stored'))`, and `artifacts.encoding` enforces `CHECK (encoding IN ('gzip'))` `[0001_tracking.sql:artifacts]`.
- `crawls.status` enforces `CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'))`, with `discovered_count`, `fetched_count`, and `failed_count` defaulting to `0` `[0001_tracking.sql:crawls]`.
- `pages.url` enforces `UNIQUE` canonical page identity `[0001_tracking.sql:pages]`.
- `fetches` enforces `UNIQUE (job_id, request_id)`, `CHECK (robots_decision IN ('allowed', 'disallowed', 'unreachable', 'not_checked'))`, required foreign key `page_id NOT NULL REFERENCES pages(id)`, and nullable foreign keys `crawl_id REFERENCES crawls(id)` and `blob_sha256 REFERENCES artifacts(blob_sha256)` `[0001_tracking.sql:fetches]`.
- `documents` enforces `UNIQUE (content_sha256, format, pipeline_version)` `[0001_tracking.sql:documents]`.

## Side Effects
- Executes DDL `CREATE TABLE` statements creating `artifacts`, `crawls`, `pages`, `fetches`, and `documents` in the target SQLite / D1 database `[0001_tracking.sql:artifacts]` `[0001_tracking.sql:crawls]` `[0001_tracking.sql:pages]` `[0001_tracking.sql:fetches]` `[0001_tracking.sql:documents]`.
- Executes DDL `CREATE INDEX` statements creating `artifacts_content_idx`, `pages_host_fetched_idx`, `fetches_page_time_idx`, and `fetches_crawl_time_idx` `[0001_tracking.sql:artifacts_content_idx]` `[0001_tracking.sql:pages_host_fetched_idx]` `[0001_tracking.sql:fetches_page_time_idx]` `[0001_tracking.sql:fetches_crawl_time_idx]`.

## Verification
- Run: `npm --prefix hub test`
