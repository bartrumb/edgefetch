CREATE TABLE artifacts (
  blob_sha256 TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  r2_key TEXT NOT NULL UNIQUE,
  retention TEXT NOT NULL CHECK (retention IN ('transient', 'stored')),
  encoding TEXT NOT NULL CHECK (encoding IN ('gzip')),
  stored_bytes INTEGER NOT NULL,
  content_bytes INTEGER NOT NULL,
  content_type TEXT,
  verified_at INTEGER,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
) STRICT;

CREATE INDEX artifacts_content_idx ON artifacts(content_sha256);

CREATE TABLE crawls (
  id TEXT PRIMARY KEY,
  root_url TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  options_json TEXT NOT NULL,
  workflow_instance_id TEXT,
  discovered_count INTEGER NOT NULL DEFAULT 0,
  fetched_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  finished_at INTEGER
) STRICT;

CREATE TABLE pages (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  latest_fetch_id TEXT,
  latest_status INTEGER,
  latest_outcome TEXT,
  latest_content_sha256 TEXT,
  etag TEXT,
  last_modified TEXT,
  first_seen_at INTEGER NOT NULL,
  last_fetched_at INTEGER,
  last_changed_at INTEGER
) STRICT;

CREATE INDEX pages_host_fetched_idx ON pages(host, last_fetched_at);

CREATE TABLE fetches (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  crawl_id TEXT REFERENCES crawls(id),
  page_id TEXT NOT NULL REFERENCES pages(id),
  site_id TEXT,
  via TEXT NOT NULL,
  final_host TEXT,
  status INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  robots_decision TEXT NOT NULL CHECK (robots_decision IN ('allowed', 'disallowed', 'unreachable', 'not_checked')),
  problem TEXT,
  attempts INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  ttfb_ms INTEGER,
  content_sha256 TEXT,
  blob_sha256 TEXT REFERENCES artifacts(blob_sha256),
  fetched_at INTEGER NOT NULL,
  UNIQUE (job_id, request_id)
) STRICT;

CREATE INDEX fetches_page_time_idx ON fetches(page_id, fetched_at DESC);

CREATE INDEX fetches_crawl_time_idx ON fetches(crawl_id, fetched_at DESC);

CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  format TEXT NOT NULL,
  pipeline_version INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  title TEXT,
  language TEXT,
  bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (content_sha256, format, pipeline_version)
) STRICT;
