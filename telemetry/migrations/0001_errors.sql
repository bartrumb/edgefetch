-- Opt-In Structural Dev Error Fingerprint Store (`telemetry/migrations/0001_errors.sql`)
-- Zero URLs, zero hostnames, zero paths, zero content, zero tokens — deduplicated strictly by structural SHA-256 fingerprint.

CREATE TABLE IF NOT EXISTS error_fingerprints (
  fingerprint TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL DEFAULT 1,
  version TEXT NOT NULL,
  runtime TEXT NOT NULL,
  os TEXT NOT NULL,
  arch TEXT NOT NULL,
  mode TEXT NOT NULL,
  span_name TEXT NOT NULL,
  adapter_id TEXT NOT NULL DEFAULT '',
  waf_vendor TEXT NOT NULL DEFAULT '',
  http_status INTEGER NOT NULL DEFAULT 0,
  error_class TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_error_fingerprints_count_recent
  ON error_fingerprints (count DESC, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_error_fingerprints_adapter
  ON error_fingerprints (adapter_id, count DESC, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_error_fingerprints_last_seen
  ON error_fingerprints (last_seen_at DESC, count DESC);

CREATE INDEX IF NOT EXISTS idx_error_fingerprints_evict
  ON error_fingerprints (count ASC, last_seen_at ASC);
