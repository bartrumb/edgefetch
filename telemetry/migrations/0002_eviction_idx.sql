-- Eviction index protecting multi-hit (`count >= 2`) regressions (`telemetry/migrations/0002_eviction_idx.sql`)
CREATE INDEX IF NOT EXISTS idx_error_fingerprints_evict
  ON error_fingerprints (count ASC, last_seen_at ASC);
