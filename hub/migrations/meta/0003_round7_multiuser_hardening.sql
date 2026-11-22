ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

ALTER TABLE crawls ADD COLUMN user_id TEXT NOT NULL DEFAULT 'owner';
CREATE INDEX IF NOT EXISTS crawls_user_idx ON crawls(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS catalog_runs (
  catalog_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL DEFAULT 'owner',
  origin TEXT NOT NULL,
  platform TEXT NOT NULL,
  collection TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  products_count INTEGER NOT NULL DEFAULT 0,
  variants_count INTEGER NOT NULL DEFAULT 0,
  pages_read INTEGER NOT NULL DEFAULT 0,
  artifact_id TEXT,
  hashes_json TEXT,
  summary_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_catalog_runs_origin_status ON catalog_runs(origin, collection, status, created_at);
CREATE INDEX IF NOT EXISTS idx_catalog_runs_user ON catalog_runs(user_id, created_at DESC);
