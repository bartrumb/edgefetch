CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  github_id TEXT UNIQUE,
  github_login TEXT NOT NULL,
  avatar_url TEXT,
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')) DEFAULT 'member',
  created_at INTEGER NOT NULL,
  last_login_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS users_github_login_idx ON users(github_login);

CREATE TABLE IF NOT EXISTS agent_runs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL DEFAULT 'owner',
  thread_id TEXT NOT NULL,
  status TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS agent_runs_user_idx ON agent_runs(user_id, created_at DESC);
