-- Round 10: Vault v2 secret_version column & OAuth refresh rotation / per-grant rate limit schema
CREATE TABLE IF NOT EXISTS user_mcp_servers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL DEFAULT 'owner',
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  remote_url TEXT NOT NULL,
  remote_origin TEXT NOT NULL,
  transport TEXT NOT NULL DEFAULT 'streamable-http',
  auth_type TEXT NOT NULL DEFAULT 'headers',
  encrypted_credentials TEXT,
  secret_version INTEGER NOT NULL DEFAULT 1,
  auth_summary_json TEXT NOT NULL DEFAULT '{}',
  domains_json TEXT NOT NULL DEFAULT '[]',
  auto_route_scrape INTEGER NOT NULL DEFAULT 0,
  cached_tools_json TEXT NOT NULL DEFAULT '[]',
  tool_count INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_verified_at INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (user_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_user_mcp_servers_user ON user_mcp_servers(user_id);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  resource TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT 'owner',
  user_role TEXT NOT NULL DEFAULT 'owner',
  used_at INTEGER,
  rotation_counter INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_grant ON oauth_tokens(grant_id);

CREATE TABLE IF NOT EXISTS oauth_grant_rate_limits (
  grant_id TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);
