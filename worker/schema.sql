-- Proxiv3 D1 schema (Phase 0). Apply: wrangler d1 execute proxiv3_db --file=schema.sql
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS votes (
  proxy_key TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  vote INTEGER NOT NULL CHECK (vote IN (1, -1)),
  ts INTEGER NOT NULL,
  PRIMARY KEY (proxy_key, user_id)
);
CREATE TABLE IF NOT EXISTS processed_updates (
  update_id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL
);
