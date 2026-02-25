-- Bring schema in sync with onboarding + inspector workers.

CREATE TABLE IF NOT EXISTS session_vars (
  session_id TEXT NOT NULL,
  block_id TEXT NOT NULL,
  independent_json TEXT NOT NULL,
  dependent_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, block_id)
);

CREATE TABLE IF NOT EXISTS convo_events (
  session_id TEXT NOT NULL,
  turn_id INTEGER NOT NULL,
  speaker TEXT NOT NULL,
  state TEXT,
  text TEXT NOT NULL,
  ts INTEGER NOT NULL,
  PRIMARY KEY (session_id, turn_id, speaker)
);

CREATE INDEX IF NOT EXISTS idx_convo_events_session_turn
ON convo_events (session_id, turn_id);

CREATE TABLE IF NOT EXISTS site_scan_requests (
  request_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  url TEXT NOT NULL,
  status TEXT NOT NULL, -- running | done | failed
  error TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_site_scan_requests_session_created
ON site_scan_requests (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS site_scan_results (
  request_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  url TEXT NOT NULL,
  final_url TEXT,
  title TEXT,
  h1 TEXT,
  meta_description TEXT,
  emails_json TEXT NOT NULL,
  phones_json TEXT NOT NULL,
  socials_json TEXT NOT NULL,
  platform_hint TEXT,
  schema_types_json TEXT NOT NULL,
  raw_size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS market_search_results (
  request_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  business_type TEXT NOT NULL,
  location TEXT,
  source TEXT NOT NULL, -- openai_web_search | duckduckgo
  results_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_market_search_session_created
ON market_search_results (session_id, created_at DESC);
