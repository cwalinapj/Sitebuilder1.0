-- Expand site_scan_results to store richer inspector intelligence.
-- Adds addresses + DNS/infra/vendor profiles used for personalization.

PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS site_scan_results_next (
  request_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  url TEXT NOT NULL,
  final_url TEXT,
  title TEXT,
  h1 TEXT,
  meta_description TEXT,
  emails_json TEXT NOT NULL,
  phones_json TEXT NOT NULL,
  addresses_json TEXT NOT NULL DEFAULT '[]',
  socials_json TEXT NOT NULL,
  platform_hint TEXT,
  schema_types_json TEXT NOT NULL,
  dns_json TEXT,
  infrastructure_json TEXT,
  vendors_json TEXT,
  raw_size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

INSERT OR REPLACE INTO site_scan_results_next (
  request_id,
  session_id,
  url,
  final_url,
  title,
  h1,
  meta_description,
  emails_json,
  phones_json,
  addresses_json,
  socials_json,
  platform_hint,
  schema_types_json,
  dns_json,
  infrastructure_json,
  vendors_json,
  raw_size,
  created_at
)
SELECT
  request_id,
  session_id,
  url,
  final_url,
  title,
  h1,
  meta_description,
  emails_json,
  phones_json,
  '[]' AS addresses_json,
  socials_json,
  platform_hint,
  schema_types_json,
  NULL AS dns_json,
  NULL AS infrastructure_json,
  NULL AS vendors_json,
  raw_size,
  created_at
FROM site_scan_results;

DROP TABLE site_scan_results;
ALTER TABLE site_scan_results_next RENAME TO site_scan_results;

CREATE INDEX IF NOT EXISTS idx_site_scan_results_session_created
ON site_scan_results (session_id, created_at DESC);

PRAGMA foreign_keys = ON;
