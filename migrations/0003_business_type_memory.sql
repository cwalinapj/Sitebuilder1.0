-- Memory of user-confirmed business type mappings from free-text descriptions.

CREATE TABLE IF NOT EXISTS business_type_memory (
  phrase TEXT PRIMARY KEY,          -- normalized phrase from Q1 description
  canonical_type TEXT NOT NULL,     -- user-confirmed business type
  source TEXT NOT NULL,             -- heuristic | openai | manual | remembered
  confirmed_count INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_business_type_memory_updated
ON business_type_memory (updated_at DESC);
