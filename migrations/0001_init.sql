-- Users / sessions
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

-- Events (for trend learning + explainability)
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_id TEXT,
  event_type TEXT NOT NULL,        -- like|dislike|view|choose|publish|question_answer
  payload_json TEXT NOT NULL,      -- raw structured event
  created_at INTEGER NOT NULL
);

-- Purchases & upsells
CREATE TABLE IF NOT EXISTS purchases (
  purchase_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  sku TEXT NOT NULL,               -- e.g. premium_isotope
  amount_usd_cents INTEGER NOT NULL,
  status TEXT NOT NULL,            -- pending|paid|refunded
  created_at INTEGER NOT NULL
);

-- Patron rewards / points ledger (closed-loop credits)
CREATE TABLE IF NOT EXISTS credits_ledger (
  ledger_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  reason TEXT NOT NULL,            -- purchase|patron_reward|promo|manual
  delta_cents INTEGER NOT NULL,    -- + credits, - redemption
  ref_id TEXT,                     -- purchase_id or other reference
  created_at INTEGER NOT NULL
);

-- Premium SKU config (so you can change rules without code)
CREATE TABLE IF NOT EXISTS premium_skus (
  sku TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  patron_reward_cents INTEGER NOT NULL, -- how much to pay patron per subsequent purchase
  patron_cap_cents INTEGER NOT NULL     -- hard cap (keeps it from sounding like “income stream”)
);
