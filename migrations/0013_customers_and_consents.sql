CREATE TABLE IF NOT EXISTS customers (
  customer_id TEXT PRIMARY KEY,
  primary_user_id TEXT,
  primary_session_id TEXT,
  first_name TEXT,
  last_name TEXT,
  wallet_address TEXT,
  wallet_chain_id INTEGER,
  email TEXT,
  phone TEXT,
  business_name TEXT,
  business_description TEXT,
  business_type TEXT,
  business_subtype TEXT,
  website_url TEXT,
  reference_site_url TEXT,
  service_area TEXT,
  address TEXT,
  goal TEXT,
  vibe TEXT,
  colors TEXT,
  consent_training INTEGER,
  consent_followup INTEGER,
  consent_marketing INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_active_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_customers_email
ON customers (email);

CREATE INDEX IF NOT EXISTS idx_customers_wallet
ON customers (wallet_address, wallet_chain_id);

CREATE INDEX IF NOT EXISTS idx_customers_business_type
ON customers (business_type, business_subtype);

CREATE TABLE IF NOT EXISTS customer_identities (
  identity_type TEXT NOT NULL,
  identity_value TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (identity_type, identity_value),
  FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_customer_identities_customer
ON customer_identities (customer_id, identity_type);

CREATE TABLE IF NOT EXISTS customer_sessions (
  session_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  linked_at INTEGER NOT NULL,
  linkage_source TEXT NOT NULL,
  FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE INDEX IF NOT EXISTS idx_customer_sessions_customer
ON customer_sessions (customer_id, linked_at DESC);
