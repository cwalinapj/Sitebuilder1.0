ALTER TABLE customers ADD COLUMN notes TEXT;

CREATE INDEX IF NOT EXISTS idx_customers_last_active_at
ON customers (last_active_at DESC);
