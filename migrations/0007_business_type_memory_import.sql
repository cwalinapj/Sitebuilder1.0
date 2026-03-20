-- Import currently confirmed memory labels into the canonical D1 catalog
-- so both approved catalog labels and live user-confirmed labels live in one source of truth.

INSERT OR IGNORE INTO business_type_catalog (
  canonical_type,
  display_label,
  category,
  is_confirmed,
  is_active,
  created_at,
  updated_at
) VALUES
  ('auto detailing', 'Auto Detailing', 'automotive_and_travel', 1, 1, 1742428800000, 1742428800000),
  ('car', 'Car', 'needs_review', 1, 0, 1742428800000, 1742428800000),
  ('car detailing', 'Car Detailing', 'automotive_and_travel', 1, 1, 1742428800000, 1742428800000),
  ('car rental agency', 'Car Rental Agency', 'automotive_and_travel', 1, 1, 1742428800000, 1742428800000),
  ('developer repo marketplace', 'Developer Repo Marketplace', 'professional_services', 1, 1, 1742428800000, 1742428800000),
  ('dive services', 'Dive Services', 'automotive_and_travel', 1, 1, 1742428800000, 1742428800000),
  ('fishing charter', 'Fishing Charter', 'automotive_and_travel', 1, 1, 1742428800000, 1742428800000),
  ('freelance developer', 'Freelance Developer', 'professional_services', 1, 1, 1742428800000, 1742428800000),
  ('metal fabrication', 'Metal Fabrication', 'home_and_local_services', 1, 1, 1742428800000, 1742428800000),
  ('software sales', 'Software Sales', 'professional_services', 1, 1, 1742428800000, 1742428800000),
  ('web 3 development', 'Web 3 Development', 'professional_services', 1, 1, 1742428800000, 1742428800000),
  ('web development service', 'Web Development Service', 'professional_services', 1, 1, 1742428800000, 1742428800000);
