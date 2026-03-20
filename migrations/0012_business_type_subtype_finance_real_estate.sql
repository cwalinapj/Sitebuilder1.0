PRAGMA foreign_keys = ON;

INSERT OR REPLACE INTO business_type_subtype_catalog (
  subtype_key, canonical_type, display_label, category, is_active, created_at, updated_at
) VALUES
  ('property appraisal service', 'real estate agency', 'Property Appraisal Service', 'finance_and_real_estate_specialties', 1, 1742428800000, 1742428800000),
  ('real estate photography', 'photography studio', 'Real Estate Photography', 'finance_and_real_estate_specialties', 1, 1742428800000, 1742428800000),
  ('mortgage brokerage', 'mortgage broker', 'Mortgage Brokerage', 'finance_and_real_estate_specialties', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_alias_catalog (
  alias_phrase, subtype_key, source, is_active, created_at, updated_at
) VALUES
  ('property appraiser', 'property appraisal service', 'seed', 1, 1742428800000, 1742428800000),
  ('real estate appraiser', 'property appraisal service', 'seed', 1, 1742428800000, 1742428800000),
  ('property valuation service', 'property appraisal service', 'seed', 1, 1742428800000, 1742428800000),
  ('real estate photographer', 'real estate photography', 'seed', 1, 1742428800000, 1742428800000),
  ('property photographer', 'real estate photography', 'seed', 1, 1742428800000, 1742428800000),
  ('listing photographer', 'real estate photography', 'seed', 1, 1742428800000, 1742428800000),
  ('loan officer', 'mortgage brokerage', 'seed', 1, 1742428800000, 1742428800000),
  ('home loan specialist', 'mortgage brokerage', 'seed', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_signal_catalog (
  subtype_key, signal_type, value, normalized_value, weight, notes, is_active, created_at, updated_at
) VALUES
  ('property appraisal service', 'profession', 'property appraiser', 'property appraiser', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('property appraisal service', 'profession', 'real estate appraiser', 'real estate appraiser', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('property appraisal service', 'service', 'property valuation', 'property valuation', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('real estate photography', 'profession', 'real estate photographer', 'real estate photographer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('real estate photography', 'industry_term', 'listing photos', 'listing photos', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('real estate photography', 'industry_term', 'property photos', 'property photos', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('mortgage brokerage', 'profession', 'loan officer', 'loan officer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('mortgage brokerage', 'profession', 'mortgage broker', 'mortgage broker', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('mortgage brokerage', 'service', 'home loans', 'home loans', 2.6, NULL, 1, 1742428800000, 1742428800000);
