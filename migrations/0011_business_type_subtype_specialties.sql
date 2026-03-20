PRAGMA foreign_keys = ON;

INSERT OR REPLACE INTO business_type_subtype_catalog (
  subtype_key, canonical_type, display_label, category, is_active, created_at, updated_at
) VALUES
  ('family law firm', 'law firm', 'Family Law Firm', 'legal_specialties', 1, 1742428800000, 1742428800000),
  ('personal injury attorney', 'law firm', 'Personal Injury Attorney', 'legal_specialties', 1, 1742428800000, 1742428800000),
  ('immigration law firm', 'law firm', 'Immigration Law Firm', 'legal_specialties', 1, 1742428800000, 1742428800000),
  ('estate planning attorney', 'law firm', 'Estate Planning Attorney', 'legal_specialties', 1, 1742428800000, 1742428800000),
  ('tax attorney', 'law firm', 'Tax Attorney', 'legal_specialties', 1, 1742428800000, 1742428800000),
  ('orthodontic practice', 'dental office', 'Orthodontic Practice', 'medical_specialties', 1, 1742428800000, 1742428800000),
  ('cosmetic dentistry practice', 'dental office', 'Cosmetic Dentistry Practice', 'medical_specialties', 1, 1742428800000, 1742428800000),
  ('urgent care clinic', 'medical clinic', 'Urgent Care Clinic', 'medical_specialties', 1, 1742428800000, 1742428800000),
  ('dermatology clinic', 'medical clinic', 'Dermatology Clinic', 'medical_specialties', 1, 1742428800000, 1742428800000),
  ('pediatrics clinic', 'medical clinic', 'Pediatrics Clinic', 'medical_specialties', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_alias_catalog (
  alias_phrase, subtype_key, source, is_active, created_at, updated_at
) VALUES
  ('family lawyer', 'family law firm', 'seed', 1, 1742428800000, 1742428800000),
  ('divorce lawyer', 'family law firm', 'seed', 1, 1742428800000, 1742428800000),
  ('custody lawyer', 'family law firm', 'seed', 1, 1742428800000, 1742428800000),
  ('accident lawyer', 'personal injury attorney', 'seed', 1, 1742428800000, 1742428800000),
  ('injury lawyer', 'personal injury attorney', 'seed', 1, 1742428800000, 1742428800000),
  ('immigration lawyer', 'immigration law firm', 'seed', 1, 1742428800000, 1742428800000),
  ('visa lawyer', 'immigration law firm', 'seed', 1, 1742428800000, 1742428800000),
  ('wills and trusts lawyer', 'estate planning attorney', 'seed', 1, 1742428800000, 1742428800000),
  ('irs lawyer', 'tax attorney', 'seed', 1, 1742428800000, 1742428800000),
  ('orthodontist', 'orthodontic practice', 'seed', 1, 1742428800000, 1742428800000),
  ('braces clinic', 'orthodontic practice', 'seed', 1, 1742428800000, 1742428800000),
  ('cosmetic dentist', 'cosmetic dentistry practice', 'seed', 1, 1742428800000, 1742428800000),
  ('walk in clinic', 'urgent care clinic', 'seed', 1, 1742428800000, 1742428800000),
  ('skin doctor', 'dermatology clinic', 'seed', 1, 1742428800000, 1742428800000),
  ('pediatrician office', 'pediatrics clinic', 'seed', 1, 1742428800000, 1742428800000);

INSERT OR REPLACE INTO business_type_subtype_signal_catalog (
  subtype_key, signal_type, value, normalized_value, weight, notes, is_active, created_at, updated_at
) VALUES
  ('family law firm', 'profession', 'family lawyer', 'family lawyer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('family law firm', 'service', 'divorce', 'divorce', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('family law firm', 'service', 'custody', 'custody', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('personal injury attorney', 'profession', 'injury lawyer', 'injury lawyer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('personal injury attorney', 'service', 'personal injury', 'personal injury', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('personal injury attorney', 'industry_term', 'accident claims', 'accident claims', 2.2, NULL, 1, 1742428800000, 1742428800000),
  ('immigration law firm', 'profession', 'immigration lawyer', 'immigration lawyer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('immigration law firm', 'service', 'visa services', 'visa services', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('immigration law firm', 'service', 'green card', 'green card', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('estate planning attorney', 'profession', 'estate lawyer', 'estate lawyer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('estate planning attorney', 'service', 'wills and trusts', 'wills and trusts', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('tax attorney', 'profession', 'tax lawyer', 'tax lawyer', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('tax attorney', 'service', 'tax disputes', 'tax disputes', 2.6, NULL, 1, 1742428800000, 1742428800000),
  ('orthodontic practice', 'profession', 'orthodontist', 'orthodontist', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('orthodontic practice', 'service', 'braces', 'braces', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('orthodontic practice', 'service', 'invisalign', 'invisalign', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('cosmetic dentistry practice', 'profession', 'cosmetic dentist', 'cosmetic dentist', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('cosmetic dentistry practice', 'service', 'veneers', 'veneers', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('cosmetic dentistry practice', 'service', 'smile makeover', 'smile makeover', 2.4, NULL, 1, 1742428800000, 1742428800000),
  ('urgent care clinic', 'strong_keyword', 'urgent care', 'urgent care', 3.0, NULL, 1, 1742428800000, 1742428800000),
  ('urgent care clinic', 'industry_term', 'walk in clinic', 'walk in clinic', 2.5, NULL, 1, 1742428800000, 1742428800000),
  ('dermatology clinic', 'profession', 'dermatologist', 'dermatologist', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('dermatology clinic', 'industry_term', 'skin doctor', 'skin doctor', 2.8, NULL, 1, 1742428800000, 1742428800000),
  ('pediatrics clinic', 'profession', 'pediatrician', 'pediatrician', 4.0, NULL, 1, 1742428800000, 1742428800000),
  ('pediatrics clinic', 'industry_term', 'child health', 'child health', 2.2, NULL, 1, 1742428800000, 1742428800000);
