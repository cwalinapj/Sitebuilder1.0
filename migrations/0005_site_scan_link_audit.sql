-- Add link audit JSON payload for broken internal link analysis.

ALTER TABLE site_scan_results ADD COLUMN link_audit_json TEXT;
