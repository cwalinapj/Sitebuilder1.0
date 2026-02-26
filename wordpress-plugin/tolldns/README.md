# TollDNS WordPress Plugin

TollDNS provides DNS readiness checks and a local points ledger so free-tier eligibility can be verified before AI WebAdmin features are fully enabled.

## What it does

1. Checks NS records for your monitored domain.
2. Supports strict matching for expected nameserver 1 + 2.
3. Awards/deducts points per check and stores a local ledger.
4. Runs hourly checks via WP-Cron.
5. Exposes admin summary in `Settings -> TollDNS`.

## Install

1. Upload `tolldns.zip` from `Plugins -> Add New -> Upload Plugin`.
2. Activate `TollDNS`.
3. Open `Settings -> TollDNS`.
4. Set:
   - Monitored domain
   - Expected nameserver 1
   - Expected nameserver 2
5. Click `Run Nameserver Check Now`.

## Notes

- AI WebAdmin detects TollDNS by plugin slug `tolldns/tolldns.php`.
- REST summary endpoint: `GET /wp-json/tolldns/v1/points` (admin capability required).
