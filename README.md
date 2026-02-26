# Sitebuilder1.0

Static site builder that reads `business_profile.json`, auto-categorizes the business, and renders a deployable site into `/site`.

## Build

```bash
python3 src/build.py
```

## Test

```bash
npm test
```

```bash
python3 -m unittest discover -s src/tests -t . -p 'test_*.py'
```

## Categories

`src/categorize.py` returns one of: `plumber`, `electrician`, `barber`, `restaurant`, `general`.

## Deployment

GitHub Actions workflow at `.github/workflows/pages.yml` builds `/site` and deploys to Cloudflare Pages when the required secrets are configured.

Before first deploy, create the Vectorize indexes (768 dimensions, cosine metric):

```bash
npm run vectorize:create
```

## Workers

This repo now runs as two Cloudflare Workers:

1. **Onboarding worker** (`worker/index.js`, `wrangler.toml`)
2. **Inspector worker** (`SitebuilderInspector/worker.js`, `SitebuilderInspector/wrangler.toml`)

The onboarding worker orchestrates chat state and triggers the inspector worker to scan existing customer websites.

### Onboarding Worker Endpoints

- `POST /q1/start`
- `GET /auth/wallet/challenge?provider=...&protocol=...` (wallet sign-in nonce/message)
- `POST /q1/answer`
- `GET /build/brief?session_id=...` (internal-only compiled build prompt for site engine)
- `GET /billing/config` (premium hybrid model + pricing constants)
- `GET /billing/status?session_id=...` (session premium token/point balance + quote status)
- `POST /billing/quote` (estimate premium build cost in active charge unit)
- `GET /billing/points/options?session_id=...` (point-pack + ad-reward availability)
- `POST /billing/spl/credit` (SPL payment webhook crediting session tokens)
- `POST /billing/points/credit` (app-points credit webhook for non-wallet sessions)
- `POST /billing/points/ad/reward` (signed ad-completion reward credit)
- `POST /q1/scan/start` (manual scan trigger)
- `GET /q1/scan/status?session_id=...` (scan status/result bridge)
- `GET /security/config` (Turnstile frontend config)
- `GET /funnel/status?session_id=...` (conversion stage + CTA actions)
- `POST /funnel/signal` (external/plugin signal ingestion)
- `POST /plugin/connect/start` (start WordPress plugin + Cloudflare connect flow)
- `POST /plugin/connect/verify` (verify TollDNS + Cloudflare token + GitHub connection requirement and persist masked metadata)
- `POST /plugin/wp/comments/moderate` (signed WordPress comment moderation decision endpoint)
- `POST /plugin/wp/audit/sync` (signed WordPress telemetry sync for audit counts)
- `POST /plugin/wp/access/profile` (signed WordPress access profile sync; stores usernames/public keys/scoped tokens, rejects plaintext passwords)
- `POST /plugin/wp/schema/profile` (signed WordPress schema profile fetch for plugin JSON-LD injection)
- `POST /plugin/wp/redirects/profile` (signed broken-link redirect profile for plugin 301 fallback rules)
- `POST /plugin/wp/secrets/vault` (signed direct secret upload; encrypts and stores masked metadata in Worker vault state)
- `POST /plugin/wp/sandbox/preflight` (signed non-persistent plugin-update sandbox preflight report)

### Inspector Worker Endpoints

- `POST /inspect` (runs page scan and stores result + DNS/infra/vendor intelligence)
- `GET /inspect/status?session_id=...` (latest scan status + normalized result payload)
- `POST /market/nearby` (find top reference websites by business type + location)

## Second Worker Wiring

`wrangler.toml` includes a service binding:

- `INSPECTOR` -> `sitebuilder-inspector`

If service bindings are unavailable in your environment, set:

- `INSPECTOR_BASE_URL` to the inspector worker URL.
- `DEMO_PUBLIC_BASE_URL` to a public base URL that serves R2 demo HTML keys.
- `DEMO_ASSET_CACHE_CONTROL` and `DEMO_HTML_CACHE_CONTROL` to tune cache behavior for demo static assets in R2.
- `CORS_ALLOWED_ORIGINS` (comma-separated) for custom frontend domains, for example `https://app.cardetailingreno.com`.
- `WP_PLUGIN_SHARED_SECRET` for HMAC verification from the WordPress plugin.
- `WALLETCONNECT_PROJECT_ID` to enable WalletConnect/Ledger wallet sign-in from the frontend UI.
- `BUILD_BRIEF_DEBUG_KEY` to protect internal `/build/brief` access.
- Premium metering:
  - `PREMIUM_BUILDER_ENABLED`
  - `PREMIUM_WALLET_REQUIRED`
  - `PREMIUM_POINTS_ENABLED`
  - `PREMIUM_SPL_SYMBOL`
  - `PREMIUM_POINTS_SYMBOL`
  - `PREMIUM_FREE_TOKENS`
  - `PREMIUM_FREE_POINTS`
  - `PREMIUM_TOKENS_PER_SPL`
  - `PREMIUM_POINTS_PER_TOKEN`
  - `PREMIUM_BASE_COST_TOKENS`
  - `PREMIUM_PER_PAGE_COST_TOKENS`
  - `PREMIUM_PER_30_WORD_COST_TOKENS`
  - `PREMIUM_COMPLEXITY_UNIT_COST_TOKENS`
  - `PREMIUM_TOPUP_URL`
  - `PREMIUM_POINTS_TOPUP_URL`
  - `PREMIUM_POINTS_PACK_PRICE_USD`
  - `PREMIUM_POINTS_PACK_AMOUNT`
  - `PREMIUM_POINTS_CHECKOUT_URL`
  - `PREMIUM_AD_REWARDS_ENABLED`
  - `PREMIUM_AD_REWARD_POINTS`
  - `PREMIUM_AD_REWARD_COOLDOWN_SEC`
  - `PREMIUM_SPL_WEBHOOK_SECRET` (optional HMAC verification for `/billing/spl/credit`)
  - `PREMIUM_POINTS_WEBHOOK_SECRET` (optional HMAC verification for `/billing/points/credit`)
  - `PREMIUM_AD_REWARD_WEBHOOK_SECRET` (optional HMAC verification for `/billing/points/ad/reward`)

## New Flow (Localized References + Preference Memory)

When the user agrees to view examples:

1. Onboarding worker sends business type + geolocation (derived from client IP metadata) to inspector worker.
2. Inspector worker searches for nearby/top industry websites:
   - Prioritizes direct business websites and filters directory/aggregator pages.
   - Can extract business websites from Yelp listing pages while avoiding Yelp search/list links.
   - Uses OpenAI web search if `OPENAI_API_KEY` exists.
   - Falls back to DuckDuckGo when OpenAI is unavailable.
3. Chat returns a reference link and opens it in a new tab.
4. User likes/dislikes are captured and persisted in:
   - `session_vars` in D1
   - `preferences/<session_id>.json` in R2
5. At the end of onboarding, a static demo HTML file is generated and stored to:
   - `demos/<session_id>/index.html` in R2
   - `demos/<session_id>/assets/*` (hashed CSS/JS/SVG) in R2 with long-lived immutable cache headers
   - If `DEMO_PUBLIC_BASE_URL` is configured, the user receives a public URL immediately.

## Business Type Confirmation + Memory

- If the initial heuristic guess is too broad (for example `local business`), the onboarding worker asks OpenAI for likely subtypes (for example `auto repair shop`, `mechanic shop`, `tire repair shop`).
- The user must explicitly confirm the selected type before it is saved.
- Confirmed mappings from free-text description to canonical type are saved in D1 for future sessions.
- The flow is server-state-locked to prevent question skipping via client-side state tampering.
- New repo-seller intent path:
  - Descriptions like "I develop web repos for sale" infer `developer repo marketplace`.
  - Worker silently compiles a high-quality build brief prompt in `dependent.build_brief`.
  - Internal systems can fetch that prompt through `/build/brief` for generation without extra user friction.

## Premium Hybrid Billing (Implemented)

- Standard chat flow (name-based) continues to work without premium generation.
- Premium long-form build instructions are metered by estimated complexity and page count:
  - 5-page builds cost more tokens than 1-page builds.
- Wallet-authenticated users are charged in premium tokens (SPL top-up path).
- Non-wallet users are charged in app points (points top-up path).
- Public APIs expose only active-unit quotes (no public point/token conversion ratios).
- Premium flow:
  1. User submits advanced build instruction.
  2. Worker creates a quote in the session's active unit (`tokens` or `points`) and moves to `Q_PREMIUM_CONFIRM`.
  3. On `yes`, the active-unit balance is charged and premium mode is activated for the session.
  4. If balance is insufficient, user is prompted to top up using the active unit path.

- Free trial credits:
  - New wallet-authenticated sessions receive `PREMIUM_FREE_TOKENS`.
  - New non-wallet sessions receive `PREMIUM_FREE_POINTS` when points mode is enabled.
- Monetization options:
  - Point packs (default `$9.99`) via standard merchant checkout URL.
  - Optional ad-reward points for users who watch verified ads.

## Database Migrations

Apply all migration files:

- `migrations/0001_init.sql`
- `migrations/0002_onboarding_and_scan.sql`
- `migrations/0003_business_type_memory.sql`
- `migrations/0004_site_scan_intelligence.sql`
- `migrations/0005_site_scan_link_audit.sql`

## Security Hardening (Implemented)

1. **Turnstile challenge on session start**
- Worker verifies `turnstile_token` against Cloudflare Turnstile before creating a session.
- Configure:
  - `TURNSTILE_SITE_KEY` in `wrangler.toml` vars (public key)
  - `TURNSTILE_SECRET_KEY` via secret:
    - `wrangler secret put TURNSTILE_SECRET_KEY`

2. **Expensive action gating**
- Scan/search/build actions require a security-verified session.
- If verification is missing, worker returns `SECURITY_VERIFICATION_REQUIRED`.

3. **In-worker abuse throttling**
- Per-IP limits are applied for:
  - `/q1/start`
  - `/q1/answer`
  - `/q1/scan/start`
  - `/q1/scan/status`
  - Inspector `/inspect`, `/inspect/status`, `/market/nearby`

4. **Source map leakage protection**
- `public/_redirects` blocks `*.map` requests with `404`.
- `.gitignore` now excludes `*.map`.

## Public Lead-Gen Funnel (Implemented)

The worker now tracks upgrade intent signals in session state and emits CTA actions in responses:

1. `forms_enabled`
2. `traffic_over_threshold`
3. `multiple_edits`
4. `custom_domain_requested`

Funnel stage is computed as:

1. `demo_only`
2. `ready_for_connect`
3. `ready_for_migration`

CTA URLs are configured via:

1. `CONNECT_CLOUDFLARE_URL`
2. `MIGRATE_HOSTING_URL`
3. `DUAL_SERVER_UPGRADE_URL`
4. `UPGRADE_PAYPAL_URL`
5. `UPGRADE_CRYPTO_URL`
6. `FREE_VPS_BRIDGE_URL`
7. `FREE_VPS_OFFER_WINDOW_DAYS` (default `30`)
8. `PLUGIN_FREE_URL`
9. `TOLLDNS_URL`
10. `GITHUB_SIGNUP_URL`
11. `UPGRADE_TRAFFIC_THRESHOLD`

Dual-server upgrade offer rules:

1. Offer appears when session reaches `ready_for_migration` (or user explicitly asks for high availability/dual server/failover).
2. Billing is month-to-month only.
3. Auto-enrollment/auto-renew is disabled.
4. Payment methods shown are PayPal and Crypto only (when URLs are configured).
5. If domain/managed-hosting expiry is in the configured pre-renewal window (default 30 days), the Free VPS Bridge CTA is shown.

## WordPress Offer Flow (Implemented)

When a user confirms they own a site and the scan identifies `platform_hint=wordpress`:

1. Chat offers a WordPress security + speed + schema audit.
2. Audit includes operational counts when plugin telemetry is available:
   - `email_queue_count`
   - `outdated_plugin_count`
   - `inactive_plugin_count`
   - `redundant_plugin_count`
   - `sso_plugin_count`
   - `pending_comment_moderation_count`
   - `broken_link_count`
3. Chat can start a guided schema Q&A flow, saves user-confirmed schema profile, and exposes it to plugin sync.
4. Audit includes projected improvement ranges by category:
   - speed points
   - security points
   - schema points
   - reliability points
5. Scan results persist infrastructure + personalization signals:
   - domain registrar
   - domain expiration date (when available)
   - nameservers
   - IP addresses
   - server hardware hints (public-scan limited)
   - hosting company hint
   - DNS-derived email provider
   - detected third-party vendors (CRM, merchanting/payments, booking, etc.)
   - broken internal links (count + paths) for redirect remediation
6. Plugin can sync audited broken paths and apply 301 fallback redirects to homepage for dead internal URLs.
7. Chat can recommend wp-admin SSO hardening via Cloudflare Access (Google/Facebook IdP) without FTP/SSH.
8. Access vault policy: plaintext passwords are blocked. Use scoped API tokens + SSH public-key auth.
9. Expiry-driven migration policy: when expiry enters the month-before window, offer free VPS bridge hosting so customer can cancel shared hosting on time while site continuity stays on Cloudflare + GitHub.

## WordPress Plugin (Comment Moderation MVP)

Plugin source in:

- `wordpress-plugin/ai-webadmin`

The plugin can send new comments to Worker moderation and automatically set status to:

1. `approve`
2. `hold`
3. `spam`
4. `trash`

Security model:

1. HMAC signature header (`X-Plugin-Signature`)
2. Timestamp header (`X-Plugin-Timestamp`) with replay window checks
3. Shared secret configured as `WP_PLUGIN_SHARED_SECRET`

## Edge WAF Rules

Recommended Cloudflare WAF/Rate Limiting rules are included at:

- `cloudflare/waf-rules.md`
- `cloudflare/plugin-onboarding-spec.md`
