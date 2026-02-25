# WordPress Plugin Onboarding + Token Scope Matrix

## Funnel Stages

1. Free demo on our infrastructure.
2. Connect Cloudflare for free 1-month hosting + subdomain activation.
3. Promote managed migration after value is proven.

## Value-Proven Upgrade Signals

1. `forms_enabled`
2. `traffic_over_threshold`
3. `multiple_edits`
4. `custom_domain_requested`

## API Token Strategy

Never request the Global API key. Use scoped API tokens only.

### MVP Token Scope (Connect + Basic Watchdog)

Use when user wants free month + subdomain + protected form handling.

1. Zone: Read
2. DNS: Edit (only if plugin needs to create/verify records)
3. Cache Purge: Purge (optional but useful)
4. Workers Scripts: Edit
5. Workers Routes: Edit
6. R2: Edit (bucket restricted if possible)
7. Turnstile: Edit (if auto-provisioning widgets)

Recommended restrictions:
1. Zone/resource scoping to selected zone only
2. Short TTL for provisioning token
3. IP restrictions to your backend egress IPs

### Advanced Token Scope (Managed Migration)

Use only after explicit migration consent.

1. Everything in MVP scope
2. Pages: Edit
3. Access: Edit (if plugin sets gated admin tools)
4. Additional DNS scopes required for full cutover automation

Apply as two-token model:
1. short-lived setup token
2. long-lived runtime token with narrower scope

## Plugin Onboarding Screens

1. **Welcome**
- Explain free demo flow and what data is collected.

2. **Connect Cloudflare**
- CTA to create/login Cloudflare.
- Explain why token is needed and what scopes are requested.

3. **Token Permissions Preview**
- Show exact requested permissions in plain language.
- Require explicit confirmation.

4. **Paste Token + Verify**
- User pastes scoped token.
- Plugin calls backend verification endpoint.

5. **Enable Features**
- Toggles for:
  - CDN/media acceleration
  - Worker form handler + Turnstile
  - Watchdog health checks
  - wp-admin SSO hardening with Cloudflare Access + Google/Facebook IdP

6. **Activation Complete**
- Show activated subdomain and free month expiration date.
- Show optional CTA: migrate to managed hosting.

7. **Migration Offer**
- Display only when upgrade signals indicate value.
- Include estimated migration time and rollback safety note.

## Backend/Plugin Responsibilities

Plugin:
1. collects consent and token
2. stores installation ID and short-lived auth context
3. forwards metrics/signals
4. sends signed comment moderation payloads to `POST /plugin/wp/comments/moderate`
5. sends signed audit telemetry payloads to `POST /plugin/wp/audit/sync`
6. pulls saved schema profile from `POST /plugin/wp/schema/profile` and injects JSON-LD when enabled
7. pulls broken-link profile from `POST /plugin/wp/redirects/profile` and applies 301 fallback redirects
8. applies returned moderation action (`approve|hold|spam|trash`) to local WP comments

Backend:
1. stores token securely (vault/secret manager)
2. executes Cloudflare API operations
3. rotates/revokes tokens
4. drives funnel stage logic from collected signals
5. verifies HMAC plugin signatures and timestamp replay window for moderation requests
